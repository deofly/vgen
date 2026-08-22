"""Validated public release metadata and an optional local file fallback.

Large public installers should normally be served by Nginx or an object store.
The Gateway reads the same small manifests so clients have one authenticated
control-plane endpoint for release discovery.  Development deployments may
explicitly enable the local file fallback; it only serves artifacts declared
by an immutable version manifest.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

_VERSION = re.compile(
    r"^[0-9]+(?:\.[0-9]+){2}(?:[-+][A-Za-z0-9][A-Za-z0-9.-]{0,63})?$"
)
_ARTIFACT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PUBLISHED_AT = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_CONTENT_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$"
)
_PLATFORMS = frozenset({"macos", "windows", "linux"})
_KINDS = frozenset({"cli-installer", "worker-installer"})
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 1024**5


class PublicReleaseArtifact(BaseModel):
    """Public, non-secret installer metadata returned to clients."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=_ARTIFACT_NAME.pattern)
    kind: Literal["cli-installer", "worker-installer"]
    platform: Literal["macos", "windows", "linux"]
    filename: str = Field(pattern=_FILENAME.pattern)
    size: int = Field(ge=1, le=_MAX_ARTIFACT_BYTES)
    sha256: str = Field(pattern=_SHA256.pattern)
    content_type: str = Field(pattern=_CONTENT_TYPE.pattern)
    url: str


class PublicReleaseManifest(BaseModel):
    """Materialized immutable release manifest."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    audience: Literal["public"] = "public"
    version: str = Field(pattern=_VERSION.pattern)
    published_at: str = Field(pattern=_PUBLISHED_AT.pattern)
    manifest_sha256: str = Field(pattern=_SHA256.pattern)
    artifacts: list[PublicReleaseArtifact]
    channel: Literal["stable"] | None = None


class ReleaseNotFound(LookupError):
    """The requested channel, version, or declared artifact does not exist."""


class ReleaseManifestInvalid(ValueError):
    """A release manifest violates the closed public metadata contract."""


@dataclass(frozen=True, slots=True)
class ReleaseFile:
    path: Path
    filename: str
    size: int
    sha256: str
    content_type: str


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    if not _regular_file(path):
        raise ReleaseNotFound
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ReleaseNotFound from exc
    if size <= 0 or size > _MAX_MANIFEST_BYTES:
        raise ReleaseManifestInvalid("release manifest size is invalid")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseManifestInvalid("release manifest contains a duplicate field")
            result[key] = value
        return result

    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseManifestInvalid("release manifest is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ReleaseManifestInvalid("release manifest must be a JSON object")
    return value, raw


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _closed_keys(value: dict[str, Any], expected: frozenset[str], *, label: str) -> None:
    if set(value) != expected:
        raise ReleaseManifestInvalid(f"{label} fields do not match the public contract")


def _safe_version(value: object) -> str:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ReleaseManifestInvalid("release version is invalid")
    return value


def _safe_filename(value: object) -> str:
    if not isinstance(value, str) or not _FILENAME.fullmatch(value) or ".." in value:
        raise ReleaseManifestInvalid("release filename is invalid")
    return value


def _public_base_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    if not candidate:
        raise ValueError("release public base URL must not be empty")
    parsed = urlsplit(candidate)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("release public base URL must not contain credentials, query, or fragment")
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.path:
            raise ValueError("release public base URL must be an HTTP(S) URL with a path")
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))
    if parsed.netloc or not candidate.startswith("/") or candidate.startswith("//"):
        raise ValueError("release public base URL must be an absolute path or HTTP(S) URL")
    if any(part in {"", ".", ".."} for part in candidate.removeprefix("/").split("/")):
        raise ValueError("release public base URL path is invalid")
    return candidate


class ReleaseCatalog:
    """Read a closed, public-only release directory.

    Directory layout::

        channels/stable.json
        0.3.0/manifest.json
        0.3.0/VGen-macOS-0.3.0.pkg
        0.3.0/VGen-Worker-Windows-0.3.0.exe

    ``channels/stable.json`` is a mutable pointer with the SHA-256 of the
    immutable version manifest.  Artifact URLs never point through the channel
    name, so caches cannot serve a new version under an old immutable URL.
    """

    def __init__(
        self,
        root: str | Path | None,
        *,
        public_base_url: str = "/releases",
        serve_files: bool = False,
    ) -> None:
        self.root = Path(root).expanduser().resolve(strict=False) if root else None
        self.public_base_url = _public_base_url(public_base_url)
        self.serve_files = bool(serve_files)

    def _path(self, *parts: str) -> Path:
        if self.root is None:
            raise ReleaseNotFound
        candidate = self.root.joinpath(*parts)
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise ReleaseManifestInvalid("release path escapes the configured root") from exc
        return candidate

    def _load_version(self, version: str) -> tuple[dict[str, Any], str]:
        version = _safe_version(version)
        manifest, raw = _read_json(self._path(version, "manifest.json"))
        _closed_keys(
            manifest,
            frozenset({"schema_version", "audience", "version", "published_at", "artifacts"}),
            label="version manifest",
        )
        if manifest.get("schema_version") != 1 or manifest.get("audience") != "public":
            raise ReleaseManifestInvalid("release manifest is not public schema version 1")
        if manifest.get("version") != version:
            raise ReleaseManifestInvalid("release manifest version does not match its path")
        published_at = manifest.get("published_at")
        if not isinstance(published_at, str) or not _PUBLISHED_AT.fullmatch(published_at):
            raise ReleaseManifestInvalid("release published_at is invalid")
        raw_artifacts = manifest.get("artifacts")
        if not isinstance(raw_artifacts, list) or not raw_artifacts or len(raw_artifacts) > 16:
            raise ReleaseManifestInvalid("release artifacts must be a non-empty bounded list")

        artifacts: list[dict[str, Any]] = []
        names: set[str] = set()
        filenames: set[str] = set()
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, dict):
                raise ReleaseManifestInvalid("release artifact must be an object")
            _closed_keys(
                raw_artifact,
                frozenset(
                    {"name", "kind", "platform", "filename", "size", "sha256", "content_type"}
                ),
                label="release artifact",
            )
            name = raw_artifact.get("name")
            kind = raw_artifact.get("kind")
            platform = raw_artifact.get("platform")
            filename = _safe_filename(raw_artifact.get("filename"))
            size = raw_artifact.get("size")
            digest = raw_artifact.get("sha256")
            content_type = raw_artifact.get("content_type")
            if not isinstance(name, str) or not _ARTIFACT_NAME.fullmatch(name):
                raise ReleaseManifestInvalid("release artifact name is invalid")
            if kind not in _KINDS or platform not in _PLATFORMS:
                raise ReleaseManifestInvalid("release artifact kind or platform is invalid")
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= _MAX_ARTIFACT_BYTES:
                raise ReleaseManifestInvalid("release artifact size is invalid")
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise ReleaseManifestInvalid("release artifact SHA-256 is invalid")
            if not isinstance(content_type, str) or not _CONTENT_TYPE.fullmatch(content_type):
                raise ReleaseManifestInvalid("release artifact content type is invalid")
            if name in names or filename in filenames:
                raise ReleaseManifestInvalid("release artifact identifiers must be unique")
            names.add(name)
            filenames.add(filename)
            artifacts.append(
                {
                    **raw_artifact,
                    "url": (
                        f"{self.public_base_url}/{quote(version, safe='')}/"
                        f"{quote(filename, safe='')}"
                    ),
                }
            )

        digest = hashlib.sha256(raw).hexdigest()
        return {
            "schema_version": 1,
            "audience": "public",
            "version": version,
            "published_at": published_at,
            "manifest_sha256": digest,
            "artifacts": artifacts,
        }, digest

    def version(self, version: str) -> dict[str, Any]:
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ReleaseNotFound
        manifest, _ = self._load_version(version)
        return manifest

    def channel(self, channel: str) -> dict[str, Any]:
        if channel != "stable":
            raise ReleaseNotFound
        pointer, _ = _read_json(self._path("channels", "stable.json"))
        _closed_keys(
            pointer,
            frozenset({"schema_version", "channel", "version", "manifest_sha256"}),
            label="channel manifest",
        )
        if pointer.get("schema_version") != 1 or pointer.get("channel") != "stable":
            raise ReleaseManifestInvalid("stable channel manifest is invalid")
        version = _safe_version(pointer.get("version"))
        expected_digest = pointer.get("manifest_sha256")
        if not isinstance(expected_digest, str) or not _SHA256.fullmatch(expected_digest):
            raise ReleaseManifestInvalid("stable channel manifest digest is invalid")
        manifest, actual_digest = self._load_version(version)
        if actual_digest != expected_digest:
            raise ReleaseManifestInvalid("stable channel manifest digest does not match")
        manifest["channel"] = "stable"
        return manifest

    def file(self, version: str, filename: str) -> ReleaseFile:
        if not self.serve_files:
            raise ReleaseNotFound
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise ReleaseNotFound
        if (
            not isinstance(filename, str)
            or not _FILENAME.fullmatch(filename)
            or ".." in filename
        ):
            raise ReleaseNotFound
        version = _safe_version(version)
        filename = _safe_filename(filename)
        manifest, _ = self._load_version(version)
        metadata = next(
            (item for item in manifest["artifacts"] if item["filename"] == filename),
            None,
        )
        if metadata is None:
            raise ReleaseNotFound
        path = self._path(version, filename)
        if not _regular_file(path):
            raise ReleaseNotFound
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ReleaseNotFound from exc
        if size != metadata["size"]:
            raise ReleaseManifestInvalid("release artifact size does not match its manifest")
        try:
            digest = _sha256_file(path)
        except OSError as exc:
            raise ReleaseNotFound from exc
        if digest != metadata["sha256"]:
            raise ReleaseManifestInvalid("release artifact SHA-256 does not match its manifest")
        return ReleaseFile(
            path=path,
            filename=filename,
            size=size,
            sha256=digest,
            content_type=metadata["content_type"],
        )
