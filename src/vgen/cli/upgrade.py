from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.version import InvalidVersion, Version

from vgen import __version__

from .profile import GatewayProfile, ProfileStore

_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_METADATA_BYTES = 1024 * 1024
_MAX_ARTIFACT_BYTES = 2 * 1024 * 1024 * 1024


class UpgradeError(ValueError):
    """A safe, user-actionable CLI upgrade failure."""


class UpgradeNetworkError(TimeoutError):
    """The configured release source could not be reached."""


@dataclass(frozen=True, slots=True)
class UpgradeCandidate:
    version: str
    artifact_url: str
    filename: str
    size: int
    sha256: str


def _origin_key(value: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(value)
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port


def _same_origin(url: str, endpoint: str) -> bool:
    return _origin_key(url) == _origin_key(endpoint)


def _validated_release_origin(value: str) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(candidate)
    loopback = (parsed.hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (parsed.scheme != "https" and not loopback)
    ):
        raise UpgradeError("release origin must be a credential-free HTTPS origin")
    return candidate


def _release_source_path() -> Path:
    return (
        Path.home()
        / "Library"
        / "Application Support"
        / "VGen"
        / "cli"
        / "release-source.json"
    )


def _configured_release_origin(legacy_gateway_endpoint: str) -> str:
    """Read the installer-pinned release origin, with a v0.5 legacy bridge."""

    path = _release_source_path()
    if not path.exists():
        return _validated_release_origin(legacy_gateway_endpoint)
    if path.is_symlink() or not path.is_file():
        raise UpgradeError("managed release source is not a regular file")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise UpgradeError("managed release source permissions are too broad")
    try:
        value = _json_object(path.read_bytes(), label="managed release source")
    except OSError as exc:
        raise UpgradeError("managed release source could not be read") from exc
    if set(value) != {"schema_version", "release_origin"} or value.get("schema_version") != 1:
        raise UpgradeError("managed release source contract is invalid")
    release_origin = value.get("release_origin")
    if not isinstance(release_origin, str):
        raise UpgradeError("managed release origin is invalid")
    return _validated_release_origin(release_origin)


class _SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, endpoint: str) -> None:
        super().__init__()
        self.endpoint = endpoint

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        if not _same_origin(absolute, self.endpoint):
            raise urllib.error.HTTPError(
                absolute, code, "cross-origin release redirect refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, absolute)


def _fetch(opener, url: str, *, endpoint: str, limit: int, accept: str) -> bytes:  # type: ignore[no-untyped-def]
    if not _same_origin(url, endpoint):
        raise UpgradeError("release URL is not on the configured release origin")
    request = urllib.request.Request(url, headers={"Accept": accept})
    try:
        with opener.open(request, timeout=30) as response:
            value = response.read(limit + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise UpgradeNetworkError("could not download metadata from the release source") from exc
    if len(value) > limit:
        raise UpgradeError("release metadata exceeded its size limit")
    return value


def _json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise UpgradeError(f"{label} contains duplicate fields")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpgradeError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise UpgradeError(f"{label} must be an object")
    return value


def _candidate(release_origin: str, opener) -> UpgradeCandidate:  # type: ignore[no-untyped-def]
    stable_url = f"{release_origin}/releases/channels/stable.json"
    stable = _json_object(
        _fetch(
            opener,
            stable_url,
            endpoint=release_origin,
            limit=_MAX_METADATA_BYTES,
            accept="application/json",
        ),
        label="stable release metadata",
    )
    version = stable.get("version")
    manifest_digest = stable.get("manifest_sha256")
    if (
        stable.get("schema_version") != 1
        or stable.get("channel") != "stable"
        or not isinstance(version, str)
        or _VERSION.fullmatch(version) is None
        or not isinstance(manifest_digest, str)
        or _SHA256.fullmatch(manifest_digest) is None
        or set(stable) != {"schema_version", "channel", "version", "manifest_sha256"}
    ):
        raise UpgradeError("stable release metadata contract is invalid")

    manifest_url = f"{release_origin}/releases/{version}/manifest.json"
    manifest_bytes = _fetch(
        opener,
        manifest_url,
        endpoint=release_origin,
        limit=_MAX_METADATA_BYTES,
        accept="application/json",
    )
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest:
        raise UpgradeError("immutable release manifest digest does not match stable")
    manifest = _json_object(manifest_bytes, label="immutable release manifest")
    if (
        set(manifest) != {"schema_version", "audience", "version", "published_at", "artifacts"}
        or manifest.get("schema_version") != 1
        or manifest.get("audience") != "public"
        or manifest.get("version") != version
        or not isinstance(manifest.get("artifacts"), list)
    ):
        raise UpgradeError("immutable release manifest contract is invalid")

    immutable_matches = [
        item
        for item in manifest["artifacts"]
        if isinstance(item, dict)
        and item.get("name") == "macos-cli"
        and item.get("kind") == "cli-installer"
        and item.get("platform") == "macos"
    ]
    if len(immutable_matches) != 1:
        raise UpgradeError("release has no unique macOS CLI artifact")
    artifact = immutable_matches[0]
    expected_keys = {
        "name",
        "kind",
        "platform",
        "filename",
        "size",
        "sha256",
        "content_type",
    }
    if set(artifact) != expected_keys:
        raise UpgradeError("immutable macOS artifact metadata is invalid")
    filename = artifact.get("filename")
    size = artifact.get("size")
    digest = artifact.get("sha256")
    if (
        filename != f"VGen-macOS-{version}.zip"
        or isinstance(size, bool)
        or not isinstance(size, int)
        or not 1 <= size <= _MAX_ARTIFACT_BYTES
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
    ):
        raise UpgradeError("macOS CLI artifact metadata is invalid")
    artifact_url = f"{release_origin}/releases/{version}/{filename}"
    if not _same_origin(artifact_url, release_origin):
        raise UpgradeError("macOS CLI artifact URL is not on the pinned release origin")
    return UpgradeCandidate(version, artifact_url, filename, size, digest)


def _download(opener, candidate: UpgradeCandidate, destination: Path, release_origin: str) -> None:  # type: ignore[no-untyped-def]
    request = urllib.request.Request(
        candidate.artifact_url, headers={"Accept": "application/zip"}
    )
    digest = hashlib.sha256()
    downloaded = 0
    try:
        with opener.open(request, timeout=60) as response, destination.open("xb") as output:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) != candidate.size:
                raise UpgradeError("macOS CLI Content-Length does not match the manifest")
            while True:
                block = response.read(min(1024 * 1024, candidate.size - downloaded + 1))
                if not block:
                    break
                downloaded += len(block)
                if downloaded > candidate.size:
                    raise UpgradeError("macOS CLI download exceeded its declared size")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    except UpgradeError:
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise UpgradeNetworkError("could not download the macOS CLI artifact") from exc
    if downloaded != candidate.size or digest.hexdigest() != candidate.sha256:
        raise UpgradeError("macOS CLI artifact size or SHA-256 does not match")
    if not _same_origin(candidate.artifact_url, release_origin):
        raise UpgradeError("macOS CLI artifact origin changed during download")


def _extract_bundle(archive_path: Path, output: Path, version: str) -> Path:
    prefix = f"VGen-macOS-{version}/"
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > 4096:
                raise UpgradeError("macOS CLI ZIP has an invalid entry count")
            files: dict[str, zipfile.ZipInfo] = {}
            folded: set[str] = set()
            total = 0
            for info in infos:
                name = info.filename
                path = PurePosixPath(name.rstrip("/"))
                normalized = path.as_posix()
                if (
                    "\\" in name
                    or "\x00" in name
                    or name.startswith("/")
                    or not path.parts
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or ":" in path.parts[0]
                    or not name.startswith(prefix)
                    or normalized.casefold() in folded
                    or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
                    or info.flag_bits & 1
                ):
                    raise UpgradeError("macOS CLI ZIP contains an unsafe path")
                folded.add(normalized.casefold())
                total += info.file_size
                if total > _MAX_ARTIFACT_BYTES:
                    raise UpgradeError("macOS CLI ZIP expands beyond its size limit")
                if not info.is_dir():
                    files[normalized] = info
            required = {
                prefix + "README.md",
                prefix + "SHA256SUMS",
                prefix + "install.command",
                prefix + f"vgen-{version}-py3-none-any.whl",
            }
            optional = prefix + "gateway-default.txt"
            if set(files) not in (required, required | {optional}):
                raise UpgradeError("macOS CLI ZIP file list is invalid")
            if archive.testzip() is not None:
                raise UpgradeError("macOS CLI ZIP failed its integrity check")
            checksum_lines = archive.read(files[prefix + "SHA256SUMS"]).decode("ascii").splitlines()
            checksums: dict[str, str] = {}
            for line in checksum_lines:
                match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
                if match is None or match.group(2) in checksums:
                    raise UpgradeError("macOS CLI SHA256SUMS is invalid")
                checksums[match.group(2)] = match.group(1)
            expected_checksums = {
                name.removeprefix(prefix)
                for name in files
                if name != prefix + "SHA256SUMS"
            }
            if set(checksums) != expected_checksums:
                raise UpgradeError("macOS CLI SHA256SUMS does not cover exactly its files")
            for name, expected in checksums.items():
                if hashlib.sha256(archive.read(files[prefix + name])).hexdigest() != expected:
                    raise UpgradeError("macOS CLI embedded file digest does not match")
            for name, info in files.items():
                target = output.joinpath(*PurePosixPath(name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as destination:
                    while True:
                        block = source.read(1024 * 1024)
                        if not block:
                            break
                        destination.write(block)
                target.chmod(0o755 if name == prefix + "install.command" else 0o644)
    except UnicodeDecodeError as exc:
        raise UpgradeError("macOS CLI ZIP metadata is not valid ASCII") from exc
    except zipfile.BadZipFile as exc:
        raise UpgradeError("macOS CLI artifact is not a valid ZIP") from exc
    return output / prefix.rstrip("/")


@contextmanager
def stable_worker_wheel(profile: GatewayProfile) -> Iterator[tuple[str, Path]]:
    """Yield the stable Worker wheel through the installer-pinned release trust chain."""

    release_origin = _configured_release_origin(profile.endpoint)
    opener = urllib.request.build_opener(_SameOriginRedirects(release_origin))
    candidate = _candidate(release_origin, opener)
    with tempfile.TemporaryDirectory(prefix="vgen-worker-upgrade-") as temporary:
        work = Path(temporary)
        archive = work / candidate.filename
        _download(opener, candidate, archive, release_origin)
        bundle = _extract_bundle(archive, work / "bundle", candidate.version)
        wheel = bundle / f"vgen-{candidate.version}-py3-none-any.whl"
        if wheel.is_symlink() or not wheel.is_file():
            raise UpgradeError("stable release bundle has no regular Worker wheel")
        yield candidate.version, wheel


def _managed_launcher() -> tuple[Path, str, Path]:
    launcher = Path.home() / ".local" / "bin" / "vgen"
    if not launcher.is_symlink():
        raise UpgradeError("current CLI is not a managed VGen install; use the official installer")
    raw_target = os.readlink(launcher)
    target = Path(raw_target)
    absolute = target if target.is_absolute() else launcher.parent / target
    absolute = absolute.absolute()
    install_root = Path.home() / "Library" / "Application Support" / "VGen" / "cli"
    try:
        relative = absolute.relative_to(install_root / "releases")
    except ValueError as exc:
        raise UpgradeError("current CLI launcher points outside the managed release directory") from exc
    if len(relative.parts) != 3 or relative.parts[-2:] != ("bin", "vgen"):
        raise UpgradeError("current CLI launcher target is not a managed release executable")
    marker = absolute.parents[1] / ".vgen-managed-install"
    if not marker.is_file() or marker.is_symlink() or not absolute.is_file():
        raise UpgradeError("current CLI managed-install marker is missing")
    return launcher, raw_target, absolute


def _restore_launcher(launcher: Path, raw_target: str) -> None:
    temporary = launcher.with_name(f".vgen-rollback-{uuid.uuid4().hex}")
    os.symlink(raw_target, temporary)
    os.replace(temporary, launcher)


def _run_checked(command: list[str], *, label: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        detail = " ".join((result.stderr or result.stdout or "").split())[:500]
        raise UpgradeError(f"{label} failed" + (f": {detail}" if detail else ""))
    return result


def upgrade_cli(
    profile: GatewayProfile,
    *,
    check_only: bool = False,
    assume_yes: bool = False,
) -> dict[str, Any]:
    if sys.platform != "darwin":
        raise UpgradeError("self-upgrade currently supports macOS only")
    release_origin = _configured_release_origin(profile.endpoint)
    opener = urllib.request.build_opener(_SameOriginRedirects(release_origin))
    candidate = _candidate(release_origin, opener)
    try:
        current = Version(__version__)
        available = Version(candidate.version)
    except InvalidVersion as exc:
        raise UpgradeError("current or available VGen version is invalid") from exc
    if available <= current:
        return {
            "status": "up_to_date" if available == current else "ahead_of_stable",
            "current_version": __version__,
            "available_version": candidate.version,
        }
    if check_only:
        return {
            "status": "update_available",
            "current_version": __version__,
            "available_version": candidate.version,
        }
    if not assume_yes:
        answer = input(f"Upgrade VGen {__version__} → {candidate.version}? [y/N]: ").strip()
        if answer.casefold() not in {"y", "yes"}:
            raise UpgradeError("upgrade cancelled")

    launcher, old_raw_target, old_executable = _managed_launcher()
    with tempfile.TemporaryDirectory(prefix="vgen-upgrade-") as temporary:
        work = Path(temporary)
        archive = work / candidate.filename
        _download(opener, candidate, archive, release_origin)
        bundle = _extract_bundle(archive, work, candidate.version)
        installer = bundle / "install.command"
        try:
            _run_checked(["/bin/bash", str(installer), "--install-only"], label="CLI install")
            _, _, new_executable = _managed_launcher()
            version_result = _run_checked([str(new_executable), "--version"], label="new CLI check")
            if version_result.stdout.strip() != f"vgen {candidate.version}":
                raise UpgradeError("new CLI version does not match the stable release")
            refresh_result = _run_checked(
                [str(new_executable), "broker", "service-refresh"],
                label="Home Broker refresh",
            )
            refresh_payload = _json_object(
                refresh_result.stdout.encode(), label="Home Broker refresh result"
            )
            broker_refreshed = not bool(refresh_payload.get("skipped"))
        except Exception:
            _restore_launcher(launcher, old_raw_target)
            subprocess.run(
                [str(old_executable), "broker", "service-refresh"],
                check=False,
                capture_output=True,
                text=True,
            )
            raise
    return {
        "status": "upgraded",
        "previous_version": __version__,
        "current_version": candidate.version,
        "home_broker_refreshed": broker_refreshed,
    }


def upgrade_command(args: Any) -> None:
    profile = ProfileStore().get(args.profile)
    value = upgrade_cli(profile, check_only=args.check, assume_yes=args.yes)
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
