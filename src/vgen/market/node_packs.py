"""Deterministic, self-contained ComfyUI custom-node packages.

A Node Pack contains reviewed source bytes plus exact offline wheels.  It is a
separate executable artifact from an inert workflow release so several
workflows can reuse one content-addressed installation without downloading or
executing dependencies again.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vgen.crypto import canonical_json

from .models import validate_workflow_id, validate_workflow_version
from .paths import canonical_package_path, package_path_key

_MANIFEST_NAME = "node-pack.json"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_FILES = 2048
_MAX_UNCOMPRESSED_BYTES = 512 * 1024 * 1024


class NodePackError(RuntimeError):
    """A Node Pack could not be built or verified safely."""


class NodePackFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    size: int = Field(ge=0)
    executable: bool = False

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        canonical = canonical_package_path(value, label="Node Pack file")
        if not canonical.startswith("source/"):
            raise ValueError("Node Pack source file must be below source/")
        return canonical

    @field_validator("sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        normalized = value.removeprefix("sha256:").lower()
        if not _DIGEST.fullmatch(normalized):
            raise ValueError("Node Pack digest must be SHA-256")
        return normalized


class NodePackWheel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    sha256: str
    size: int = Field(ge=0)

    @field_validator("filename")
    @classmethod
    def canonical_filename(cls, value: str) -> str:
        canonical = canonical_package_path(value, label="Node Pack wheel")
        if "/" in canonical or not canonical.casefold().endswith(".whl"):
            raise ValueError("Node Pack wheel must be one .whl filename")
        return canonical

    @field_validator("sha256")
    @classmethod
    def valid_digest(cls, value: str) -> str:
        normalized = value.removeprefix("sha256:").lower()
        if not _DIGEST.fullmatch(normalized):
            raise ValueError("Node Pack wheel digest must be SHA-256")
        return normalized


class NodePackManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    id: str
    version: str
    directory: str
    source: str
    revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    license: str | None = Field(default=None, min_length=1, max_length=120)
    node_classes: list[str] = Field(min_length=1, max_length=256)
    files: list[NodePackFile] = Field(min_length=1, max_length=_MAX_FILES)
    wheels: list[NodePackWheel] = Field(default_factory=list, max_length=256)

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return validate_workflow_id(value)

    @field_validator("version")
    @classmethod
    def valid_version(cls, value: str) -> str:
        return validate_workflow_version(value)

    @field_validator("directory")
    @classmethod
    def valid_directory(cls, value: str) -> str:
        canonical = canonical_package_path(value, label="Node Pack directory")
        if "/" in canonical:
            raise ValueError("Node Pack directory must be one portable name")
        return canonical

    @field_validator("source")
    @classmethod
    def secure_source(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("Node Pack source must use HTTPS")
        return value

    @field_validator("node_classes")
    @classmethod
    def unique_node_classes(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 160 for item in value):
            raise ValueError("Node Pack node classes must be non-empty and bounded")
        if len(value) != len(set(value)):
            raise ValueError("Node Pack node classes must be unique")
        return value

    @model_validator(mode="after")
    def unique_members(self) -> NodePackManifest:
        paths = [item.path for item in self.files]
        paths.extend(f"wheels/{item.filename}" for item in self.wheels)
        keys = [package_path_key(item) for item in paths]
        if len(keys) != len(set(keys)):
            raise ValueError("Node Pack members must be unique on Windows")
        return self


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _regular_files(root: Path, *, wheel_only: bool = False) -> list[Path]:
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise NodePackError("NODE_PACK_SOURCE_UNAVAILABLE") from exc
    if not stat.S_ISDIR(metadata.st_mode) or root.is_symlink():
        raise NodePackError("NODE_PACK_SOURCE_UNSAFE")
    files: list[Path] = []
    try:
        for item in root.rglob("*"):
            relative = item.relative_to(root).as_posix()
            if ".git" in item.relative_to(root).parts:
                continue
            item_metadata = item.lstat()
            if stat.S_ISDIR(item_metadata.st_mode) and not item.is_symlink():
                continue
            if not stat.S_ISREG(item_metadata.st_mode) or item.is_symlink():
                raise NodePackError("NODE_PACK_SOURCE_UNSAFE")
            canonical_package_path(relative, label="Node Pack source path")
            if wheel_only and not relative.casefold().endswith(".whl"):
                raise NodePackError("NODE_PACK_WHEEL_INVALID")
            if wheel_only and "/" in relative:
                raise NodePackError("NODE_PACK_WHEEL_INVALID")
            files.append(item)
    except (OSError, ValueError) as exc:
        raise NodePackError("NODE_PACK_SOURCE_UNSAFE") from exc
    if not files and not wheel_only:
        raise NodePackError("NODE_PACK_SOURCE_EMPTY")
    return sorted(files, key=lambda item: item.relative_to(root).as_posix().encode("utf-8"))


def build_node_pack_archive(
    source_root: Path,
    output: Path,
    *,
    node_pack_id: str,
    version: str,
    directory: str,
    source: str,
    revision: str,
    node_classes: list[str],
    wheel_root: Path | None = None,
    license: str | None = None,
) -> tuple[NodePackManifest, str]:
    """Build a deterministic Node Pack and return its manifest and digest."""

    resolved_source = source_root.resolve(strict=True)
    resolved_output = output.resolve()
    if resolved_output.is_relative_to(resolved_source):
        raise NodePackError("NODE_PACK_OUTPUT_INSIDE_SOURCE")
    source_files = _regular_files(resolved_source)
    wheel_files: list[Path] = []
    resolved_wheels: Path | None = None
    if wheel_root is not None:
        resolved_wheels = wheel_root.resolve(strict=True)
        if resolved_output.is_relative_to(resolved_wheels):
            raise NodePackError("NODE_PACK_OUTPUT_INSIDE_SOURCE")
        wheel_files = _regular_files(resolved_wheels, wheel_only=True)

    files = [
        NodePackFile(
            path=f"source/{path.relative_to(resolved_source).as_posix()}",
            sha256=_sha256_file(path),
            size=path.stat().st_size,
            executable=bool(stat.S_IMODE(path.stat().st_mode) & 0o111),
        )
        for path in source_files
    ]
    wheels = [
        NodePackWheel(
            filename=path.name,
            sha256=_sha256_file(path),
            size=path.stat().st_size,
        )
        for path in wheel_files
    ]
    manifest = NodePackManifest(
        id=node_pack_id,
        version=version,
        directory=directory,
        source=source,
        revision=revision,
        license=license,
        node_classes=node_classes,
        files=files,
        wheels=wheels,
    )
    manifest_bytes = canonical_json(manifest.model_dump(mode="json")) + b"\n"
    archive_entries: list[tuple[str, bytes, bool]] = [(_MANIFEST_NAME, manifest_bytes, False)]
    archive_entries.extend(
        (item.path, path.read_bytes(), item.executable)
        for item, path in zip(files, source_files, strict=True)
    )
    if resolved_wheels is not None:
        archive_entries.extend(
            (f"wheels/{item.filename}", path.read_bytes(), False)
            for item, path in zip(wheels, wheel_files, strict=True)
        )
    archive_entries.sort(key=lambda item: item[0].encode("utf-8"))

    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=".vgen-node-pack-", dir=output.parent) as temp:
            staged = Path(temp) / output.name
            with zipfile.ZipFile(
                staged, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
            ) as archive:
                for relative, data, executable in archive_entries:
                    info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = (0o100755 if executable else 0o100644) << 16
                    archive.writestr(info, data)
            digest = _sha256_file(staged)
            os.replace(staged, output)
    except OSError as exc:
        raise NodePackError("NODE_PACK_BUILD_FAILED") from exc
    return manifest, digest


def materialize_node_pack(
    archive_path: Path,
    destination: Path,
) -> tuple[NodePackManifest, Path, Path, str]:
    """Verify and extract a Node Pack without trusting ZIP extraction helpers."""

    if destination.exists():
        raise NodePackError("NODE_PACK_DESTINATION_EXISTS")
    artifact_digest = _sha256_file(archive_path)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > _MAX_FILES + 257:
                raise NodePackError("NODE_PACK_ARCHIVE_INVALID")
            by_key: dict[str, zipfile.ZipInfo] = {}
            total = 0
            for info in infos:
                if info.is_dir() or info.flag_bits & 0x1:
                    raise NodePackError("NODE_PACK_ARCHIVE_INVALID")
                try:
                    canonical = canonical_package_path(
                        info.filename, label="Node Pack archive path"
                    )
                except ValueError as exc:
                    raise NodePackError("NODE_PACK_ARCHIVE_INVALID") from exc
                if canonical != info.filename:
                    raise NodePackError("NODE_PACK_ARCHIVE_INVALID")
                key = package_path_key(canonical)
                if key in by_key:
                    raise NodePackError("NODE_PACK_ARCHIVE_INVALID")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise NodePackError("NODE_PACK_ARCHIVE_INVALID")
                total += info.file_size
                if total > _MAX_UNCOMPRESSED_BYTES:
                    raise NodePackError("NODE_PACK_ARCHIVE_INVALID")
                by_key[key] = info
            manifest_info = by_key.get(_MANIFEST_NAME)
            if manifest_info is None:
                raise NodePackError("NODE_PACK_MANIFEST_MISSING")
            try:
                manifest = NodePackManifest.model_validate_json(archive.read(manifest_info))
            except Exception as exc:
                raise NodePackError("NODE_PACK_MANIFEST_INVALID") from exc

            expected: dict[str, tuple[str, int, bool]] = {
                item.path: (item.sha256, item.size, item.executable) for item in manifest.files
            }
            expected.update(
                {
                    f"wheels/{item.filename}": (item.sha256, item.size, False)
                    for item in manifest.wheels
                }
            )
            if set(by_key) != {
                package_path_key(_MANIFEST_NAME),
                *(package_path_key(path) for path in expected),
            }:
                raise NodePackError("NODE_PACK_ARCHIVE_UNDECLARED_MEMBER")

            destination.mkdir(parents=True)
            destination_root = destination.resolve(strict=True)
            for relative, (digest, size, executable) in expected.items():
                info = by_key[package_path_key(relative)]
                data = archive.read(info)
                if len(data) != size or _sha256_bytes(data) != digest:
                    raise NodePackError("NODE_PACK_MEMBER_DIGEST_MISMATCH")
                target = destination_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o755 if executable else 0o644)
    except NodePackError:
        if destination.exists():
            import shutil

            shutil.rmtree(destination, ignore_errors=True)
        raise
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, KeyError) as exc:
        if destination.exists():
            import shutil

            shutil.rmtree(destination, ignore_errors=True)
        raise NodePackError("NODE_PACK_ARCHIVE_INVALID") from exc
    return manifest, destination / "source", destination / "wheels", artifact_digest


def fetch_node_pack(source: str, output: Path, *, expected_sha256: str) -> Path:
    """Download one bounded public Node Pack and bind it to an expected digest."""

    expected = expected_sha256.removeprefix("sha256:").lower()
    if not _DIGEST.fullmatch(expected):
        raise NodePackError("NODE_PACK_EXPECTED_DIGEST_INVALID")
    try:
        # Reuse the workflow registry's redirect, public-address, TLS and size
        # policy. The local import avoids a market package import cycle.
        from .registry import WorkflowRegistry  # noqa: PLC0415

        data = WorkflowRegistry._download(  # noqa: SLF001
            source,
            max_bytes=_MAX_UNCOMPRESSED_BYTES,
            timeout=120,
        )
    except Exception as exc:
        raise NodePackError("NODE_PACK_DOWNLOAD_FAILED") from exc
    if _sha256_bytes(data) != expected:
        raise NodePackError("NODE_PACK_ARTIFACT_DIGEST_MISMATCH")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.parent / f".{output.name}.{os.urandom(12).hex()}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except OSError as exc:
        raise NodePackError("NODE_PACK_DOWNLOAD_STORE_FAILED") from exc
    finally:
        temporary.unlink(missing_ok=True)
    return output


__all__ = [
    "NodePackError",
    "NodePackFile",
    "NodePackManifest",
    "NodePackWheel",
    "build_node_pack_archive",
    "fetch_node_pack",
    "materialize_node_pack",
]
