from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import shutil
import socket
import stat
import tempfile
import urllib.parse
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from platformdirs import user_data_path

from .models import (
    RESERVED_WORKFLOW_ROOT_FILES,
    WorkflowManifest,
    validate_workflow_id,
    validate_workflow_version,
)
from .paths import canonical_package_path, package_path_key

MAX_PACKAGE_FILES = 2_048
MAX_ARCHIVE_BYTES = 64 * 1024**2
MAX_UNCOMPRESSED_BYTES = 256 * 1024**2
MAX_INDEX_BYTES = 8 * 1024**2
MAX_REDIRECTS = 5


class RegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class InstallResult:
    manifest: WorkflowManifest
    path: Path
    digest: str
    signed: bool


def package_files(directory: Path) -> list[Path]:
    files: list[Path] = []
    total = 0
    seen: dict[str, str] = {}
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise RegistryError("workflow packages cannot contain symbolic links")
        relative = path.relative_to(directory).as_posix()
        try:
            canonical = canonical_package_path(relative, label="workflow package path")
            key = package_path_key(canonical)
        except ValueError as exc:
            raise RegistryError("workflow package contains a non-portable path") from exc
        previous = seen.setdefault(key, canonical)
        if previous != canonical:
            raise RegistryError("workflow package contains cross-platform path collisions")
        if key in RESERVED_WORKFLOW_ROOT_FILES:
            if canonical != key:
                raise RegistryError("workflow package metadata names must use canonical spelling")
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise RegistryError("workflow package contains an unsupported filesystem entry")
        files.append(path)
        total += path.stat().st_size
        if len(files) > MAX_PACKAGE_FILES or total > MAX_UNCOMPRESSED_BYTES:
            raise RegistryError("workflow package exceeds the file or size limit")
    # Path ordering is platform-specific: WindowsPath compares case-insensitively,
    # while PosixPath compares case-sensitively.  The package digest is a wire
    # identity, so order by the UTF-8 bytes that are actually hashed instead.
    return sorted(
        files,
        key=lambda path: path.relative_to(directory).as_posix().encode("utf-8"),
    )


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def package_digest(directory: Path) -> str:
    digest = hashlib.sha256()
    for path in package_files(directory):
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data_digest = bytes.fromhex(file_digest(path))
        digest.update(data_digest)
    return digest.hexdigest()


def write_checksums(directory: Path) -> str:
    lines = [
        f"{file_digest(path)}  {path.relative_to(directory).as_posix()}"
        for path in package_files(directory)
    ]
    content = "\n".join(lines) + "\n"
    (directory / "checksums.sha256").write_text(content, encoding="utf-8")
    return package_digest(directory)


def verify_checksums(directory: Path) -> None:
    checksum_file = directory / "checksums.sha256"
    if not checksum_file.is_file():
        raise RegistryError("workflow package has no checksums.sha256")
    expected: dict[str, str] = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if not separator or len(digest) != 64:
            raise RegistryError("invalid checksums.sha256 entry")
        path = Path(relative)
        if (
            path.is_absolute()
            or ".." in path.parts
            or "\\" in relative
            or "\x00" in relative
            or relative in expected
        ):
            raise RegistryError("checksum path escapes the package")
        expected[path.as_posix()] = digest
    actual = {
        path.relative_to(directory).as_posix(): file_digest(path)
        for path in package_files(directory)
    }
    if expected != actual:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(
            name for name in set(expected) & set(actual) if expected[name] != actual[name]
        )
        raise RegistryError(
            f"workflow checksum mismatch; missing={missing}, extra={extra}, changed={changed}"
        )


def verify_signature(directory: Path, manifest: WorkflowManifest) -> bool:
    signature_path = directory / "artifact.sig"
    public_key = manifest.publisher.public_key
    if not signature_path.is_file() or not public_key:
        return False
    try:
        verifier = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key, validate=True))
        signature = base64.b64decode(
            signature_path.read_text(encoding="ascii").strip(), validate=True
        )
        verifier.verify(signature, bytes.fromhex(package_digest(directory)))
    except (ValueError, InvalidSignature) as exc:
        raise RegistryError("workflow publisher signature is invalid") from exc
    return True


def sign_package(directory: Path, private_key: Ed25519PrivateKey) -> str:
    """Attach publisher public key, checksums, and a detached digest signature."""

    manifest_path = directory / "manifest.yaml"
    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("publisher"), dict):
        raise RegistryError("manifest publisher is missing")
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    raw["publisher"]["public_key"] = base64.b64encode(public).decode("ascii")
    manifest_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    digest = write_checksums(directory)
    signature = private_key.sign(bytes.fromhex(digest))
    (directory / "artifact.sig").write_text(
        base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii"
    )
    return digest


def build_archive(
    directory: Path,
    output: Path,
    *,
    allow_unsigned: bool = False,
) -> Path:
    """Build a deterministic zip suitable for a static workflow registry."""

    validate_package(directory, allow_unsigned=allow_unsigned)
    source_root = directory.resolve()
    output_path = output.resolve()
    if output_path.is_relative_to(source_root):
        raise RegistryError("workflow archive output must be outside the package directory")
    archive_files = sorted(
        (
            item
            for item in directory.rglob("*")
            if item.is_file()
            and package_path_key(item.relative_to(directory).as_posix()) != "workflow.lock"
        ),
        key=lambda path: path.relative_to(directory).as_posix().encode("utf-8"),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".vgen-archive-", dir=output.parent) as temp:
        staged = Path(temp) / output.name
        with zipfile.ZipFile(
            staged, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path in archive_files:
                relative = path.relative_to(directory).as_posix()
                info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())
        staged.replace(output)
    return output


def validate_package(
    directory: Path, allow_unsigned: bool = False
) -> tuple[WorkflowManifest, str, bool]:
    try:
        manifest = WorkflowManifest.load(directory / "manifest.yaml")
        verify_checksums(directory)
        for variant in manifest.variants:
            for relative in (variant.payload, variant.mapping):
                if relative and not (directory / relative).is_file():
                    raise RegistryError(f"workflow file is missing: {relative}")
        digest = package_digest(directory)
        signed = verify_signature(directory, manifest)
        if not signed and not allow_unsigned:
            raise RegistryError(
                "workflow is unsigned; pass --allow-unsigned to trust it explicitly"
            )
        return manifest, digest, signed
    except RegistryError:
        raise
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
        raise RegistryError("workflow package is invalid or unreadable") from exc


class WorkflowRegistry:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or user_data_path("vgen") / "workflows"

    def inspect_source(
        self,
        source: str | Path,
        *,
        allow_unsigned: bool = False,
    ) -> tuple[WorkflowManifest, str, bool]:
        """Materialize and validate a package without installing it.

        Archive extraction and remote downloads stay inside the same bounded
        temporary directory and use the same path, size, and redirect checks as
        installation.  Only the validated metadata escapes that directory.
        """

        with tempfile.TemporaryDirectory(prefix="vgen-workflow-inspect-") as temp:
            unpacked = self._materialize(source, Path(temp))
            return validate_package(unpacked, allow_unsigned=allow_unsigned)

    def installed(self) -> list[InstallResult]:
        results: list[InstallResult] = []
        if not self.root.is_dir():
            return results
        for manifest_path in self.root.glob("*/*/*/*/manifest.yaml"):
            directory = manifest_path.parent
            try:
                manifest, digest, signed = validate_package(directory, allow_unsigned=True)
            except (RegistryError, ValueError):
                continue
            results.append(InstallResult(manifest, directory, digest, signed))
        return sorted(results, key=lambda item: (item.manifest.id, item.manifest.version))

    def install(
        self,
        source: str | Path,
        allow_unsigned: bool = False,
        *,
        expected_digest: str | None = None,
        expected_publisher_key: str | None = None,
        expected_workflow_id: str | None = None,
        expected_version: str | None = None,
    ) -> InstallResult:
        with tempfile.TemporaryDirectory(prefix="vgen-workflow-") as temp:
            unpacked = self._materialize(source, Path(temp))
            manifest, digest, signed = validate_package(unpacked, allow_unsigned=allow_unsigned)
            if expected_workflow_id is not None and manifest.id != expected_workflow_id:
                raise RegistryError("workflow package id does not match the requested target")
            if expected_version is not None and manifest.version != expected_version:
                raise RegistryError("workflow package version does not match the requested target")
            normalized_expected = (expected_digest or "").removeprefix("sha256:")
            if normalized_expected and normalized_expected != digest:
                raise RegistryError("market index digest does not match the signed package")
            publisher_key = manifest.publisher.public_key
            if expected_publisher_key is not None:
                try:
                    decoded_expected = base64.b64decode(expected_publisher_key, validate=True)
                except ValueError as exc:
                    raise RegistryError("trusted publisher key is not valid base64") from exc
                if len(decoded_expected) != 32:
                    raise RegistryError("trusted publisher key must encode 32 bytes")
                if not signed or publisher_key != expected_publisher_key:
                    raise RegistryError("workflow publisher key does not match the trusted pin")
            parsed_source = urllib.parse.urlsplit(str(source))
            if parsed_source.scheme in {"http", "https"} and expected_publisher_key is None:
                raise RegistryError(
                    "remote workflow install requires an out-of-band --publisher-key pin"
                )
            namespace, name = manifest.id.split("/", 1)
            target = self.root / manifest.provenance / namespace / name / manifest.version
            if target.exists():
                return self._existing_install(
                    target,
                    digest,
                    require_signed=signed,
                    expected_publisher_key=expected_publisher_key,
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            lock: dict[str, Any] = {
                "schema_version": 1,
                "source": self._lock_source(source),
                "id": manifest.id,
                "version": manifest.version,
                "digest": f"sha256:{digest}",
                "publisher": manifest.publisher.id,
                "publisher_key": publisher_key,
                "signed": signed,
            }
            try:
                with tempfile.TemporaryDirectory(
                    prefix=f".{manifest.version}.vgen-staging-",
                    dir=target.parent,
                ) as staging_text:
                    staging = Path(staging_text)
                    shutil.copytree(unpacked, staging, dirs_exist_ok=True)
                    staged_manifest, staged_digest, staged_signed = validate_package(
                        staging, allow_unsigned=allow_unsigned
                    )
                    if (
                        staged_digest != digest
                        or staged_manifest.id != manifest.id
                        or staged_manifest.version != manifest.version
                        or staged_manifest.provenance != manifest.provenance
                        or staged_signed != signed
                    ):
                        raise RegistryError("workflow source changed while it was being installed")
                    (staging / "workflow.lock").write_text(
                        yaml.safe_dump(lock, sort_keys=False), encoding="utf-8"
                    )
                    final_manifest, final_digest, final_signed = validate_package(
                        staging, allow_unsigned=allow_unsigned
                    )
                    if (
                        final_digest != digest
                        or final_manifest.id != manifest.id
                        or final_manifest.version != manifest.version
                        or final_signed != signed
                    ):
                        raise RegistryError(
                            "workflow changed while installation metadata was finalized"
                        )
                    try:
                        staging.rename(target)
                    except OSError as exc:
                        if target.exists():
                            return self._existing_install(
                                target,
                                digest,
                                require_signed=signed,
                                expected_publisher_key=expected_publisher_key,
                            )
                        raise RegistryError("workflow could not be activated atomically") from exc
            except RegistryError:
                raise
            except (OSError, shutil.Error) as exc:
                raise RegistryError("workflow could not be staged safely") from exc
            return InstallResult(manifest, target, digest, signed)

    @staticmethod
    def _existing_install(
        target: Path,
        expected_digest: str,
        *,
        require_signed: bool,
        expected_publisher_key: str | None,
    ) -> InstallResult:
        installed_manifest, installed_digest, installed_signed = validate_package(
            target, allow_unsigned=True
        )
        if installed_digest != expected_digest:
            raise RegistryError(
                "same workflow version already exists with a different digest; publish a new version"
            )
        if require_signed and not installed_signed:
            raise RegistryError("existing workflow is missing its required publisher signature")
        if expected_publisher_key is not None and (
            not installed_signed
            or installed_manifest.publisher.public_key != expected_publisher_key
        ):
            raise RegistryError("existing workflow does not match the trusted publisher key")
        return InstallResult(installed_manifest, target, installed_digest, installed_signed)

    @staticmethod
    def _lock_source(source: str | Path) -> str:
        """Persist provenance without retaining URL credentials or capabilities."""

        value = str(source)
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            return value
        try:
            hostname = parsed.hostname or ""
            port = parsed.port
        except ValueError:
            return f"{parsed.scheme}://<invalid>"
        authority = f"[{hostname}]" if ":" in hostname else hostname
        if port is not None:
            authority += f":{port}"
        return urllib.parse.urlunsplit((parsed.scheme, authority, "", "", ""))

    def remove(
        self,
        workflow_id: str,
        version: str,
        *,
        provenance: str | None = None,
    ) -> None:
        try:
            validate_workflow_id(workflow_id)
            validate_workflow_version(version)
        except ValueError as exc:
            raise RegistryError(str(exc)) from exc
        if provenance not in {None, "market", "custom"}:
            raise RegistryError("workflow provenance must be market or custom")
        namespace, _, name = workflow_id.partition("/")
        provenances = (provenance,) if provenance else ("market", "custom")
        targets = [
            self.root / source / namespace / name / version
            for source in provenances
            if (self.root / source / namespace / name / version).is_dir()
        ]
        if not targets:
            raise RegistryError("workflow version is not installed")
        if len(targets) > 1:
            raise RegistryError("both market and custom versions exist; select --provenance")
        shutil.rmtree(targets[0])

    def search_index(self, index_url: str, query: str) -> list[dict[str, Any]]:
        payload = json.loads(self._download(index_url, max_bytes=MAX_INDEX_BYTES, timeout=20))
        entries = payload.get("workflows", []) if isinstance(payload, dict) else []
        lowered = query.casefold()
        return [
            entry
            for entry in entries
            if lowered in json.dumps(entry, ensure_ascii=False).casefold()
        ]

    @staticmethod
    def _materialize(source: str | Path, temp: Path) -> Path:
        source_text = str(source)
        parsed = urllib.parse.urlparse(source_text)
        local_path: Path
        if parsed.scheme in {"http", "https"}:
            local_path = temp / "package.zip"
            local_path.write_bytes(
                WorkflowRegistry._download(source_text, max_bytes=MAX_ARCHIVE_BYTES, timeout=60)
            )
        else:
            local_path = Path(source).expanduser().resolve()
        if local_path.is_dir():
            return local_path
        if not local_path.is_file() or not zipfile.is_zipfile(local_path):
            raise RegistryError("workflow source must be a directory or zip archive")
        destination = temp / "unpacked"
        destination.mkdir()
        try:
            with zipfile.ZipFile(local_path) as archive:
                members = archive.infolist()
                if len(members) > MAX_PACKAGE_FILES:
                    raise RegistryError("workflow archive contains too many files")
                seen: set[str] = set()
                required_directories: set[str] = set()
                files: set[str] = set()
                total = 0
                for info in members:
                    member_name = info.filename
                    directory_entry = info.is_dir()
                    path_text = member_name[:-1] if directory_entry else member_name
                    try:
                        canonical = canonical_package_path(
                            path_text,
                            label="workflow archive path",
                        )
                        key = package_path_key(canonical)
                    except ValueError as exc:
                        raise RegistryError("workflow archive contains an invalid path") from exc
                    if canonical != path_text:
                        raise RegistryError("workflow archive path is not canonical")
                    if key in RESERVED_WORKFLOW_ROOT_FILES and canonical != key:
                        raise RegistryError("workflow archive metadata name is not canonical")
                    if info.flag_bits & 0x1:
                        raise RegistryError("encrypted workflow archives are not supported")
                    if key in seen:
                        raise RegistryError("workflow archive contains duplicate paths")
                    parents = canonical.split("/")[:-1]
                    parent_key = ""
                    for part in parents:
                        parent_key = f"{parent_key}/{part.casefold()}".lstrip("/")
                        if parent_key in files:
                            raise RegistryError("workflow archive has a file-directory conflict")
                        required_directories.add(parent_key)
                    if not directory_entry and key in required_directories:
                        raise RegistryError("workflow archive has a file-directory conflict")
                    seen.add(key)
                    if not directory_entry:
                        files.add(key)
                    target = (destination / canonical).resolve()
                    if not target.is_relative_to(destination.resolve()):
                        raise RegistryError("workflow archive contains a path traversal")
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise RegistryError("workflow archive contains a symbolic link")
                    total += info.file_size
                    if total > MAX_UNCOMPRESSED_BYTES:
                        raise RegistryError("workflow archive exceeds the uncompressed size limit")
                archive.extractall(destination)
        except RegistryError:
            raise
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise RegistryError("workflow archive is invalid or unreadable") from exc
        manifests = list(destination.glob("**/manifest.yaml"))
        if len(manifests) != 1:
            raise RegistryError("workflow archive must contain exactly one manifest.yaml")
        return manifests[0].parent

    @staticmethod
    def _download(url: str, *, max_bytes: int, timeout: float) -> bytes:
        initial = WorkflowRegistry._remote_origin(url)
        current = url
        try:
            for redirect_count in range(MAX_REDIRECTS + 1):
                with httpx.stream(
                    "GET",
                    current,
                    timeout=timeout,
                    follow_redirects=False,
                    trust_env=False,
                ) as response:
                    WorkflowRegistry._validate_response_peer(response)
                    if 300 <= response.status_code < 400:
                        if redirect_count >= MAX_REDIRECTS:
                            raise RegistryError("remote workflow redirect limit exceeded")
                        location = response.headers.get("Location")
                        if not location:
                            raise RegistryError("remote workflow redirect has no location")
                        redirected = urllib.parse.urljoin(current, location)
                        if WorkflowRegistry._remote_origin(redirected) != initial:
                            raise RegistryError("remote workflow redirect changed origin")
                        current = redirected
                        continue

                    response.raise_for_status()
                    chunks: list[bytes] = []
                    size = 0
                    content_length = response.headers.get("Content-Length")
                    if content_length:
                        try:
                            declared_size = int(content_length)
                        except ValueError as exc:
                            raise RegistryError(
                                "remote workflow response has an invalid size"
                            ) from exc
                        if declared_size < 0 or declared_size > max_bytes:
                            raise RegistryError("remote workflow response exceeds the size limit")
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > max_bytes:
                            raise RegistryError("remote workflow response exceeds the size limit")
                        chunks.append(chunk)
                    return b"".join(chunks)
        except RegistryError:
            raise
        except httpx.HTTPError as exc:
            raise RegistryError("remote workflow download failed") from exc
        raise RegistryError("remote workflow redirect limit exceeded")

    @staticmethod
    def _remote_origin(url: str) -> tuple[str, str, int]:
        try:
            parsed = urllib.parse.urlsplit(url)
            hostname = (parsed.hostname or "").casefold()
            port = parsed.port
        except ValueError as exc:
            raise RegistryError("remote workflow URL is invalid") from exc
        if parsed.scheme != "https":
            raise RegistryError("remote workflow URLs must use HTTPS")
        if parsed.username or parsed.password or not hostname or parsed.fragment:
            raise RegistryError("remote workflow URL is invalid")
        effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
        WorkflowRegistry._validate_public_host(hostname, effective_port)
        return parsed.scheme, hostname, effective_port

    @staticmethod
    def _resolve_remote(host: str, port: int) -> tuple[str, ...]:
        try:
            values = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise RegistryError("remote workflow host is unavailable") from exc
        return tuple(dict.fromkeys(str(item[4][0]) for item in values))

    @staticmethod
    def _validate_public_host(host: str, port: int) -> None:
        addresses = WorkflowRegistry._resolve_remote(host, port)
        if not addresses:
            raise RegistryError("remote workflow host is unavailable")
        try:
            if any(not ipaddress.ip_address(address).is_global for address in addresses):
                raise RegistryError("remote workflow URL must resolve to public addresses")
        except ValueError as exc:
            raise RegistryError("remote workflow host is invalid") from exc

    @staticmethod
    def _validate_response_peer(response: Any) -> None:
        """Recheck the connected peer when the HTTP transport exposes it."""

        extensions = getattr(response, "extensions", None)
        if not isinstance(extensions, dict):
            raise RegistryError("remote workflow peer address is unavailable")
        stream = extensions.get("network_stream")
        get_extra_info = getattr(stream, "get_extra_info", None)
        if not callable(get_extra_info):
            raise RegistryError("remote workflow peer address is unavailable")
        peer = get_extra_info("server_addr")
        if not isinstance(peer, tuple) or not peer or not isinstance(peer[0], str):
            raise RegistryError("remote workflow peer address is unavailable")
        try:
            if not ipaddress.ip_address(peer[0]).is_global:
                raise RegistryError("remote workflow peer is not public")
        except ValueError as exc:
            raise RegistryError("remote workflow peer address is invalid") from exc
