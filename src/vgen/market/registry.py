from __future__ import annotations

import base64
import hashlib
import json
import shutil
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

from .models import SEMVER_RE, WORKFLOW_ID_RE, WorkflowManifest

IGNORED_DIGEST_FILES = {"checksums.sha256", "artifact.sig", "workflow.lock"}
MAX_PACKAGE_FILES = 2_048
MAX_ARCHIVE_BYTES = 64 * 1024**2
MAX_UNCOMPRESSED_BYTES = 256 * 1024**2
MAX_INDEX_BYTES = 8 * 1024**2


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
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise RegistryError("workflow packages cannot contain symbolic links")
        if not path.is_file() or path.name in IGNORED_DIGEST_FILES:
            continue
        files.append(path)
        total += path.stat().st_size
        if len(files) > MAX_PACKAGE_FILES or total > MAX_UNCOMPRESSED_BYTES:
            raise RegistryError("workflow package exceeds the file or size limit")
    return sorted(files)


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


def build_archive(directory: Path, output: Path) -> Path:
    """Build a deterministic zip suitable for a static workflow registry."""

    validate_package(directory, allow_unsigned=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(item for item in directory.rglob("*") if item.is_file()):
            relative = path.relative_to(directory).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return output


def validate_package(
    directory: Path, allow_unsigned: bool = False
) -> tuple[WorkflowManifest, str, bool]:
    manifest = WorkflowManifest.load(directory / "manifest.yaml")
    verify_checksums(directory)
    for variant in manifest.variants:
        for relative in (variant.payload, variant.mapping):
            if relative and not (directory / relative).is_file():
                raise RegistryError(f"workflow file is missing: {relative}")
    digest = package_digest(directory)
    signed = verify_signature(directory, manifest)
    if not signed and not allow_unsigned:
        raise RegistryError("workflow is unsigned; pass --allow-unsigned to trust it explicitly")
    return manifest, digest, signed


class WorkflowRegistry:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or user_data_path("vgen") / "workflows"

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
    ) -> InstallResult:
        with tempfile.TemporaryDirectory(prefix="vgen-workflow-") as temp:
            unpacked = self._materialize(source, Path(temp))
            manifest, digest, signed = validate_package(unpacked, allow_unsigned=allow_unsigned)
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
            if (
                manifest.provenance == "market"
                and signed
                and parsed_source.scheme in {"http", "https"}
                and expected_publisher_key is None
            ):
                raise RegistryError(
                    "remote market install requires an out-of-band --publisher-key pin"
                )
            namespace, name = manifest.id.split("/", 1)
            target = self.root / manifest.provenance / namespace / name / manifest.version
            if target.exists():
                installed_manifest, installed_digest, installed_signed = validate_package(
                    target, allow_unsigned=True
                )
                if installed_digest != digest:
                    raise RegistryError(
                        "same workflow version already exists with a different digest; publish a new version"
                    )
                return InstallResult(installed_manifest, target, installed_digest, installed_signed)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(unpacked, target)
            lock: dict[str, Any] = {
                "schema_version": 1,
                "source": str(source),
                "id": manifest.id,
                "version": manifest.version,
                "digest": f"sha256:{digest}",
                "publisher": manifest.publisher.id,
                "publisher_key": publisher_key,
                "signed": signed,
            }
            (target / "workflow.lock").write_text(
                yaml.safe_dump(lock, sort_keys=False), encoding="utf-8"
            )
            return InstallResult(manifest, target, digest, signed)

    def remove(
        self,
        workflow_id: str,
        version: str,
        *,
        provenance: str | None = None,
    ) -> None:
        if not WORKFLOW_ID_RE.fullmatch(workflow_id):
            raise RegistryError("workflow id must be namespace/name using lowercase characters")
        if not SEMVER_RE.fullmatch(version):
            raise RegistryError("workflow version must be SemVer")
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
        with zipfile.ZipFile(local_path) as archive:
            members = archive.infolist()
            if len(members) > MAX_PACKAGE_FILES:
                raise RegistryError("workflow archive contains too many files")
            seen: set[str] = set()
            total = 0
            for info in members:
                member_name = info.filename
                if info.flag_bits & 0x1:
                    raise RegistryError("encrypted workflow archives are not supported")
                if (
                    not member_name
                    or "\\" in member_name
                    or "\x00" in member_name
                    or member_name.startswith("/")
                    or (
                        len(member_name) >= 2 and member_name[0].isalpha() and member_name[1] == ":"
                    )
                ):
                    raise RegistryError("workflow archive contains an invalid path")
                if member_name in seen:
                    raise RegistryError("workflow archive contains duplicate paths")
                seen.add(member_name)
                target = (destination / member_name).resolve()
                if not target.is_relative_to(destination.resolve()):
                    raise RegistryError("workflow archive contains a path traversal")
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise RegistryError("workflow archive contains a symbolic link")
                total += info.file_size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise RegistryError("workflow archive exceeds the uncompressed size limit")
            archive.extractall(destination)
        manifests = list(destination.glob("**/manifest.yaml"))
        if len(manifests) != 1:
            raise RegistryError("workflow archive must contain exactly one manifest.yaml")
        return manifests[0].parent

    @staticmethod
    def _download(url: str, *, max_bytes: int, timeout: float) -> bytes:
        parsed = urllib.parse.urlsplit(url)
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
            raise RegistryError("remote workflow URLs must use HTTPS")
        if parsed.username or parsed.password or not parsed.hostname:
            raise RegistryError("remote workflow URL is invalid")
        chunks: list[bytes] = []
        size = 0
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as response:
            response.raise_for_status()
            final = urllib.parse.urlsplit(str(response.url))
            final_loopback = final.hostname in {"localhost", "127.0.0.1", "::1"}
            if final_loopback != loopback or (
                final.scheme != "https"
                and not (final.scheme == "http" and loopback and final_loopback)
            ):
                raise RegistryError("remote workflow redirect left the trusted HTTPS origin class")
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise RegistryError("remote workflow response has an invalid size") from exc
                if declared_size < 0 or declared_size > max_bytes:
                    raise RegistryError("remote workflow response exceeds the size limit")
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise RegistryError("remote workflow response exceeds the size limit")
                chunks.append(chunk)
        return b"".join(chunks)
