"""Build the public release tree consumed by Gateway and Nginx.

The tool publishes two immutable, credential-free ZIP files plus a mutable
``stable`` pointer and fail-closed macOS/Windows bootstraps.  It never signs an
artifact: HTTPS and the recorded SHA-256 values provide transport and
integrity checks, not publisher authenticity.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from datetime import datetime
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

REPOSITORY = Path(__file__).resolve().parents[1]
_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
_PUBLISHED_AT = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._+-]+)$")
_MAX_ARCHIVE_ENTRIES = 4096
_MAX_UNCOMPRESSED_BYTES = 2 * 1024**3
_BOOTSTRAP_NAME = "install-macos.sh"
_WINDOWS_BOOTSTRAP_NAME = "install-windows-worker.ps1"


class PublicReleaseBuildError(ValueError):
    """A public release input or destination is unsafe or inconsistent."""


@dataclass(frozen=True, slots=True)
class ReleaseBuildResult:
    root: Path
    version_root: Path
    manifest: Path
    stable_pointer: Path
    macos_bootstrap: Path
    windows_worker_bootstrap: Path
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class _Artifact:
    source: Path
    name: str
    kind: str
    platform: str
    content_type: str = "application/zip"

    def metadata(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "platform": self.platform,
            "filename": self.source.name,
            "size": self.source.stat().st_size,
            "sha256": _sha256_file(self.source),
            "content_type": self.content_type,
        }


def _project_version(repository: Path) -> str:
    with (repository / "pyproject.toml").open("rb") as handle:
        value = tomllib.load(handle).get("project", {}).get("version")
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None:
        raise PublicReleaseBuildError("project.version must be MAJOR.MINOR.PATCH")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _absolute(path: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else Path.cwd() / expanded


def _regular_source(path: Path, *, label: str) -> Path:
    candidate = _absolute(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise PublicReleaseBuildError(f"{label} must be a regular file, not a symbolic link")
    if candidate.stat().st_size <= 0:
        raise PublicReleaseBuildError(f"{label} must not be empty")
    return candidate


def _validated_published_at(value: str) -> str:
    if _PUBLISHED_AT.fullmatch(value) is None:
        raise PublicReleaseBuildError("published_at must use RFC 3339 UTC seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PublicReleaseBuildError("published_at is not a real UTC timestamp") from exc
    return value


def _validated_gateway_origin(value: str) -> str:
    candidate = value.strip().rstrip("/")
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise PublicReleaseBuildError("origin is invalid") from exc
    loopback = (parsed.hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or (parsed.scheme != "https" and not loopback)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None and parsed.netloc.endswith(":")
    ):
        raise PublicReleaseBuildError(
            "origin must be HTTPS without credentials, path, query, or fragment"
        )
    return candidate


def _safe_zip_entries(archive: zipfile.ZipFile, *, label: str) -> dict[str, zipfile.ZipInfo]:
    entries: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    total = 0
    if not archive.infolist() or len(archive.infolist()) > _MAX_ARCHIVE_ENTRIES:
        raise PublicReleaseBuildError(f"{label} has an invalid entry count")
    for info in archive.infolist():
        name = info.filename
        if "\\" in name or "\x00" in name or name.startswith("/"):
            raise PublicReleaseBuildError(f"{label} contains an unsafe path")
        path = PurePosixPath(name.rstrip("/"))
        if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise PublicReleaseBuildError(f"{label} contains an unsafe path")
        if ":" in path.parts[0]:
            raise PublicReleaseBuildError(f"{label} contains an unsafe drive path")
        normalized = path.as_posix()
        key = normalized.casefold()
        if normalized in entries or key in folded:
            raise PublicReleaseBuildError(f"{label} contains duplicate paths")
        unix_mode = info.external_attr >> 16
        if stat.S_IFMT(unix_mode) == stat.S_IFLNK:
            raise PublicReleaseBuildError(f"{label} contains a symbolic link")
        if info.flag_bits & 0x1:
            raise PublicReleaseBuildError(f"{label} contains an encrypted entry")
        if info.file_size < 0 or info.compress_size < 0:
            raise PublicReleaseBuildError(f"{label} contains an invalid entry size")
        total += info.file_size
        if total > _MAX_UNCOMPRESSED_BYTES:
            raise PublicReleaseBuildError(f"{label} expands beyond the public installer limit")
        entries[normalized] = info
        folded.add(key)
    corrupt = archive.testzip()
    if corrupt is not None:
        raise PublicReleaseBuildError(f"{label} contains a corrupt entry")
    return entries


def _verify_checksums(
    archive: zipfile.ZipFile,
    entries: dict[str, zipfile.ZipInfo],
    *,
    prefix: str,
    label: str,
) -> None:
    manifest_name = f"{prefix}SHA256SUMS"
    if manifest_name not in entries or entries[manifest_name].is_dir():
        raise PublicReleaseBuildError(f"{label} has no regular SHA256SUMS")
    try:
        lines = archive.read(entries[manifest_name]).decode("ascii").splitlines()
    except (KeyError, UnicodeDecodeError, RuntimeError) as exc:
        raise PublicReleaseBuildError(f"{label} has an unreadable SHA256SUMS") from exc
    expected: dict[str, str] = {}
    for line in lines:
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None or match.group(2) in expected:
            raise PublicReleaseBuildError(f"{label} has an invalid SHA256SUMS")
        expected[match.group(2)] = match.group(1)
    actual_names = {
        name.removeprefix(prefix)
        for name, info in entries.items()
        if name.startswith(prefix) and name != manifest_name and not info.is_dir()
    }
    if set(expected) != actual_names:
        raise PublicReleaseBuildError(f"{label} SHA256SUMS does not cover exactly its files")
    for name, digest in expected.items():
        if hashlib.sha256(archive.read(entries[f"{prefix}{name}"])).hexdigest() != digest:
            raise PublicReleaseBuildError(f"{label} SHA256SUMS does not match {name}")


def _validated_embedded_wheel(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    version: str,
    label: str,
) -> str:
    try:
        value = archive.read(info)
        with zipfile.ZipFile(io.BytesIO(value)) as wheel:
            entries = _safe_zip_entries(wheel, label=f"{label} VGen wheel")
            metadata_names = [name for name in entries if name.endswith(".dist-info/METADATA")]
            wheel_names = [name for name in entries if name.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise PublicReleaseBuildError(
                    f"{label} VGen wheel must contain exactly one METADATA and WHEEL"
                )
            metadata_root = metadata_names[0].removesuffix("/METADATA")
            wheel_root = wheel_names[0].removesuffix("/WHEEL")
            if metadata_root != wheel_root or metadata_root != f"vgen-{version}.dist-info":
                raise PublicReleaseBuildError(f"{label} VGen wheel dist-info is invalid")
            metadata = Parser().parsestr(wheel.read(metadata_names[0]).decode("utf-8"))
            wheel_metadata = wheel.read(wheel_names[0]).decode("utf-8")
    except (KeyError, OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise PublicReleaseBuildError(f"{label} contains an unreadable VGen wheel") from exc
    if metadata.get("Name", "").casefold() != "vgen":
        raise PublicReleaseBuildError(f"{label} wheel distribution name must be vgen")
    if metadata.get("Version") != version:
        raise PublicReleaseBuildError(f"{label} wheel version must be {version}")
    if "Tag: py3-none-any" not in wheel_metadata.splitlines():
        raise PublicReleaseBuildError(f"{label} wheel must contain the py3-none-any tag")
    return hashlib.sha256(value).hexdigest()


def _validate_macos_bundle(path: Path, *, version: str, gateway_origin: str) -> str:
    expected_name = f"VGen-macOS-{version}.zip"
    if path.name != expected_name:
        raise PublicReleaseBuildError(f"macOS CLI bundle must be named {expected_name}")
    prefix = f"VGen-macOS-{version}/"
    try:
        with zipfile.ZipFile(path) as archive:
            entries = _safe_zip_entries(archive, label="macOS CLI bundle")
            if any(not name.startswith(prefix) for name in entries):
                raise PublicReleaseBuildError("macOS CLI bundle must have one versioned root")
            required = {
                f"{prefix}README.md",
                f"{prefix}install.command",
                f"{prefix}SHA256SUMS",
                f"{prefix}vgen-{version}-py3-none-any.whl",
            }
            optional_gateway = f"{prefix}gateway-default.txt"
            if frozenset(entries) not in {
                frozenset(required),
                frozenset({*required, optional_gateway}),
            }:
                raise PublicReleaseBuildError(
                    "macOS CLI bundle files do not match the closed public allowlist"
                )
            if entries[f"{prefix}install.command"].is_dir():
                raise PublicReleaseBuildError("macOS install.command must be a regular file")
            if entries[f"{prefix}install.command"].external_attr >> 16 & 0o111 == 0:
                raise PublicReleaseBuildError("macOS install.command must be executable")
            if optional_gateway in entries:
                try:
                    configured_gateway = archive.read(optional_gateway).decode("utf-8").strip()
                except (KeyError, UnicodeDecodeError) as exc:
                    raise PublicReleaseBuildError(
                        "macOS gateway-default.txt is unreadable"
                    ) from exc
                if configured_gateway != gateway_origin:
                    raise PublicReleaseBuildError(
                        "macOS gateway-default.txt does not match the release Gateway"
                    )
            _verify_checksums(
                archive,
                entries,
                prefix=prefix,
                label="macOS CLI bundle",
            )
            return _validated_embedded_wheel(
                archive,
                entries[f"{prefix}vgen-{version}-py3-none-any.whl"],
                version=version,
                label="macOS CLI bundle",
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise PublicReleaseBuildError("macOS CLI bundle is not a readable ZIP") from exc


def _validate_windows_bundle(path: Path, *, version: str, gateway_origin: str) -> str:
    expected_name = f"vgen-windows-worker-installer-{version}.zip"
    if path.name != expected_name:
        raise PublicReleaseBuildError(f"Windows Worker bundle must be named {expected_name}")
    try:
        with zipfile.ZipFile(path) as archive:
            entries = _safe_zip_entries(archive, label="Windows Worker bundle")
            if any("/" in name for name in entries):
                raise PublicReleaseBuildError("Windows Worker bundle entries must be top-level")
            forbidden = {
                "worker-credentials.json",
                "worker-identity.json",
                ".worker-enrollment-identity.json",
            }
            if forbidden.intersection(entries):
                raise PublicReleaseBuildError("public Windows Worker bundle contains credentials")
            required = {
                "INSTALL.txt",
                "enroll-worker.ps1",
                "start-worker.cmd",
                "setup-worker.ps1",
                "vgen-worker-bundle.json",
                "comfyui-minimax-h3-policy.yaml",
                "SHA256SUMS",
                f"vgen-{version}-py3-none-any.whl",
            }
            if set(entries) != required:
                raise PublicReleaseBuildError(
                    "Windows Worker bundle files do not match the closed public allowlist"
                )
            _verify_checksums(archive, entries, prefix="", label="Windows Worker bundle")
            config = json.loads(archive.read("vgen-worker-bundle.json"))
            wheel_sha256 = _validated_embedded_wheel(
                archive,
                entries[f"vgen-{version}-py3-none-any.whl"],
                version=version,
                label="Windows Worker bundle",
            )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise PublicReleaseBuildError("Windows Worker bundle is not a valid public ZIP") from exc
    enrollment = config.get("enrollment") if isinstance(config, dict) else None
    wheel = config.get("wheel") if isinstance(config, dict) else None
    if (
        not isinstance(config, dict)
        or config.get("format") != "vgen-windows-worker-bundle"
        or config.get("gateway_url") != gateway_origin
        or not isinstance(enrollment, dict)
        or enrollment.get("kind") != "worker"
        or enrollment.get("identity") != "generated_on_worker"
        or enrollment.get("secret_input") != "hidden_prompt_or_stdin"
        or not isinstance(wheel, dict)
        or wheel.get("name") != f"vgen-{version}-py3-none-any.whl"
        or wheel.get("version") != version
        or wheel.get("sha256") != wheel_sha256
        or any(key in config for key in ("worker_id", "session_token", "invite_uri"))
    ):
        raise PublicReleaseBuildError(
            "Windows Worker bundle is not the credential-free enrollment format"
        )
    return wheel_sha256


def _ensure_directory(path: Path, *, mode: int = 0o755) -> None:
    if path.is_symlink():
        raise PublicReleaseBuildError(f"release destination must not be a symbolic link: {path}")
    if path.exists() and not path.is_dir():
        raise PublicReleaseBuildError(f"release destination must be a directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if path.is_symlink() or not path.is_dir():
        raise PublicReleaseBuildError(f"release destination is unsafe: {path}")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _same_version_tree(path: Path, expected: dict[str, tuple[int, str]]) -> bool:
    if path.is_symlink() or not path.is_dir():
        return False
    children = list(path.iterdir())
    if {child.name for child in children} != set(expected):
        return False
    for child in children:
        size, digest = expected[child.name]
        if child.is_symlink() or not child.is_file() or child.stat().st_size != size:
            return False
        if _sha256_file(child) != digest:
            return False
    return True


def _copy_regular(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise PublicReleaseBuildError(f"refusing to overwrite staging file: {destination}")
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    destination.chmod(0o644)


def _atomic_public_file(path: Path, content: bytes, *, mode: int) -> None:
    if path.is_symlink() or path.exists() and not path.is_file():
        raise PublicReleaseBuildError(f"refusing to replace unsafe public file: {path}")
    if path.is_file() and path.read_bytes() == content:
        path.chmod(mode)
        return
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
        if path.is_symlink() or path.exists() and not path.is_file():
            raise PublicReleaseBuildError(f"refusing to replace unsafe public file: {path}")
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _macos_bootstrap(
    *,
    gateway_origin: str,
    release_origin: str,
    version: str,
    manifest_sha256: str,
) -> bytes:
    gateway = shlex.quote(gateway_origin)
    release = shlex.quote(release_origin)
    expected_version = shlex.quote(version)
    expected_manifest = shlex.quote(manifest_sha256)
    script = f'''#!/bin/sh
set -eu
umask 077

GATEWAY_ORIGIN={gateway}
RELEASE_ORIGIN={release}
EXPECTED_VERSION={expected_version}
EXPECTED_MANIFEST_SHA256={expected_manifest}
readonly GATEWAY_ORIGIN RELEASE_ORIGIN EXPECTED_VERSION EXPECTED_MANIFEST_SHA256
export GATEWAY_ORIGIN RELEASE_ORIGIN EXPECTED_VERSION EXPECTED_MANIFEST_SHA256

PYTHON_BIN=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && \
     "$candidate" -I -B -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v "$candidate")"
    break
  fi
done
if [ -z "$PYTHON_BIN" ]; then
  printf '%s\n' 'VGen requires Python 3.11 or newer from python.org.' >&2
  exit 1
fi

WORK_DIR="$(mktemp -d "${{TMPDIR:-/tmp}}/vgen-macos-install.XXXXXXXX")"
cleanup() {{ rm -rf "$WORK_DIR"; }}
trap cleanup EXIT HUP INT TERM
export VGEN_BOOTSTRAP_WORK_DIR="$WORK_DIR"

"$PYTHON_BIN" -I -B <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

gateway_origin = os.environ["GATEWAY_ORIGIN"]
origin = os.environ["RELEASE_ORIGIN"]
expected_version = os.environ["EXPECTED_VERSION"]
expected_manifest_sha256 = os.environ["EXPECTED_MANIFEST_SHA256"]
work = Path(os.environ["VGEN_BOOTSTRAP_WORK_DIR"])
origin_parts = urllib.parse.urlsplit(origin)
origin_key = (origin_parts.scheme, origin_parts.hostname, origin_parts.port)
loopback = (origin_parts.hostname or "").lower() in {{"127.0.0.1", "::1", "localhost"}}
if origin_parts.scheme != "https" and not (origin_parts.scheme == "http" and loopback):
    raise SystemExit("VGen release origin must use HTTPS")


def same_origin(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.scheme, parts.hostname, parts.port) == origin_key and (
        parts.scheme == "https" or loopback
    )


class SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute = urllib.parse.urljoin(req.full_url, newurl)
        if not same_origin(absolute):
            raise urllib.error.HTTPError(
                absolute, code, "cross-origin release redirect refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, absolute)


opener = urllib.request.build_opener(SameOriginRedirects())


def status(message):
    print("[vgen] " + message, file=sys.stderr, flush=True)


def error_summary(exc):
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {{exc.code}}"
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    detail = " ".join(str(reason).split())
    detail = "".join(character if character.isprintable() else "?" for character in detail)
    if detail:
        return f"{{type(exc).__name__}}: {{detail[:200]}}"
    return type(exc).__name__


def fetch(url, limit):
    if not same_origin(url):
        raise SystemExit("cross-origin release URL refused")
    request = urllib.request.Request(url, headers={{"Accept": "application/json"}})
    with opener.open(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise SystemExit("release metadata exceeded its size limit")
    return data


status("Checking the latest VGen release...")
stable_url = origin + "/releases/channels/stable.json"
try:
    stable = json.loads(fetch(stable_url, 1024 * 1024))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit("could not read the stable VGen release metadata") from exc
if (
    not isinstance(stable, dict)
    or set(stable) != {{"schema_version", "channel", "version", "manifest_sha256"}}
    or stable.get("schema_version") != 1
    or stable.get("channel") != "stable"
    or stable.get("version") != expected_version
    or stable.get("manifest_sha256") != expected_manifest_sha256
):
    raise SystemExit("stable release metadata does not match this reviewed bootstrap")

manifest_url = origin + "/releases/" + expected_version + "/manifest.json"
manifest_bytes = fetch(manifest_url, 1024 * 1024)
if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256:
    raise SystemExit("version manifest SHA-256 mismatch")
try:
    manifest = json.loads(manifest_bytes)
except (UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit("version manifest is invalid") from exc
if (
    not isinstance(manifest, dict)
    or set(manifest) != {{"schema_version", "audience", "version", "published_at", "artifacts"}}
    or manifest.get("schema_version") != 1
    or manifest.get("audience") != "public"
    or manifest.get("version") != expected_version
    or not isinstance(manifest.get("artifacts"), list)
):
    raise SystemExit("version manifest contract mismatch")
matches = [
    item
    for item in manifest["artifacts"]
    if isinstance(item, dict)
    and item.get("name") == "macos-cli"
    and item.get("kind") == "cli-installer"
    and item.get("platform") == "macos"
]
if len(matches) != 1:
    raise SystemExit("version manifest has no unique macOS CLI bundle")
artifact = matches[0]
if set(artifact) != {{"name", "kind", "platform", "filename", "size", "sha256", "content_type"}}:
    raise SystemExit("macOS artifact metadata contract mismatch")
filename = artifact.get("filename")
size = artifact.get("size")
digest = artifact.get("sha256")
expected_filename = "VGen-macOS-" + expected_version + ".zip"
if (
    filename != expected_filename
    or not isinstance(size, int)
    or isinstance(size, bool)
    or size <= 0
    or not isinstance(digest, str)
    or len(digest) != 64
    or any(character not in "0123456789abcdef" for character in digest)
):
    raise SystemExit("macOS artifact metadata is invalid")
artifact_url = origin + "/releases/" + expected_version + "/" + filename
if not same_origin(artifact_url):
    raise SystemExit("cross-origin macOS artifact URL refused")
archive_path = work / filename
request = urllib.request.Request(artifact_url, headers={{"Accept": "application/zip"}})
status(
    f"Downloading VGen macOS {{expected_version}} "
    f"({{(size + 1023) // 1024}} KiB)..."
)
downloaded = 0
hasher = hashlib.sha256()
for attempt in range(1, 4):
    archive_path.unlink(missing_ok=True)
    downloaded = 0
    hasher = hashlib.sha256()
    try:
        with opener.open(request, timeout=60) as response, archive_path.open("xb") as output:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) != size:
                raise ValueError("Content-Length mismatch")
            while True:
                block = response.read(min(1024 * 1024, size - downloaded + 1))
                if not block:
                    break
                downloaded += len(block)
                if downloaded > size:
                    raise ValueError("download exceeded its declared size")
                hasher.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        break
    except (OSError, ValueError) as exc:
        archive_path.unlink(missing_ok=True)
        http_code = exc.code if isinstance(exc, urllib.error.HTTPError) else None
        retryable = http_code is None or http_code in {{408, 429}} or http_code >= 500
        if attempt == 3 or not retryable:
            raise SystemExit(
                "could not download the macOS CLI bundle after "
                f"{{attempt}} attempt(s): {{error_summary(exc)}}"
            ) from None
        status(f"Download interrupted; retrying ({{attempt}}/3)...")
        time.sleep(attempt)
if downloaded != size or hasher.hexdigest() != digest:
    raise SystemExit("macOS artifact size or SHA-256 mismatch")
status("Download complete; verifying the package...")

prefix = "VGen-macOS-" + expected_version + "/"
try:
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > 4096:
            raise SystemExit("macOS CLI ZIP has an invalid entry count")
        entries = {{}}
        folded = set()
        total = 0
        for info in infos:
            name = info.filename
            path = PurePosixPath(name.rstrip("/"))
            normalized = path.as_posix()
            if (
                "\\\\" in name
                or "\\x00" in name
                or name.startswith("/")
                or not path.parts
                or any(part in {{"", ".", ".."}} for part in path.parts)
                or ":" in path.parts[0]
                or not name.startswith(prefix)
                or normalized.casefold() in folded
                or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
                or info.flag_bits & 1
            ):
                raise SystemExit("macOS CLI ZIP contains an unsafe path")
            folded.add(normalized.casefold())
            entries[normalized] = info
            total += info.file_size
            if total > 2 * 1024 * 1024 * 1024:
                raise SystemExit("macOS CLI ZIP expands beyond its limit")
        required = {{
            prefix + "README.md",
            prefix + "SHA256SUMS",
            prefix + "install.command",
            prefix + "vgen-" + expected_version + "-py3-none-any.whl",
        }}
        optional_gateway = prefix + "gateway-default.txt"
        allowed = (required, required | {{optional_gateway}})
        if set(entries) not in allowed or archive.testzip() is not None:
            raise SystemExit("macOS CLI ZIP is incomplete or corrupt")
        if entries[prefix + "install.command"].external_attr >> 16 & 0o111 == 0:
            raise SystemExit("macOS install.command is not executable")
        if optional_gateway in entries:
            try:
                configured_gateway = archive.read(entries[optional_gateway]).decode("utf-8").strip()
            except UnicodeDecodeError as exc:
                raise SystemExit("macOS gateway-default.txt is unreadable") from exc
            if configured_gateway != gateway_origin:
                raise SystemExit("macOS gateway-default.txt does not match this Gateway")
        try:
            checksum_lines = archive.read(entries[prefix + "SHA256SUMS"]).decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise SystemExit("macOS CLI SHA256SUMS is unreadable") from exc
        checksums = {{}}
        for line in checksum_lines:
            match = re.fullmatch(r"([0-9a-f]{{64}})  ([A-Za-z0-9._+-]+)", line)
            if match is None or match.group(2) in checksums:
                raise SystemExit("macOS CLI SHA256SUMS is invalid")
            checksums[match.group(2)] = match.group(1)
        expected_files = {{
            name.removeprefix(prefix)
            for name in entries
            if name != prefix + "SHA256SUMS"
        }}
        if set(checksums) != expected_files:
            raise SystemExit("macOS CLI SHA256SUMS does not cover exactly its files")
        for name, expected in checksums.items():
            if hashlib.sha256(archive.read(entries[prefix + name])).hexdigest() != expected:
                raise SystemExit("macOS CLI embedded file SHA-256 mismatch")
        for info in infos:
            if info.is_dir():
                continue
            target = work.joinpath(*PurePosixPath(info.filename).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("xb") as output:
                while block := source.read(1024 * 1024):
                    output.write(block)
            mode = info.external_attr >> 16 & 0o777
            target.chmod(mode or (0o755 if target.name == "install.command" else 0o644))
except (OSError, zipfile.BadZipFile) as exc:
    raise SystemExit("could not safely extract the macOS CLI bundle") from exc
PY

printf '\nVerified VGen macOS %s from %s.\n' "$EXPECTED_VERSION" "$RELEASE_ORIGIN"
if [ "${{VGEN_INSTALL_YES:-0}}" = '1' ]; then
  answer=y
else
  if ! printf 'Install the CLI for the current user now? [y/N] ' 2>/dev/null >/dev/tty; then
    printf '%s\n' 'An interactive terminal is required; rerun from a terminal or set VGEN_INSTALL_YES=1.' >&2
    exit 1
  fi
  if ! IFS= read -r answer 2>/dev/null </dev/tty; then
    printf '%s\n' 'Could not read installation confirmation from the terminal.' >&2
    exit 1
  fi
fi
case "$answer" in
  y|Y) ;;
  *) printf '%s\n' 'Installation cancelled.'; exit 1 ;;
esac
"$WORK_DIR/VGen-macOS-$EXPECTED_VERSION/install.command" --install-only
VGEN_BIN="$HOME/.local/bin/vgen"
if [ ! -x "$VGEN_BIN" ] || [ "$("$VGEN_BIN" --version)" != "vgen $EXPECTED_VERSION" ]; then
  printf '%s\n' 'The managed VGen launcher did not switch to the verified version.' >&2
  exit 1
fi
if "$VGEN_BIN" profile show >/dev/null 2>&1; then
  "$VGEN_BIN" broker service-refresh
  printf '\nVGen CLI and Home Broker upgraded to %s.\n' "$EXPECTED_VERSION"
else
  printf '\nNext: "%s" join --gateway %s\n' "$VGEN_BIN" "$GATEWAY_ORIGIN"
fi
'''
    return script.encode("utf-8")


def _windows_worker_bootstrap(
    *,
    release_origin: str,
    version: str,
    manifest_sha256: str,
) -> bytes:
    """Return a pinned, credential-free PowerShell installer bootstrap."""

    # JSON encoding gives PowerShell-safe double-quoted constants for the
    # validated HTTPS origins and strict version/digest alphabets used here.
    release = json.dumps(release_origin)
    expected_version = json.dumps(version)
    expected_manifest = json.dumps(manifest_sha256)
    script = rf'''$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Net.Http

$ReleaseOrigin = {release}
$ExpectedVersion = {expected_version}
$ExpectedManifestSha256 = {expected_manifest}
$ExpectedArtifact = "vgen-windows-worker-installer-$ExpectedVersion.zip"

function Get-VGenBytes([string]$Url, [int64]$Limit) {{
    $uri = [Uri]$Url
    $origin = [Uri]$ReleaseOrigin
    if ($uri.Scheme -ne $origin.Scheme -or $uri.Host -ne $origin.Host -or $uri.Port -ne $origin.Port) {{
        throw "Cross-origin release URL refused."
    }}
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $response = $null
    try {{
        $response = $client.GetAsync($uri).GetAwaiter().GetResult()
        if (-not $response.IsSuccessStatusCode) {{
            throw "Release download returned HTTP $([int]$response.StatusCode)."
        }}
        $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        if ($bytes.LongLength -gt $Limit) {{ throw "Release file exceeded its size limit." }}
        return $bytes
    }}
    finally {{
        if ($null -ne $response) {{ $response.Dispose() }}
        $client.Dispose()
        $handler.Dispose()
    }}
}}

function Get-Sha256([byte[]]$Bytes) {{
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {{
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }}
    finally {{ $sha.Dispose() }}
}}

Write-Host "[vgen] Checking the latest Windows Worker installer..."
$stableBytes = Get-VGenBytes "$ReleaseOrigin/releases/channels/stable.json" 1048576
$stable = [Text.Encoding]::UTF8.GetString($stableBytes) | ConvertFrom-Json
if ($stable.schema_version -ne 1 -or $stable.channel -ne "stable" -or
    $stable.version -ne $ExpectedVersion -or
    $stable.manifest_sha256 -ne $ExpectedManifestSha256) {{
    throw "Stable release metadata does not match this reviewed installer. Download the installer command again."
}}

$manifestBytes = Get-VGenBytes "$ReleaseOrigin/releases/$ExpectedVersion/manifest.json" 1048576
if ((Get-Sha256 $manifestBytes) -ne $ExpectedManifestSha256) {{
    throw "Release manifest SHA-256 mismatch."
}}
$manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
$matches = @($manifest.artifacts | Where-Object {{
    $_.name -eq "windows-worker-installer" -and
    $_.kind -eq "worker-installer" -and
    $_.platform -eq "windows"
}})
if ($manifest.schema_version -ne 1 -or $manifest.audience -ne "public" -or
    $manifest.version -ne $ExpectedVersion -or $matches.Count -ne 1) {{
    throw "Release manifest does not contain one Windows Worker installer."
}}
$artifact = $matches[0]
if ($artifact.filename -ne $ExpectedArtifact -or $artifact.content_type -ne "application/zip" -or
    (($artifact.size -isnot [long]) -and ($artifact.size -isnot [int])) -or
    [int64]$artifact.size -le 0 -or [int64]$artifact.size -gt 536870912 -or
    [string]$artifact.sha256 -notmatch '^[0-9a-f]{{64}}$') {{
    throw "Windows Worker artifact metadata is invalid."
}}

Write-Host "[vgen] Downloading and verifying VGen Windows Worker $ExpectedVersion..."
$archiveBytes = Get-VGenBytes "$ReleaseOrigin/releases/$ExpectedVersion/$ExpectedArtifact" 536870912
if ($archiveBytes.LongLength -ne [int64]$artifact.size -or
    (Get-Sha256 $archiveBytes) -ne [string]$artifact.sha256) {{
    throw "Windows Worker installer size or SHA-256 mismatch."
}}

$installRoot = Join-Path $env:LOCALAPPDATA "VGen\installer\$ExpectedVersion-$($ExpectedManifestSha256.Substring(0, 12))"
$parent = Split-Path -Parent $installRoot
[IO.Directory]::CreateDirectory($parent) | Out-Null
$staging = "$installRoot.staging-$([Guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($staging) | Out-Null
$archivePath = Join-Path $staging $ExpectedArtifact
[IO.File]::WriteAllBytes($archivePath, $archiveBytes)

try {{
    Add-Type -AssemblyName System.IO.Compression
    $stream = [IO.File]::OpenRead($archivePath)
    try {{
        $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read)
        try {{
            $required = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            @(
                "INSTALL.txt", "enroll-worker.ps1", "start-worker.cmd", "setup-worker.ps1",
                "vgen-worker-bundle.json", "comfyui-minimax-h3-policy.yaml", "SHA256SUMS",
                "vgen-$ExpectedVersion-py3-none-any.whl"
            ) | ForEach-Object {{ [void]$required.Add($_) }}
            if ($zip.Entries.Count -ne $required.Count) {{ throw "Installer ZIP has an unexpected file count." }}
            foreach ($entry in $zip.Entries) {{
                if (-not $required.Remove($entry.FullName) -or
                    $entry.FullName.Contains("/") -or $entry.FullName.Contains("\") -or
                    [string]::IsNullOrWhiteSpace($entry.Name)) {{
                    throw "Installer ZIP contains an unexpected or unsafe path."
                }}
                $target = Join-Path $staging $entry.Name
                $input = $entry.Open()
                try {{
                    $output = [IO.File]::Create($target)
                    try {{ $input.CopyTo($output) }} finally {{ $output.Dispose() }}
                }} finally {{ $input.Dispose() }}
            }}
            if ($required.Count -ne 0) {{ throw "Installer ZIP is incomplete." }}
        }} finally {{ $zip.Dispose() }}
    }} finally {{ $stream.Dispose() }}
    Remove-Item -LiteralPath $archivePath -Force
    if (Test-Path -LiteralPath $installRoot) {{
        $existing = Get-Item -LiteralPath $installRoot -Force
        if (-not $existing.PSIsContainer -or
            ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
            throw "Existing VGen installer directory is unsafe."
        }}
        Remove-Item -LiteralPath $installRoot -Recurse -Force
    }}
    Move-Item -LiteralPath $staging -Destination $installRoot
}} catch {{
    if (Test-Path -LiteralPath $staging) {{ Remove-Item -LiteralPath $staging -Recurse -Force }}
    throw
}}

Write-Host "[vgen] Verified. Starting the universal Worker installer..."
& (Join-Path $installRoot "start-worker.cmd")
if ($LASTEXITCODE -ne 0) {{ throw "Windows Worker setup stopped with exit code $LASTEXITCODE." }}
'''
    return script.encode("utf-8")


def build_public_release(
    *,
    version: str,
    published_at: str,
    gateway_origin: str,
    release_origin: str,
    macos_bundle: Path,
    windows_worker_bundle: Path,
    output_root: Path,
) -> ReleaseBuildResult:
    if _VERSION.fullmatch(version) is None:
        raise PublicReleaseBuildError("version must be MAJOR.MINOR.PATCH")
    published_at = _validated_published_at(published_at)
    gateway_origin = _validated_gateway_origin(gateway_origin)
    release_origin = _validated_gateway_origin(release_origin)
    macos_bundle = _regular_source(macos_bundle, label="macOS CLI bundle")
    windows_worker_bundle = _regular_source(
        windows_worker_bundle, label="Windows Worker bundle"
    )
    if macos_bundle == windows_worker_bundle:
        raise PublicReleaseBuildError("public artifacts must be distinct files")
    macos_wheel_sha256 = _validate_macos_bundle(
        macos_bundle,
        version=version,
        gateway_origin=gateway_origin,
    )
    windows_wheel_sha256 = _validate_windows_bundle(
        windows_worker_bundle,
        version=version,
        gateway_origin=gateway_origin,
    )
    if macos_wheel_sha256 != windows_wheel_sha256:
        raise PublicReleaseBuildError(
            "macOS and Windows public installers must contain the same reviewed VGen wheel"
        )

    artifacts = [
        _Artifact(macos_bundle, "macos-cli", "cli-installer", "macos"),
        _Artifact(
            windows_worker_bundle,
            "windows-worker-installer",
            "worker-installer",
            "windows",
        ),
    ]
    filenames = [artifact.source.name for artifact in artifacts]
    if len(set(name.casefold() for name in filenames)) != len(filenames):
        raise PublicReleaseBuildError("public artifact filenames must be unique")
    artifact_metadata = [artifact.metadata() for artifact in artifacts]
    manifest_value = {
        "schema_version": 1,
        "audience": "public",
        "version": version,
        "published_at": published_at,
        "artifacts": artifact_metadata,
    }
    manifest_bytes = _json_bytes(manifest_value)
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    expected = {
        str(item["filename"]): (int(item["size"]), str(item["sha256"]))
        for item in artifact_metadata
    }
    expected["manifest.json"] = (len(manifest_bytes), manifest_sha256)

    root = _absolute(output_root)
    _ensure_directory(root)
    version_root = root / version
    if version_root.exists() or version_root.is_symlink():
        if not _same_version_tree(version_root, expected):
            raise PublicReleaseBuildError(
                f"refusing to overwrite non-identical immutable release: {version_root}"
            )
    else:
        staging = Path(tempfile.mkdtemp(prefix=f".vgen-release-{version}-", dir=root))
        try:
            for artifact in artifacts:
                _copy_regular(artifact.source, staging / artifact.source.name)
            manifest_path = staging / "manifest.json"
            manifest_path.write_bytes(manifest_bytes)
            manifest_path.chmod(0o644)
            with manifest_path.open("rb") as handle:
                os.fsync(handle.fileno())
            staging.chmod(0o755)
            _fsync_directory(staging)
            if not _same_version_tree(staging, expected):
                raise PublicReleaseBuildError(
                    "public artifact changed while its immutable manifest was being staged"
                )
            try:
                os.rename(staging, version_root)
            except FileExistsError:
                if not _same_version_tree(version_root, expected):
                    raise PublicReleaseBuildError(
                        f"another process published different content for {version}"
                    ) from None
            _fsync_directory(root)
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    bootstrap = _macos_bootstrap(
        gateway_origin=gateway_origin,
        release_origin=release_origin,
        version=version,
        manifest_sha256=manifest_sha256,
    )
    bootstrap_path = root / _BOOTSTRAP_NAME
    _atomic_public_file(bootstrap_path, bootstrap, mode=0o755)
    windows_bootstrap = _windows_worker_bootstrap(
        release_origin=release_origin,
        version=version,
        manifest_sha256=manifest_sha256,
    )
    windows_bootstrap_path = root / _WINDOWS_BOOTSTRAP_NAME
    _atomic_public_file(windows_bootstrap_path, windows_bootstrap, mode=0o644)

    channels = root / "channels"
    _ensure_directory(channels)
    pointer_bytes = _json_bytes(
        {
            "schema_version": 1,
            "channel": "stable",
            "version": version,
            "manifest_sha256": manifest_sha256,
        }
    )
    stable_pointer = channels / "stable.json"
    _atomic_public_file(stable_pointer, pointer_bytes, mode=0o644)
    return ReleaseBuildResult(
        root=root,
        version_root=version_root,
        manifest=version_root / "manifest.json",
        stable_pointer=stable_pointer,
        macos_bootstrap=bootstrap_path,
        windows_worker_bootstrap=windows_bootstrap_path,
        manifest_sha256=manifest_sha256,
    )


def _parser() -> argparse.ArgumentParser:
    version = _project_version(REPOSITORY)
    parser = argparse.ArgumentParser(
        description="Build an auditable VGen public release staging tree."
    )
    parser.add_argument("--version", default=version)
    parser.add_argument("--published-at", required=True, metavar="YYYY-MM-DDTHH:MM:SSZ")
    parser.add_argument("--gateway-origin", required=True, metavar="https://gateway.example")
    parser.add_argument("--release-origin", required=True, metavar="https://download.example")
    parser.add_argument("--mac-bundle", type=Path)
    parser.add_argument("--windows-worker-bundle", type=Path)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=REPOSITORY / "dist" / "public-releases",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    version = arguments.version
    macos_bundle = arguments.mac_bundle or (
        REPOSITORY / "dist" / f"VGen-macOS-{version}.zip"
    )
    windows_bundle = arguments.windows_worker_bundle or (
        REPOSITORY / "dist" / f"vgen-windows-worker-installer-{version}.zip"
    )
    result = build_public_release(
        version=version,
        published_at=arguments.published_at,
        gateway_origin=arguments.gateway_origin,
        release_origin=arguments.release_origin,
        macos_bundle=macos_bundle,
        windows_worker_bundle=windows_bundle,
        output_root=arguments.output_root,
    )
    print(f"release_root={result.root}")
    print(f"version={version}")
    print(f"manifest_sha256={result.manifest_sha256}")
    print(f"stable_pointer={result.stable_pointer}")
    print(f"macos_bootstrap={result.macos_bootstrap}")
    print(f"windows_worker_bootstrap={result.windows_worker_bootstrap}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
