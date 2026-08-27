"""Build the credential-free Windows Worker release artifact."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from email.parser import Parser
from importlib import metadata, resources
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from packaging.markers import UndefinedComparison, UndefinedEnvironmentName, default_environment
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import Tag, compatible_tags, cpython_tags, parse_tag
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import Version

from vgen import __version__

_BUNDLE_FORMAT = "vgen-windows-worker-bundle"
_BUNDLE_VERSION = 2
_EXECUTOR_VERSION = "1.1.0"
_POLICY_NAME = "comfyui-minimax-h3-policy.yaml"
_SCRIPT_NAME = "setup-worker.ps1"
_LAUNCHER_NAME = "start-worker.cmd"
_ENROLLMENT_SCRIPT_NAME = "enroll-worker.ps1"
_SUPERVISOR_SCRIPT_NAME = "supervise-worker.ps1"
_RUNTIME_REQUIREMENTS_NAME = "vgen-worker-requirements.txt"
_MAX_WHEELHOUSE_FILES = 128
_MAX_WHEELHOUSE_BYTES = 512 * 1024 * 1024
_WORKER_UPDATE_VERSION = re.compile(r"^(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})$")
_RUNTIME_PYTHON_PATCHES = tuple(Version(f"3.11.{patch}") for patch in range(100))


class WorkerBundleError(ValueError):
    """A safe, user-actionable bundle provisioning error."""


@dataclass(frozen=True, slots=True)
class WorkerInstallerBundleResult:
    """A credential-free bundle safe for public release distribution."""

    path: Path
    gateway_url: str

    def public_dict(self) -> dict[str, str]:
        return {
            "bundle": str(self.path),
            "gateway": self.gateway_url,
            "credentials": "generated-locally-after-one-time-invite",
            "next": "Extract the ZIP on Windows, then double-click start-worker.cmd.",
        }


@dataclass(frozen=True, slots=True)
class WorkerUpdateArtifact:
    path: Path
    version: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _RuntimeWheel:
    name: str
    distribution: str
    version: Version
    sha256: str
    value: bytes
    requirements: tuple[str, ...]
    requires_python: str | None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, (2020, 2, 2, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | stat.S_IMODE(mode)) << 16
    return info


def _asset_bytes(name: str) -> bytes:
    packaged = resources.files("vgen").joinpath("assets", "worker", name)
    if packaged.is_file():
        return packaged.read_bytes()
    repository = Path(__file__).resolve().parents[3]
    if name in {
        _SCRIPT_NAME,
        _LAUNCHER_NAME,
        _ENROLLMENT_SCRIPT_NAME,
        _SUPERVISOR_SCRIPT_NAME,
    }:
        source = repository / "examples" / "windows-worker" / name
    else:
        source = repository / "examples" / name
    try:
        return source.read_bytes()
    except OSError as exc:
        raise WorkerBundleError(f"Bundled Windows Worker asset is unavailable: {name}") from exc


def _validate_wheel(name: str, value: bytes, *, expected_version: str = __version__) -> None:
    expected_name = f"vgen-{expected_version}-py3-none-any.whl"
    if name != expected_name:
        raise WorkerBundleError(f"The Worker wheel must be named {expected_name}.")
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            names = archive.namelist()
            if any(
                item.startswith(("/", "\\")) or ".." in Path(item.replace("\\", "/")).parts
                for item in names
            ):
                raise WorkerBundleError("The Worker wheel contains an unsafe path.")
            metadata_names = [item for item in names if item.endswith(".dist-info/METADATA")]
            wheel_names = [item for item in names if item.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise WorkerBundleError("The Worker wheel metadata is incomplete.")
            package_metadata = archive.read(metadata_names[0]).decode("utf-8")
            wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
        raise WorkerBundleError("The Worker wheel is not a readable Python wheel.") from exc
    if not re.search(r"(?m)^Name:\s*vgen\s*$", package_metadata):
        raise WorkerBundleError("The Worker wheel is not the VGen distribution.")
    if not re.search(rf"(?m)^Version:\s*{re.escape(expected_version)}\s*$", package_metadata):
        raise WorkerBundleError(f"The Worker wheel must be VGen {expected_version}.")
    if not re.search(r"(?m)^Tag:\s*py3-none-any\s*$", wheel_metadata):
        raise WorkerBundleError("The Worker wheel must be the reviewed py3-none-any build.")


def _validate_public_installer_wheel(value: bytes) -> None:
    """Reject a stale wheel which cannot perform local Invite enrollment."""

    required = {
        "vgen/cli/main.py",
        "vgen/cli/worker_enrollment.py",
        "vgen/assets/worker/enroll-worker.ps1",
        "vgen/assets/worker/supervise-worker.ps1",
    }
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            missing = sorted(required - set(archive.namelist()))
    except zipfile.BadZipFile as exc:
        raise WorkerBundleError("The Worker wheel is not a readable Python wheel.") from exc
    if missing:
        raise WorkerBundleError(
            "The Worker wheel predates credential-free enrollment; build the current release first."
        )


def _runtime_target_tags() -> frozenset[Tag]:
    tags = set(
        cpython_tags(
            python_version=(3, 11),
            abis=("cp311", "abi3", "none"),
            platforms=("win_amd64",),
        )
    )
    tags.update(
        compatible_tags(
            python_version=(3, 11),
            interpreter="cp311",
            platforms=("win_amd64",),
        )
    )
    return frozenset(tags)


_RUNTIME_TARGET_TAGS = _runtime_target_tags()


def _inspect_runtime_wheel(name: str, value: bytes) -> _RuntimeWheel:
    if (
        Path(name).name != name
        or not name.endswith(".whl")
        or not 1 <= len(value) <= _MAX_WHEELHOUSE_BYTES
    ):
        raise WorkerBundleError("The Worker wheelhouse contains an invalid wheel file.")
    try:
        filename_distribution, filename_version, _build, filename_tags = parse_wheel_filename(name)
    except InvalidWheelFilename as exc:
        raise WorkerBundleError(f"The Worker wheelhouse filename is invalid: {name}") from exc
    if not filename_tags.intersection(_RUNTIME_TARGET_TAGS):
        raise WorkerBundleError(f"The Worker wheel is not compatible with CPython 3.11: {name}")
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > 8192:
                raise WorkerBundleError(f"The Worker wheel has an invalid entry count: {name}")
            seen: set[str] = set()
            folded: set[str] = set()
            total = 0
            for info in infos:
                path = info.filename
                normalized = path.replace("\\", "/")
                parts = PurePosixPath(normalized.rstrip("/")).parts
                key = normalized.casefold()
                if (
                    path != normalized
                    or path.startswith("/")
                    or "\x00" in path
                    or not parts
                    or any(part in {"", ".", ".."} for part in parts)
                    or normalized in seen
                    or key in folded
                    or stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK
                    or info.flag_bits & 0x1
                    or info.file_size < 0
                ):
                    raise WorkerBundleError(f"The Worker wheel contains an unsafe entry: {name}")
                seen.add(normalized)
                folded.add(key)
                total += info.file_size
                if total > _MAX_WHEELHOUSE_BYTES:
                    raise WorkerBundleError(f"The Worker wheel expands beyond its limit: {name}")
            metadata_names = [item for item in seen if item.endswith(".dist-info/METADATA")]
            wheel_names = [item for item in seen if item.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise WorkerBundleError(f"The Worker wheel metadata is incomplete: {name}")
            package_metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
            wheel_metadata = Parser().parsestr(archive.read(wheel_names[0]).decode("utf-8"))
            if archive.testzip() is not None:
                raise WorkerBundleError(f"The Worker wheel contains corrupt data: {name}")
    except WorkerBundleError:
        raise
    except (KeyError, OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise WorkerBundleError(f"The Worker wheel is unreadable: {name}") from exc
    distribution = canonicalize_name(package_metadata.get("Name", ""))
    try:
        version = Version(package_metadata.get("Version", ""))
    except ValueError as exc:
        raise WorkerBundleError(f"The Worker wheel version is invalid: {name}") from exc
    declared_tags: set[Tag] = set()
    for raw_tag in wheel_metadata.get_all("Tag", []):
        try:
            declared_tags.update(parse_tag(raw_tag))
        except ValueError as exc:
            raise WorkerBundleError(f"The Worker wheel tag metadata is invalid: {name}") from exc
    if (
        distribution != canonicalize_name(filename_distribution)
        or version != filename_version
        or not declared_tags
        or declared_tags != filename_tags
    ):
        raise WorkerBundleError(f"The Worker wheel identity does not match its filename: {name}")
    requires_python = package_metadata.get("Requires-Python")
    if requires_python:
        try:
            python_specifier = SpecifierSet(requires_python)
        except InvalidSpecifier as exc:
            raise WorkerBundleError(f"The Worker wheel Requires-Python is invalid: {name}") from exc
        if not all(
            python_specifier.contains(candidate, prereleases=True)
            for candidate in _RUNTIME_PYTHON_PATCHES
        ):
            raise WorkerBundleError(
                f"The Worker wheel does not support the complete Python 3.11 target: {name}"
            )
    return _RuntimeWheel(
        name=name,
        distribution=distribution,
        version=version,
        sha256=_sha256(value),
        value=value,
        requirements=tuple(package_metadata.get_all("Requires-Dist", [])),
        requires_python=requires_python,
    )


def validate_windows_worker_runtime_wheelhouse(
    root: Path,
    *,
    vgen_name: str,
    vgen_value: bytes,
) -> tuple[list[_RuntimeWheel], bytes, _RuntimeWheel]:
    expanded = root.expanduser()
    try:
        if expanded.is_symlink():
            raise WorkerBundleError("The Worker wheelhouse must not be a symbolic link.")
        candidate = expanded.resolve(strict=True)
    except WorkerBundleError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WorkerBundleError(
            "The Worker wheelhouse must be a regular local directory."
        ) from exc
    if not candidate.is_dir():
        raise WorkerBundleError("The Worker wheelhouse must be a regular local directory.")
    paths = sorted(candidate.iterdir(), key=lambda item: item.name.encode("utf-8"))
    if not paths or len(paths) >= _MAX_WHEELHOUSE_FILES:
        raise WorkerBundleError("The Worker wheelhouse has an invalid file count.")
    total = len(vgen_value)
    wheels = [_inspect_runtime_wheel(vgen_name, vgen_value)]
    names = {vgen_name.casefold()}
    for path in paths:
        if path.is_symlink() or not path.is_file() or path.name != path.name.strip():
            raise WorkerBundleError("The Worker wheelhouse may contain only regular wheel files.")
        if path.name.casefold() in names:
            raise WorkerBundleError(f"The Worker wheelhouse has a duplicate filename: {path.name}")
        try:
            value = path.read_bytes()
        except OSError as exc:
            raise WorkerBundleError(
                f"The Worker wheelhouse file cannot be read: {path.name}"
            ) from exc
        total += len(value)
        if total > _MAX_WHEELHOUSE_BYTES:
            raise WorkerBundleError("The Worker wheelhouse exceeds its size limit.")
        wheels.append(_inspect_runtime_wheel(path.name, value))
        names.add(path.name.casefold())

    by_distribution: dict[str, _RuntimeWheel] = {}
    for wheel in wheels:
        if wheel.distribution in by_distribution:
            raise WorkerBundleError(
                f"The Worker wheelhouse contains more than one {wheel.distribution} wheel."
            )
        by_distribution[wheel.distribution] = wheel
    pip_wheel = by_distribution.get("pip")
    if pip_wheel is None:
        raise WorkerBundleError("The Worker wheelhouse has no reviewed bootstrap pip wheel.")

    environment_base = default_environment()
    environment_base.update(
        {
            "implementation_name": "cpython",
            "os_name": "nt",
            "platform_machine": "AMD64",
            "platform_python_implementation": "CPython",
            "platform_system": "Windows",
            "python_version": "3.11",
            "sys_platform": "win32",
        }
    )
    if "vgen" not in by_distribution:
        raise WorkerBundleError("The Worker wheelhouse has no VGen wheel.")
    reachable: set[str] = set()
    for python_version in _RUNTIME_PYTHON_PATCHES:
        python_full_version = str(python_version)
        environment = {**environment_base, "python_full_version": python_full_version}
        environment_reachable = {"vgen"}
        requested_extras: dict[str, set[str]] = {"vgen": {"worker-comfyui"}}
        changed = True
        while changed:
            changed = False
            for distribution in tuple(sorted(environment_reachable)):
                wheel = by_distribution[distribution]
                contexts = {"", *requested_extras.get(distribution, set())}
                for raw in wheel.requirements:
                    try:
                        requirement = Requirement(raw)
                    except InvalidRequirement as exc:
                        raise WorkerBundleError(
                            f"The Worker wheel has an invalid dependency: {wheel.name}"
                        ) from exc
                    try:
                        active = requirement.marker is None or any(
                            requirement.marker.evaluate({**environment, "extra": extra})
                            for extra in contexts
                        )
                    except (UndefinedComparison, UndefinedEnvironmentName) as exc:
                        raise WorkerBundleError(
                            f"The Worker wheel dependency marker cannot be evaluated: {wheel.name}"
                        ) from exc
                    if not active:
                        continue
                    dependency = by_distribution.get(canonicalize_name(requirement.name))
                    if dependency is None or (
                        requirement.specifier
                        and not requirement.specifier.contains(dependency.version, prereleases=True)
                    ):
                        raise WorkerBundleError(
                            f"The Worker wheelhouse does not satisfy {raw!r} from {wheel.name}."
                        )
                    if requirement.url is not None:
                        raise WorkerBundleError(
                            f"The Worker wheel uses an unreviewed direct dependency URL: {wheel.name}"
                        )
                    if dependency.distribution not in environment_reachable:
                        environment_reachable.add(dependency.distribution)
                        requested_extras[dependency.distribution] = set()
                        changed = True
                    before = len(requested_extras[dependency.distribution])
                    requested_extras[dependency.distribution].update(requirement.extras)
                    changed = changed or len(requested_extras[dependency.distribution]) != before
        reachable.update(environment_reachable)

    orphans = set(by_distribution) - reachable - {"pip"}
    if orphans:
        raise WorkerBundleError(
            "The Worker wheelhouse contains unrelated distributions: " + ", ".join(sorted(orphans))
        )

    lines = ["# Generated from the reviewed Windows Worker wheelhouse; do not edit."]
    for wheel in sorted(wheels, key=lambda item: item.distribution):
        requirement_name = wheel.distribution
        if wheel.distribution == "vgen":
            requirement_name += "[worker-comfyui]"
        lines.append(f"{requirement_name}=={wheel.version} --hash=sha256:{wheel.sha256}")
    requirements = ("\n".join(lines) + "\n").encode("ascii")
    return wheels, requirements, pip_wheel


def inspect_worker_update_wheel(path: Path) -> WorkerUpdateArtifact:
    """Validate a local, pure-Python VGen wheel without importing its code."""

    expanded = path.expanduser()
    try:
        if expanded.is_symlink():
            raise WorkerBundleError("The Worker update wheel must not be a symbolic link.")
        resolved = expanded.resolve(strict=True)
        metadata = resolved.stat()
    except WorkerBundleError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WorkerBundleError("The Worker update wheel must be a regular local file.") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise WorkerBundleError("The Worker update wheel must be a regular local file.")
    match = re.fullmatch(r"vgen-(.+)-py3-none-any\.whl", resolved.name)
    if match is None or not match.group(1):
        raise WorkerBundleError(
            "The Worker update wheel must be named vgen-<version>-py3-none-any.whl."
        )
    version = match.group(1)
    if _WORKER_UPDATE_VERSION.fullmatch(version) is None:
        raise WorkerBundleError("The Worker update wheel version must be MAJOR.MINOR.PATCH.")
    if not 1 <= metadata.st_size <= 512 * 1024 * 1024:
        raise WorkerBundleError("The Worker update wheel size is outside the supported limit.")
    try:
        value = resolved.read_bytes()
    except OSError as exc:
        raise WorkerBundleError("The Worker update wheel cannot be read.") from exc
    if len(value) != metadata.st_size:
        raise WorkerBundleError("The Worker update wheel changed while it was being reviewed.")
    _validate_wheel(resolved.name, value, expected_version=version)
    return WorkerUpdateArtifact(
        path=resolved,
        version=version,
        size_bytes=len(value),
        sha256=_sha256(value),
    )


def _direct_url_wheel() -> Path | None:
    try:
        raw = metadata.distribution("vgen").read_text("direct_url.json")
        value = json.loads(raw) if raw else {}
        parsed = urlparse(str(value.get("url", "")))
        if parsed.scheme != "file":
            return None
        path = Path(unquote(parsed.path))
        return path if path.suffix == ".whl" and path.is_file() else None
    except (metadata.PackageNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return None


def _installed_wheel_bytes() -> tuple[str, bytes]:
    """Rebuild the installed pure-Python distribution without network access."""

    try:
        distribution = metadata.distribution("vgen")
        files = distribution.files or []
    except metadata.PackageNotFoundError as exc:
        raise WorkerBundleError(
            "No VGen Worker wheel is available. Reinstall the downloadable VGen CLI package."
        ) from exc

    selected: list[tuple[str, bytes]] = []
    dist_info_prefix: str | None = None
    for entry in files:
        relative = str(entry).replace("\\", "/")
        first = relative.split("/", 1)[0]
        if first == "vgen":
            pass
        elif first.endswith(".dist-info") and first.lower().startswith("vgen-"):
            dist_info_prefix = first
        else:
            continue
        if relative.endswith(".dist-info/RECORD"):
            continue
        resolved = Path(distribution.locate_file(entry))
        if not resolved.is_file() or resolved.is_symlink():
            continue
        selected.append((relative, resolved.read_bytes()))

    if not selected or dist_info_prefix is None:
        raise WorkerBundleError(
            "The installed VGen CLI cannot materialize its Worker wheel; reinstall the CLI."
        )

    record_name = f"{dist_info_prefix}/RECORD"
    buffer = io.BytesIO()
    records: list[list[str]] = []
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(selected):
            info = _canonical_zip_info(name, 0o644)
            archive.writestr(info, value)
            digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
            records.append([name, f"sha256={digest}", str(len(value))])
        record_buffer = io.StringIO(newline="")
        writer = csv.writer(record_buffer, lineterminator="\n")
        writer.writerows(records)
        writer.writerow([record_name, "", ""])
        info = _canonical_zip_info(record_name, 0o644)
        archive.writestr(info, record_buffer.getvalue().encode("utf-8"))
    return f"vgen-{__version__}-py3-none-any.whl", buffer.getvalue()


def load_worker_wheel(explicit: Path | None = None) -> tuple[str, bytes]:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())
    else:
        repository = Path(__file__).resolve().parents[3]
        candidates.extend(
            sorted((repository / "dist").glob(f"vgen-{__version__}-py3-none-any.whl"))
        )
        direct = _direct_url_wheel()
        if direct is not None and direct not in candidates:
            candidates.append(direct)

    if candidates:
        selected = candidates[0].resolve()
        try:
            value = selected.read_bytes()
        except OSError as exc:
            raise WorkerBundleError("The selected Worker wheel cannot be read.") from exc
        _validate_wheel(selected.name, value)
        return selected.name, value

    name, value = _installed_wheel_bytes()
    _validate_wheel(name, value)
    return name, value


def select_pool(
    pools: list[dict[str, Any]],
    *,
    requested: str | None,
    default: str | None = None,
) -> dict[str, Any]:
    selector = requested or default
    if selector:
        matches = [
            pool for pool in pools if selector in {str(pool.get("id")), str(pool.get("name"))}
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise WorkerBundleError(f"No active Pool named '{selector}' exists in this Workspace.")
        raise WorkerBundleError(
            f"More than one active Pool is named '{selector}'. Rename one first."
        )
    if len(pools) == 1:
        return pools[0]
    if not pools:
        raise WorkerBundleError(
            "This Workspace has no Pool. Create one, then run this command again."
        )
    names = ", ".join(sorted(str(pool.get("name") or "unnamed") for pool in pools))
    raise WorkerBundleError(f"Choose a Pool by name with --pool. Available Pools: {names}")


def _safe_installer_output_path(output: Path | None) -> Path:
    if output is None:
        target_root = Path.home() / "Downloads"
        if not target_root.is_dir():
            target_root = Path.cwd()
        output = target_root / f"vgen-windows-worker-installer-{__version__}.zip"
    target = output.expanduser().resolve()
    if target.suffix.lower() != ".zip":
        raise WorkerBundleError("Worker installer bundle output must use the .zip extension.")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _validated_gateway_origin(value: str) -> str:
    endpoint = value.strip().rstrip("/")
    try:
        parsed = urlparse(endpoint)
        _ = parsed.port
    except ValueError as exc:
        raise WorkerBundleError("Gateway URL is invalid.") from exc
    localhost = (parsed.hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or (parsed.scheme != "https" and not localhost)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise WorkerBundleError(
            "Gateway URL must be an HTTPS origin without credentials, path, query, or fragment."
        )
    return endpoint


def _write_public_installer_bundle(
    target: Path,
    *,
    overwrite: bool,
    entries: list[tuple[str, bytes, int]],
) -> None:
    if target.exists() and not overwrite:
        raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        checksums = b"".join(
            f"{_sha256(value)}  {name}\n".encode("ascii") for name, value, _ in entries
        )
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value, mode in [*entries, ("SHA256SUMS", checksums, 0o644)]:
                info = _canonical_zip_info(name, mode)
                archive.writestr(info, value)
        if target.exists() and not overwrite:
            raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
        os.replace(temporary, target)
        os.chmod(target, 0o644)
    finally:
        temporary.unlink(missing_ok=True)


def create_public_windows_worker_installer_bundle(
    *,
    gateway_url: str,
    wheelhouse_path: Path,
    runtime_lock_set_sha256: str,
    output: Path | None = None,
    wheel_path: Path | None = None,
    overwrite: bool = False,
) -> WorkerInstallerBundleResult:
    """Create a reusable Windows ZIP with no principal credentials.

    The ZIP is byte-for-byte independent of a Worker or Invite.  Windows
    generates its private key only after extraction and the Invite is entered
    into a hidden prompt.  Authenticating this public ZIP is the responsibility
    of the signed release manifest/notarized installer layer.
    """

    endpoint = _validated_gateway_origin(gateway_url)
    if re.fullmatch(r"[0-9a-f]{64}", runtime_lock_set_sha256) is None:
        raise WorkerBundleError("Worker runtime lock-set digest must be lowercase SHA-256.")
    target = _safe_installer_output_path(output)
    if target.exists() and not overwrite:
        raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
    script = _asset_bytes(_SCRIPT_NAME)
    launcher = _asset_bytes(_LAUNCHER_NAME)
    enrollment_script = _asset_bytes(_ENROLLMENT_SCRIPT_NAME)
    supervisor_script = _asset_bytes(_SUPERVISOR_SCRIPT_NAME)
    policy = _asset_bytes(_POLICY_NAME)
    wheel_name, wheel = load_worker_wheel(wheel_path)
    _validate_public_installer_wheel(wheel)
    runtime_wheels, runtime_requirements, bootstrap_pip = (
        validate_windows_worker_runtime_wheelhouse(
            wheelhouse_path,
            vgen_name=wheel_name,
            vgen_value=wheel,
        )
    )
    config = {
        "format": _BUNDLE_FORMAT,
        "version": _BUNDLE_VERSION,
        "gateway_url": endpoint,
        "worker_credentials": "worker-credentials.json",
        "comfyui_root": None,
        "comfyui_data_root": None,
        "wheel": {
            "name": wheel_name,
            "version": __version__,
            "sha256": _sha256(wheel),
        },
        "python_runtime": {
            "implementation": "cp",
            "python_version": "3.11",
            "platform": "win_amd64",
            "lock_set_sha256": runtime_lock_set_sha256,
            "requirements": {
                "name": _RUNTIME_REQUIREMENTS_NAME,
                "sha256": _sha256(runtime_requirements),
            },
            "bootstrap_pip": {
                "name": bootstrap_pip.name,
                "sha256": bootstrap_pip.sha256,
            },
            "wheels": [
                {
                    "name": item.name,
                    "distribution": item.distribution,
                    "version": str(item.version),
                    "sha256": item.sha256,
                }
                for item in sorted(runtime_wheels, key=lambda item: item.name.encode("utf-8"))
            ],
        },
        "policy": {"name": _POLICY_NAME, "sha256": _sha256(policy)},
        "enrollment": {
            "kind": "worker",
            "secret_input": "hidden_prompt_or_stdin",
            "identity": "generated_on_worker",
        },
    }
    config_bytes = json.dumps(config, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    install_text = (
        b"VGen Windows Worker\r\n"
        b"===================\r\n\r\n"
        b"1. Extract every file in this ZIP to a normal local folder.\r\n"
        b"2. Double-click start-worker.cmd.\r\n"
        b"3. On the owner's Mac, run: vgen worker add\r\n"
        b"4. Paste the displayed one-time Invite only into the hidden Windows prompt.\r\n"
        b"5. Enter the Windows verification code into the still-running Mac command.\r\n"
        b"6. After validation, Task Scheduler keeps Worker control and ComfyUI running.\r\n\r\n"
        b"This public installer contains no Worker identity or credentials.\r\n"
    )
    _write_public_installer_bundle(
        target,
        overwrite=overwrite,
        entries=[
            ("INSTALL.txt", install_text, 0o644),
            (_ENROLLMENT_SCRIPT_NAME, enrollment_script, 0o644),
            (_LAUNCHER_NAME, launcher, 0o755),
            (_SCRIPT_NAME, script, 0o644),
            (_SUPERVISOR_SCRIPT_NAME, supervisor_script, 0o644),
            ("vgen-worker-bundle.json", config_bytes, 0o644),
            (_POLICY_NAME, policy, 0o644),
            (_RUNTIME_REQUIREMENTS_NAME, runtime_requirements, 0o644),
            *[
                (item.name, item.value, 0o644)
                for item in sorted(runtime_wheels, key=lambda item: item.name.encode("utf-8"))
            ],
        ],
    )
    return WorkerInstallerBundleResult(target, endpoint)
