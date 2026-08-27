"""Versioned, rollback-capable Worker runtime staging.

The updater never mutates the Python environment of the running process.  It
copies that environment, installs one exact VGen wheel with ``--no-deps``, and
atomically switches a small pointer consumed by the foreground Windows launcher.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.version import Version

from vgen import __version__


class WorkerUpdateError(RuntimeError):
    """A safe update error without a path, URL, command line, or process output."""

    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class WorkerRuntimeState:
    active_python: Path
    previous_python: Path | None
    pending: bool
    active_available: bool = True
    activation_verified: bool = False
    superseded_pending: bool = False


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})\.(?:0|[1-9]\d{0,8})$")
_POINTER_FORMAT = "vgen-worker-runtime-pointer"
_POINTER_VERSION = 1
_MAX_WHEEL_ENTRIES = 4096
_MAX_WHEEL_FILE_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024


def _isolated_subprocess_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith(("PIP_", "PYTHON")) and key.upper() != "VIRTUAL_ENV"
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    return environment


def _file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                size += len(block)
                digest.update(block)
    except OSError as exc:
        raise WorkerUpdateError("WORKER_UPDATE_ARTIFACT_UNREADABLE") from exc
    return size, digest.hexdigest()


def _runtime_size(path: Path) -> int:
    total = 0
    try:
        for root, directories, files in os.walk(path, followlinks=False):
            root_path = Path(root)
            directories[:] = [name for name in directories if not _is_reparse(root_path / name)]
            for name in files:
                candidate = root_path / name
                if _is_reparse(candidate):
                    continue
                metadata = candidate.stat()
                if stat.S_ISREG(metadata.st_mode):
                    total += metadata.st_size
    except OSError as exc:
        raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_UNREADABLE") from exc
    return total


def _runtime_python(runtime: Path) -> Path:
    return runtime / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


class RuntimeUpdater:
    def __init__(
        self,
        work_root: Path,
        *,
        current_python: Path | None = None,
        current_version: str = __version__,
        source_runtime: Path | None = None,
        runner: Any = subprocess.run,
    ) -> None:
        raw_work_root = work_root.expanduser()
        if _is_reparse(raw_work_root):
            raise WorkerUpdateError("WORKER_UPDATE_ROOT_INVALID")
        self.work_root = raw_work_root.resolve()
        self.work_root.mkdir(parents=True, exist_ok=True)
        if _is_reparse(self.work_root) or not self.work_root.is_dir():
            raise WorkerUpdateError("WORKER_UPDATE_ROOT_INVALID")
        self.releases_root = self.work_root / "runtime-releases"
        self.download_root = self.work_root / "maintenance-downloads"
        self.pointer_path = self.work_root / "runtime-active.json"
        self.pointer_lock_path = self.work_root / ".runtime-active.lock"
        self.current_python = (current_python or Path(sys.executable)).resolve()
        self.current_version = current_version
        self.source_runtime = (source_runtime or Path(sys.prefix)).resolve()
        if _is_reparse(self.source_runtime) or not self.source_runtime.is_dir():
            raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
        self._runner = runner

    def validate_wheel(
        self,
        wheel: Path,
        *,
        target_version: str,
        expected_size: int,
        expected_sha256: str,
    ) -> str:
        digest = expected_sha256.removeprefix("sha256:").lower()
        if not _DIGEST.fullmatch(digest) or expected_size < 1:
            raise WorkerUpdateError("WORKER_UPDATE_SPEC_INVALID")
        if not _VERSION.fullmatch(target_version):
            raise WorkerUpdateError("WORKER_UPDATE_VERSION_INVALID")
        try:
            target = Version(target_version)
            current = Version(self.current_version)
        except ValueError as exc:
            raise WorkerUpdateError("WORKER_UPDATE_VERSION_INVALID") from exc
        if target <= current:
            raise WorkerUpdateError("WORKER_UPDATE_DOWNGRADE_DENIED")
        if not wheel.is_file() or _is_reparse(wheel):
            raise WorkerUpdateError("WORKER_UPDATE_ARTIFACT_UNREADABLE")
        size, actual = _file_digest(wheel)
        if size != expected_size:
            raise WorkerUpdateError("WORKER_UPDATE_SIZE_MISMATCH")
        if actual != digest:
            raise WorkerUpdateError("WORKER_UPDATE_INTEGRITY_FAILED")

        try:
            with zipfile.ZipFile(wheel) as archive:
                infos = archive.infolist()
                names = [item.filename for item in infos]
                if (
                    len(names) != len(set(names))
                    or len(infos) > _MAX_WHEEL_ENTRIES
                    or sum(item.file_size for item in infos) > _MAX_WHEEL_UNCOMPRESSED_BYTES
                    or any(item.file_size > _MAX_WHEEL_FILE_BYTES for item in infos)
                ):
                    raise WorkerUpdateError("WORKER_UPDATE_WHEEL_INVALID")
                for item in infos:
                    name = item.filename
                    normalized = PurePosixPath(name.replace("\\", "/"))
                    if (
                        name.startswith(("/", "\\"))
                        or "\\" in name
                        or ".." in normalized.parts
                        or item.is_dir()
                        and not name.endswith("/")
                        or stat.S_ISLNK(item.external_attr >> 16)
                    ):
                        raise WorkerUpdateError("WORKER_UPDATE_WHEEL_INVALID")
                metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
                wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
                if len(metadata_names) != 1 or len(wheel_names) != 1:
                    raise WorkerUpdateError("WORKER_UPDATE_WHEEL_INVALID")
                metadata = BytesParser().parsebytes(archive.read(metadata_names[0]))
                wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
        except WorkerUpdateError:
            raise
        except (OSError, UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
            raise WorkerUpdateError("WORKER_UPDATE_WHEEL_INVALID") from exc
        if metadata.get("Name", "").casefold() != "vgen":
            raise WorkerUpdateError("WORKER_UPDATE_WHEEL_INVALID")
        if metadata.get("Version") != target_version:
            raise WorkerUpdateError("WORKER_UPDATE_VERSION_MISMATCH")
        tags = {
            line.partition(":")[2].strip()
            for line in wheel_metadata.splitlines()
            if line.startswith("Tag:")
        }
        if tags != {"py3-none-any"}:
            raise WorkerUpdateError("WORKER_UPDATE_WHEEL_INCOMPATIBLE")
        return digest

    def stage(
        self,
        wheel: Path,
        *,
        job_id: str,
        fencing_token: int,
        target_version: str,
        expected_size: int,
        expected_sha256: str,
    ) -> dict[str, Any]:
        digest = self.validate_wheel(
            wheel,
            target_version=target_version,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
        )
        release = self.releases_root / f"{target_version}-{digest[:16]}"
        if release.exists():
            if _is_reparse(release) or not release.is_dir():
                raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
            self._verify_installed_runtime(release, target_version)
        else:
            self.releases_root.mkdir(parents=True, exist_ok=True)
            if _is_reparse(self.releases_root) or not self.releases_root.is_dir():
                raise WorkerUpdateError("WORKER_UPDATE_ROOT_INVALID")
            required = _runtime_size(self.source_runtime) + expected_size + 64 * 1024 * 1024
            try:
                free = shutil.disk_usage(self.releases_root).free
            except OSError as exc:
                raise WorkerUpdateError("WORKER_UPDATE_DISK_UNAVAILABLE", retryable=True) from exc
            if free < required:
                raise WorkerUpdateError("WORKER_UPDATE_DISK_FULL")
            staging = self.releases_root / f".{release.name}.{uuid.uuid4().hex}.staging"
            try:
                shutil.copytree(
                    self.source_runtime,
                    staging,
                    symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                python = _runtime_python(staging)
                if not python.is_file():
                    raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
                reviewed_wheel = staging / f"vgen-{target_version}-py3-none-any.whl"
                shutil.copyfile(wheel, reviewed_wheel)
                completed = self._runner(
                    [
                        str(python),
                        "-I",
                        "-m",
                        "pip",
                        "--isolated",
                        "install",
                        "--disable-pip-version-check",
                        "--no-deps",
                        "--upgrade",
                        "--force-reinstall",
                        str(reviewed_wheel),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=600,
                    check=False,
                    env=_isolated_subprocess_environment(),
                )
                reviewed_wheel.unlink(missing_ok=True)
                if completed.returncode != 0:
                    raise WorkerUpdateError("WORKER_UPDATE_INSTALL_FAILED")
                self._verify_installed_runtime(staging, target_version)
                try:
                    staging.rename(release)
                except FileExistsError:
                    self._verify_installed_runtime(release, target_version)
            except WorkerUpdateError:
                shutil.rmtree(staging, ignore_errors=True)
                raise
            except (OSError, shutil.Error, subprocess.SubprocessError) as exc:
                shutil.rmtree(staging, ignore_errors=True)
                raise WorkerUpdateError("WORKER_UPDATE_INSTALL_FAILED") from exc
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)

        target_python = _runtime_python(release).resolve()
        pointer = {
            "format": _POINTER_FORMAT,
            "version": _POINTER_VERSION,
            "active_python": str(target_python),
            "active_version": target_version,
            "release_dir": str(release.resolve()),
            "previous_python": str(self.current_python),
            "previous_version": self.current_version,
            "pending_job_id": job_id,
            "pending_fencing_token": int(fencing_token),
            "artifact_sha256": digest,
            "switched_at": int(time.time()),
        }
        self._write_pending_pointer(pointer)
        return pointer

    def pending_activation(self) -> dict[str, Any] | None:
        value = self._read_pointer()
        if not value or not value.get("pending_job_id"):
            return None
        return value

    def is_target_process(self, pointer: dict[str, Any]) -> bool:
        try:
            return Path(str(pointer["active_python"])).resolve() == self.current_python
        except (KeyError, OSError, TypeError, ValueError):
            return False

    def activation_verified(self, pointer: dict[str, Any]) -> bool:
        """Return whether the target already passed its authenticated probe."""

        value = pointer.get("activation_verified_at")
        if value is None:
            return False
        if type(value) is not int or value < 1:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        return True

    def mark_activation_verified(self, pointer: dict[str, Any]) -> dict[str, Any]:
        """Persist target health before attempting the idempotent Gateway commit."""

        with self._pointer_lock():
            current = self._read_pointer()
            if current is None or _pointer_identity(current) != _pointer_identity(pointer):
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_STALE")
            verified_at = current.get("activation_verified_at")
            if verified_at is not None:
                if type(verified_at) is int and verified_at >= 1:
                    return current
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
            if current != pointer:
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_STALE")
            current["activation_verified_at"] = int(time.time())
            self._write_pointer_unlocked(current)
            return current

    def mark_activation_succeeded(self, pointer: dict[str, Any]) -> None:
        def succeeded(value: dict[str, Any]) -> dict[str, Any]:
            for key in (
                "activation_verified_at",
                "pending_job_id",
                "pending_fencing_token",
                "previous_python",
                "previous_version",
            ):
                value.pop(key, None)
            value["last_verified_at"] = int(time.time())
            return value

        self._transition_pointer(pointer, succeeded)

    def mark_activation_rolled_back(self, pointer: dict[str, Any]) -> None:
        trusted_fallback = self.current_python.resolve()
        base_version = _release_version(
            self.current_version,
            error_code="WORKER_UPDATE_VERSION_INVALID",
        )

        def rolled_back(value: dict[str, Any]) -> dict[str, Any]:
            previous_python, previous_version = self._pending_rollback_runtime(
                value,
                trusted_fallback,
                base_version,
            )
            return {
                "format": _POINTER_FORMAT,
                "version": _POINTER_VERSION,
                "active_python": str(previous_python),
                "active_version": previous_version,
                "rolled_back_job_id": value.get("pending_job_id"),
                "rolled_back_at": int(time.time()),
            }

        self._transition_pointer(pointer, rolled_back)

    def active_python(self, *, fallback: Path | None = None) -> Path:
        value = self._read_pointer()
        raw = value.get("active_python") if value else None
        if not isinstance(raw, str) or not raw:
            return (fallback or self.current_python).resolve()
        return Path(raw).resolve()

    def supervisor_state(self, *, fallback: Path | None = None) -> WorkerRuntimeState:
        """Return a pointer state safe for launching a Worker subprocess."""

        trusted_fallback = (fallback or self.current_python).resolve()
        value = self._read_pointer()
        if value is None:
            return WorkerRuntimeState(trusted_fallback, None, False)
        pending = isinstance(value.get("pending_job_id"), str) and bool(
            value["pending_job_id"].strip()
        )
        activation_verified = self.activation_verified(value) if pending else False
        rolled_back = isinstance(value.get("rolled_back_job_id"), str) and bool(
            value["rolled_back_job_id"].strip()
        )
        active_version = _release_version(
            value.get("active_version"),
            error_code="WORKER_UPDATE_POINTER_INVALID",
        )
        base_version = _release_version(
            self.current_version,
            error_code="WORKER_UPDATE_VERSION_INVALID",
        )
        if rolled_back and not pending and active_version <= base_version:
            # A terminal rollback can point at an old immutable installer path.
            # If the current reviewed base is at least as new, ignore that path
            # entirely. A newer in-store rollback remains authoritative.
            return WorkerRuntimeState(trusted_fallback, None, False)
        active, active_available = self._supervisor_python(
            value.get("active_python"),
            trusted_fallback,
            allow_missing=pending or active_version <= base_version,
        )
        if not pending:
            # Completed remote activations remain authoritative unless a newer
            # reviewed installer supplied the immutable base runtime. Compare
            # before resolving an older path so a removed superseded runtime
            # cannot prevent the trusted newer base from starting.
            if active_version < base_version:
                return WorkerRuntimeState(trusted_fallback, None, False)
            if not active_available:
                if active_version == base_version:
                    return WorkerRuntimeState(trusted_fallback, None, False)
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        previous = None
        if pending:
            previous, _previous_version = self._pending_rollback_runtime(
                value,
                trusted_fallback,
                base_version,
            )
        return WorkerRuntimeState(
            active,
            previous,
            pending,
            active_available,
            activation_verified,
            pending and active_version < base_version,
        )

    def _pending_rollback_runtime(
        self,
        pointer: dict[str, Any],
        trusted_fallback: Path,
        base_version: Version,
    ) -> tuple[Path, str]:
        """Select a rollback which remains trusted after an installer takeover.

        A pending remote activation may name the immutable base directory from
        the installer which started it. A newer installer has a different base
        path, so that old path is outside its current trust roots. If the new
        reviewed base is at least as new, it is the safe rollback; a newer
        previous runtime must still resolve inside the private release store.
        """

        previous_version = _release_version(
            pointer.get("previous_version"),
            error_code="WORKER_UPDATE_POINTER_INVALID",
        )
        if previous_version <= base_version:
            return trusted_fallback, str(base_version)
        previous, _available = self._supervisor_python(
            pointer.get("previous_python"), trusted_fallback
        )
        return previous, str(previous_version)

    def _supervisor_python(
        self,
        raw: object,
        trusted_fallback: Path,
        *,
        allow_missing: bool = False,
    ) -> tuple[Path, bool]:
        if not isinstance(raw, str) or not raw:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        try:
            raw_candidate = Path(raw)
            if not raw_candidate.is_absolute():
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
            lexical_candidate = Path(os.path.abspath(raw_candidate))
            lexical_fallback = Path(os.path.abspath(trusted_fallback))
            lexical_releases_root = Path(os.path.abspath(self.releases_root))
            if lexical_candidate != lexical_fallback:
                if not lexical_candidate.is_relative_to(lexical_releases_root):
                    raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
                if _has_reparse_component(lexical_candidate, self.work_root):
                    raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
            candidate = lexical_candidate.resolve()
            releases_root = lexical_releases_root.resolve()
            in_releases = candidate.is_relative_to(releases_root)
        except WorkerUpdateError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID") from exc
        if candidate != trusted_fallback and not in_releases:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        if candidate != trusted_fallback and _is_reparse(candidate):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        available = candidate.is_file()
        if not available and not allow_missing:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        return candidate, available

    def _verify_installed_runtime(self, runtime: Path, expected_version: str) -> None:
        python = _runtime_python(runtime)
        if not python.is_file() or _is_reparse(python):
            raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
        try:
            completed = self._runner(
                [
                    str(python),
                    "-I",
                    "-c",
                    "import importlib.metadata as m; print(m.version('vgen'))",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=60,
                check=False,
                text=True,
                env=_isolated_subprocess_environment(),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID") from exc
        if completed.returncode != 0 or completed.stdout.strip() != expected_version:
            raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")

    def _read_pointer(self) -> dict[str, Any] | None:
        if not self.pointer_path.exists():
            return None
        if self.pointer_path.is_symlink() or _is_reparse(self.pointer_path):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        try:
            value = json.loads(self.pointer_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID") from exc
        if (
            not isinstance(value, dict)
            or value.get("format") != _POINTER_FORMAT
            or value.get("version") != _POINTER_VERSION
        ):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        _validate_pointer_schema(value)
        return value

    def _write_pointer(self, value: dict[str, Any]) -> None:
        with self._pointer_lock():
            self._write_pointer_unlocked(value)

    def _write_pending_pointer(self, value: dict[str, Any]) -> None:
        with self._pointer_lock():
            current = self._read_pointer()
            if (
                current is not None
                and isinstance(current.get("pending_job_id"), str)
                and current["pending_job_id"]
                and current != value
            ):
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_BUSY")
            self._write_pointer_unlocked(value)

    def _transition_pointer(
        self,
        expected: dict[str, Any],
        transform: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> dict[str, Any]:
        """Atomically transition only the pending activation the caller observed."""

        expected_identity = _pointer_identity(expected)
        if (
            not isinstance(expected_identity[0], str)
            or not expected_identity[0]
            or type(expected_identity[1]) is not int
            or expected_identity[1] < 1
        ):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        with self._pointer_lock():
            current = self._read_pointer()
            if current is None or current != expected:
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_STALE")
            value = transform(dict(current))
            self._write_pointer_unlocked(value)
            return value

    @contextmanager
    def _pointer_lock(self) -> Iterator[None]:
        if _is_reparse(self.pointer_lock_path):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        try:
            descriptor = os.open(self.pointer_lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_LOCK_UNAVAILABLE") from exc
        with os.fdopen(descriptor, "a+b", buffering=0) as lock_file:
            try:
                lock_file.seek(0, os.SEEK_END)
                if lock_file.tell() == 0:
                    lock_file.write(b"0")
                lock_file.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_LOCK_UNAVAILABLE") from exc
            try:
                yield
            finally:
                try:
                    lock_file.seek(0)
                    if os.name == "nt":
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                except OSError as exc:
                    raise WorkerUpdateError("WORKER_UPDATE_POINTER_LOCK_UNAVAILABLE") from exc

    def _write_pointer_unlocked(self, value: dict[str, Any]) -> None:
        self.pointer_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".runtime-active-", suffix=".tmp", dir=self.pointer_path.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                json.dump(value, output, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            if os.name != "nt":
                temporary.chmod(0o600)
            os.replace(temporary, self.pointer_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise


def _is_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _has_reparse_component(candidate: Path, boundary: Path) -> bool:
    """Check the complete trusted path, including a reparse-point root."""

    try:
        candidate.relative_to(boundary)
    except ValueError:
        return True
    current = candidate
    while True:
        if _is_reparse(current):
            return True
        if current == boundary:
            return False
        parent = current.parent
        if parent == current:
            return True
        current = parent


def _release_version(value: object, *, error_code: str) -> Version:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise WorkerUpdateError(error_code)
    try:
        return Version(value)
    except ValueError as exc:
        raise WorkerUpdateError(error_code) from exc


def _pointer_identity(value: dict[str, Any]) -> tuple[Any, ...]:
    return (
        value.get("pending_job_id"),
        value.get("pending_fencing_token"),
        value.get("active_python"),
        value.get("active_version"),
        value.get("artifact_sha256"),
    )


def _validate_pointer_schema(value: dict[str, Any]) -> None:
    """Reject partial state-machine records before supervisor interpretation."""

    active_python = value.get("active_python")
    active_version = value.get("active_version")
    if (
        not isinstance(active_python, str)
        or not active_python
        or any(character in active_python for character in ("\x00", "\r", "\n"))
        or not isinstance(active_version, str)
        or _VERSION.fullmatch(active_version) is None
    ):
        raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")

    pending_keys = {
        "pending_job_id",
        "pending_fencing_token",
        "previous_python",
        "previous_version",
        "activation_verified_at",
    }
    pending = bool(pending_keys & value.keys())
    rollback_keys = {"rolled_back_job_id", "rolled_back_at"}
    rolled_back = bool(rollback_keys & value.keys())
    if pending and rolled_back:
        raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
    if pending:
        job_id = value.get("pending_job_id")
        fencing_token = value.get("pending_fencing_token")
        previous_python = value.get("previous_python")
        previous_version = value.get("previous_version")
        artifact_sha256 = value.get("artifact_sha256")
        if (
            not isinstance(job_id, str)
            or not 1 <= len(job_id) <= 256
            or not job_id.strip()
            or any(character in job_id for character in ("\x00", "\r", "\n"))
            or type(fencing_token) is not int
            or fencing_token < 1
            or not isinstance(previous_python, str)
            or not previous_python.strip()
            or any(character in previous_python for character in ("\x00", "\r", "\n"))
            or not isinstance(previous_version, str)
            or _VERSION.fullmatch(previous_version) is None
            or not isinstance(artifact_sha256, str)
            or _DIGEST.fullmatch(artifact_sha256) is None
        ):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
        verified_at = value.get("activation_verified_at")
        if verified_at is not None and (type(verified_at) is not int or verified_at < 1):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")

    if rolled_back:
        rolled_back_job_id = value.get("rolled_back_job_id")
        rolled_back_at = value.get("rolled_back_at")
        if (
            not isinstance(rolled_back_job_id, str)
            or not 1 <= len(rolled_back_job_id) <= 256
            or not rolled_back_job_id.strip()
            or any(character in rolled_back_job_id for character in ("\x00", "\r", "\n"))
            or type(rolled_back_at) is not int
            or rolled_back_at < 1
        ):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")

    for field in ("last_verified_at", "switched_at"):
        timestamp = value.get(field)
        if timestamp is not None and (type(timestamp) is not int or timestamp < 1):
            raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
    artifact_sha256 = value.get("artifact_sha256")
    if artifact_sha256 is not None and (
        not isinstance(artifact_sha256, str) or _DIGEST.fullmatch(artifact_sha256) is None
    ):
        raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")


__all__ = ["RuntimeUpdater", "WorkerRuntimeState", "WorkerUpdateError"]
