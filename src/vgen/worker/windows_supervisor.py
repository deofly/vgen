"""Stage and attest the user-level Windows Worker host controller."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import time
from collections.abc import Callable
from importlib import resources
from pathlib import Path

_ASSET = "supervise-worker.ps1"
_STATUS = "host-control-status.json"
_STATUS_FORMAT = "vgen-windows-worker-host-control"
_STATUS_VERSION = 1
_MAX_STATUS_BYTES = 4096
_MAX_HEARTBEAT_AGE_SECONDS = 15
_REPARSE_POINT = 0x400


def _is_safe_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and not (getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT)
        and resolved == path
    )


def _bundled_supervisor() -> bytes:
    return resources.files("vgen").joinpath("assets", "worker", _ASSET).read_bytes()


def _write_atomically(path: Path, value: bytes) -> None:
    temporary = path.parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    try:
        with temporary.open("xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_windows_supervisor(
    work_root: Path,
    *,
    platform: str | None = None,
    local_app_data: str | None = None,
    clock: Callable[[], float] = time.time,
) -> bool:
    """Stage the reviewed script and report whether its live host supports control.

    Replacing the script is safe while PowerShell is running because the current
    process has already parsed it. The new controller becomes active on the next
    scheduled-task start. Until its fresh status receipt appears, Node Pack
    maintenance remains unavailable instead of waiting for a pause timeout.
    """

    selected_platform = os.name if platform is None else platform
    if selected_platform != "nt":
        return True
    selected_local_app_data = (
        os.environ.get("LOCALAPPDATA") if local_app_data is None else local_app_data
    )
    if not selected_local_app_data:
        return False
    try:
        vgen_root = (Path(selected_local_app_data).expanduser().absolute() / "VGen").resolve(
            strict=True
        )
        workers_root = vgen_root / "workers"
        resolved_work_root = work_root.expanduser().absolute().resolve(strict=True)
    except OSError:
        return False
    if (
        not _is_safe_directory(vgen_root)
        or not _is_safe_directory(workers_root)
        or not _is_safe_directory(resolved_work_root)
        or resolved_work_root.parent != workers_root
    ):
        return False
    supervisor_root = vgen_root / "supervisor"
    if not _is_safe_directory(supervisor_root):
        return False
    target = supervisor_root / _ASSET
    try:
        bundled = _bundled_supervisor()
        expected_digest = hashlib.sha256(bundled).hexdigest()
        if target.exists():
            metadata = target.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or target.is_symlink()
                or getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
            ):
                return False
            current_digest = hashlib.sha256(target.read_bytes()).hexdigest()
        else:
            current_digest = None
        if current_digest != expected_digest:
            _write_atomically(target, bundled)
        marker = resolved_work_root / _STATUS
        metadata = marker.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or marker.is_symlink()
            or getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
            or metadata.st_size <= 0
            or metadata.st_size > _MAX_STATUS_BYTES
        ):
            return False
        value = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(value, dict) or set(value) != {
        "format",
        "version",
        "process_id",
        "script_sha256",
        "heartbeat_at",
    }:
        return False
    heartbeat_at = value.get("heartbeat_at")
    return (
        value.get("format") == _STATUS_FORMAT
        and value.get("version") == _STATUS_VERSION
        and type(value.get("process_id")) is int
        and value["process_id"] > 0
        and value.get("script_sha256") == expected_digest
        and type(heartbeat_at) is int
        and -5 <= float(clock()) - heartbeat_at <= _MAX_HEARTBEAT_AGE_SECONDS
    )


__all__ = ["prepare_windows_supervisor"]
