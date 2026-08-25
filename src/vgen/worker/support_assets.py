"""Refresh reviewed Windows launcher assets from an activated Worker wheel."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

from .updater import WorkerUpdateError

_LAUNCHER_ENV: Final = "VGEN_WORKER_VERSION_LAUNCHER"
_ASSET_NAMES: Final = ("enroll-worker.ps1", "setup-worker.ps1", "start-worker.cmd")
_MAX_ASSET_BYTES: Final = 2 * 1024 * 1024


def refresh_windows_support_assets(
    *,
    launcher: Path | None = None,
    asset_root: Path | None = None,
    allowed_root: Path | None = None,
) -> Path | None:
    """Atomically refresh the currently selected reviewed installer scripts.

    The wheel itself has already passed owner-authorized update verification.
    This function only writes the three bundled support assets beside the exact
    version launcher inherited from the public installer.
    """

    raw_launcher = launcher or _environment_launcher()
    if raw_launcher is None:
        return None
    target_launcher = raw_launcher.expanduser()
    if not target_launcher.is_absolute() or target_launcher.name.casefold() != "start-worker.cmd":
        raise WorkerUpdateError("WORKER_SUPPORT_LAUNCHER_INVALID")

    target_directory = target_launcher.parent.resolve(strict=True)
    trusted_root = (allowed_root or _default_allowed_root()).resolve(strict=True)
    if not target_directory.is_relative_to(trusted_root):
        raise WorkerUpdateError("WORKER_SUPPORT_LAUNCHER_INVALID")
    _assert_plain_ancestry(target_directory, trusted_root)

    source_root = asset_root or (Path(__file__).resolve().parents[1] / "assets" / "worker")
    changed = False
    for name in _ASSET_NAMES:
        source = source_root / name
        target = target_directory / name
        data = _read_reviewed_asset(source)
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_file():
                raise WorkerUpdateError("WORKER_SUPPORT_ASSET_CONFLICT")
            if target.read_bytes() == data:
                continue
        _atomic_replace(target, data)
        changed = True
    return target_launcher.resolve(strict=True) if changed else None


def schedule_windows_launcher_restart(launcher: Path, *, delay_seconds: int = 8) -> None:
    """Start the refreshed launcher after the current wrapper stops ComfyUI."""

    if os.name != "nt":
        raise WorkerUpdateError("WORKER_SUPPORT_RESTART_UNAVAILABLE")
    if not 1 <= delay_seconds <= 60 or not launcher.is_absolute() or not launcher.is_file():
        raise WorkerUpdateError("WORKER_SUPPORT_LAUNCHER_INVALID")
    helper = (
        "import os,sys,time;"
        "time.sleep(int(sys.argv[1]));"
        "os.startfile(sys.argv[2])"
    )
    creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
        subprocess, "DETACHED_PROCESS", 0
    )
    try:
        subprocess.Popen(  # noqa: S603 - fixed interpreter and fixed helper program
            [sys.executable, "-I", "-c", helper, str(delay_seconds), str(launcher)],
            close_fds=True,
            creationflags=creation_flags,
        )
    except OSError as exc:
        raise WorkerUpdateError("WORKER_SUPPORT_RESTART_UNAVAILABLE") from exc


def _environment_launcher() -> Path | None:
    value = os.environ.get(_LAUNCHER_ENV)
    return Path(value) if value else None


def _default_allowed_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise WorkerUpdateError("WORKER_SUPPORT_LAUNCHER_INVALID")
    return Path(local_app_data) / "VGen" / "installer"


def _assert_plain_ancestry(path: Path, root: Path) -> None:
    current = path
    while True:
        metadata = current.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if current.is_symlink() or bool(attributes & reparse):
            raise WorkerUpdateError("WORKER_SUPPORT_LAUNCHER_INVALID")
        if current == root:
            return
        if current.parent == current:
            raise WorkerUpdateError("WORKER_SUPPORT_LAUNCHER_INVALID")
        current = current.parent


def _read_reviewed_asset(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise WorkerUpdateError("WORKER_SUPPORT_ASSET_INVALID")
        data = path.read_bytes()
    except OSError as exc:
        raise WorkerUpdateError("WORKER_SUPPORT_ASSET_INVALID") from exc
    if not data or len(data) > _MAX_ASSET_BYTES:
        raise WorkerUpdateError("WORKER_SUPPORT_ASSET_INVALID")
    return data


def _atomic_replace(target: Path, data: bytes) -> None:
    temporary: Path | None = None
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(raw_path)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except OSError as exc:
        raise WorkerUpdateError("WORKER_SUPPORT_ASSET_WRITE_FAILED") from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


__all__ = ["refresh_windows_support_assets", "schedule_windows_launcher_restart"]
