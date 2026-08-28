"""File-based control channel for the persistent Windows Worker host.

The PowerShell host owns the ComfyUI process, while the authenticated Python
Worker owns maintenance authorization.  A short-lived request file lets the
Worker pause ComfyUI without enumerating or killing an unverified process.
Requests expire so a crashed maintenance child cannot leave ComfyUI stopped
indefinitely.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

_FORMAT = "vgen-comfyui-pause-request"
_ACK_FORMAT = "vgen-comfyui-pause-ack"
_VERSION = 1
_MAX_REQUEST_BYTES = 4096
_MAX_TTL_SECONDS = 900


class ComfyUIHostControlError(RuntimeError):
    """The persistent host did not honor a safe ComfyUI control request."""


class ComfyUIHostControl:
    def __init__(
        self,
        work_root: Path,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.work_root = work_root.expanduser().absolute()
        self.request_path = self.work_root / "comfyui-pause.request"
        self.ack_path = self.work_root / "comfyui-pause.ack"
        self._clock = clock
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._nonce: str | None = None

    def pause(self, *, timeout: float = 60, ttl_seconds: int = 300) -> None:
        if timeout <= 0 or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS:
            raise ValueError("invalid ComfyUI pause timeout or TTL")
        self._validate_root()
        if self._nonce is not None:
            raise ComfyUIHostControlError("COMFYUI_HOST_ALREADY_PAUSED")
        if self.request_path.exists():
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_BUSY")
        self._remove_regular_file(self.ack_path, missing_ok=True)
        nonce = secrets.token_hex(24)
        now = int(self._clock())
        self._write_request(
            {
                "format": _FORMAT,
                "version": _VERSION,
                "nonce": nonce,
                "requested_at": now,
                "expires_at": now + ttl_seconds,
            }
        )
        deadline = self._monotonic() + timeout
        try:
            while self._monotonic() < deadline:
                acknowledgement = self._read_ack()
                if acknowledgement is not None and acknowledgement["nonce"] == nonce:
                    self._nonce = nonce
                    return
                self._sleeper(0.1)
        except BaseException:
            self._remove_regular_file(self.request_path, missing_ok=True)
            raise
        self._remove_regular_file(self.request_path, missing_ok=True)
        raise ComfyUIHostControlError("COMFYUI_HOST_PAUSE_TIMEOUT")

    def resume(self, *, timeout: float = 60) -> None:
        if timeout <= 0:
            raise ValueError("invalid ComfyUI resume timeout")
        if self._nonce is None:
            return
        self._remove_regular_file(self.request_path, missing_ok=True)
        deadline = self._monotonic() + timeout
        while self._monotonic() < deadline:
            if self._read_ack() is None:
                self._nonce = None
                return
            self._sleeper(0.1)
        raise ComfyUIHostControlError("COMFYUI_HOST_RESUME_TIMEOUT")

    @contextmanager
    def paused(
        self, *, timeout: float = 60, ttl_seconds: int = 300
    ) -> Iterator[None]:
        self.pause(timeout=timeout, ttl_seconds=ttl_seconds)
        try:
            yield
        finally:
            self.resume(timeout=timeout)

    def _validate_root(self) -> None:
        try:
            metadata = self.work_root.lstat()
        except OSError as exc:
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_ROOT_INVALID") from exc
        try:
            resolved = self.work_root.resolve(strict=True)
        except OSError as exc:
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_ROOT_INVALID") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or self.work_root.is_symlink()
            or resolved != self.work_root
        ):
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_ROOT_INVALID")

    def _write_request(self, value: dict[str, object]) -> None:
        data = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        temporary = self.work_root / f".comfyui-pause.{secrets.token_hex(12)}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.request_path)
        except OSError as exc:
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_WRITE_FAILED") from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_ack(self) -> dict[str, object] | None:
        try:
            metadata = self.ack_path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or self.ack_path.is_symlink()
                or metadata.st_size <= 0
                or metadata.st_size > _MAX_REQUEST_BYTES
            ):
                raise ValueError
            value = json.loads(self.ack_path.read_text(encoding="utf-8"))
            if (
                not isinstance(value, dict)
                or set(value) != {"format", "version", "nonce", "paused_at"}
                or value.get("format") != _ACK_FORMAT
                or value.get("version") != _VERSION
                or not isinstance(value.get("nonce"), str)
                or len(value["nonce"]) != 48
                or any(character not in "0123456789abcdef" for character in value["nonce"])
                or type(value.get("paused_at")) is not int
            ):
                raise ValueError
            return value
        except FileNotFoundError:
            return None
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise ComfyUIHostControlError("COMFYUI_HOST_ACK_INVALID") from exc

    @staticmethod
    def _remove_regular_file(path: Path, *, missing_ok: bool) -> None:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        except OSError as exc:
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_PATH_INVALID") from exc
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_PATH_INVALID")
        try:
            path.unlink()
        except OSError as exc:
            raise ComfyUIHostControlError("COMFYUI_HOST_CONTROL_REMOVE_FAILED") from exc


__all__ = ["ComfyUIHostControl", "ComfyUIHostControlError"]
