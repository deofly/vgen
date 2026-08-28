from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from vgen.worker.host_control import ComfyUIHostControl, ComfyUIHostControlError


def _host_once(root: Path, *, leave_ack: bool = False) -> threading.Thread:
    def run() -> None:
        request = root / "comfyui-pause.request"
        deadline = time.monotonic() + 2
        while not request.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        value = json.loads(request.read_text(encoding="utf-8"))
        (root / "comfyui-pause.ack").write_text(
            json.dumps(
                {
                    "format": "vgen-comfyui-pause-ack",
                    "version": 1,
                    "nonce": value["nonce"],
                    "paused_at": int(time.time()),
                }
            ),
            encoding="utf-8",
        )
        if leave_ack:
            return
        while request.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        (root / "comfyui-pause.ack").unlink(missing_ok=True)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def test_host_control_pauses_and_resumes_with_matching_nonce(tmp_path: Path) -> None:
    host = _host_once(tmp_path)
    control = ComfyUIHostControl(tmp_path)

    with control.paused(timeout=2):
        request = json.loads((tmp_path / "comfyui-pause.request").read_text())
        assert request["format"] == "vgen-comfyui-pause-request"
        assert request["expires_at"] > request["requested_at"]
        assert (tmp_path / "comfyui-pause.ack").exists()

    host.join(timeout=2)
    assert not (tmp_path / "comfyui-pause.request").exists()
    assert not (tmp_path / "comfyui-pause.ack").exists()


def test_host_control_rejects_malformed_host_ack(tmp_path: Path) -> None:
    def malformed_host() -> None:
        request = tmp_path / "comfyui-pause.request"
        deadline = time.monotonic() + 2
        while not request.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        (tmp_path / "comfyui-pause.ack").write_text("{}", encoding="utf-8")

    host = threading.Thread(target=malformed_host, daemon=True)
    host.start()
    control = ComfyUIHostControl(tmp_path)

    with pytest.raises(ComfyUIHostControlError, match="ACK_INVALID"):
        control.pause(timeout=2)

    host.join(timeout=2)
    assert not (tmp_path / "comfyui-pause.request").exists()


def test_host_control_resume_timeout_does_not_restore_pause_request(tmp_path: Path) -> None:
    host = _host_once(tmp_path, leave_ack=True)
    control = ComfyUIHostControl(tmp_path)
    control.pause(timeout=2)

    with pytest.raises(ComfyUIHostControlError, match="RESUME_TIMEOUT"):
        control.resume(timeout=0.1)

    host.join(timeout=2)
    assert not (tmp_path / "comfyui-pause.request").exists()


def test_host_control_pause_retries_when_ack_removed_while_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current = 0.0
    ack_written = False
    ack_removed = False

    def monotonic() -> float:
        return current

    def sleeper(seconds: float) -> None:
        nonlocal current, ack_written
        if not ack_written:
            request = json.loads(control.request_path.read_text(encoding="utf-8"))
            control.ack_path.write_text(
                json.dumps(
                    {
                        "format": "vgen-comfyui-pause-ack",
                        "version": 1,
                        "nonce": request["nonce"],
                        "paused_at": int(time.time()),
                    }
                ),
                encoding="utf-8",
            )
            ack_written = True
        current += seconds

    control = ComfyUIHostControl(tmp_path, monotonic=monotonic, sleeper=sleeper)
    original_read_text = Path.read_text

    def remove_ack_before_read(path: Path, *args: object, **kwargs: object) -> str:
        nonlocal ack_removed
        if path == control.ack_path:
            path.unlink()
            ack_removed = True
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", remove_ack_before_read)

    with pytest.raises(ComfyUIHostControlError, match="PAUSE_TIMEOUT"):
        control.pause(timeout=0.2)

    assert ack_written
    assert ack_removed
    assert not (tmp_path / "comfyui-pause.request").exists()
    assert not (tmp_path / "comfyui-pause.ack").exists()


def test_host_control_resume_accepts_ack_removed_while_reading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _host_once(tmp_path, leave_ack=True)
    control = ComfyUIHostControl(tmp_path)
    control.pause(timeout=2)
    host.join(timeout=2)
    original_read_text = Path.read_text

    def remove_ack_before_read(path: Path, *args: object, **kwargs: object) -> str:
        if path == control.ack_path:
            path.unlink()
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", remove_ack_before_read)

    control.resume(timeout=0.1)

    assert not (tmp_path / "comfyui-pause.request").exists()
    assert not (tmp_path / "comfyui-pause.ack").exists()
