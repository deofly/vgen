from __future__ import annotations

import hashlib
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vgen.worker.updater import RuntimeUpdater, WorkerUpdateError


def _wait_for_file(path: Path, *, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {path.name}")
        time.sleep(0.01)


def build_wheel(path: Path, version: str, *, tag: str = "py3-none-any") -> tuple[int, str]:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"vgen-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: vgen\nVersion: {version}\n",
        )
        archive.writestr(
            f"vgen-{version}.dist-info/WHEEL",
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n",
        )
        archive.writestr("vgen/__init__.py", f'__version__ = "{version}"\n')
    content = path.read_bytes()
    return len(content), hashlib.sha256(content).hexdigest()


def test_runtime_pointer_lock_serializes_independent_processes(tmp_path: Path) -> None:
    source = tmp_path / "runtime"
    python = source / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    work = tmp_path / "work"
    held = tmp_path / "held"
    release = tmp_path / "release"
    acquired = tmp_path / "acquired"
    helper = """
import sys
import time
from pathlib import Path
from vgen.worker.updater import RuntimeUpdater

work, current, source, mode, marker, release = map(Path, sys.argv[1:7])
updater = RuntimeUpdater(
    work,
    current_python=current,
    current_version="0.13.10",
    source_runtime=source,
)
with updater._pointer_lock():
    marker.write_text("locked", encoding="utf-8")
    if mode.name == "hold":
        deadline = time.monotonic() + 10
        while not release.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        if not release.exists():
            raise SystemExit(3)
"""
    first = subprocess.Popen(
        [
            sys.executable,
            "-c",
            helper,
            str(work),
            str(python),
            str(source),
            "hold",
            str(held),
            str(release),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    second: subprocess.Popen[str] | None = None
    try:
        _wait_for_file(held)
        second = subprocess.Popen(
            [
                sys.executable,
                "-c",
                helper,
                str(work),
                str(python),
                str(source),
                "acquire",
                str(acquired),
                str(release),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.2)
        assert not acquired.exists()
        release.write_text("release", encoding="utf-8")
        first_output = first.communicate(timeout=5)
        second_output = second.communicate(timeout=5)
        assert first.returncode == 0, first_output
        assert second.returncode == 0, second_output
        assert acquired.read_text(encoding="utf-8") == "locked"
    finally:
        release.touch(exist_ok=True)
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate()


def test_runtime_pointer_lock_open_failure_is_normalized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    updater = RuntimeUpdater(tmp_path / "work", current_version="0.13.10")
    original_open = __import__("os").open

    def fail_lock_open(path: Any, *args: Any, **kwargs: Any) -> int:
        if Path(path) == updater.pointer_lock_path:
            raise OSError("simulated lock failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("vgen.worker.updater.os.open", fail_lock_open)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_LOCK_UNAVAILABLE"):
        updater._write_pointer(
            {
                "format": "vgen-worker-runtime-pointer",
                "version": 1,
                "active_python": str(updater.current_python),
                "active_version": "0.13.10",
            }
        )


@pytest.mark.parametrize(
    "partial",
    [
        {"pending_job_id": 0},
        {"pending_job_id": "mtn_partial"},
        {"pending_fencing_token": 1},
        {"activation_verified_at": 1},
        {
            "pending_job_id": "mtn_partial",
            "pending_fencing_token": 0,
            "previous_python": "C:/runtime/python.exe",
            "previous_version": "0.13.9",
        },
        {
            "pending_job_id": "mtn_missing_artifact",
            "pending_fencing_token": 1,
            "previous_python": "C:/runtime/python.exe",
            "previous_version": "0.13.9",
        },
        {
            "pending_job_id": "   ",
            "pending_fencing_token": 1,
            "previous_python": "C:/runtime/python.exe",
            "previous_version": "0.13.9",
            "artifact_sha256": "a" * 64,
        },
        {
            "pending_job_id": "mtn_mixed",
            "pending_fencing_token": 1,
            "previous_python": "C:/runtime/python.exe",
            "previous_version": "0.13.9",
            "artifact_sha256": "a" * 64,
            "rolled_back_job_id": "mtn_old",
            "rolled_back_at": 1,
        },
        {"rolled_back_job_id": "mtn_partial"},
        {"artifact_sha256": "not-a-digest"},
        {"format": "VGEN-WORKER-RUNTIME-POINTER"},
        {"last_verified_at": 0},
    ],
)
def test_runtime_pointer_rejects_partial_state_machine_records(
    tmp_path: Path, partial: dict[str, Any]
) -> None:
    updater = RuntimeUpdater(tmp_path / "work", current_version="0.13.10")
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(updater.current_python),
            "active_version": "0.13.10",
            **partial,
        }
    )

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=updater.current_python)


def test_wheel_validation_checks_digest_metadata_tag_and_downgrade(tmp_path: Path) -> None:
    wheel = tmp_path / "vgen.whl"
    size, digest = build_wheel(wheel, "0.2.0")
    updater = RuntimeUpdater(tmp_path / "work", current_version="0.1.1")
    assert (
        updater.validate_wheel(
            wheel,
            target_version="0.2.0",
            expected_size=size,
            expected_sha256=digest,
        )
        == digest
    )
    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_INTEGRITY_FAILED"):
        updater.validate_wheel(
            wheel,
            target_version="0.2.0",
            expected_size=size,
            expected_sha256="0" * 64,
        )
    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_DOWNGRADE_DENIED"):
        updater.validate_wheel(
            wheel,
            target_version="0.1.0",
            expected_size=size,
            expected_sha256=digest,
        )

    incompatible = tmp_path / "incompatible.whl"
    incompatible_size, incompatible_digest = build_wheel(
        incompatible, "0.3.0", tag="cp311-cp311-win_amd64"
    )
    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_WHEEL_INCOMPATIBLE"):
        updater.validate_wheel(
            incompatible,
            target_version="0.3.0",
            expected_size=incompatible_size,
            expected_sha256=incompatible_digest,
        )


def test_wheel_validation_rejects_archive_entry_resource_bomb(tmp_path: Path) -> None:
    wheel = tmp_path / "entry-bomb.whl"
    build_wheel(wheel, "0.2.0")
    with zipfile.ZipFile(wheel, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        for index in range(4096):
            archive.writestr(f"vgen/generated/{index}.txt", b"")
    content = wheel.read_bytes()
    updater = RuntimeUpdater(tmp_path / "work", current_version="0.1.1")

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_WHEEL_INVALID"):
        updater.validate_wheel(
            wheel,
            target_version="0.2.0",
            expected_size=len(content),
            expected_sha256=hashlib.sha256(content).hexdigest(),
        )


def test_stages_separate_runtime_and_writes_pending_activation_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = tmp_path / "vgen.whl"
    size, digest = build_wheel(wheel, "0.2.0")
    source = tmp_path / "source-runtime"
    python = source / "bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"fake python")

    monkeypatch.setenv("PYTHONPATH", "untrusted-python-path")
    monkeypatch.setenv("PYTHONHOME", "untrusted-python-home")
    monkeypatch.setenv("VIRTUAL_ENV", "untrusted-virtualenv")
    monkeypatch.setenv("PIP_INDEX_URL", "https://untrusted.invalid/simple")
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        calls.append((command, kwargs))
        if "pip" in command:
            return SimpleNamespace(returncode=0, stdout="")
        return SimpleNamespace(returncode=0, stdout="0.2.0\n")

    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=python,
        current_version="0.1.1",
        source_runtime=source,
        runner=runner,
    )
    pointer = updater.stage(
        wheel,
        job_id="mtn_test",
        fencing_token=7,
        target_version="0.2.0",
        expected_size=size,
        expected_sha256=digest,
    )

    assert pointer["pending_job_id"] == "mtn_test"
    assert pointer["previous_python"] == str(python.resolve())
    assert Path(pointer["active_python"]).is_file()
    assert Path(pointer["active_python"]) != python.resolve()
    assert updater.pending_activation() == pointer
    state = updater.supervisor_state(fallback=python)
    assert state.active_python == Path(pointer["active_python"])
    assert state.previous_python == python.resolve()
    assert state.pending
    assert not state.activation_verified
    pip_command, pip_kwargs = next(item for item in calls if "pip" in item[0])
    assert pip_command[1:5] == ["-I", "-m", "pip", "--isolated"]
    assert "--no-deps" in pip_command
    isolated_env = pip_kwargs["env"]
    assert isolated_env["PIP_NO_INPUT"] == "1"
    assert isolated_env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "PYTHONPATH" not in isolated_env
    assert "PYTHONHOME" not in isolated_env
    assert "VIRTUAL_ENV" not in isolated_env
    assert "PIP_INDEX_URL" not in isolated_env

    verified = updater.mark_activation_verified(pointer)
    assert updater.activation_verified(verified)
    assert updater.pending_activation() == verified
    assert updater.supervisor_state(fallback=python).activation_verified

    updater.mark_activation_succeeded(verified)
    assert updater.pending_activation() is None
    assert updater.active_python() == Path(pointer["active_python"])


def test_rollback_pointer_switches_back_to_previous_python(tmp_path: Path) -> None:
    source = tmp_path / "runtime"
    python = source / "bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=python,
        current_version="0.1.1",
        source_runtime=source,
    )
    pointer = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(tmp_path / "new/bin/python"),
        "active_version": "0.2.0",
        "previous_python": str(python),
        "previous_version": "0.1.1",
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 2,
        "artifact_sha256": "a" * 64,
    }
    updater._write_pointer(pointer)
    updater.mark_activation_rolled_back(pointer)
    assert updater.active_python() == python.resolve()
    assert updater.pending_activation() is None


@pytest.mark.parametrize("marker", [0, -1, True, "1", 1.0])
def test_supervisor_state_rejects_invalid_activation_verified_marker(
    tmp_path: Path,
    marker: object,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base")
    work_root = tmp_path / "work"
    target = work_root / "runtime-releases/0.13.11/bin/python"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"target")
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(target),
            "active_version": "0.13.11",
            "previous_python": str(fallback),
            "previous_version": "0.13.10",
            "pending_job_id": "mtn_pending",
            "pending_fencing_token": 1,
            "artifact_sha256": "a" * 64,
            "activation_verified_at": marker,
        }
    )

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=fallback)


def test_supervisor_uses_new_installer_runtime_after_terminal_old_rollback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "runtime-0.9.1"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"python")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=fallback,
        current_version="0.9.1",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(tmp_path / "worker-runtime-0.8.4/bin/python"),
            "active_version": "0.8.4",
            "rolled_back_job_id": "mtn_old",
            "rolled_back_at": 1,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == fallback.resolve()
    assert state.previous_python is None
    assert not state.pending


def test_terminal_rollback_keeps_newer_verified_release_across_restart(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base")
    work_root = tmp_path / "work"
    recovered = work_root / "runtime-releases/0.14.0/bin/python"
    recovered.parent.mkdir(parents=True)
    recovered.write_bytes(b"recovered")
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(recovered),
            "active_version": "0.14.0",
            "rolled_back_job_id": "mtn_failed_0_15_0",
            "rolled_back_at": 1,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == recovered.resolve()
    assert state.previous_python is None
    assert not state.pending


def test_terminal_rollback_rejects_newer_runtime_outside_release_store(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base")
    outside = tmp_path / "outside-0.14.0/bin/python"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"outside")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(outside),
            "active_version": "0.14.0",
            "rolled_back_job_id": "mtn_failed_0_15_0",
            "rolled_back_at": 1,
        }
    )

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=fallback)


@pytest.mark.parametrize(
    ("active_version", "expected_runtime"),
    [
        ("0.13.9", "base"),
        ("0.13.10", "active"),
        ("0.14.0", "active"),
    ],
)
def test_supervisor_selects_completed_runtime_by_version(
    tmp_path: Path,
    active_version: str,
    expected_runtime: str,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base python")
    work_root = tmp_path / "work"
    active = work_root / "runtime-releases" / active_version / "bin/python"
    active.parent.mkdir(parents=True)
    active.write_bytes(b"active python")
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(active),
            "active_version": active_version,
            "last_verified_at": 1,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    expected = fallback if expected_runtime == "base" else active
    assert state.active_python == expected.resolve()
    assert state.previous_python is None
    assert not state.pending


def test_newer_base_does_not_require_superseded_runtime_to_still_exist(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base python")
    work_root = tmp_path / "work"
    missing_active = work_root / "runtime-releases/0.13.9/bin/python"
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(missing_active),
            "active_version": "0.13.9",
            "last_verified_at": 1,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == fallback.resolve()
    assert state.previous_python is None
    assert not state.pending


def test_same_version_repair_recovers_when_completed_runtime_is_missing(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"reviewed base")
    work_root = tmp_path / "work"
    missing_active = work_root / "runtime-releases/0.13.10/bin/python"
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(missing_active),
            "active_version": "0.13.10",
            "last_verified_at": 1,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == fallback.resolve()
    assert state.previous_python is None
    assert not state.pending


def test_supervisor_marks_pending_activation_as_superseded_when_base_is_newer(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base python")
    work_root = tmp_path / "work"
    active = work_root / "runtime-releases" / "0.13.9" / "bin/python"
    active.parent.mkdir(parents=True)
    active.write_bytes(b"pending python")
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(active),
            "active_version": "0.13.9",
            "previous_python": str(fallback),
            "previous_version": "0.13.8",
            "pending_job_id": "mtn_pending",
            "pending_fencing_token": 1,
            "artifact_sha256": "a" * 64,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == active.resolve()
    assert state.previous_python == fallback.resolve()
    assert state.pending
    assert state.superseded_pending


def test_missing_pending_target_returns_available_rollback_runtime(tmp_path: Path) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"base")
    work_root = tmp_path / "work"
    missing = work_root / "runtime-releases/0.13.11/bin/python"
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(missing),
            "active_version": "0.13.11",
            "previous_python": str(fallback),
            "previous_version": "0.13.10",
            "pending_job_id": "mtn_pending",
            "pending_fencing_token": 1,
            "artifact_sha256": "a" * 64,
        }
    )

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == missing.resolve()
    assert not state.active_available
    assert state.previous_python == fallback.resolve()
    assert state.pending
    assert not state.superseded_pending


def test_new_installer_base_replaces_stale_pending_rollback_path(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"reviewed base")
    work_root = tmp_path / "work"
    active = work_root / "runtime-releases/0.13.9/bin/python"
    active.parent.mkdir(parents=True)
    active.write_bytes(b"pending target")
    stale_base = tmp_path / "worker-runtime-0.13.8/bin/python"
    stale_base.parent.mkdir(parents=True)
    stale_base.write_bytes(b"old installer base")
    pointer = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(active),
        "active_version": "0.13.9",
        "previous_python": str(stale_base),
        "previous_version": "0.13.8",
        "pending_job_id": "mtn_pending",
        "pending_fencing_token": 1,
        "artifact_sha256": "a" * 64,
    }
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(pointer)

    state = updater.supervisor_state(fallback=fallback)

    assert state.active_python == active.resolve()
    assert state.previous_python == fallback.resolve()
    assert state.pending
    assert state.superseded_pending

    updater.mark_activation_rolled_back(pointer)
    rolled_back = updater.supervisor_state(fallback=fallback)
    assert rolled_back.active_python == fallback.resolve()
    assert rolled_back.previous_python is None
    assert not rolled_back.pending


def test_new_installer_base_replaces_existing_older_release_rollback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"reviewed base")
    work_root = tmp_path / "work"
    active = work_root / "runtime-releases/0.13.9/bin/python"
    previous = work_root / "runtime-releases/0.13.8/bin/python"
    for path, content in ((active, b"pending target"), (previous, b"older release")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    pointer = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(active),
        "active_version": "0.13.9",
        "previous_python": str(previous),
        "previous_version": "0.13.8",
        "pending_job_id": "mtn_pending",
        "pending_fencing_token": 1,
        "artifact_sha256": "a" * 64,
    }
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(pointer)

    state = updater.supervisor_state(fallback=fallback)
    assert state.previous_python == fallback.resolve()

    updater.mark_activation_rolled_back(pointer)
    assert updater.active_python() == fallback.resolve()


def test_pending_pointer_rejects_newer_untrusted_rollback_path(tmp_path: Path) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"reviewed base")
    work_root = tmp_path / "work"
    active = work_root / "runtime-releases/0.13.11/bin/python"
    active.parent.mkdir(parents=True)
    active.write_bytes(b"pending target")
    untrusted = tmp_path / "outside-0.14.0/bin/python"
    untrusted.parent.mkdir(parents=True)
    untrusted.write_bytes(b"untrusted runtime")
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    pointer = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(active),
        "active_version": "0.13.11",
        "previous_python": str(untrusted),
        "previous_version": "0.14.0",
        "pending_job_id": "mtn_pending",
        "pending_fencing_token": 1,
        "artifact_sha256": "a" * 64,
    }
    updater._write_pointer(pointer)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=fallback)
    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.mark_activation_rolled_back(pointer)


def test_pending_pointer_never_uses_active_runtime_outside_trust_roots(
    tmp_path: Path,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"reviewed base")
    outside = tmp_path / "outside/bin/python"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"outside runtime")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(outside),
            "active_version": "0.13.11",
            "previous_python": str(fallback),
            "previous_version": "0.13.10",
            "pending_job_id": "mtn_pending",
            "pending_fencing_token": 1,
            "artifact_sha256": "a" * 64,
        }
    )

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=fallback)


def test_runtime_release_root_symlink_cannot_escape_trust_boundary(tmp_path: Path) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    fallback = source / "bin/python"
    fallback.parent.mkdir(parents=True)
    fallback.write_bytes(b"reviewed base")
    outside = tmp_path / "outside"
    evil = outside / "evil/bin/python"
    evil.parent.mkdir(parents=True)
    evil.write_bytes(b"outside runtime")
    work_root = tmp_path / "work"
    work_root.mkdir()
    (work_root / "runtime-releases").symlink_to(outside, target_is_directory=True)
    updater = RuntimeUpdater(
        work_root,
        current_python=fallback,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(work_root / "runtime-releases/evil/bin/python"),
            "active_version": "0.14.0",
            "last_verified_at": 1,
        }
    )

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=fallback)


def test_stale_activation_transition_cannot_overwrite_new_pointer_state(
    tmp_path: Path,
) -> None:
    source = tmp_path / "runtime"
    python = source / "bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=python,
        current_version="0.13.10",
        source_runtime=source,
    )
    original = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(tmp_path / "work/runtime-releases/0.13.11/bin/python"),
        "active_version": "0.13.11",
        "previous_python": str(python),
        "previous_version": "0.13.10",
        "pending_job_id": "mtn_pending",
        "pending_fencing_token": 1,
        "artifact_sha256": "a" * 64,
    }
    updater._write_pointer(original)
    verified = updater.mark_activation_verified(original)
    assert updater.mark_activation_verified(original) == verified

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_BUSY"):
        updater._write_pending_pointer(original)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_STALE"):
        updater.mark_activation_succeeded(original)
    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_STALE"):
        updater.mark_activation_rolled_back(original)

    assert updater.pending_activation() == verified


def test_stale_job_cannot_overwrite_new_pending_activation(tmp_path: Path) -> None:
    source = tmp_path / "runtime"
    python = source / "bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=python,
        current_version="0.13.10",
        source_runtime=source,
    )
    first = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(tmp_path / "work/runtime-releases/0.13.11/bin/python"),
        "active_version": "0.13.11",
        "previous_python": str(python),
        "previous_version": "0.13.10",
        "pending_job_id": "mtn_first",
        "pending_fencing_token": 1,
        "artifact_sha256": "a" * 64,
    }
    second = {
        **first,
        "active_python": str(tmp_path / "work/runtime-releases/0.13.12/bin/python"),
        "active_version": "0.13.12",
        "pending_job_id": "mtn_second",
        "pending_fencing_token": 2,
        "artifact_sha256": "b" * 64,
    }
    updater._write_pointer(first)
    updater._write_pointer(second)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_STALE"):
        updater.mark_activation_succeeded(first)

    assert updater.pending_activation() == second


def test_runtime_pointer_rejects_unbounded_release_version(tmp_path: Path) -> None:
    source = tmp_path / "runtime"
    python = source / "bin/python"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    updater = RuntimeUpdater(
        tmp_path / "work",
        current_python=python,
        current_version="0.13.10",
        source_runtime=source,
    )
    updater._write_pointer(
        {
            "format": "vgen-worker-runtime-pointer",
            "version": 1,
            "active_python": str(python),
            "active_version": f"{'9' * 5000}.0.0",
        }
    )

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        updater.supervisor_state(fallback=python)
