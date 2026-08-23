from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vgen.worker.updater import RuntimeUpdater, WorkerUpdateError


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

    updater.mark_activation_succeeded(pointer)
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
    updater.mark_activation_rolled_back(pointer)
    assert updater.active_python() == python.resolve()
    assert updater.pending_activation() is None


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
