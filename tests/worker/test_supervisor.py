from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import vgen.worker.supervisor as supervisor_module
from vgen.worker.supervisor import (
    EXIT_UPDATE_RESTART,
    EXIT_UPDATE_ROLLBACK,
    supervise_worker,
)
from vgen.worker.updater import WorkerUpdateError


def _python(runtime: Path) -> Path:
    python = runtime / "bin" / "python"
    python.parent.mkdir(parents=True, exist_ok=True)
    python.write_bytes(b"python")
    return python.resolve()


def _write_pointer(
    work_root: Path,
    *,
    active: Path,
    previous: Path | None = None,
    pending: bool = False,
    activation_verified: bool = False,
    active_version: str = "0.13.11",
) -> None:
    value: dict[str, Any] = {
        "format": "vgen-worker-runtime-pointer",
        "version": 1,
        "active_python": str(active),
        "active_version": active_version,
    }
    if pending:
        value.update(
            {
                "previous_python": str(previous),
                "previous_version": "0.9.0",
                "pending_job_id": "mtn_test",
                "pending_fencing_token": 1,
                "artifact_sha256": "a" * 64,
            }
        )
        if activation_verified:
            value["activation_verified_at"] = 1
    (work_root / "runtime-active.json").write_text(json.dumps(value), encoding="utf-8")


@pytest.mark.parametrize(
    ("active_version", "expected_runtime"),
    [
        ("0.13.9", "initial"),
        ("0.13.10", "active"),
        ("0.14.0", "active"),
    ],
)
def test_supervisor_launches_completed_runtime_selected_by_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    active_version: str,
    expected_runtime: str,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    initial = _python(source)
    work_root = tmp_path / "work"
    active = _python(work_root / "runtime-releases" / active_version)
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(work_root, active=active, active_version=active_version)
    launches: list[Path] = []

    def runner(command: list[str], **_kwargs: Any) -> Any:
        launches.append(Path(command[0]))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(supervisor_module, "__version__", "0.13.10")

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    expected = initial if expected_runtime == "initial" else active
    assert launches == [expected]


def test_supervisor_never_launches_pending_target_older_than_reviewed_base(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "worker-runtime-0.13.10"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases/0.13.9")
    stale_base = _python(tmp_path / "worker-runtime-0.13.8")
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(
        work_root,
        active=target,
        previous=stale_base,
        pending=True,
        active_version="0.13.9",
    )
    launches: list[tuple[Path, str | None, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_SUPERVISOR_BASE_VERSION"),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(supervisor_module, "__version__", "0.13.10")

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(initial, "0.13.10", True)]


def test_supervisor_switches_to_reviewed_runtime_after_restart_request(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        commands.append(command)
        assert kwargs["env"]["VGEN_WORKER_SUPERVISED_CHILD"] == "1"
        if len(commands) == 1:
            _write_pointer(work_root, active=target, previous=initial, pending=True)
            return SimpleNamespace(returncode=EXIT_UPDATE_RESTART)
        _write_pointer(work_root, active=target)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve", "--json"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert commands == [
        [str(initial), "-I", "-m", "vgen.worker.main", "serve", "--json"],
        [str(target), "-I", "-m", "vgen.worker.main", "serve", "--json"],
    ]


def test_supervisor_restarts_verified_target_after_nonzero_exit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(work_root, active=target, previous=initial, pending=True)
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        if len(launches) == 1:
            # The target journaled successful activation and may already have
            # committed it remotely, but crashed before clearing the pointer.
            _write_pointer(
                work_root,
                active=target,
                previous=initial,
                pending=True,
                activation_verified=True,
            )
            return SimpleNamespace(returncode=2)
        _write_pointer(work_root, active=target)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(target, False), (target, False)]


def test_supervisor_retries_verified_target_after_launch_error(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(
        work_root,
        active=target,
        previous=initial,
        pending=True,
        activation_verified=True,
    )
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        if len(launches) == 1:
            raise OSError("transient process launch failure")
        _write_pointer(work_root, active=target)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(target, False), (target, False)]


def test_supervisor_never_falls_back_from_missing_verified_target(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = work_root / "runtime-releases" / "0.9.1-a" / "bin" / "python"
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(
        work_root,
        active=target,
        previous=initial,
        pending=True,
        activation_verified=True,
    )
    launches: list[list[str]] = []

    def runner(command: list[str], **_kwargs: Any) -> Any:
        launches.append(command)
        return SimpleNamespace(returncode=0)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_RUNTIME_INVALID"):
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
    assert launches == []


def test_supervisor_restarts_previous_runtime_with_rollback_marker(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        if len(launches) == 1:
            _write_pointer(work_root, active=target, previous=initial, pending=True)
            return SimpleNamespace(returncode=EXIT_UPDATE_RESTART)
        if len(launches) == 2:
            _write_pointer(
                work_root,
                active=target,
                previous=initial,
                pending=True,
                activation_verified=True,
            )
            return SimpleNamespace(returncode=EXIT_UPDATE_ROLLBACK)
        _write_pointer(work_root, active=initial)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(initial, False), (target, False), (initial, True)]


def test_supervisor_rolls_back_when_target_runtime_cannot_start(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        if len(launches) == 1:
            _write_pointer(work_root, active=target, previous=initial, pending=True)
            return SimpleNamespace(returncode=EXIT_UPDATE_RESTART)
        if len(launches) == 2:
            raise OSError("target interpreter is unavailable")
        _write_pointer(work_root, active=initial)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(initial, False), (target, False), (initial, True)]


def test_supervisor_rolls_back_when_staged_target_disappears_before_launch(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        if len(launches) == 1:
            _write_pointer(work_root, active=target, previous=initial, pending=True)
            target.unlink()
            return SimpleNamespace(returncode=EXIT_UPDATE_RESTART)
        _write_pointer(work_root, active=initial)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(initial, False), (initial, True)]


def test_supervisor_retries_crashing_rollback_runtime_within_budget(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(work_root, active=target, previous=initial, pending=True)
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        if len(launches) < 3:
            return SimpleNamespace(returncode=2)
        _write_pointer(work_root, active=initial)
        return SimpleNamespace(returncode=0)

    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(target, False), (initial, True), (initial, True)]


def test_supervisor_honors_rollback_requested_by_legacy_windows_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    target = _python(work_root / "runtime-releases" / "0.9.1-a")
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(
        work_root,
        active=target,
        previous=initial,
        pending=True,
        activation_verified=True,
    )
    launches: list[tuple[Path, bool]] = []

    def runner(command: list[str], **kwargs: Any) -> Any:
        launches.append(
            (
                Path(command[0]),
                kwargs["env"].get("VGEN_WORKER_UPDATE_ROLLBACK") == "1",
            )
        )
        _write_pointer(work_root, active=initial)
        return SimpleNamespace(returncode=0)

    monkeypatch.setenv("VGEN_WORKER_UPDATE_ROLLBACK", "1")
    assert (
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
            runner=runner,
        )
        == 0
    )
    assert launches == [(initial, True)]


def test_supervisor_rejects_pointer_outside_trusted_runtime_roots(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    outside = _python(tmp_path / "outside")
    work_root.mkdir(parents=True)
    _write_pointer(work_root, active=outside)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
        )


def test_supervisor_rejects_reparse_target_even_with_safe_previous_runtime(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    initial = _python(source)
    work_root = tmp_path / "work"
    outside = _python(tmp_path / "outside")
    target = work_root / "runtime-releases" / "0.9.1-a" / "bin" / "python"
    target.parent.mkdir(parents=True)
    target.symlink_to(outside)
    work_root.mkdir(parents=True, exist_ok=True)
    _write_pointer(work_root, active=target, previous=initial, pending=True)

    with pytest.raises(WorkerUpdateError, match="WORKER_UPDATE_POINTER_INVALID"):
        supervise_worker(
            ["serve"],
            work_root=work_root,
            initial_python=initial,
            source_runtime=source,
        )
