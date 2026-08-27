"""Stable Worker subprocess supervisor for remote runtime activation."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from vgen import __version__

from .updater import RuntimeUpdater, WorkerUpdateError

EXIT_UPDATE_RESTART = 75
EXIT_UPDATE_ROLLBACK = 76
_CHILD_ENV = "VGEN_WORKER_SUPERVISED_CHILD"
_ROLLBACK_ENV = "VGEN_WORKER_UPDATE_ROLLBACK"
_BASE_VERSION_ENV = "VGEN_WORKER_SUPERVISOR_BASE_VERSION"
_MAX_ROLLBACK_ATTEMPTS = 3
_MAX_VERIFIED_RESTART_ATTEMPTS = 3

Runner = Callable[..., Any]


def is_supervised_child() -> bool:
    return os.environ.get(_CHILD_ENV) == "1"


def supervise_worker(
    argv: Sequence[str],
    *,
    work_root: Path,
    initial_python: Path | None = None,
    source_runtime: Path | None = None,
    runner: Runner = subprocess.run,
) -> int:
    """Run Worker children and follow the reviewed runtime pointer.

    The supervisor stays on the original interpreter while children may move
    between immutable runtimes. This makes Broker updates independent of a
    PowerShell wrapper and keeps one previous runtime available for rollback.
    """

    initial = (initial_python or Path(sys.executable)).resolve()
    updater = RuntimeUpdater(
        work_root,
        current_python=initial,
        current_version=__version__,
        source_runtime=(source_runtime or Path(sys.prefix)).resolve(),
    )
    state = updater.supervisor_state(fallback=initial)
    rollback = os.environ.get(_ROLLBACK_ENV) == "1"
    if rollback:
        if not state.pending or state.previous_python is None:
            raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
        selected = state.previous_python
    elif state.pending and state.superseded_pending:
        # A target built before this supervisor protocol cannot be expected to
        # observe VGEN_WORKER_SUPERVISOR_BASE_VERSION and yield after clearing
        # the pointer. Start the newer reviewed base as the rollback runtime so
        # it resolves the old maintenance transaction without handing process
        # control to an indefinitely resident older child.
        if state.previous_python is None:
            raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
        selected = state.previous_python
        rollback = True
    elif state.pending and state.activation_verified and not state.active_available:
        # Once the target is verified, only that target may finish the
        # idempotent Gateway commit and local pointer cleanup. Falling back here
        # could report a rollback after the Gateway already accepted success.
        raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
    elif state.pending and not state.active_available:
        if state.previous_python is None:
            raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
        selected = state.previous_python
        rollback = True
    else:
        selected = state.active_python
    rollback_attempts = 0
    verified_restart_attempts = 0

    while True:
        environment = os.environ.copy()
        environment[_CHILD_ENV] = "1"
        environment[_BASE_VERSION_ENV] = __version__
        if rollback:
            environment[_ROLLBACK_ENV] = "1"
        else:
            environment.pop(_ROLLBACK_ENV, None)
        try:
            completed = runner(
                [str(selected), "-I", "-m", "vgen.worker.main", *argv],
                env=environment,
                check=False,
            )
        except OSError as exc:
            state = updater.supervisor_state(fallback=initial)
            if state.pending and state.activation_verified and not rollback:
                if not state.active_available:
                    raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID") from exc
                verified_restart_attempts += 1
                if verified_restart_attempts > _MAX_VERIFIED_RESTART_ATTEMPTS:
                    raise WorkerUpdateError("WORKER_UPDATE_ACTIVATION_RETRY_LIMIT") from exc
                selected = state.active_python
                rollback = False
                rollback_attempts = 0
                continue
            if (
                state.pending
                and state.previous_python is not None
                and selected in {state.active_python, state.previous_python}
            ):
                rollback_attempts += 1
                if rollback_attempts > _MAX_ROLLBACK_ATTEMPTS:
                    raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_LIMIT") from exc
                selected = state.previous_python
                rollback = True
                continue
            raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID") from exc

        exit_code = int(completed.returncode)
        state = updater.supervisor_state(fallback=initial)
        if exit_code == EXIT_UPDATE_RESTART:
            if state.active_python == selected:
                raise WorkerUpdateError("WORKER_UPDATE_POINTER_NOT_ADVANCED")
            if state.pending and not state.active_available:
                if state.activation_verified:
                    raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
                if state.previous_python is None:
                    raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
                selected = state.previous_python
                rollback = True
            else:
                selected = state.active_python
                rollback = False
            rollback_attempts = 0
            verified_restart_attempts = 0
            continue
        if exit_code == EXIT_UPDATE_ROLLBACK:
            if not state.pending or state.previous_python is None:
                raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
            rollback_attempts += 1
            if rollback_attempts > _MAX_ROLLBACK_ATTEMPTS:
                raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_LIMIT")
            selected = state.previous_python
            rollback = True
            verified_restart_attempts = 0
            continue
        if exit_code != 0 and state.pending and state.activation_verified and not rollback:
            if not state.active_available:
                raise WorkerUpdateError("WORKER_UPDATE_RUNTIME_INVALID")
            verified_restart_attempts += 1
            if verified_restart_attempts > _MAX_VERIFIED_RESTART_ATTEMPTS:
                raise WorkerUpdateError("WORKER_UPDATE_ACTIVATION_RETRY_LIMIT")
            selected = state.active_python
            rollback = False
            rollback_attempts = 0
            continue
        failed_pending_runtime = (
            exit_code != 0
            and state.pending
            and state.previous_python is not None
            and selected in {state.active_python, state.previous_python}
        )
        if failed_pending_runtime:
            if not state.pending or state.previous_python is None:
                raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
            rollback_attempts += 1
            if rollback_attempts > _MAX_ROLLBACK_ATTEMPTS:
                raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_LIMIT")
            selected = state.previous_python
            rollback = True
            verified_restart_attempts = 0
            continue
        return exit_code


__all__ = [
    "EXIT_UPDATE_RESTART",
    "EXIT_UPDATE_ROLLBACK",
    "is_supervised_child",
    "supervise_worker",
]
