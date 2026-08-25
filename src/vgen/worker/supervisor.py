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
_MAX_ROLLBACK_ATTEMPTS = 3

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
    elif state.pending and not state.active_available:
        if state.previous_python is None:
            raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
        selected = state.previous_python
        rollback = True
    else:
        selected = state.active_python
    rollback_attempts = 0

    while True:
        environment = os.environ.copy()
        environment[_CHILD_ENV] = "1"
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
                if state.previous_python is None:
                    raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
                selected = state.previous_python
                rollback = True
            else:
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
        if exit_code == EXIT_UPDATE_ROLLBACK or failed_pending_runtime:
            if not state.pending or state.previous_python is None:
                raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_UNAVAILABLE")
            rollback_attempts += 1
            if rollback_attempts > _MAX_ROLLBACK_ATTEMPTS:
                raise WorkerUpdateError("WORKER_UPDATE_ROLLBACK_LIMIT")
            selected = state.previous_python
            rollback = True
            continue
        return exit_code


__all__ = [
    "EXIT_UPDATE_RESTART",
    "EXIT_UPDATE_ROLLBACK",
    "is_supervised_child",
    "supervise_worker",
]
