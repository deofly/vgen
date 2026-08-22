from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from vgen.executors import (
    ExecutionArtifact,
    ExecutionContext,
    ExecutionRequest,
    ExecutionResult,
    Executor,
    ExecutorDescriptor,
    ExecutorHealth,
    ExecutorRegistry,
    ProgressEvent,
    UsageMetrics,
)


class FakeExecutor:
    def __init__(self) -> None:
        self.cancelled_handle: str | None = None

    def descriptor(self) -> ExecutorDescriptor:
        return ExecutorDescriptor("fake", "1.0.0", ("fake/v1",), ("t2v",))

    def health(self) -> ExecutorHealth:
        return ExecutorHealth(True, "ready")

    def capabilities(self) -> Mapping[str, Any]:
        return {"deterministic": True}

    def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
        context.raise_if_cancelled()
        context.progress(0.5, "generating")
        destination = context.work_dir / "fake.bin"
        destination.write_bytes(request.payload)
        context.progress(1.0, "generated")
        return ExecutionResult(
            (ExecutionArtifact("primary", destination),),
            usage=UsageMetrics(executor_wall_ms=1),
            executor_run_id="fake-run",
        )

    def cancel(self, handle: str | None = None) -> None:
        self.cancelled_handle = handle


def test_fake_executor_satisfies_contract(tmp_path: Path) -> None:
    executor = FakeExecutor()
    assert isinstance(executor, Executor)
    descriptor = executor.descriptor()
    assert descriptor.payload_formats == ("fake/v1",)
    assert executor.health().healthy
    assert executor.capabilities() == {"deterministic": True}

    progress: list[ProgressEvent] = []
    result = executor.execute(
        ExecutionRequest(
            task_id="tsk_test",
            attempt_id="att_test",
            workflow_digest="a" * 64,
            operation="t2v",
            payload_format="fake/v1",
            payload=b"deterministic",
        ),
        ExecutionContext(tmp_path, progress.append),
    )
    assert result.executor_run_id == "fake-run"
    assert result.artifacts[0].path.read_bytes() == b"deterministic"
    assert [event.fraction for event in progress] == [0.5, 1.0]
    executor.cancel("fake-run")
    assert executor.cancelled_handle == "fake-run"


def test_registry_rejects_duplicate_executor_type() -> None:
    registry = ExecutorRegistry(FakeExecutor())
    assert registry.get("fake").descriptor().executor_type == "fake"
    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeExecutor())
