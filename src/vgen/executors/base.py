"""Stable worker-to-executor API.

The worker sees payload bytes and common artifacts.  Only an executor adapter is
allowed to interpret those bytes as a ComfyUI graph, a Diffusers invocation, or
an SGLang request.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from vgen.artifacts import ArtifactDescriptor
from vgen.protocol.errors import ErrorCode, RetryAction, sanitize_details


@dataclass(frozen=True)
class ExecutorDescriptor:
    executor_type: str
    version: str
    payload_formats: tuple[str, ...]
    operations: tuple[str, ...]
    max_concurrency: int = 1
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.executor_type or not self.version:
            raise ValueError("executor_type and version are required")
        if not self.payload_formats:
            raise ValueError("executor must accept at least one payload format")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least one")
        object.__setattr__(self, "payload_formats", tuple(self.payload_formats))
        object.__setattr__(self, "operations", tuple(self.operations))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class ExecutorHealth:
    healthy: bool
    status: str
    checked_at: float = field(default_factory=time.time)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", MappingProxyType(dict(self.details)))


@dataclass(frozen=True)
class ExecutionInput:
    name: str
    path: Path
    artifact: ArtifactDescriptor


@dataclass(frozen=True)
class ExecutionRequest:
    task_id: str
    attempt_id: str
    workflow_digest: str
    operation: str
    payload_format: str
    payload: bytes
    inputs: tuple[ExecutionInput, ...] = ()
    timeout_seconds: float = 3600.0

    def __post_init__(self) -> None:
        if not self.task_id or not self.attempt_id:
            raise ValueError("task_id and attempt_id are required")
        if not isinstance(self.payload, bytes):
            raise TypeError("executor payload must be bytes")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        object.__setattr__(self, "inputs", tuple(self.inputs))


@dataclass(frozen=True)
class ProgressEvent:
    fraction: float
    stage: str
    message: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.fraction <= 1.0:
            raise ValueError("progress fraction must be between zero and one")
        if not self.stage:
            raise ValueError("progress stage is required")


@dataclass(frozen=True)
class ExecutionArtifact:
    name: str
    path: Path
    media_type: str = "application/octet-stream"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("execution artifact name is required")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class UsageMetrics:
    """Raw immutable measurements; billing policy remains on the Gateway."""

    executor_wall_ms: int = 0
    gpu_active_ms: int | None = None
    gpu_count: int = 1
    input_bytes: int = 0
    output_bytes: int = 0
    frames: int | None = None
    duration_ms: int | None = None
    denoise_steps: int | None = None
    native: Mapping[str, int | float | bool | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        numeric = (
            self.executor_wall_ms,
            self.gpu_count,
            self.input_bytes,
            self.output_bytes,
        )
        if any(value < 0 for value in numeric):
            raise ValueError("usage metrics cannot be negative")
        if self.gpu_count < 1:
            raise ValueError("gpu_count must be at least one")
        for value in (self.gpu_active_ms, self.frames, self.duration_ms, self.denoise_steps):
            if value is not None and value < 0:
                raise ValueError("usage metrics cannot be negative")
        if any(
            value is not None and not isinstance(value, (bool, int, float))
            for value in self.native.values()
        ):
            raise TypeError("native usage metrics must be numeric, boolean, or null")
        object.__setattr__(self, "native", MappingProxyType(dict(self.native)))


@dataclass(frozen=True)
class ExecutionResult:
    artifacts: tuple[ExecutionArtifact, ...]
    usage: UsageMetrics = field(default_factory=UsageMetrics)
    executor_run_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.artifacts:
            raise ValueError("executor must return at least one artifact")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


class ExecutorFailure(Exception):
    """A normalized and safe error suitable for a Gateway failure report."""

    def __init__(
        self,
        code: int,
        name: str,
        message: str,
        *,
        retry_action: RetryAction = RetryAction.NONE,
        responsibility: str = "provider",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        if code < 100000 or code > 999999:
            raise ValueError("executor error code must be a six-digit integer")
        super().__init__(message)
        self.code = code
        self.name = name
        self.message = message
        self.retry_action = retry_action
        self.responsibility = responsibility
        self.details = MappingProxyType(sanitize_details(details))


class ExecutionCancelled(ExecutorFailure):
    def __init__(self) -> None:
        super().__init__(
            ErrorCode.EXECUTION_CANCELLED,
            "EXECUTION_CANCELLED",
            "Execution was cancelled.",
            retry_action=RetryAction.NONE,
            responsibility="consumer",
        )


@dataclass
class ExecutionContext:
    work_dir: Path
    on_progress: Callable[[ProgressEvent], None] = lambda _event: None
    is_cancelled: Callable[[], bool] = lambda: False

    def progress(self, fraction: float, stage: str, message: str | None = None) -> None:
        self.on_progress(ProgressEvent(fraction, stage, message))

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise ExecutionCancelled()


@runtime_checkable
class Executor(Protocol):
    def descriptor(self) -> ExecutorDescriptor: ...

    def health(self) -> ExecutorHealth: ...

    def capabilities(self) -> Mapping[str, Any]: ...

    def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult: ...

    def cancel(self, handle: str | None = None) -> None: ...
