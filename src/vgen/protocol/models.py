"""Executor-neutral v1 models and state-machine invariants.

These models intentionally use only the Python standard library. Gateway,
Worker, Broker, and third-party executor plugins can therefore share the wire
contract without importing FastAPI or a particular validation framework.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .errors import ErrorCode, VGenError

PROTOCOL_VERSION = "v1"


class TaskState(StrEnum):
    PREPARED = "prepared"
    COMMITTED = "committed"
    QUEUED = "queued"
    RESERVED = "reserved"
    RUNNING = "running"
    REKEY_REQUIRED = "rekey_required"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class AttemptState(StrEnum):
    RESERVED = "reserved"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


TASK_TRANSITIONS: Mapping[TaskState, frozenset[TaskState]] = {
    TaskState.PREPARED: frozenset({TaskState.COMMITTED, TaskState.CANCELLED, TaskState.EXPIRED}),
    TaskState.COMMITTED: frozenset({TaskState.QUEUED, TaskState.CANCELLED}),
    TaskState.QUEUED: frozenset({TaskState.RESERVED, TaskState.CANCELLED, TaskState.EXPIRED}),
    TaskState.RESERVED: frozenset(
        {TaskState.RUNNING, TaskState.REKEY_REQUIRED, TaskState.CANCELLED, TaskState.EXPIRED}
    ),
    TaskState.RUNNING: frozenset(
        {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED, TaskState.REKEY_REQUIRED}
    ),
    TaskState.REKEY_REQUIRED: frozenset(
        {TaskState.QUEUED, TaskState.RESERVED, TaskState.CANCELLED, TaskState.EXPIRED}
    ),
    TaskState.SUCCEEDED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELLED: frozenset(),
    TaskState.EXPIRED: frozenset(),
}

ATTEMPT_TRANSITIONS: Mapping[AttemptState, frozenset[AttemptState]] = {
    AttemptState.RESERVED: frozenset(
        {AttemptState.LEASED, AttemptState.CANCELLED, AttemptState.EXPIRED}
    ),
    AttemptState.LEASED: frozenset(
        {AttemptState.RUNNING, AttemptState.FAILED, AttemptState.CANCELLED, AttemptState.EXPIRED}
    ),
    AttemptState.RUNNING: frozenset(
        {AttemptState.SUCCEEDED, AttemptState.FAILED, AttemptState.CANCELLED, AttemptState.EXPIRED}
    ),
    AttemptState.SUCCEEDED: frozenset(),
    AttemptState.FAILED: frozenset(),
    AttemptState.CANCELLED: frozenset(),
    AttemptState.EXPIRED: frozenset(),
}


def can_transition_task(current: TaskState | str, target: TaskState | str) -> bool:
    return TaskState(target) in TASK_TRANSITIONS[TaskState(current)]


def can_transition_attempt(
    current: AttemptState | str,
    target: AttemptState | str,
) -> bool:
    return AttemptState(target) in ATTEMPT_TRANSITIONS[AttemptState(current)]


def require_task_transition(current: TaskState | str, target: TaskState | str) -> None:
    source = TaskState(current)
    destination = TaskState(target)
    if not can_transition_task(source, destination):
        raise VGenError(
            ErrorCode.TASK_STATE_CONFLICT,
            details={"from_state": source.value, "to_state": destination.value},
        )


def require_attempt_transition(
    current: AttemptState | str,
    target: AttemptState | str,
) -> None:
    source = AttemptState(current)
    destination = AttemptState(target)
    if not can_transition_attempt(source, destination):
        raise VGenError(
            ErrorCode.TASK_STATE_CONFLICT,
            details={
                "resource": "attempt",
                "from_state": source.value,
                "to_state": destination.value,
            },
        )


def _copy_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    return dict(value or {})


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url value") from exc


@dataclass(frozen=True, slots=True)
class ExecutorDescriptor:
    executor_type: str
    version: str
    payload_formats: tuple[str, ...]
    operations: tuple[str, ...]
    max_concurrency: int = 1
    capabilities: Mapping[str, Any] = field(default_factory=dict)
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if not self.executor_type or not self.version:
            raise ValueError("executor type and version are required")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        object.__setattr__(self, "payload_formats", tuple(self.payload_formats))
        object.__setattr__(self, "operations", tuple(self.operations))
        object.__setattr__(self, "capabilities", _copy_mapping(self.capabilities))

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "type": self.executor_type,
            "version": self.version,
            "payload_formats": list(self.payload_formats),
            "operations": list(self.operations),
            "max_concurrency": self.max_concurrency,
            "capabilities": dict(self.capabilities),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExecutorDescriptor:
        return cls(
            protocol_version=str(value.get("protocol_version", PROTOCOL_VERSION)),
            executor_type=str(value["type"]),
            version=str(value["version"]),
            payload_formats=tuple(str(item) for item in value.get("payload_formats", ())),
            operations=tuple(str(item) for item in value.get("operations", ())),
            max_concurrency=int(value.get("max_concurrency", 1)),
            capabilities=_copy_mapping(value.get("capabilities")),
        )


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    artifact_id: str
    role: str
    media_type: str
    size_bytes: int
    sha256: str
    ticket: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("artifact size must not be negative")
        digest = self.sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("artifact sha256 must be 64 lowercase hexadecimal characters")
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "ticket", _copy_mapping(self.ticket))

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "role": self.role,
            "media_type": self.media_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "ticket": dict(self.ticket),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ArtifactRef:
        return cls(
            artifact_id=str(value["artifact_id"]),
            role=str(value["role"]),
            media_type=str(value["media_type"]),
            size_bytes=int(value["size_bytes"]),
            sha256=str(value["sha256"]),
            ticket=_copy_mapping(value.get("ticket")),
        )


@dataclass(frozen=True, slots=True)
class ExecutionArtifact:
    role: str
    media_type: str
    path: str
    size_bytes: int
    sha256: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("artifact size must not be negative")
        digest = self.sha256.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("artifact sha256 must be 64 lowercase hexadecimal characters")
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "metadata", _copy_mapping(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "media_type": self.media_type,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExecutionArtifact:
        return cls(
            role=str(value["role"]),
            media_type=str(value["media_type"]),
            path=str(value["path"]),
            size_bytes=int(value["size_bytes"]),
            sha256=str(value["sha256"]),
            metadata=_copy_mapping(value.get("metadata")),
        )


@dataclass(frozen=True, slots=True)
class UsageReport:
    gpu_active_ms: int = 0
    gateway_wall_ms: int = 0
    gpu_count: int = 1
    input_bytes: int = 0
    output_bytes: int = 0
    upload_bytes: int = 0
    download_bytes: int = 0
    egress_bytes: int = 0
    width: int | None = None
    height: int | None = None
    frames: int | None = None
    duration_ms: int | None = None
    denoise_steps: int | None = None
    executor_metrics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        nonnegative = (
            self.gpu_active_ms,
            self.gateway_wall_ms,
            self.input_bytes,
            self.output_bytes,
            self.upload_bytes,
            self.download_bytes,
            self.egress_bytes,
        )
        if any(value < 0 for value in nonnegative) or self.gpu_count < 1:
            raise ValueError("usage counters must not be negative and gpu_count must be positive")
        optional_nonnegative = (
            self.width,
            self.height,
            self.frames,
            self.duration_ms,
            self.denoise_steps,
        )
        if any(value is not None and value < 0 for value in optional_nonnegative):
            raise ValueError("optional usage counters must not be negative")
        object.__setattr__(self, "executor_metrics", _copy_mapping(self.executor_metrics))

    def to_dict(self) -> dict[str, Any]:
        return {
            "gpu_active_ms": self.gpu_active_ms,
            "gateway_wall_ms": self.gateway_wall_ms,
            "gpu_count": self.gpu_count,
            "input_bytes": self.input_bytes,
            "output_bytes": self.output_bytes,
            "upload_bytes": self.upload_bytes,
            "download_bytes": self.download_bytes,
            "egress_bytes": self.egress_bytes,
            "width": self.width,
            "height": self.height,
            "frames": self.frames,
            "duration_ms": self.duration_ms,
            "denoise_steps": self.denoise_steps,
            "executor_metrics": dict(self.executor_metrics),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> UsageReport:
        optional = ("width", "height", "frames", "duration_ms", "denoise_steps")
        kwargs: dict[str, Any] = {
            "gpu_active_ms": int(value.get("gpu_active_ms", 0)),
            "gateway_wall_ms": int(value.get("gateway_wall_ms", 0)),
            "gpu_count": int(value.get("gpu_count", 1)),
            "input_bytes": int(value.get("input_bytes", 0)),
            "output_bytes": int(value.get("output_bytes", 0)),
            "upload_bytes": int(value.get("upload_bytes", 0)),
            "download_bytes": int(value.get("download_bytes", 0)),
            "egress_bytes": int(value.get("egress_bytes", 0)),
            "executor_metrics": _copy_mapping(value.get("executor_metrics")),
        }
        for name in optional:
            raw = value.get(name)
            kwargs[name] = None if raw is None else int(raw)
        return cls(**kwargs)


@dataclass(frozen=True, slots=True)
class ExecutionRequest:
    task_id: str
    attempt_id: str
    fencing_token: int
    workflow_digest: str
    executor_type: str
    payload_format: str
    opaque_payload: bytes
    inputs: tuple[ArtifactRef, ...] = ()
    deadline_unix_ms: int | None = None
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.fencing_token < 1:
            raise ValueError("fencing_token must be positive")
        if not isinstance(self.opaque_payload, bytes):
            raise TypeError("opaque_payload must be bytes")
        object.__setattr__(self, "inputs", tuple(self.inputs))

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "task_id": self.task_id,
            "attempt_id": self.attempt_id,
            "fencing_token": self.fencing_token,
            "workflow_digest": self.workflow_digest,
            "executor_type": self.executor_type,
            "payload_format": self.payload_format,
            "opaque_payload": _b64_encode(self.opaque_payload),
            "inputs": [item.to_dict() for item in self.inputs],
            "deadline_unix_ms": self.deadline_unix_ms,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExecutionRequest:
        return cls(
            protocol_version=str(value.get("protocol_version", PROTOCOL_VERSION)),
            task_id=str(value["task_id"]),
            attempt_id=str(value["attempt_id"]),
            fencing_token=int(value["fencing_token"]),
            workflow_digest=str(value["workflow_digest"]),
            executor_type=str(value["executor_type"]),
            payload_format=str(value["payload_format"]),
            opaque_payload=_b64_decode(str(value["opaque_payload"])),
            inputs=tuple(ArtifactRef.from_dict(item) for item in value.get("inputs", ())),
            deadline_unix_ms=(
                None if value.get("deadline_unix_ms") is None else int(value["deadline_unix_ms"])
            ),
        )


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    executor_run_id: str | None
    artifacts: tuple[ExecutionArtifact, ...]
    usage: UsageReport
    media_metadata: Mapping[str, Any] = field(default_factory=dict)
    protocol_version: str = PROTOCOL_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "media_metadata", _copy_mapping(self.media_metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "executor_run_id": self.executor_run_id,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "usage": self.usage.to_dict(),
            "media_metadata": dict(self.media_metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ExecutionResult:
        return cls(
            protocol_version=str(value.get("protocol_version", PROTOCOL_VERSION)),
            executor_run_id=(
                None if value.get("executor_run_id") is None else str(value["executor_run_id"])
            ),
            artifacts=tuple(
                ExecutionArtifact.from_dict(item) for item in value.get("artifacts", ())
            ),
            usage=UsageReport.from_dict(value.get("usage", {})),
            media_metadata=_copy_mapping(value.get("media_metadata")),
        )
