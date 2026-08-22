"""Generic lease/result types consumed by Worker Core.

Executor payload bytes are opaque here.  The crypto/session layer resolves an
E2EE envelope before constructing this object; only the selected Executor is
permitted to interpret the plaintext bytes.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from vgen.artifacts import ArtifactDescriptor, TransferTicket
from vgen.executors import RetryAction, UsageMetrics
from vgen.protocol.errors import sanitize_details


@dataclass(frozen=True)
class LeaseReference:
    lease_id: str
    task_id: str
    attempt_id: str
    worker_id: str
    fencing_token: int

    def __post_init__(self) -> None:
        if not all((self.lease_id, self.task_id, self.attempt_id, self.worker_id)):
            raise ValueError("lease reference identifiers are required")
        if self.fencing_token < 1:
            raise ValueError("fencing_token must be positive")


@dataclass(frozen=True)
class ExecutorPayload:
    executor_type: str
    payload_format: str
    operation: str
    workflow_digest: str
    data: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not all((self.executor_type, self.payload_format, self.operation, self.workflow_digest)):
            raise ValueError("executor payload metadata is required")
        if not isinstance(self.data, bytes):
            raise TypeError("executor payload data must be bytes")


@dataclass(frozen=True)
class ArtifactInput:
    name: str
    artifact: ArtifactDescriptor
    download: TransferTicket

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("artifact input name is required")


@dataclass(frozen=True)
class ArtifactOutputTarget:
    name: str
    artifact: ArtifactDescriptor
    upload: TransferTicket
    kind: str = "output"
    store_type: str = "local"
    object_ref: str | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("artifact output target name is required")
        if not self.kind or not self.store_type:
            raise ValueError("artifact output commit metadata is required")


@dataclass(frozen=True)
class LeaseCryptoContext:
    """Decrypted task key plus the public context to which it is bound."""

    workspace_id: str
    content_attempt_id: str
    key_version: int
    task_data_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not self.workspace_id:
            raise ValueError("workspace_id is required for an encrypted lease")
        if not self.content_attempt_id:
            raise ValueError("content_attempt_id is required for an encrypted lease")
        if self.key_version < 1:
            raise ValueError("key_version must be positive")
        if not isinstance(self.task_data_key, bytes) or len(self.task_data_key) != 32:
            raise ValueError("task_data_key must contain 32 bytes")


@dataclass(frozen=True)
class ExecutionLease:
    reference: LeaseReference
    payload: ExecutorPayload
    inputs: tuple[ArtifactInput, ...] = ()
    outputs: tuple[ArtifactOutputTarget, ...] = ()
    crypto: LeaseCryptoContext | None = field(default=None, repr=False)
    expires_at: float | None = None
    timeout_seconds: float = 3600.0

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not self.outputs:
            raise ValueError("a lease must authorize at least one output artifact")
        input_names = [item.name for item in self.inputs]
        output_names = [item.name for item in self.outputs]
        if len(input_names) != len(set(input_names)):
            raise ValueError("artifact input names must be unique")
        if len(output_names) != len(set(output_names)):
            raise ValueError("artifact output names must be unique")
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "outputs", tuple(self.outputs))


@dataclass(frozen=True)
class HeartbeatDirective:
    cancelled: bool = False
    lease_expires_at: float | None = None


@dataclass(frozen=True)
class WorkerResultArtifact:
    artifact_id: str
    name: str
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    kind: str = "output"
    store_type: str = "local"
    object_ref: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class WorkerResult:
    artifacts: tuple[WorkerResultArtifact, ...]
    usage: UsageMetrics
    executor_type: str
    executor_version: str
    executor_run_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.artifacts:
            raise ValueError("worker result must contain at least one artifact")
        object.__setattr__(self, "artifacts", tuple(self.artifacts))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))


@dataclass(frozen=True)
class WorkerFailureReport:
    code: int
    name: str
    message: str
    retry_action: RetryAction
    responsibility: str
    occurred_after_start: bool
    details: Mapping[str, Any] = field(default_factory=dict)
    usage: UsageMetrics = field(default_factory=UsageMetrics)

    def __post_init__(self) -> None:
        if self.code < 100000 or self.code > 999999:
            raise ValueError("worker failure code must be six digits")
        object.__setattr__(self, "details", MappingProxyType(sanitize_details(self.details)))


@dataclass(frozen=True)
class WorkerOutcome:
    result: WorkerResult | None = None
    failure: WorkerFailureReport | None = None

    def __post_init__(self) -> None:
        if (self.result is None) == (self.failure is None):
            raise ValueError("worker outcome must contain exactly one result or failure")

    @property
    def succeeded(self) -> bool:
        return self.result is not None
