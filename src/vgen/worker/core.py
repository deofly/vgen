"""Generic Worker execution lifecycle.

This module owns lease/fencing propagation, artifact transfer, cancellation,
executor selection, result normalization, and safe failure reporting.  It has no
ComfyUI or cloud-provider fields.
"""

from __future__ import annotations

import logging
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from vgen.artifacts import (
    ArtifactAdapterRegistry,
    ArtifactTransferError,
    with_safe_media_extension,
)
from vgen.artifacts.base import TransferTicket, file_digest
from vgen.crypto import decrypt_stream, encrypt_stream, task_aad
from vgen.executors import (
    ExecutionContext,
    ExecutionInput,
    ExecutionRequest,
    ExecutorFailure,
    ExecutorRegistry,
    ProgressEvent,
    RetryAction,
    UsageMetrics,
)
from vgen.protocol import ErrorCode, VGenError, get_error_spec
from vgen.protocol.media import canonical_media_probes

from .models import (
    ExecutionLease,
    HeartbeatDirective,
    LeaseReference,
    WorkerFailureReport,
    WorkerOutcome,
    WorkerResult,
    WorkerResultArtifact,
)
from .spool import UploadJournal, UploadJournalError

logger = logging.getLogger("vgen.worker.core")


class LeaseLostError(Exception):
    """Raised by a Gateway adapter after TTL expiry or fencing rejection."""

    code = ErrorCode.LEASE_LOST
    name = "LEASE_LOST"


class GatewayUnavailableError(Exception):
    """A transient control-plane error; the caller must retry the same mutation."""

    code = ErrorCode.GATEWAY_UNREACHABLE
    name = "GATEWAY_UNREACHABLE"


class GatewayRequestError(VGenError):
    """A typed Gateway rejection which must not become an Executor failure."""


class UploadPendingError(Exception):
    """Encrypted outputs are durable and must be uploaded without re-execution."""

    code = ErrorCode.OUTPUT_UPLOAD_FAILED
    name = "OUTPUT_UPLOAD_FAILED"

    def __init__(self, attempt_id: str) -> None:
        self.attempt_id = attempt_id
        super().__init__("Encrypted outputs are waiting for upload retry.")


@runtime_checkable
class WorkerGateway(Protocol):
    def heartbeat(
        self, reference: LeaseReference, progress: ProgressEvent
    ) -> HeartbeatDirective: ...

    def mark_started(self, reference: LeaseReference) -> HeartbeatDirective: ...

    def complete(self, reference: LeaseReference, result: WorkerResult) -> None: ...

    def fail(self, reference: LeaseReference, failure: WorkerFailureReport) -> None: ...


@runtime_checkable
class UploadRenewingGateway(Protocol):
    def renew_output_tickets(
        self,
        reference: LeaseReference,
        artifact_ids: frozenset[str],
    ) -> Mapping[str, TransferTicket]: ...

    def heartbeat(
        self, reference: LeaseReference, progress: ProgressEvent
    ) -> HeartbeatDirective: ...

    def complete(self, reference: LeaseReference, result: WorkerResult) -> None: ...

    def fail(self, reference: LeaseReference, failure: WorkerFailureReport) -> None: ...


class WorkerCore:
    def __init__(
        self,
        executors: ExecutorRegistry,
        artifacts: ArtifactAdapterRegistry,
        *,
        work_root: Path | None = None,
        heartbeat_interval_seconds: float = 15.0,
    ) -> None:
        descriptors = executors.descriptors()
        if len(descriptors) != 1:
            raise ValueError("v1 requires exactly one executor per Worker identity")
        self._executors = executors
        self._artifacts = artifacts
        if heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        self._heartbeat_interval_seconds = heartbeat_interval_seconds
        self._work_root = work_root.expanduser().resolve() if work_root else None
        self._upload_journal = (
            UploadJournal(self._work_root / "upload-spool") if self._work_root else None
        )
        if self._work_root:
            self._work_root.mkdir(parents=True, exist_ok=True)

    def capabilities(self) -> Mapping[str, Any]:
        """Advertise a list shape now so future multi-executor workers are wire-compatible."""

        entries: list[dict[str, Any]] = []
        for executor in self._executors:
            descriptor = executor.descriptor()
            entries.append(
                {
                    "type": descriptor.executor_type,
                    "version": descriptor.version,
                    "payload_formats": list(descriptor.payload_formats),
                    "operations": list(descriptor.operations),
                    "max_concurrency": descriptor.max_concurrency,
                    "capabilities": dict(executor.capabilities()),
                }
            )
        return {"executors": entries}

    def resume_pending(self, gateway: UploadRenewingGateway) -> WorkerOutcome | None:
        """Upload the oldest durable ciphertext result without invoking an Executor."""

        if self._upload_journal is None:
            return None
        if not isinstance(gateway, UploadRenewingGateway):
            raise TypeError("gateway does not support output ticket renewal")
        pending = self._upload_journal.oldest_pending()
        if pending is None:
            return None
        heartbeat_lock = threading.Lock()
        heartbeat_stop = threading.Event()
        heartbeat_error: list[Exception] = []
        last_progress = ProgressEvent(0.90, "resuming_output_upload")

        def report(event: ProgressEvent) -> None:
            nonlocal last_progress
            with heartbeat_lock:
                if heartbeat_error:
                    raise heartbeat_error[0]
                gateway.heartbeat(pending.reference, event)
                last_progress = event

        def keep_lease_alive() -> None:
            while not heartbeat_stop.wait(self._heartbeat_interval_seconds):
                try:
                    with heartbeat_lock:
                        gateway.heartbeat(pending.reference, last_progress)
                except Exception as exc:
                    heartbeat_error.append(exc)
                    heartbeat_stop.set()
                    return

        heartbeat_thread: threading.Thread | None = None

        def stop_heartbeat() -> None:
            heartbeat_stop.set()
            if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
                heartbeat_thread.join()

        try:
            # Renew before any adapter performs its potentially long digest
            # pass, then keep the fenced attempt alive through hashing, upload,
            # and receipt verification.  Every call shares the heartbeat lock
            # because authenticated Gateway clients may own non-thread-safe
            # sessions and token-refresh state.
            report(last_progress)
            heartbeat_thread = threading.Thread(
                target=keep_lease_alive,
                name=f"vgen-resume-heartbeat-{pending.reference.attempt_id}",
                daemon=True,
            )
            heartbeat_thread.start()
            with heartbeat_lock:
                if heartbeat_error:
                    raise heartbeat_error[0]
                tickets = (
                    gateway.renew_output_tickets(
                        pending.reference,
                        pending.pending_artifact_ids,
                    )
                    if pending.pending_artifact_ids
                    else {}
                )
            renewed_ids = set(tickets)
            if not renewed_ids.issubset(pending.pending_artifact_ids):
                raise ArtifactTransferError(
                    "renew",
                    "The Gateway returned an unexpected output ticket.",
                    retryable=False,
                )
            if renewed_ids != set(pending.pending_artifact_ids):
                raise ArtifactTransferError(
                    "renew",
                    "The Gateway did not renew every pending output ticket.",
                    retryable=True,
                )
            artifacts = {artifact.artifact_id: artifact for artifact in pending.result.artifacts}
            total = max(len(pending.pending_artifact_ids), 1)
            for index, artifact_id in enumerate(sorted(pending.pending_artifact_ids)):
                artifact = artifacts[artifact_id]
                receipt = self._artifacts.upload(
                    tickets[artifact_id],
                    pending.files[artifact_id],
                    on_progress=lambda consumed, size, current=index: report(
                        ProgressEvent(
                            0.90 + _transfer_fraction(current, total, consumed, size, 0.10),
                            "resuming_output_upload",
                        )
                    ),
                )
                if receipt.size_bytes != artifact.size_bytes or receipt.sha256 != artifact.sha256:
                    try:
                        self._upload_journal.quarantine(pending.reference.attempt_id)
                    except UploadJournalError:
                        logger.exception("Could not quarantine a corrupt output spool attempt.")
                    failure = WorkerFailureReport(
                        code=ErrorCode.ARTIFACT_INTEGRITY_FAILED,
                        name="ARTIFACT_INTEGRITY_FAILED",
                        message="A durable output failed integrity verification.",
                        retry_action=RetryAction.NONE,
                        responsibility="platform",
                        occurred_after_start=True,
                        usage=pending.result.usage,
                    )
                    stop_heartbeat()
                    return _report_failure(gateway, pending.reference, failure)
                self._upload_journal.mark_uploaded(pending.reference.attempt_id, artifact_id)
            # The terminal mutation is serialized after the keeper exits.  A
            # heartbeat sent after completion could race a reused fencing token
            # or a client-side credential refresh.
            stop_heartbeat()
            with heartbeat_lock:
                if heartbeat_error:
                    raise heartbeat_error[0]
                gateway.complete(pending.reference, pending.result)
            self._discard_pending_attempt(pending.reference.attempt_id)
            return WorkerOutcome(result=pending.result)
        except ArtifactTransferError as exc:
            if exc.retryable:
                raise UploadPendingError(pending.reference.attempt_id) from exc
            self._discard_pending_attempt(pending.reference.attempt_id)
            failure = WorkerFailureReport(
                code=ErrorCode.OUTPUT_UPLOAD_FAILED,
                name="OUTPUT_UPLOAD_FAILED",
                message="A durable output cannot be uploaded with the renewed capability.",
                retry_action=RetryAction.NONE,
                responsibility="platform",
                occurred_after_start=True,
                usage=pending.result.usage,
            )
            stop_heartbeat()
            return _report_failure(gateway, pending.reference, failure)
        except LeaseLostError:
            self._discard_pending_attempt(pending.reference.attempt_id)
            return WorkerOutcome(
                failure=WorkerFailureReport(
                    code=ErrorCode.LEASE_LOST,
                    name="LEASE_LOST",
                    message="The worker lease is no longer valid.",
                    retry_action=RetryAction.NONE,
                    responsibility="platform",
                    occurred_after_start=True,
                )
            )
        except GatewayRequestError:
            # A deterministic Gateway rejection cannot become an infinite
            # lease-renewing spool loop. The server transaction is atomic; let
            # its normal lease recovery decide whether the task is retried.
            self._discard_pending_attempt(pending.reference.attempt_id)
            raise
        finally:
            stop_heartbeat()

    def _discard_pending_attempt(self, attempt_id: str) -> None:
        if self._upload_journal is None:
            return
        try:
            self._upload_journal.remove(attempt_id)
        except UploadJournalError:
            try:
                self._upload_journal.quarantine(attempt_id)
            except UploadJournalError:
                logger.exception("Could not discard one terminal output spool attempt.")

    def process(self, lease: ExecutionLease, gateway: WorkerGateway) -> WorkerOutcome:
        """Process one already-decrypted lease and report exactly one terminal event."""

        if not isinstance(gateway, WorkerGateway):
            raise TypeError("gateway does not implement WorkerGateway")
        started = False
        phase = "preparing"
        journaled = False
        execution_started_monotonic: float | None = None
        input_bytes = 0
        heartbeat_stop: threading.Event | None = None
        heartbeat_thread: threading.Thread | None = None

        def stop_heartbeat_keeper() -> None:
            if heartbeat_stop is not None:
                heartbeat_stop.set()
            if heartbeat_thread is not None and heartbeat_thread is not threading.current_thread():
                heartbeat_thread.join()

        try:
            if lease.expires_at is not None and time.time() >= lease.expires_at:
                raise ExecutorFailure(
                    ErrorCode.RESERVATION_EXPIRED,
                    "RESERVATION_EXPIRED",
                    "The worker reservation expired before execution started.",
                    retry_action=RetryAction.ANOTHER_WORKER,
                    responsibility="platform",
                )
            executor = self._executors.get(lease.payload.executor_type)
            descriptor = executor.descriptor()
            if lease.payload.payload_format not in descriptor.payload_formats:
                raise ExecutorFailure(
                    ErrorCode.UNSUPPORTED_PAYLOAD,
                    "UNSUPPORTED_PAYLOAD",
                    "The selected executor does not support this payload format.",
                    retry_action=RetryAction.ANOTHER_WORKER,
                    details={"payload_format": lease.payload.payload_format},
                )
            if lease.payload.operation not in descriptor.operations:
                raise ExecutorFailure(
                    ErrorCode.UNSUPPORTED_PAYLOAD,
                    "UNSUPPORTED_PAYLOAD",
                    "The selected executor does not support this operation.",
                    retry_action=RetryAction.ANOTHER_WORKER,
                    details={"operation": lease.payload.operation},
                )

            cancelled = False
            heartbeat_lock = threading.Lock()
            last_progress = ProgressEvent(0.0, "preparing")
            heartbeat_error: list[Exception] = []

            def report(event: ProgressEvent) -> None:
                nonlocal cancelled, last_progress
                with heartbeat_lock:
                    if heartbeat_error:
                        raise heartbeat_error[0]
                    directive = gateway.heartbeat(lease.reference, event)
                    last_progress = event
                    cancelled = cancelled or directive.cancelled

            report(ProgressEvent(0.0, "preparing"))
            heartbeat_stop = threading.Event()
            heartbeat_interval = self._heartbeat_interval_seconds
            if lease.expires_at is not None:
                heartbeat_interval = min(
                    heartbeat_interval,
                    max(0.25, (lease.expires_at - time.time()) / 3),
                )

            def keep_lease_alive() -> None:
                nonlocal cancelled
                while not heartbeat_stop.wait(heartbeat_interval):
                    try:
                        with heartbeat_lock:
                            directive = gateway.heartbeat(
                                lease.reference,
                                last_progress,
                            )
                            cancelled = cancelled or directive.cancelled
                    except Exception as exc:
                        heartbeat_error.append(exc)
                        cancelled = True
                        heartbeat_stop.set()
                        return

            heartbeat_thread = threading.Thread(
                target=keep_lease_alive,
                name=f"vgen-heartbeat-{lease.reference.attempt_id}",
                daemon=True,
            )
            heartbeat_thread.start()
            with tempfile.TemporaryDirectory(
                prefix=f"vgen-{lease.reference.attempt_id}-",
                dir=str(self._work_root) if self._work_root else None,
            ) as temp_name:
                work_dir = Path(temp_name)
                input_dir = work_dir / "inputs"
                input_dir.mkdir()
                execution_inputs: list[ExecutionInput] = []
                for index, item in enumerate(lease.inputs):
                    destination = input_dir / f"{index:02d}-{item.artifact.filename}"
                    transfer_destination = (
                        destination
                        if lease.crypto is None
                        else input_dir / f".{index:02d}-{item.artifact.filename}.encrypted"
                    )
                    receipt = self._artifacts.download(
                        item.download,
                        transfer_destination,
                        on_progress=lambda consumed, total, current=index: report(
                            ProgressEvent(
                                _transfer_fraction(
                                    current, len(lease.inputs), consumed, total, 0.10
                                ),
                                "downloading_inputs",
                            )
                        ),
                    )
                    input_bytes += receipt.size_bytes
                    if lease.crypto is not None:
                        try:
                            with (
                                transfer_destination.open("rb") as encrypted_stream,
                                destination.open("wb") as plaintext_stream,
                            ):
                                decrypt_stream(
                                    encrypted_stream,
                                    plaintext_stream,
                                    lease.crypto.task_data_key,
                                    aad=_input_artifact_aad(lease, item.artifact.artifact_id),
                                )
                        finally:
                            transfer_destination.unlink(missing_ok=True)
                    execution_inputs.append(ExecutionInput(item.name, destination, item.artifact))
                if cancelled:
                    raise ExecutorFailure(
                        ErrorCode.EXECUTION_CANCELLED,
                        "EXECUTION_CANCELLED",
                        "Execution was cancelled before it started.",
                        responsibility="consumer",
                    )

                with heartbeat_lock:
                    if heartbeat_error:
                        raise heartbeat_error[0]
                    start_directive = gateway.mark_started(lease.reference)
                    cancelled = cancelled or start_directive.cancelled
                if cancelled:
                    raise ExecutorFailure(
                        ErrorCode.EXECUTION_CANCELLED,
                        "EXECUTION_CANCELLED",
                        "Execution was cancelled at the start boundary.",
                        responsibility="consumer",
                    )
                started = True
                phase = "executing"
                wall_started = time.monotonic()
                execution_started_monotonic = wall_started
                result = executor.execute(
                    ExecutionRequest(
                        task_id=lease.reference.task_id,
                        attempt_id=lease.reference.attempt_id,
                        workflow_digest=lease.payload.workflow_digest,
                        operation=lease.payload.operation,
                        payload_format=lease.payload.payload_format,
                        payload=lease.payload.data,
                        inputs=tuple(execution_inputs),
                        timeout_seconds=lease.timeout_seconds,
                    ),
                    ExecutionContext(
                        work_dir=work_dir,
                        on_progress=lambda event: report(
                            ProgressEvent(
                                0.10 + event.fraction * 0.80,
                                event.stage,
                                event.message,
                            )
                        ),
                        is_cancelled=lambda: cancelled,
                    ),
                )
                with heartbeat_lock:
                    if heartbeat_error:
                        raise heartbeat_error[0]
                measured_wall_ms = max(1, round((time.monotonic() - wall_started) * 1000))

                phase = "uploading"
                targets = {target.name: target for target in lease.outputs}
                normalized_artifacts: list[WorkerResultArtifact] = []
                staged_files: dict[str, Path] = {}
                output_bytes = 0
                for index, artifact in enumerate(result.artifacts):
                    target = targets.get(artifact.name)
                    if target is None:
                        raise ArtifactTransferError(
                            "upload",
                            "The lease has no upload ticket for an executor output.",
                            retryable=False,
                        )
                    upload_source = artifact.path
                    if lease.crypto is not None:
                        upload_source = (
                            self._upload_journal.output_path(
                                lease.reference,
                                target.artifact.artifact_id,
                            )
                            if self._upload_journal is not None
                            else work_dir / f"encrypted-output-{index:02d}.vgen"
                        )
                        with (
                            artifact.path.open("rb") as plaintext_stream,
                            upload_source.open("wb") as encrypted_stream,
                        ):
                            encrypt_stream(
                                plaintext_stream,
                                encrypted_stream,
                                lease.crypto.task_data_key,
                                aad=_output_artifact_aad(lease, target.artifact.artifact_id),
                            )
                    size_bytes, digest = file_digest(upload_source)
                    output_bytes += size_bytes
                    staged_files[target.artifact.artifact_id] = upload_source
                    normalized_artifacts.append(
                        WorkerResultArtifact(
                            artifact_id=target.artifact.artifact_id,
                            name=artifact.name,
                            filename=with_safe_media_extension(
                                target.artifact.filename,
                                artifact.media_type,
                            ),
                            media_type=artifact.media_type,
                            size_bytes=size_bytes,
                            sha256=digest,
                            kind=target.kind,
                            store_type=target.store_type,
                            object_ref=target.object_ref,
                            metadata=_public_metadata(artifact.metadata),
                        )
                    )

                usage = replace(
                    result.usage,
                    executor_wall_ms=result.usage.executor_wall_ms or measured_wall_ms,
                    input_bytes=input_bytes,
                    output_bytes=output_bytes,
                )
                if cancelled:
                    failure = WorkerFailureReport(
                        code=ErrorCode.EXECUTION_CANCELLED,
                        name="EXECUTION_CANCELLED",
                        message="Execution was cancelled after it started.",
                        retry_action=RetryAction.NONE,
                        responsibility="consumer",
                        occurred_after_start=True,
                        usage=usage,
                    )
                    stop_heartbeat_keeper()
                    return _report_failure(gateway, lease.reference, failure)
                normalized = WorkerResult(
                    artifacts=tuple(normalized_artifacts),
                    usage=usage,
                    executor_type=descriptor.executor_type,
                    executor_version=descriptor.version,
                    executor_run_id=result.executor_run_id,
                    metadata=_public_metadata(result.metadata),
                )
                if self._upload_journal is not None and lease.crypto is not None:
                    self._upload_journal.save(
                        lease.reference,
                        normalized,
                        staged_files,
                    )
                    journaled = True
                targets_by_artifact = {
                    target.artifact.artifact_id: target for target in lease.outputs
                }
                for index, artifact in enumerate(normalized.artifacts):
                    target = targets_by_artifact[artifact.artifact_id]
                    receipt = self._artifacts.upload(
                        target.upload,
                        staged_files[artifact.artifact_id],
                        on_progress=lambda consumed, total, current=index: report(
                            ProgressEvent(
                                0.90
                                + _transfer_fraction(
                                    current, len(normalized.artifacts), consumed, total, 0.10
                                ),
                                "uploading_outputs",
                            )
                        ),
                    )
                    if (
                        receipt.size_bytes != artifact.size_bytes
                        or receipt.sha256 != artifact.sha256
                    ):
                        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
                    if journaled and self._upload_journal is not None:
                        self._upload_journal.mark_uploaded(
                            lease.reference.attempt_id,
                            artifact.artifact_id,
                        )
                with heartbeat_lock:
                    if heartbeat_error:
                        raise heartbeat_error[0]
                    cancelled_after_upload = cancelled
                if cancelled_after_upload:
                    if journaled and self._upload_journal is not None:
                        self._discard_pending_attempt(lease.reference.attempt_id)
                        journaled = False
                    failure = WorkerFailureReport(
                        code=ErrorCode.EXECUTION_CANCELLED,
                        name="EXECUTION_CANCELLED",
                        message="Execution was cancelled after it started.",
                        retry_action=RetryAction.NONE,
                        responsibility="consumer",
                        occurred_after_start=True,
                        usage=usage,
                    )
                    stop_heartbeat_keeper()
                    return _report_failure(gateway, lease.reference, failure)
                stop_heartbeat_keeper()
                gateway.complete(lease.reference, normalized)
                if journaled and self._upload_journal is not None:
                    self._discard_pending_attempt(lease.reference.attempt_id)
                return WorkerOutcome(result=normalized)
        except GatewayUnavailableError:
            # The daemon journal must retry the exact heartbeat/terminal call;
            # translating it to task failure would risk duplicate execution.
            raise
        except GatewayRequestError:
            if journaled and self._upload_journal is not None:
                self._discard_pending_attempt(lease.reference.attempt_id)
            raise
        except LeaseLostError:
            if journaled and self._upload_journal is not None:
                self._discard_pending_attempt(lease.reference.attempt_id)
            failure = WorkerFailureReport(
                code=ErrorCode.LEASE_LOST,
                name="LEASE_LOST",
                message="The worker lease is no longer valid.",
                retry_action=RetryAction.NONE,
                responsibility="platform",
                occurred_after_start=started,
            )
            # A fenced attempt must not send another terminal mutation.
            return WorkerOutcome(failure=failure)
        except ArtifactTransferError as exc:
            is_upload = phase == "uploading"
            if is_upload and journaled and exc.retryable:
                raise UploadPendingError(lease.reference.attempt_id) from exc
            if is_upload and journaled:
                self._discard_pending_attempt(lease.reference.attempt_id)
                journaled = False
            failure = WorkerFailureReport(
                code=(
                    ErrorCode.OUTPUT_UPLOAD_FAILED if is_upload else ErrorCode.INPUT_DOWNLOAD_FAILED
                ),
                name="OUTPUT_UPLOAD_FAILED" if is_upload else "INPUT_DOWNLOAD_FAILED",
                message=(
                    "An output artifact could not be uploaded."
                    if is_upload
                    else "An input artifact could not be downloaded."
                ),
                retry_action=(RetryAction.RESUME_UPLOAD if is_upload else RetryAction.SAME_WORKER),
                responsibility="platform",
                occurred_after_start=started,
                details={
                    "operation": exc.operation,
                    "status_code": exc.status_code,
                    "retryable": exc.retryable,
                },
            )
            stop_heartbeat_keeper()
            return _report_failure(gateway, lease.reference, failure)
        except VGenError as exc:
            spec = get_error_spec(exc.code)
            if journaled and exc.code == ErrorCode.ARTIFACT_INTEGRITY_FAILED:
                self._discard_pending_attempt(lease.reference.attempt_id)
                journaled = False
            failure = WorkerFailureReport(
                code=exc.code,
                name=exc.code.name,
                message=spec.message,
                retry_action=RetryAction(spec.retry_action.value),
                responsibility=(
                    "platform"
                    if spec.responsibility.value == "unknown"
                    else spec.responsibility.value
                ),
                occurred_after_start=started,
                details=exc.details,
            )
            stop_heartbeat_keeper()
            return _report_failure(gateway, lease.reference, failure)
        except ExecutorFailure as exc:
            usage = UsageMetrics()
            if started and execution_started_monotonic is not None:
                usage = UsageMetrics(
                    executor_wall_ms=max(
                        1, round((time.monotonic() - execution_started_monotonic) * 1000)
                    ),
                    input_bytes=input_bytes,
                )
            failure = WorkerFailureReport(
                code=exc.code,
                name=exc.name,
                message=exc.message,
                retry_action=exc.retry_action,
                responsibility=exc.responsibility,
                occurred_after_start=started,
                details=exc.details,
                usage=usage,
            )
            stop_heartbeat_keeper()
            return _report_failure(gateway, lease.reference, failure)
        except Exception as exc:  # Never expose exception text or payload/ticket secrets.
            failure = WorkerFailureReport(
                code=ErrorCode.INTERNAL_ERROR,
                name="INTERNAL_ERROR",
                message="The worker encountered an unexpected internal error.",
                retry_action=RetryAction.SAME_WORKER,
                responsibility="provider",
                occurred_after_start=started,
                details={"error_type": type(exc).__name__, "phase": phase},
            )
            stop_heartbeat_keeper()
            return _report_failure(gateway, lease.reference, failure)
        finally:
            # Keep the fenced lease alive from input preflight through output
            # encryption/upload, then serialize the terminal mutation after the
            # keeper has stopped.
            stop_heartbeat_keeper()


def _transfer_fraction(
    item_index: int,
    item_count: int,
    consumed: int,
    total: int | None,
    weight: float,
) -> float:
    if item_count <= 0:
        return weight
    current = min(consumed / total, 1.0) if total else 0.0
    return min(((item_index + current) / item_count) * weight, weight)


def _input_artifact_aad(lease: ExecutionLease, artifact_id: str) -> bytes:
    if lease.crypto is None:
        raise ValueError("artifact AAD requires an encrypted lease")
    return task_aad(
        workspace_id=lease.crypto.workspace_id,
        task_id=lease.reference.task_id,
        attempt_id=lease.crypto.content_attempt_id,
        artifact_id=artifact_id,
        key_version=lease.crypto.key_version,
    )


def _output_artifact_aad(lease: ExecutionLease, artifact_id: str) -> bytes:
    if lease.crypto is None:
        raise ValueError("artifact AAD requires an encrypted lease")
    return task_aad(
        workspace_id=lease.crypto.workspace_id,
        task_id=lease.reference.task_id,
        attempt_id=lease.reference.attempt_id,
        artifact_id=artifact_id,
        key_version=lease.crypto.key_version,
    )


def _report_failure(
    gateway: WorkerGateway,
    reference: LeaseReference,
    failure: WorkerFailureReport,
) -> WorkerOutcome:
    try:
        gateway.fail(reference, failure)
        return WorkerOutcome(failure=failure)
    except LeaseLostError:
        return WorkerOutcome(
            failure=WorkerFailureReport(
                code=ErrorCode.LEASE_LOST,
                name="LEASE_LOST",
                message="The worker lease is no longer valid.",
                retry_action=RetryAction.NONE,
                responsibility="platform",
                occurred_after_start=failure.occurred_after_start,
            )
        )


def _public_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    """Prevent executor-private payload data from entering Gateway metadata."""

    return canonical_media_probes(metadata)
