from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

import vgen.worker.core as worker_core_module
from vgen.artifacts import (
    ArtifactAdapterRegistry,
    ArtifactDescriptor,
    ArtifactTransferError,
    LocalArtifactAdapter,
    TransferTicket,
)
from vgen.executors import (
    ExecutionArtifact,
    ExecutionContext,
    ExecutionRequest,
    ExecutionResult,
    ExecutorDescriptor,
    ExecutorHealth,
    ExecutorRegistry,
    ProgressEvent,
    UsageMetrics,
)
from vgen.protocol import ErrorCode
from vgen.worker import (
    ArtifactInput,
    ArtifactOutputTarget,
    ExecutionLease,
    ExecutorPayload,
    GatewayUnavailableError,
    HeartbeatDirective,
    LeaseCryptoContext,
    LeaseReference,
    UploadPendingError,
    WorkerCore,
    WorkerFailureReport,
    WorkerResult,
    WorkerResultArtifact,
)
from vgen.worker.spool import UploadJournal


class FakeExecutor:
    def __init__(self) -> None:
        self.executed = False

    def descriptor(self) -> ExecutorDescriptor:
        return ExecutorDescriptor("fake", "1.2.3", ("fake/v1",), ("t2v",))

    def health(self) -> ExecutorHealth:
        return ExecutorHealth(True, "ready")

    def capabilities(self) -> Mapping[str, Any]:
        return {"model_digests": ["a" * 64]}

    def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
        self.executed = True
        assert request.inputs[0].path.read_bytes() == b"input"
        context.progress(0.5, "sampling")
        output = context.work_dir / "result.bin"
        output.write_bytes(request.payload + request.inputs[0].path.read_bytes())
        context.progress(1.0, "sampled")
        return ExecutionResult(
            (ExecutionArtifact("primary", output, "application/octet-stream"),),
            usage=UsageMetrics(gpu_active_ms=25, denoise_steps=8),
            executor_run_id="run_1",
        )

    def cancel(self, handle: str | None = None) -> None:
        return None


class FakeGateway:
    def __init__(self, *, cancel_on_first_heartbeat: bool = False) -> None:
        self.events: list[tuple[str, Any]] = []
        self.cancel_on_first_heartbeat = cancel_on_first_heartbeat

    def heartbeat(self, reference: LeaseReference, progress: ProgressEvent) -> HeartbeatDirective:
        self.events.append(("heartbeat", (reference, progress)))
        cancelled = self.cancel_on_first_heartbeat and len(self.events) == 1
        return HeartbeatDirective(cancelled=cancelled)

    def mark_started(self, reference: LeaseReference) -> HeartbeatDirective:
        self.events.append(("started", reference))
        return HeartbeatDirective()

    def complete(self, reference: LeaseReference, result: WorkerResult) -> None:
        self.events.append(("complete", (reference, result)))

    def fail(self, reference: LeaseReference, failure: WorkerFailureReport) -> None:
        self.events.append(("failed", (reference, failure)))


def make_lease(
    tmp_path: Path,
    *,
    output_name: str = "primary",
    output_filename: str = "published.bin",
) -> ExecutionLease:
    source = tmp_path / "source.bin"
    source.write_bytes(b"input")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    destination = tmp_path / "published.bin"
    return ExecutionLease(
        reference=LeaseReference("lea_1", "tsk_1", "att_1", "wrk_1", 7),
        payload=ExecutorPayload("fake", "fake/v1", "t2v", "a" * 64, b"payload:"),
        inputs=(
            ArtifactInput(
                "first_frame",
                ArtifactDescriptor("art_input", "source.bin", size_bytes=5, sha256=digest),
                TransferTicket(source.as_uri(), "GET", expected_size=5, expected_sha256=digest),
            ),
        ),
        outputs=(
            ArtifactOutputTarget(
                output_name,
                ArtifactDescriptor("art_output", output_filename),
                TransferTicket(destination.as_uri(), "PUT"),
            ),
        ),
    )


def make_encrypted_output_lease(tmp_path: Path, *, attempt_id: str) -> tuple[ExecutionLease, Path]:
    destination = tmp_path / f"{attempt_id}.vgen"
    return (
        ExecutionLease(
            reference=LeaseReference(
                f"lea_{attempt_id}",
                f"tsk_{attempt_id}",
                attempt_id,
                "wrk_1",
                9,
            ),
            payload=ExecutorPayload("fake", "fake/v1", "t2v", "a" * 64, b"payload"),
            outputs=(
                ArtifactOutputTarget(
                    "primary",
                    ArtifactDescriptor("art_output", "published.vgen"),
                    TransferTicket(destination.as_uri(), "PUT"),
                ),
            ),
            crypto=LeaseCryptoContext("wsp_output", attempt_id, 1, b"k" * 32),
        ),
        destination,
    )


def test_worker_core_runs_executor_and_preserves_fencing_token(tmp_path: Path) -> None:
    executor = FakeExecutor()
    core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        work_root=tmp_path / "work",
    )
    gateway = FakeGateway()
    outcome = core.process(make_lease(tmp_path), gateway)

    assert outcome.succeeded
    assert (tmp_path / "published.bin").read_bytes() == b"payload:input"
    result = outcome.result
    assert result is not None
    assert result.executor_type == "fake"
    assert result.usage.input_bytes == 5
    assert result.usage.output_bytes == 13
    assert result.usage.gpu_active_ms == 25
    assert result.usage.denoise_steps == 8
    assert [name for name, _ in gateway.events if name in {"started", "complete"}] == [
        "started",
        "complete",
    ]
    references = []
    for name, value in gateway.events:
        references.append(value[0] if name in {"heartbeat", "complete", "failed"} else value)
    assert all(reference.fencing_token == 7 for reference in references)
    fractions = [value[1].fraction for name, value in gateway.events if name == "heartbeat"]
    assert fractions == sorted(fractions)
    assert core.capabilities()["executors"][0]["type"] == "fake"


def test_input_preparation_renews_lease_before_adapter_reports_progress(
    tmp_path: Path,
) -> None:
    background_heartbeat = threading.Event()

    class SlowLocalAdapter(LocalArtifactAdapter):
        def download(self, ticket: Any, destination: Path, on_progress: Any = None) -> Any:
            assert background_heartbeat.wait(timeout=1), "input lease was not renewed"
            return super().download(ticket, destination, on_progress)

    class RenewingGateway(FakeGateway):
        def heartbeat(
            self, reference: LeaseReference, progress: ProgressEvent
        ) -> HeartbeatDirective:
            directive = super().heartbeat(reference, progress)
            if sum(name == "heartbeat" for name, _value in self.events) >= 2:
                background_heartbeat.set()
            return directive

    core = WorkerCore(
        ExecutorRegistry(FakeExecutor()),
        ArtifactAdapterRegistry(SlowLocalAdapter((tmp_path,))),
        work_root=tmp_path / "work",
        heartbeat_interval_seconds=0.01,
    )
    outcome = core.process(make_lease(tmp_path), RenewingGateway())

    assert outcome.succeeded


def test_worker_reports_allowlisted_extension_without_exposing_executor_filename(
    tmp_path: Path,
) -> None:
    class PrivateVideoExecutor(FakeExecutor):
        def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
            self.executed = True
            assert request.inputs[0].path.read_bytes() == b"input"
            output = context.work_dir / "private-comfy-workflow-prefix-00001.mp4"
            output.write_bytes(b"private-video")
            return ExecutionResult(
                (
                    ExecutionArtifact(
                        "primary",
                        output,
                        "video/mp4",
                        metadata={
                            "frames": 81,
                            "duration_ms": 1.5,
                            "width": True,
                            "height": float("nan"),
                            "denoise_steps": 100_001,
                        },
                    ),
                ),
                usage=UsageMetrics(gpu_active_ms=25),
            )

    core = WorkerCore(
        ExecutorRegistry(PrivateVideoExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        work_root=tmp_path / "work",
    )
    gateway = FakeGateway()
    outcome = core.process(
        make_lease(tmp_path, output_filename="output-00.bin"),
        gateway,
    )

    assert outcome.succeeded
    assert outcome.result is not None
    artifact = outcome.result.artifacts[0]
    assert artifact.filename == "output-00.mp4"
    assert artifact.media_type == "video/mp4"
    assert artifact.metadata == {"frames": 81}
    assert "private-comfy-workflow-prefix" not in repr(outcome.result)


def test_worker_core_cancellation_before_start_is_not_billable(tmp_path: Path) -> None:
    executor = FakeExecutor()
    core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
    )
    gateway = FakeGateway(cancel_on_first_heartbeat=True)
    outcome = core.process(make_lease(tmp_path), gateway)
    assert not outcome.succeeded
    assert outcome.failure is not None
    assert outcome.failure.code == ErrorCode.EXECUTION_CANCELLED
    assert outcome.failure.occurred_after_start is False
    assert executor.executed is False
    assert [name for name, _ in gateway.events][-1] == "failed"


def test_worker_core_cancellation_at_start_boundary_never_runs_executor(tmp_path: Path) -> None:
    class CancelAtStartGateway(FakeGateway):
        def mark_started(self, reference: LeaseReference) -> HeartbeatDirective:
            super().mark_started(reference)
            return HeartbeatDirective(cancelled=True)

    executor = FakeExecutor()
    core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
    )
    gateway = CancelAtStartGateway()

    outcome = core.process(make_lease(tmp_path), gateway)

    assert outcome.failure is not None
    assert outcome.failure.code == ErrorCode.EXECUTION_CANCELLED
    assert outcome.failure.occurred_after_start is False
    assert executor.executed is False
    assert [name for name, _ in gateway.events][-2:] == ["started", "failed"]


def test_worker_core_running_cancellation_reports_measured_usage(tmp_path: Path) -> None:
    class RunningCancelGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.execution_started = False

        def heartbeat(
            self, reference: LeaseReference, progress: ProgressEvent
        ) -> HeartbeatDirective:
            self.events.append(("heartbeat", (reference, progress)))
            return HeartbeatDirective(cancelled=self.execution_started)

        def mark_started(self, reference: LeaseReference) -> HeartbeatDirective:
            self.execution_started = True
            return super().mark_started(reference)

    class CooperativeExecutor(FakeExecutor):
        def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
            self.executed = True
            deadline = time.monotonic() + 1
            while not context.is_cancelled() and time.monotonic() < deadline:
                time.sleep(0.002)
            assert context.is_cancelled()
            output = context.work_dir / "result.bin"
            output.write_bytes(b"cancelled-output")
            return ExecutionResult(
                (ExecutionArtifact("primary", output),),
                usage=UsageMetrics(gpu_active_ms=37, gpu_count=1),
                executor_run_id="cancelled-run",
            )

    core = WorkerCore(
        ExecutorRegistry(CooperativeExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        heartbeat_interval_seconds=0.005,
    )
    gateway = RunningCancelGateway()
    outcome = core.process(make_lease(tmp_path), gateway)

    assert outcome.failure is not None
    assert outcome.failure.code == ErrorCode.EXECUTION_CANCELLED
    assert outcome.failure.responsibility == "consumer"
    assert outcome.failure.occurred_after_start is True
    assert outcome.failure.usage.gpu_active_ms == 37
    assert outcome.failure.usage.executor_wall_ms > 0
    assert outcome.failure.usage.input_bytes == 5
    assert not (tmp_path / "published.bin").exists()
    reported = [value for name, value in gateway.events if name == "failed"]
    assert len(reported) == 1
    assert reported[0][1].usage == outcome.failure.usage


def test_worker_core_maps_missing_output_ticket_to_safe_storage_error(tmp_path: Path) -> None:
    core = WorkerCore(
        ExecutorRegistry(FakeExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
    )
    gateway = FakeGateway()
    outcome = core.process(make_lease(tmp_path, output_name="different"), gateway)
    assert outcome.failure is not None
    assert outcome.failure.code == ErrorCode.OUTPUT_UPLOAD_FAILED
    assert outcome.failure.retry_action.value == "resume_upload"
    assert outcome.failure.occurred_after_start is True
    assert "payload:" not in outcome.failure.message
    assert not (tmp_path / "published.bin").exists()


def test_generic_lease_models_have_no_provider_or_comfy_fields() -> None:
    model_types = (
        LeaseReference,
        ExecutorPayload,
        ArtifactInput,
        ArtifactOutputTarget,
        ExecutionLease,
    )
    field_names = {field.name.lower() for model in model_types for field in fields(model)}
    forbidden = {"graph", "oss", "bucket", "region", "credential", "access_key"}
    assert field_names.isdisjoint(forbidden)
    assert "private prompt" not in repr(
        ExecutorPayload("fake", "fake/v1", "t2v", "a" * 64, b"private prompt")
    )


def test_gateway_unavailable_is_left_for_daemon_journal_to_retry(tmp_path: Path) -> None:
    class OfflineGateway(FakeGateway):
        def mark_started(self, reference: LeaseReference) -> HeartbeatDirective:
            raise GatewayUnavailableError()

    core = WorkerCore(
        ExecutorRegistry(FakeExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
    )
    gateway = OfflineGateway()
    with pytest.raises(GatewayUnavailableError):
        core.process(make_lease(tmp_path), gateway)
    assert not any(name == "failed" for name, _ in gateway.events)


def test_worker_keeps_lease_alive_while_executor_is_quiet(tmp_path: Path) -> None:
    class QuietExecutor(FakeExecutor):
        def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
            time.sleep(0.04)
            return super().execute(request, context)

    core = WorkerCore(
        ExecutorRegistry(QuietExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        heartbeat_interval_seconds=0.005,
    )
    gateway = FakeGateway()
    assert core.process(make_lease(tmp_path), gateway).succeeded
    heartbeat_events = [value for name, value in gateway.events if name == "heartbeat"]
    assert len(heartbeat_events) >= 5


def test_worker_keeps_lease_alive_through_quiet_output_processing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class OutputExecutor(FakeExecutor):
        def __init__(self) -> None:
            super().__init__()
            self.returned_at = 0.0

        def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
            self.executed = True
            output = context.work_dir / "result.bin"
            output.write_bytes(b"private generated output")
            result = ExecutionResult(
                (ExecutionArtifact("primary", output),),
                usage=UsageMetrics(gpu_active_ms=25),
            )
            self.returned_at = time.monotonic()
            return result

    quiet_windows: dict[str, tuple[float, float]] = {}

    def wait_quietly(phase: str) -> None:
        started = time.monotonic()
        time.sleep(0.03)
        quiet_windows[phase] = (started, time.monotonic())

    actual_encrypt = worker_core_module.encrypt_stream

    def slow_encrypt(*args: Any, **kwargs: Any) -> Any:
        wait_quietly("encrypt")
        return actual_encrypt(*args, **kwargs)

    actual_digest = worker_core_module.file_digest

    def slow_digest(*args: Any, **kwargs: Any) -> Any:
        wait_quietly("hash")
        return actual_digest(*args, **kwargs)

    class QuietUploadAdapter(LocalArtifactAdapter):
        def upload(self, ticket: Any, source: Path, on_progress: Any = None) -> Any:
            wait_quietly("upload")
            return super().upload(ticket, source, on_progress)

    class TimedGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.heartbeat_times: list[float] = []
            self.completed_at = 0.0

        def heartbeat(
            self, reference: LeaseReference, progress: ProgressEvent
        ) -> HeartbeatDirective:
            self.heartbeat_times.append(time.monotonic())
            return super().heartbeat(reference, progress)

        def complete(self, reference: LeaseReference, result: WorkerResult) -> None:
            self.completed_at = time.monotonic()
            super().complete(reference, result)

    monkeypatch.setattr(worker_core_module, "encrypt_stream", slow_encrypt)
    monkeypatch.setattr(worker_core_module, "file_digest", slow_digest)
    executor = OutputExecutor()
    gateway = TimedGateway()
    lease, _destination = make_encrypted_output_lease(tmp_path, attempt_id="att_quiet_output")
    core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(QuietUploadAdapter((tmp_path,))),
        work_root=tmp_path / "worker-work",
        heartbeat_interval_seconds=0.005,
    )

    assert core.process(lease, gateway).succeeded
    assert set(quiet_windows) == {"encrypt", "hash", "upload"}
    assert all(started >= executor.returned_at for started, _ended in quiet_windows.values())
    assert gateway.completed_at > max(ended for _started, ended in quiet_windows.values())
    for started, ended in quiet_windows.values():
        assert (
            len(
                [
                    timestamp
                    for timestamp in gateway.heartbeat_times
                    if started <= timestamp <= ended
                ]
            )
            >= 2
        )


def test_output_phase_cancellation_clears_spool_and_reports_once(tmp_path: Path) -> None:
    class OutputExecutor(FakeExecutor):
        def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
            self.executed = True
            output = context.work_dir / "result.bin"
            output.write_bytes(b"private generated output")
            return ExecutionResult(
                (ExecutionArtifact("primary", output),),
                usage=UsageMetrics(gpu_active_ms=37),
            )

    upload_started = threading.Event()
    cancellation_observed = threading.Event()

    class PausedUploadAdapter(LocalArtifactAdapter):
        def upload(self, ticket: Any, source: Path, on_progress: Any = None) -> Any:
            upload_started.set()
            assert cancellation_observed.wait(timeout=1)
            return super().upload(ticket, source, on_progress)

    class OutputCancelGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.cancel_directives = 0

        def heartbeat(
            self, reference: LeaseReference, progress: ProgressEvent
        ) -> HeartbeatDirective:
            self.events.append(("heartbeat", (reference, progress)))
            if upload_started.is_set() and self.cancel_directives == 0:
                self.cancel_directives += 1
                cancellation_observed.set()
                return HeartbeatDirective(cancelled=True)
            return HeartbeatDirective()

        def renew_output_tickets(
            self, reference: LeaseReference, artifact_ids: frozenset[str]
        ) -> Mapping[str, TransferTicket]:
            raise AssertionError("cancelled output must not remain resumable")

    executor = OutputExecutor()
    gateway = OutputCancelGateway()
    lease, _destination = make_encrypted_output_lease(tmp_path, attempt_id="att_cancel_output")
    work_root = tmp_path / "worker-work"
    core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(PausedUploadAdapter((tmp_path,))),
        work_root=work_root,
        heartbeat_interval_seconds=0.005,
    )

    outcome = core.process(lease, gateway)

    assert outcome.failure is not None
    assert outcome.failure.code == ErrorCode.EXECUTION_CANCELLED
    assert outcome.failure.responsibility == "consumer"
    assert outcome.failure.occurred_after_start is True
    assert outcome.failure.usage.gpu_active_ms == 37
    assert gateway.cancel_directives == 1
    assert [name for name, _value in gateway.events].count("failed") == 1
    assert not any(name == "complete" for name, _value in gateway.events)
    assert not list((work_root / "upload-spool").glob("*/upload-manifest.json"))
    assert core.resume_pending(gateway) is None


def test_pending_encrypted_upload_resumes_without_reexecuting(tmp_path: Path) -> None:
    class CountingExecutor:
        def __init__(self) -> None:
            self.calls = 0

        def descriptor(self) -> ExecutorDescriptor:
            return ExecutorDescriptor("fake", "1.0", ("fake/v1",), ("t2v",))

        def health(self) -> ExecutorHealth:
            return ExecutorHealth(True, "ready")

        def capabilities(self) -> Mapping[str, Any]:
            return {}

        def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
            self.calls += 1
            assert request.payload == b"private prompt payload"
            output = context.work_dir / "result.bin"
            output.write_bytes(b"private generated output")
            return ExecutionResult(
                (ExecutionArtifact("primary", output),),
                usage=UsageMetrics(
                    gpu_active_ms=50,
                    native={"private prompt native key": 1},
                ),
                executor_run_id="private prompt run handle",
            )

        def cancel(self, handle: str | None = None) -> None:
            return None

    class FlakyLocalAdapter(LocalArtifactAdapter):
        def __init__(self, root: Path) -> None:
            super().__init__((root,))
            self.failures = 1

        def upload(self, ticket: Any, source: Path, on_progress: Any = None) -> Any:
            if self.failures:
                self.failures -= 1
                raise ArtifactTransferError("upload", "temporary storage outage")
            return super().upload(ticket, source, on_progress)

    destination = tmp_path / "published.vgen"
    task_key = b"k" * 32
    reference = LeaseReference("lea_spool", "tsk_spool", "atm_spool", "wrk_1", 3)
    lease = ExecutionLease(
        reference=reference,
        payload=ExecutorPayload("fake", "fake/v1", "t2v", "a" * 64, b"private prompt payload"),
        outputs=(
            ArtifactOutputTarget(
                "primary",
                ArtifactDescriptor("art_spool", "result.bin"),
                TransferTicket(
                    destination.as_uri() + "?signature=must-not-be-journaled",
                    "PUT",
                ),
                kind="video",
                store_type="local",
                object_ref="art_spool",
            ),
        ),
        crypto=LeaseCryptoContext("wsp_spool", "atm_spool", 1, task_key),
    )

    class ResumableGateway(FakeGateway):
        def renew_output_tickets(
            self, actual_reference: LeaseReference, artifact_ids: frozenset[str]
        ) -> Mapping[str, TransferTicket]:
            assert actual_reference == reference
            assert artifact_ids == frozenset({"art_spool"})
            return {"art_spool": TransferTicket(destination.as_uri(), "PUT")}

    executor = CountingExecutor()
    gateway = ResumableGateway()
    core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(FlakyLocalAdapter(tmp_path)),
        work_root=tmp_path / "worker-work",
    )
    with pytest.raises(UploadPendingError):
        core.process(lease, gateway)
    assert executor.calls == 1
    assert not any(name in {"complete", "failed"} for name, _value in gateway.events)

    manifest = next((tmp_path / "worker-work" / "upload-spool").glob("*/upload-manifest.json"))
    manifest_text = manifest.read_text(encoding="utf-8")
    assert "private prompt" not in manifest_text
    assert "must-not-be-journaled" not in manifest_text
    assert "native" not in manifest_text
    assert "executor_run_id" not in manifest_text
    ciphertext = next(manifest.parent.glob("*.ciphertext")).read_bytes()
    assert b"private generated output" not in ciphertext

    # A daemon restart must discover the on-disk journal and resume the upload
    # before asking for another lease.  The Executor instance is deliberately
    # reused so any accidental second invocation remains observable.
    restarted_adapter = FlakyLocalAdapter(tmp_path)
    restarted_adapter.failures = 0
    restarted_core = WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(restarted_adapter),
        work_root=tmp_path / "worker-work",
    )
    resumed = restarted_core.resume_pending(gateway)
    assert resumed is not None and resumed.succeeded
    assert executor.calls == 1
    assert [name for name, _value in gateway.events].count("complete") == 1
    assert not list((tmp_path / "worker-work" / "upload-spool").glob("*/upload-manifest.json"))
    plaintext = tmp_path / "recovered.bin"
    with destination.open("rb") as encrypted, plaintext.open("wb") as recovered:
        from vgen.crypto import decrypt_stream, task_aad

        decrypt_stream(
            encrypted,
            recovered,
            task_key,
            aad=task_aad(
                workspace_id="wsp_spool",
                task_id="tsk_spool",
                attempt_id="atm_spool",
                artifact_id="art_spool",
                key_version=1,
            ),
        )
    assert plaintext.read_bytes() == b"private generated output"


def _save_test_upload(
    journal: UploadJournal,
    *,
    attempt_id: str,
    content: bytes,
) -> tuple[LeaseReference, Path]:
    reference = LeaseReference(
        f"lea_{attempt_id}",
        f"tsk_{attempt_id}",
        attempt_id,
        "wrk_spool",
        1,
    )
    artifact_id = f"art_{attempt_id}"
    path = journal.output_path(reference, artifact_id)
    path.write_bytes(content)
    artifact = WorkerResultArtifact(
        artifact_id=artifact_id,
        name="primary",
        filename="output.vgen",
        media_type="application/octet-stream",
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
    )
    journal.save(
        reference,
        WorkerResult(
            artifacts=(artifact,),
            usage=UsageMetrics(output_bytes=len(content)),
            executor_type="fake",
            executor_version="1.0",
        ),
        {artifact_id: path},
    )
    return reference, path


def test_corrupt_oldest_upload_is_quarantined_without_hiding_next_attempt(
    tmp_path: Path,
) -> None:
    journal = UploadJournal(tmp_path / "upload-spool")
    bad_reference, bad_path = _save_test_upload(
        journal,
        attempt_id="atm_bad",
        content=b"durable ciphertext one",
    )
    good_reference, _good_path = _save_test_upload(
        journal,
        attempt_id="atm_good",
        content=b"durable ciphertext two",
    )
    bad_path.write_bytes(b"truncated")

    pending = journal.list_pending()

    assert [item.reference.attempt_id for item in pending] == [good_reference.attempt_id]
    assert not journal._directory(bad_reference.attempt_id).exists()
    quarantined = list((tmp_path / "upload-spool-quarantine").iterdir())
    assert len(quarantined) == 1
    assert (quarantined[0] / "upload-manifest.json").is_file()


def test_invalid_upload_manifest_is_quarantined_instead_of_crashing_worker(
    tmp_path: Path,
) -> None:
    journal = UploadJournal(tmp_path / "upload-spool")
    reference, _path = _save_test_upload(
        journal,
        attempt_id="atm_invalid_manifest",
        content=b"durable ciphertext",
    )
    manifest = journal._directory(reference.attempt_id) / "upload-manifest.json"
    manifest.write_text("{not valid json", encoding="utf-8")

    assert journal.list_pending() == ()
    assert not journal._directory(reference.attempt_id).exists()
    assert len(list((tmp_path / "upload-spool-quarantine").iterdir())) == 1


def test_legacy_spool_drops_non_integer_media_probes_before_resume(tmp_path: Path) -> None:
    journal = UploadJournal(tmp_path / "upload-spool")
    reference, _path = _save_test_upload(
        journal,
        attempt_id="atm_legacy_metadata",
        content=b"durable ciphertext",
    )
    manifest = journal._directory(reference.attempt_id) / "upload-manifest.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["result"]["artifacts"][0]["metadata"] = {
        "frames": 81,
        "duration_ms": 1.5,
        "width": True,
        "denoise_steps": 100_001,
    }
    manifest.write_text(json.dumps(raw), encoding="utf-8")

    pending = journal.load(reference.attempt_id)

    assert pending.result.artifacts[0].metadata == {"frames": 81}


def test_orphaned_pre_manifest_directory_is_quarantined_before_next_attempt(
    tmp_path: Path,
) -> None:
    journal = UploadJournal(tmp_path / "upload-spool")
    orphan = LeaseReference("lea_orphan", "tsk_orphan", "atm_orphan", "wrk_spool", 1)
    journal.output_path(orphan, "art_orphan").write_bytes(b"unfinished ciphertext")
    good_reference, _path = _save_test_upload(
        journal,
        attempt_id="atm_after_orphan",
        content=b"durable ciphertext",
    )

    pending = journal.list_pending()

    assert [item.reference.attempt_id for item in pending] == [good_reference.attempt_id]
    assert not journal._directory(orphan.attempt_id).exists()
    assert len(list((tmp_path / "upload-spool-quarantine").iterdir())) == 1


def test_resume_renews_lease_while_adapter_prepares_large_upload(tmp_path: Path) -> None:
    work_root = tmp_path / "worker-work"
    journal = UploadJournal(work_root / "upload-spool")
    reference, _path = _save_test_upload(
        journal,
        attempt_id="atm_slow_resume",
        content=b"durable ciphertext",
    )
    destination = tmp_path / "resumed.bin"
    background_heartbeat = threading.Event()

    class SlowLocalAdapter(LocalArtifactAdapter):
        def upload(self, ticket: Any, source: Path, on_progress: Any = None) -> Any:
            assert background_heartbeat.wait(timeout=1), "resume lease was not renewed"
            return super().upload(ticket, source, on_progress)

    class ResumableGateway(FakeGateway):
        def renew_output_tickets(
            self,
            actual_reference: LeaseReference,
            artifact_ids: frozenset[str],
        ) -> Mapping[str, TransferTicket]:
            assert actual_reference == reference
            assert artifact_ids == frozenset({"art_atm_slow_resume"})
            return {"art_atm_slow_resume": TransferTicket(destination.as_uri(), "PUT")}

        def heartbeat(
            self, actual_reference: LeaseReference, progress: ProgressEvent
        ) -> HeartbeatDirective:
            directive = super().heartbeat(actual_reference, progress)
            if sum(name == "heartbeat" for name, _value in self.events) >= 2:
                background_heartbeat.set()
            return directive

    core = WorkerCore(
        ExecutorRegistry(FakeExecutor()),
        ArtifactAdapterRegistry(SlowLocalAdapter((tmp_path,))),
        work_root=work_root,
        heartbeat_interval_seconds=0.01,
    )
    resumed = core.resume_pending(ResumableGateway())

    assert resumed is not None and resumed.succeeded
    assert destination.read_bytes() == b"durable ciphertext"


def test_resume_missing_renewal_ticket_keeps_durable_spool_for_retry(tmp_path: Path) -> None:
    work_root = tmp_path / "worker-work"
    journal = UploadJournal(work_root / "upload-spool")
    reference, _path = _save_test_upload(
        journal,
        attempt_id="atm_missing_renewal",
        content=b"durable ciphertext",
    )

    class MissingTicketGateway(FakeGateway):
        def renew_output_tickets(
            self,
            actual_reference: LeaseReference,
            artifact_ids: frozenset[str],
        ) -> Mapping[str, TransferTicket]:
            assert actual_reference == reference
            assert artifact_ids == frozenset({"art_atm_missing_renewal"})
            return {}

    core = WorkerCore(
        ExecutorRegistry(FakeExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        work_root=work_root,
        heartbeat_interval_seconds=0.01,
    )

    with pytest.raises(UploadPendingError):
        core.resume_pending(MissingTicketGateway())

    assert journal.oldest_pending() is not None
    assert journal.oldest_pending().reference == reference


def test_resume_serializes_gateway_calls_and_stops_heartbeat_before_complete(
    tmp_path: Path,
) -> None:
    work_root = tmp_path / "worker-work"
    journal = UploadJournal(work_root / "upload-spool")
    reference, _path = _save_test_upload(
        journal,
        attempt_id="atm_serialized_resume",
        content=b"durable ciphertext",
    )
    destination = tmp_path / "serialized-resume.bin"
    upload_active = threading.Event()
    heartbeat_during_upload = threading.Event()

    class SlowLocalAdapter(LocalArtifactAdapter):
        def upload(self, ticket: Any, source: Path, on_progress: Any = None) -> Any:
            upload_active.set()
            try:
                assert heartbeat_during_upload.wait(timeout=1), "upload lease was not renewed"
                return super().upload(ticket, source, on_progress)
            finally:
                upload_active.clear()

    class SerializedGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self._state_lock = threading.Lock()
            self._active_calls: set[str] = set()
            self.overlaps: list[tuple[str, str]] = []
            self.complete_returned = threading.Event()
            self.heartbeats_after_complete = 0

        def _enter(self, name: str) -> None:
            with self._state_lock:
                self.overlaps.extend((active, name) for active in self._active_calls)
                self._active_calls.add(name)

        def _leave(self, name: str) -> None:
            with self._state_lock:
                self._active_calls.remove(name)

        def heartbeat(
            self, actual_reference: LeaseReference, progress: ProgressEvent
        ) -> HeartbeatDirective:
            self._enter("heartbeat")
            try:
                if self.complete_returned.is_set():
                    self.heartbeats_after_complete += 1
                if upload_active.is_set():
                    heartbeat_during_upload.set()
                time.sleep(0.001)
                return super().heartbeat(actual_reference, progress)
            finally:
                self._leave("heartbeat")

        def renew_output_tickets(
            self,
            actual_reference: LeaseReference,
            artifact_ids: frozenset[str],
        ) -> Mapping[str, TransferTicket]:
            self._enter("renew")
            try:
                assert actual_reference == reference
                assert artifact_ids == frozenset({"art_atm_serialized_resume"})
                time.sleep(0.03)
                return {
                    "art_atm_serialized_resume": TransferTicket(
                        destination.as_uri(),
                        "PUT",
                    )
                }
            finally:
                self._leave("renew")

        def complete(self, actual_reference: LeaseReference, result: WorkerResult) -> None:
            self._enter("complete")
            try:
                time.sleep(0.03)
                super().complete(actual_reference, result)
            finally:
                self._leave("complete")
            self.complete_returned.set()

    gateway = SerializedGateway()
    core = WorkerCore(
        ExecutorRegistry(FakeExecutor()),
        ArtifactAdapterRegistry(SlowLocalAdapter((tmp_path,))),
        work_root=work_root,
        heartbeat_interval_seconds=0.005,
    )

    resumed = core.resume_pending(gateway)
    time.sleep(0.02)

    assert resumed is not None and resumed.succeeded
    assert destination.read_bytes() == b"durable ciphertext"
    assert heartbeat_during_upload.is_set()
    assert gateway.overlaps == []
    assert gateway.heartbeats_after_complete == 0
    assert [name for name, _value in gateway.events][-1] == "complete"
