from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import vgen.worker.maintenance as maintenance_module
from vgen.artifacts import TransferTicket
from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    build_maintenance_intent_payload,
    derive_identity_keys,
    issue_device_certificate,
    sign_maintenance_intent,
)
from vgen.protocol import ErrorCode, VGenError
from vgen.worker import WorkerCredentials
from vgen.worker.core import GatewayUnavailableError
from vgen.worker.maintenance import (
    WorkerMaintenanceController,
    _capability_error_code,
    _LeaseKeeper,
    _model_error_code,
    _update_error_code,
)
from vgen.worker.model_installer import ModelInstallError, ModelInstallResult


class FakeGateway:
    def __init__(
        self, job: dict[str, Any] | None = None, *, cancel_state: str | None = None
    ) -> None:
        self.job = job
        self.cancel_state = cancel_state
        self.heartbeats: list[dict[str, Any]] = []
        self.completions: list[dict[str, Any]] = []

    def claim_maintenance(self, *, ttl_seconds: int = 60) -> dict[str, Any] | None:
        assert ttl_seconds == 60
        return self.job

    def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
        self.heartbeats.append({"job_id": job_id, **value})
        return {
            "ok": True,
            "cancelled": value.get("state") == self.cancel_state,
        }

    def complete_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
        self.completions.append({"job_id": job_id, **value})
        return {"ok": True}

    def maintenance_artifact_ticket(self, job: dict[str, Any]) -> TransferTicket:
        return job["ticket"]


def test_lease_keeper_retries_one_transient_gateway_timeout(monkeypatch: Any) -> None:
    renewed = threading.Event()

    class TransientGateway:
        attempts = 0

        def heartbeat_maintenance(self, _job_id: str, **_value: Any) -> dict[str, Any]:
            self.attempts += 1
            if self.attempts == 1:
                raise GatewayUnavailableError()
            renewed.set()
            return {"cancelled": False}

    gateway = TransientGateway()
    monkeypatch.setattr(maintenance_module, "_LEASE_RENEW_INTERVAL_SECONDS", 0.01)

    with _LeaseKeeper(
        gateway,  # type: ignore[arg-type]
        "mtj_test",
        1,
        stage="activating",
        gateway_lock=threading.Lock(),
    ) as keeper:
        assert renewed.wait(timeout=1)
        keeper.check()

    assert gateway.attempts >= 2


class FakeExecutor:
    def __init__(self, pin: Any) -> None:
        self.maintenance_model_pins = pin if isinstance(pin, tuple) else (pin,)
        self.maintenance_workflows = (("vgen/minimax-h3-8step@1.0.0", "sha256:" + "b" * 64),)
        self.invalidated = False

    def invalidate_model_digest_cache(self) -> None:
        self.invalidated = True


class FakeInstaller:
    def __init__(self, *, fail_digest: str | None = None) -> None:
        self.pins: list[Any] = []
        self.fail_digest = fail_digest

    def install(self, pin: Any, *, progress: Any = None) -> ModelInstallResult:
        self.pins.append(pin)
        if pin.sha256 == self.fail_digest:
            raise ModelInstallError("MODEL_DOWNLOAD_FAILED", retryable=True)
        if progress is not None:
            progress(pin.size, pin.size)
        return ModelInstallResult("sha256:" + pin.sha256, "installed", pin.size)


class FakeUpdater:
    def __init__(self, root: Path, pointer: dict[str, Any] | None = None) -> None:
        self.download_root = root / "downloads"
        self.pointer = pointer
        self.staged: dict[str, Any] | None = None
        self.succeeded = False
        self.rolled_back = False

    def validate_wheel(self, _wheel: Path, **_kwargs: Any) -> str:
        return "a" * 64

    def stage(self, _wheel: Path, **kwargs: Any) -> dict[str, Any]:
        self.staged = kwargs
        return {}

    def pending_activation(self) -> dict[str, Any] | None:
        return self.pointer

    def is_target_process(self, _pointer: dict[str, Any]) -> bool:
        return True

    def activation_verified(self, pointer: dict[str, Any]) -> bool:
        return type(pointer.get("activation_verified_at")) is int

    def mark_activation_verified(self, pointer: dict[str, Any]) -> dict[str, Any]:
        self.pointer = {**pointer, "activation_verified_at": 1}
        return self.pointer

    def mark_activation_succeeded(self, _pointer: dict[str, Any]) -> None:
        self.succeeded = True
        self.pointer = None

    def mark_activation_rolled_back(self, _pointer: dict[str, Any]) -> None:
        self.rolled_back = True


def signed_job(spec: dict[str, Any]) -> tuple[dict[str, Any], WorkerCredentials]:
    now = int(time.time())
    root = derive_identity_keys(b"r" * 64)
    broker_device = DeviceKeys.generate()
    certificate = issue_device_certificate(
        root,
        broker_device,
        device_id="dev_owner",
        issued_at=now - 5,
        expires_at=now + 3600,
    )
    payload = build_maintenance_intent_payload(
        worker_id="wrk_test",
        broker_id="brk_test",
        kind=spec["kind"],
        spec=spec,
        device_id="dev_owner",
        issued_at=now - 1,
        expires_at=now + 600,
        nonce="maintenance_nonce_1234",
    )
    job = {
        "id": "mtn_test",
        "worker_id": "wrk_test",
        "broker_id": "brk_test",
        "kind": spec["kind"],
        "spec": spec,
        "authorization": sign_maintenance_intent(broker_device, certificate, payload),
        "fencing_token": 3,
    }
    credentials = WorkerCredentials(
        "wrk_test",
        DeviceKeys.generate(),
        "session",
        owner_root_signing_public_key=b64url_encode(root.signing_public_bytes()),
    )
    return job, credentials


def model_fixture() -> tuple[dict[str, Any], WorkerCredentials, Any]:
    digest = "sha256:" + "c" * 64
    pin = SimpleNamespace(
        path="vae/model.safetensors",
        sha256="c" * 64,
        size=12,
        source="https://models.example.test/rev/model",
        revision="rev",
        license="Apache-2.0",
        license_url="https://licenses.example.test/apache",
        gated=False,
        manual_download=False,
    )
    spec = {
        "kind": "model_install",
        "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
        "workflow_digest": "sha256:" + "b" * 64,
        "model_digests": [digest],
    }
    job, credentials = signed_job(spec)
    return job, credentials, pin


def test_node_pack_job_installs_cached_artifact_and_reports_loaded(tmp_path: Path) -> None:
    artifact = b"reviewed node pack"
    digest = hashlib.sha256(artifact).hexdigest()
    spec = {
        "kind": "node_pack_install",
        "node_pack_ref": "vgen/comfyui-gguf@1.0.0",
        "artifact_sha256": digest,
        "artifact_size": len(artifact),
        "node_classes": ["UnetLoaderGGUF"],
        "apply": "on_idle",
    }
    job, credentials = signed_job(spec)
    job["ticket"] = TransferTicket(
        "https://gateway.example.test/node-pack",
        "GET",
        expected_size=len(artifact),
        expected_sha256=digest,
    )
    work = tmp_path / "work"
    downloads = work / "node-pack-downloads"
    downloads.mkdir(parents=True)
    archive = downloads / f"{digest}.zip"
    archive.write_bytes(artifact)
    calls: list[dict[str, Any]] = []

    class FakeNodePackInstaller:
        def install(self, path: Path, **kwargs: Any) -> Any:
            calls.append({"path": path, **kwargs})
            return SimpleNamespace(status="installed")

    gateway = FakeGateway(job)
    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=work,
        model_root=None,
        node_pack_installer=FakeNodePackInstaller(),  # type: ignore[arg-type]
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).run_one()

    assert outcome is not None and outcome.succeeded
    assert calls == [
        {
            "path": archive,
            "expected_sha256": digest,
            "expected_node_pack_ref": "vgen/comfyui-gguf@1.0.0",
            "expected_node_classes": ("UnetLoaderGGUF",),
            "stage": calls[0]["stage"],
        }
    ]
    assert callable(calls[0]["stage"])
    assert gateway.completions[-1]["result"] == {
        "kind": "node_pack_install",
        "status": "installed",
        "node_pack_ref": "vgen/comfyui-gguf@1.0.0",
        "artifact_sha256": digest,
        "loaded": True,
    }


def test_model_job_requires_signed_exact_local_workflow_and_model_pin(tmp_path: Path) -> None:
    job, credentials, pin = model_fixture()
    gateway = FakeGateway(job)
    executor = FakeExecutor(pin)
    installer = FakeInstaller()
    controller = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        executor,  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=tmp_path,
        model_installer=installer,  # type: ignore[arg-type]
    )

    outcome = controller.run_one()

    assert outcome is not None and outcome.succeeded
    assert installer.pins == [pin]
    assert executor.invalidated
    assert gateway.completions[-1]["succeeded"] is True
    assert gateway.completions[-1]["result"]["status"] == "installed"


def test_shared_model_uses_public_source_before_manual_placement(tmp_path: Path) -> None:
    digest = "d" * 64
    manual = SimpleNamespace(
        path="text_encoders/shared-manual.safetensors",
        sha256=digest,
        size=12,
        source="https://models.example.test/manual-info",
        revision="rev",
        license=None,
        license_url=None,
        gated=False,
        manual_download=True,
    )
    public = SimpleNamespace(
        **{
            **vars(manual),
            "path": "clip/shared-public.safetensors",
            "source": "https://models.example.test/rev/shared",
            "manual_download": False,
        }
    )
    spec = {
        "kind": "model_install",
        "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
        "workflow_digest": "sha256:" + "b" * 64,
        "model_digests": ["sha256:" + digest],
    }
    job, credentials = signed_job(spec)

    class CacheAwareInstaller:
        def __init__(self) -> None:
            self.pins: list[Any] = []
            self.cached = False

        def install(self, pin: Any, *, progress: Any = None) -> ModelInstallResult:
            self.pins.append(pin)
            if pin.manual_download and not self.cached:
                raise ModelInstallError("MODEL_MANUAL_ACTION_REQUIRED")
            status = "already_installed" if self.cached else "installed"
            self.cached = True
            if progress is not None:
                progress(pin.size, pin.size)
            return ModelInstallResult("sha256:" + pin.sha256, status, pin.size)

    installer = CacheAwareInstaller()
    outcome = WorkerMaintenanceController(
        credentials,
        FakeGateway(job),  # type: ignore[arg-type]
        FakeExecutor((manual, public)),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=tmp_path,
        model_installer=installer,  # type: ignore[arg-type]
    ).run_one()

    assert outcome is not None and outcome.succeeded
    assert installer.pins == [public, manual]


def test_shared_model_falls_back_to_second_public_source(tmp_path: Path) -> None:
    digest = "e" * 64
    first = SimpleNamespace(
        path="clip/a-first.safetensors",
        sha256=digest,
        size=12,
        source="https://first.example.test/model",
        revision="first-revision",
        license=None,
        license_url=None,
        gated=False,
        manual_download=False,
    )
    second = SimpleNamespace(
        **{
            **vars(first),
            "path": "text_encoders/b-second.safetensors",
            "source": "https://second.example.test/model",
            "revision": "second-revision",
        }
    )
    spec = {
        "kind": "model_install",
        "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
        "workflow_digest": "sha256:" + "b" * 64,
        "model_digests": ["sha256:" + digest],
    }
    job, credentials = signed_job(spec)

    class FallbackInstaller:
        def __init__(self) -> None:
            self.pins: list[Any] = []
            self.cached = False

        def install(self, pin: Any, *, progress: Any = None) -> ModelInstallResult:
            self.pins.append(pin)
            if pin is first and not self.cached:
                raise ModelInstallError("MODEL_DOWNLOAD_FAILED", retryable=True)
            status = "already_installed" if self.cached else "installed"
            self.cached = True
            if progress is not None:
                progress(pin.size, pin.size)
            return ModelInstallResult("sha256:" + pin.sha256, status, pin.size)

    installer = FallbackInstaller()
    outcome = WorkerMaintenanceController(
        credentials,
        FakeGateway(job),  # type: ignore[arg-type]
        FakeExecutor((first, second)),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=tmp_path,
        model_installer=installer,  # type: ignore[arg-type]
    ).run_one()

    assert outcome is not None and outcome.succeeded
    assert installer.pins == [first, second, first]


def test_tampered_job_is_rejected_before_model_files_change(tmp_path: Path) -> None:
    job, credentials, pin = model_fixture()
    job["spec"] = {**job["spec"], "workflow_digest": "sha256:" + "d" * 64}
    gateway = FakeGateway(job)
    installer = FakeInstaller()
    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(pin),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=tmp_path,
        model_installer=installer,  # type: ignore[arg-type]
    ).run_one()

    assert outcome is not None and not outcome.succeeded
    assert installer.pins == []
    assert gateway.completions[-1]["result"]["error_code"] == int(
        ErrorCode.MAINTENANCE_POLICY_DENIED
    )


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("MODEL_SOURCE_NOT_PUBLIC", ErrorCode.SOURCE_NOT_ALLOWED),
        ("MODEL_DISK_FULL", ErrorCode.DISK_SPACE_INSUFFICIENT),
        ("MODEL_TARGET_CONFLICT", ErrorCode.PATH_CONFLICT),
        ("MODEL_INTEGRITY_FAILED", ErrorCode.DIGEST_MISMATCH),
        ("MODEL_DOWNLOAD_FAILED", ErrorCode.DOWNLOAD_INTERRUPTED),
        ("MODEL_MANUAL_ACTION_REQUIRED", ErrorCode.GATED_CREDENTIAL_UNAVAILABLE),
        ("MAINTENANCE_MODEL_NOT_ALLOWED", ErrorCode.MAINTENANCE_POLICY_DENIED),
        ("MODEL_PIN_INVALID", ErrorCode.MANIFEST_UNTRUSTED),
    ],
)
def test_model_failures_use_dedicated_maintenance_codes(reason: str, expected: ErrorCode) -> None:
    assert _model_error_code(reason) == int(expected)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("CAPABILITY_ARCHIVE_INVALID", ErrorCode.CAPABILITY_ARCHIVE_INVALID),
        ("CAPABILITY_VERSION_CONFLICT", ErrorCode.CAPABILITY_VERSION_CONFLICT),
        (
            "CAPABILITY_CONTAINS_EXECUTABLE_CONTENT",
            ErrorCode.CAPABILITY_EXECUTABLE_CONTENT,
        ),
        ("CAPABILITY_RELEASE_INVALID", ErrorCode.CAPABILITY_RELEASE_INVALID),
        ("CAPABILITY_COMPILE_INVALID", ErrorCode.CAPABILITY_COMPILE_INVALID),
        ("CAPABILITY_GRAPH_INVALID", ErrorCode.CAPABILITY_GRAPH_INVALID),
        ("CAPABILITY_NODE_APPROVAL_MISMATCH", ErrorCode.MAINTENANCE_POLICY_DENIED),
        ("CAPABILITY_PUBLISHER_PIN_MISMATCH", ErrorCode.MAINTENANCE_POLICY_DENIED),
    ],
)
def test_capability_failures_use_dedicated_maintenance_codes(
    reason: str, expected: ErrorCode
) -> None:
    assert _capability_error_code(reason) == int(expected)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("WORKER_UPDATE_INTEGRITY_FAILED", ErrorCode.DIGEST_MISMATCH),
        ("WORKER_UPDATE_DISK_FULL", ErrorCode.DISK_SPACE_INSUFFICIENT),
        ("WORKER_UPDATE_DOWNLOAD_FAILED", ErrorCode.DOWNLOAD_INTERRUPTED),
        ("WORKER_UPDATE_DOWNGRADE_DENIED", ErrorCode.UPDATE_DOWNGRADE_DENIED),
        ("WORKER_UPDATE_WHEEL_INCOMPATIBLE", ErrorCode.UPDATE_INCOMPATIBLE),
        ("WORKER_UPDATE_RUNTIME_INVALID", ErrorCode.UPDATE_ACTIVATION_FAILED),
        ("WORKER_UPDATE_WHEEL_INVALID", ErrorCode.MANIFEST_UNTRUSTED),
        ("WORKER_UPDATE_TICKET_INVALID", ErrorCode.MAINTENANCE_POLICY_DENIED),
    ],
)
def test_update_failures_use_dedicated_maintenance_codes(reason: str, expected: ErrorCode) -> None:
    assert _update_error_code(reason) == int(expected)


def test_update_is_staged_but_not_completed_until_target_process_starts(
    tmp_path: Path,
) -> None:
    wheel = b"reviewed wheel"
    digest = hashlib.sha256(wheel).hexdigest()
    spec = {
        "kind": "worker_update",
        "target_version": "0.2.0",
        "artifact_sha256": digest,
        "artifact_size": len(wheel),
        "apply": "on_idle",
    }
    job, credentials = signed_job(spec)
    updater = FakeUpdater(tmp_path)
    updater.download_root.mkdir(parents=True)
    (updater.download_root / f"vgen-0.2.0-{digest[:16]}.whl").write_bytes(wheel)
    job["ticket"] = TransferTicket(
        "https://gateway.example.test/update",
        "GET",
        expected_size=len(wheel),
        expected_sha256=digest,
    )
    gateway = FakeGateway(job)
    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).run_one()

    assert outcome is not None and outcome.restart_required
    assert updater.staged is not None
    assert gateway.completions == []
    assert gateway.heartbeats[-1]["state"] == "restarting"


def test_new_target_process_completes_pending_update_activation(tmp_path: Path) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = FakeGateway()
    probes: list[str] = []
    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).recover_pending_update(activation_probe=lambda: probes.append("announced"))

    assert outcome is not None and outcome.succeeded
    assert probes == ["announced"]
    assert updater.succeeded
    assert gateway.heartbeats[0]["adopt_restart_session"] is True
    assert gateway.heartbeats[0]["state"] == "restarting"
    assert gateway.completions[-1]["result"]["status"] == "activated"


def test_target_journals_verified_activation_before_gateway_completion(
    tmp_path: Path,
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    events: list[str] = []

    class OrderingUpdater(FakeUpdater):
        def mark_activation_verified(self, value: dict[str, Any]) -> dict[str, Any]:
            events.append("verified")
            return super().mark_activation_verified(value)

        def mark_activation_succeeded(self, value: dict[str, Any]) -> None:
            events.append("cleaned")
            super().mark_activation_succeeded(value)

    class OrderingGateway(FakeGateway):
        def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            events.append("heartbeat")
            return super().heartbeat_maintenance(job_id, **value)

        def complete_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            events.append("complete")
            return super().complete_maintenance(job_id, **value)

    updater = OrderingUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    outcome = WorkerMaintenanceController(
        credentials,
        OrderingGateway(),  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(activation_probe=lambda: events.append("probe"))

    assert outcome is not None and outcome.succeeded
    assert events == ["heartbeat", "probe", "verified", "complete", "cleaned"]


def test_completed_activation_retries_transient_pointer_cleanup_without_reprobe(
    tmp_path: Path,
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }

    class CleanupRetryUpdater(FakeUpdater):
        def __init__(self, root: Path, value: dict[str, Any]) -> None:
            super().__init__(root, value)
            self.cleanup_attempts = 0

        def mark_activation_succeeded(self, value: dict[str, Any]) -> None:
            self.cleanup_attempts += 1
            if self.cleanup_attempts == 1:
                raise PermissionError("transient Windows file lock")
            super().mark_activation_succeeded(value)

    updater = CleanupRetryUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = FakeGateway()
    controller = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    )
    probes: list[str] = []

    first = controller.recover_pending_update(activation_probe=lambda: probes.append("announced"))
    second = controller.recover_pending_update(
        activation_probe=lambda: pytest.fail("verified activation must not be reprobed")
    )

    assert first is not None and first.mode == "maintenance_update_cleanup_pending"
    assert first.succeeded
    assert second is not None and second.mode == "maintenance_update_activated"
    assert second.succeeded
    assert probes == ["announced"]
    assert updater.cleanup_attempts == 2
    assert updater.succeeded
    assert len(gateway.completions) == 2
    assert len(gateway.heartbeats) == 1


def test_verified_activation_adopts_restart_lease_after_process_change(
    tmp_path: Path,
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
        "activation_verified_at": 1,
    }

    class ChangedSessionGateway(FakeGateway):
        def complete_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            self.completions.append({"job_id": job_id, **value})
            if len(self.completions) == 1:
                raise VGenError(ErrorCode.MAINTENANCE_LEASE_LOST)
            return {"ok": True}

    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = ChangedSessionGateway()
    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(
        activation_probe=lambda: pytest.fail("verified activation must not be reprobed")
    )

    assert outcome is not None and outcome.succeeded
    assert len(gateway.completions) == 2
    assert gateway.heartbeats == [
        {
            "job_id": "mtn_test",
            "fencing_token": 4,
            "ttl_seconds": 300,
            "state": "restarting",
            "adopt_restart_session": True,
            "progress": {
                "stage": "activating",
                "completed_bytes": 0,
                "total_bytes": None,
            },
        }
    ]
    assert updater.succeeded


def test_verified_activation_rolls_back_when_restart_lease_expired(
    tmp_path: Path,
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
        "activation_verified_at": 1,
    }

    class ExpiredLeaseGateway(FakeGateway):
        def complete_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            self.completions.append({"job_id": job_id, **value})
            raise VGenError(ErrorCode.MAINTENANCE_LEASE_LOST)

        def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            self.heartbeats.append({"job_id": job_id, **value})
            raise VGenError(ErrorCode.MAINTENANCE_LEASE_LOST)

    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = ExpiredLeaseGateway()

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(
        activation_probe=lambda: pytest.fail("verified activation must not be reprobed")
    )

    assert outcome is not None
    assert outcome.rollback_required
    assert not outcome.succeeded
    assert outcome.mode == "maintenance_update_activation_failed"
    assert len(gateway.completions) == 1
    assert len(gateway.heartbeats) == 1
    assert not updater.succeeded


def test_new_target_activation_keeps_immutable_installer_assets_untouched(tmp_path: Path) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = FakeGateway()
    installer = tmp_path / "installer"
    installer.mkdir()
    launcher = installer / "start-worker.cmd"
    setup = installer / "setup-worker.ps1"
    checksums = installer / "SHA256SUMS"
    launcher.write_bytes(b"reviewed launcher\r\n")
    setup.write_bytes(b"reviewed setup\r\n")
    checksums.write_bytes(b"immutable checksums\r\n")
    before = {path.name: path.read_bytes() for path in installer.iterdir()}

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).recover_pending_update()

    assert outcome is not None and outcome.succeeded
    assert outcome.mode == "maintenance_update_activated"
    assert {path.name: path.read_bytes() for path in installer.iterdir()} == before
    assert updater.succeeded
    assert gateway.completions[-1]["result"]["status"] == "activated"


def test_target_activation_renews_restarting_lease_during_slow_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )

    class RenewingGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.renewed = threading.Event()

        def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            response = super().heartbeat_maintenance(job_id, **value)
            if len(self.heartbeats) >= 2:
                self.renewed.set()
            return response

    gateway = RenewingGateway()
    monkeypatch.setattr("vgen.worker.maintenance._LEASE_RENEW_INTERVAL_SECONDS", 0.001)

    def slow_probe() -> None:
        assert gateway.renewed.wait(timeout=1)

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(activation_probe=slow_probe)

    assert outcome is not None and outcome.succeeded
    assert gateway.heartbeats[0]["adopt_restart_session"] is True
    assert gateway.heartbeats[1]["state"] == "restarting"
    assert gateway.heartbeats[1]["progress"]["stage"] == "activating"
    assert "adopt_restart_session" not in gateway.heartbeats[1]
    assert gateway.completions[-1]["succeeded"] is True


def test_target_activation_announce_is_serialized_and_precedes_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )

    class SerializedGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.guard = threading.Lock()
            self.active_calls = 0
            self.maximum_calls = 0
            self.renewed = threading.Event()
            self.events: list[str] = []

        def _enter(self, event: str) -> None:
            with self.guard:
                self.active_calls += 1
                self.maximum_calls = max(self.maximum_calls, self.active_calls)
                self.events.append(event)
            time.sleep(0.002)

        def _exit(self) -> None:
            with self.guard:
                self.active_calls -= 1

        def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            self._enter("heartbeat")
            try:
                response = super().heartbeat_maintenance(job_id, **value)
                if len(self.heartbeats) >= 2:
                    self.renewed.set()
                return response
            finally:
                self._exit()

        def complete_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            self._enter("complete")
            try:
                return super().complete_maintenance(job_id, **value)
            finally:
                self._exit()

    gateway = SerializedGateway()
    announced: list[Any] = []
    sentinel = {"executor": "verified"}
    monkeypatch.setattr("vgen.worker.maintenance._LEASE_RENEW_INTERVAL_SECONDS", 0.001)

    def slow_probe() -> Any:
        assert gateway.renewed.wait(timeout=1)
        return sentinel

    def announce(value: Any) -> None:
        gateway._enter("announce")
        try:
            announced.append(value)
        finally:
            gateway._exit()

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(
        activation_probe=slow_probe,
        activation_announce=announce,
    )

    assert outcome is not None and outcome.succeeded
    assert announced == [sentinel]
    assert gateway.maximum_calls == 1
    assert gateway.events.count("announce") == 1
    assert gateway.events.index("announce") < gateway.events.index("complete")


@pytest.mark.parametrize("failure", ["cancelled", "lease_lost"])
def test_target_activation_renewal_failure_never_completes_with_stale_fencing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )

    class FailingRenewalGateway(FakeGateway):
        def __init__(self) -> None:
            super().__init__()
            self.failed = threading.Event()

        def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
            if self.heartbeats:
                self.heartbeats.append({"job_id": job_id, **value})
                self.failed.set()
                if failure == "lease_lost":
                    from vgen.protocol import VGenError

                    raise VGenError(ErrorCode.MAINTENANCE_LEASE_LOST)
                return {"ok": True, "cancelled": True}
            return super().heartbeat_maintenance(job_id, **value)

    gateway = FailingRenewalGateway()
    monkeypatch.setattr("vgen.worker.maintenance._LEASE_RENEW_INTERVAL_SECONDS", 0.001)

    def slow_probe() -> None:
        assert gateway.failed.wait(timeout=1)

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(activation_probe=slow_probe)

    assert outcome is not None and outcome.rollback_required
    assert not outcome.succeeded
    assert gateway.heartbeats[-1]["state"] == "restarting"
    assert gateway.completions == []


def test_pending_update_activation_probe_failure_rolls_back(tmp_path: Path) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = FakeGateway()

    def unavailable() -> None:
        raise RuntimeError("new runtime cannot announce")

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update(activation_probe=unavailable)

    assert outcome is not None and not outcome.succeeded
    assert outcome.rollback_required
    assert outcome.error_code == int(ErrorCode.UPDATE_ACTIVATION_FAILED)
    assert not updater.rolled_back
    assert not updater.succeeded
    assert gateway.completions == []


def test_previous_runtime_reports_failed_activation_before_clearing_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pointer = {
        "pending_job_id": "mtn_test",
        "pending_fencing_token": 4,
        "active_version": "0.2.0",
        "artifact_sha256": "a" * 64,
    }
    updater = FakeUpdater(tmp_path, pointer)
    _, credentials = signed_job(
        {
            "kind": "worker_update",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
            "artifact_size": 1,
            "apply": "on_idle",
        }
    )
    gateway = FakeGateway()
    monkeypatch.setenv("VGEN_WORKER_UPDATE_ROLLBACK", "1")

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
    ).recover_pending_update()

    assert outcome is not None and not outcome.succeeded
    assert outcome.mode == "maintenance_update_rolled_back"
    assert updater.rolled_back
    assert gateway.completions[-1]["succeeded"] is False
    assert gateway.completions[-1]["result"]["status"] == "rolled_back"


def test_cancelled_update_resets_pending_pointer_and_never_activates(tmp_path: Path) -> None:
    wheel = b"reviewed wheel"
    digest = hashlib.sha256(wheel).hexdigest()
    spec = {
        "kind": "worker_update",
        "target_version": "0.2.0",
        "artifact_sha256": digest,
        "artifact_size": len(wheel),
        "apply": "on_idle",
    }
    job, credentials = signed_job(spec)
    updater = FakeUpdater(tmp_path)
    updater.download_root.mkdir(parents=True)
    (updater.download_root / f"vgen-0.2.0-{digest[:16]}.whl").write_bytes(wheel)
    job["ticket"] = TransferTicket(
        "https://gateway.example.test/update",
        "GET",
        expected_size=len(wheel),
        expected_sha256=digest,
    )
    gateway = FakeGateway(job, cancel_state="restarting")

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).run_one()

    assert outcome is not None and outcome.mode == "maintenance_cancelled"
    assert not outcome.restart_required
    assert updater.rolled_back
    assert gateway.completions == []


def test_update_ticket_resolving_to_private_network_is_rejected(tmp_path: Path) -> None:
    wheel = b"reviewed wheel"
    digest = hashlib.sha256(wheel).hexdigest()
    spec = {
        "kind": "worker_update",
        "target_version": "0.2.0",
        "artifact_sha256": digest,
        "artifact_size": len(wheel),
        "apply": "on_idle",
    }
    job, credentials = signed_job(spec)
    job["ticket"] = TransferTicket(
        "https://storage.example.test/update",
        "GET",
        expected_size=len(wheel),
        expected_sha256=digest,
    )
    updater = FakeUpdater(tmp_path)
    gateway = FakeGateway(job)

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
        ticket_resolver=lambda _host, _port: ("10.0.0.8",),
    ).run_one()

    assert outcome is not None and not outcome.succeeded
    assert outcome.error_code == int(ErrorCode.MAINTENANCE_POLICY_DENIED)
    assert updater.staged is None
    assert gateway.completions[-1]["result"]["error_code"] == int(
        ErrorCode.MAINTENANCE_POLICY_DENIED
    )


def test_model_failure_reports_models_already_installed_by_the_same_job(
    tmp_path: Path,
) -> None:
    first = SimpleNamespace(
        path="vae/first.safetensors",
        sha256="1" * 64,
        size=10,
        source="https://models.example.test/rev/first",
        revision="rev",
        license="Apache-2.0",
        license_url="https://licenses.example.test/apache",
        gated=False,
        manual_download=False,
    )
    second = SimpleNamespace(
        **{**vars(first), "path": "vae/second.safetensors", "sha256": "2" * 64}
    )
    spec = {
        "kind": "model_install",
        "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
        "workflow_digest": "sha256:" + "b" * 64,
        "model_digests": ["sha256:" + first.sha256, "sha256:" + second.sha256],
    }
    job, credentials = signed_job(spec)
    gateway = FakeGateway(job)
    installer = FakeInstaller(fail_digest=second.sha256)

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor((first, second)),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=tmp_path,
        model_installer=installer,  # type: ignore[arg-type]
    ).run_one()

    assert outcome is not None and not outcome.succeeded
    result = gateway.completions[-1]["result"]
    assert result["installed_model_digests"] == ["sha256:" + first.sha256]
    assert result["failed_model_digest"] == "sha256:" + second.sha256
