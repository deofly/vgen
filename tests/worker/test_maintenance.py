from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vgen.artifacts import TransferTicket
from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    build_maintenance_intent_payload,
    derive_identity_keys,
    issue_device_certificate,
    sign_maintenance_intent,
)
from vgen.protocol import ErrorCode
from vgen.worker import WorkerCredentials
from vgen.worker.maintenance import (
    WorkerMaintenanceController,
    _capability_error_code,
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

    def mark_activation_succeeded(self, _pointer: dict[str, Any]) -> None:
        self.succeeded = True

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
def test_model_failures_use_dedicated_maintenance_codes(
    reason: str, expected: ErrorCode
) -> None:
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
def test_update_failures_use_dedicated_maintenance_codes(
    reason: str, expected: ErrorCode
) -> None:
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


def test_new_target_refreshes_launcher_and_requests_outer_restart(tmp_path: Path) -> None:
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
    launcher = tmp_path / "start-worker.cmd"
    launcher.write_text("reviewed", encoding="utf-8")
    restarted: list[Path] = []

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        FakeExecutor(SimpleNamespace()),  # type: ignore[arg-type]
        work_root=tmp_path / "work",
        model_root=None,
        updater=updater,  # type: ignore[arg-type]
        support_refresher=lambda: launcher,
        launcher_restarter=restarted.append,
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).recover_pending_update()

    assert outcome is not None and outcome.succeeded
    assert outcome.launcher_restart_required
    assert outcome.mode == "maintenance_support_restart"
    assert restarted == [launcher]
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
