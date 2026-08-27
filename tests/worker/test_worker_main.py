from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import vgen.worker.main as worker_main_module
from vgen.crypto import DeviceKeys, b64url_encode
from vgen.executors import ExecutorDescriptor, ExecutorHealth
from vgen.worker import LeaseReference, WorkerCredentials, save_worker_credentials_file
from vgen.worker.main import (
    EXIT_CONFIG,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_UPDATE_RESTART,
    EXIT_UPDATE_ROLLBACK,
    _build_gateway,
    _executor_status,
    run,
    run_entrypoint,
)
from vgen.worker.maintenance import MaintenanceOutcome


class FakeExecutor:
    def __init__(self, *, healthy: bool = True) -> None:
        self.healthy = healthy

    def descriptor(self) -> ExecutorDescriptor:
        return ExecutorDescriptor("fake", "1.0.0", ("fake/v1",), ("t2v",))

    def health(self) -> ExecutorHealth:
        return ExecutorHealth(self.healthy, "ready" if self.healthy else "offline")

    def capabilities(self) -> dict[str, Any]:
        return {"gpu_count": 1}

    def execute(self, request: Any, context: Any) -> Any:
        raise NotImplementedError

    def cancel(self, handle: str | None = None) -> None:
        return None


def test_worker_gateway_enables_attempt_progress_reporting() -> None:
    arguments = SimpleNamespace(
        gateway_url="https://gateway.example.test",
        lease_ttl=60,
        allow_http=False,
        session_token_file=None,
    )

    gateway = _build_gateway(
        arguments,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
        SimpleNamespace(),  # type: ignore[arg-type]
    )

    assert gateway._report_progress is True


def test_doctor_outputs_machine_readable_executor_status(capsys: Any) -> None:
    exit_code = run(["doctor", "--json"], executor_factory=lambda _arguments: FakeExecutor())
    assert exit_code == EXIT_OK
    status = json.loads(capsys.readouterr().out)
    assert status["ok"] is True
    assert status["executor"]["type"] == "fake"
    assert status["executor"]["capabilities"] == {"gpu_count": 1}


def test_doctor_can_probe_policy_required_executor_without_execution_policy(
    capsys: Any,
) -> None:
    executor = FakeExecutor()
    executor.requires_execution_policy = True
    executor.execution_policy_configured = False

    exit_code = run(["doctor", "--json"], executor_factory=lambda _arguments: executor)

    assert exit_code == EXIT_OK
    assert json.loads(capsys.readouterr().out)["mode"] == "diagnostic"


def test_doctor_returns_unavailable_for_offline_executor(capsys: Any) -> None:
    exit_code = run(["doctor"], executor_factory=lambda _arguments: FakeExecutor(healthy=False))
    assert exit_code == EXIT_UNAVAILABLE
    assert "health=offline" in capsys.readouterr().out


def test_serve_once_runs_local_readiness_without_announcing(capsys: Any) -> None:
    exit_code = run(
        ["serve", "--once", "--json"],
        executor_factory=lambda _arguments: FakeExecutor(),
    )
    assert exit_code == EXIT_OK
    status = json.loads(capsys.readouterr().out)
    assert status["mode"] == "readiness"
    assert "gateway" not in status


def test_serve_rejects_insecure_remote_gateway(capsys: Any) -> None:
    exit_code = run(
        ["serve", "--once", "--gateway-url", "http://gpu.example.test"],
        executor_factory=lambda _arguments: FakeExecutor(),
    )
    assert exit_code == EXIT_CONFIG
    assert "must use HTTPS" in capsys.readouterr().err


def test_serve_requires_private_session_file_for_announce(tmp_path: Path, capsys: Any) -> None:
    token_file = tmp_path / "worker-token"
    token_file.write_text("secret-token", encoding="utf-8")
    token_file.chmod(0o644)
    exit_code = run(
        [
            "serve",
            "--once",
            "--gateway-url",
            "http://127.0.0.1:8000",
            "--worker-id",
            "wrk_test",
            "--session-token-file",
            str(token_file),
            "--announce",
        ],
        executor_factory=lambda _arguments: FakeExecutor(),
    )
    assert exit_code == EXIT_CONFIG
    assert "mode 0600" in capsys.readouterr().err


def test_serve_once_claims_and_executes_one_authenticated_lease(
    tmp_path: Path, capsys: Any
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    lease = SimpleNamespace(
        reference=LeaseReference("lea_test", "tsk_test", "atm_test", "wrk_test", 1)
    )

    class FakeGateway:
        announced: dict[str, Any] | None = None

        def announce(self, capabilities: dict[str, Any]) -> None:
            self.announced = capabilities

        def poll_lease(self) -> Any:
            return lease

    gateway = FakeGateway()

    class FakeCore:
        def capabilities(self) -> dict[str, Any]:
            return {"executors": [{"type": "fake"}]}

        def resume_pending(self, actual_gateway: Any) -> None:
            assert actual_gateway is gateway
            return None

        def process(self, actual_lease: Any, actual_gateway: Any) -> Any:
            assert actual_lease is lease
            assert actual_gateway is gateway
            return SimpleNamespace(succeeded=True, failure=None)

    exit_code = run(
        [
            "serve",
            "--once",
            "--json",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: FakeExecutor(),
        gateway_factory=lambda _arguments, _credentials, _session: gateway,  # type: ignore[arg-type,return-value]
        core_factory=lambda _arguments, _executor, _session: FakeCore(),  # type: ignore[return-value]
    )
    assert exit_code == EXIT_OK
    status = json.loads(capsys.readouterr().out)
    assert status["mode"] == "executed"
    assert status["attempt_id"] == "atm_test"
    assert status["succeeded"] is True
    assert gateway.announced["executors"][0]["type"] == "fake"
    assert gateway.announced["executors"][0]["capabilities"] == {"gpu_count": 1}
    assert gateway.announced["worker_runtime_version"]
    assert gateway.announced["capability_install_spec_version"] == 2
    assert gateway.announced["node_pack_install_spec_version"] == 1
    assert gateway.announced["maintenance_actions"] == []


def test_worker_refuses_credentials_pinned_to_another_gateway(tmp_path: Path, capsys: Any) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials(
            "wrk_test",
            DeviceKeys.generate(),
            "short-session",
            gateway_url="https://old-gateway.example",
        ),
    )

    exit_code = run(
        [
            "serve",
            "--once",
            "--gateway-url",
            "https://new-gateway.example",
            "--credentials-file",
            str(credential_file),
            "--announce",
        ],
        executor_factory=lambda _arguments: FakeExecutor(),
        gateway_factory=lambda *_arguments: (_ for _ in ()).throw(
            AssertionError("mismatched Gateway must not be contacted")
        ),
    )

    assert exit_code == EXIT_CONFIG
    assert "bound to a different Gateway" in capsys.readouterr().err


def test_authenticated_policyless_serve_starts_in_maintenance_only_mode(
    tmp_path: Path,
    capsys: Any,
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    owner_root = DeviceKeys.generate()
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials(
            "wrk_test",
            DeviceKeys.generate(),
            "short-session",
            owner_root_signing_public_key=b64url_encode(owner_root.signing_public_bytes()),
        ),
    )
    executor = FakeExecutor()
    executor.requires_execution_policy = True
    executor.execution_policy_configured = False
    executor.descriptor = lambda: ExecutorDescriptor(
        "comfyui", "1.2.0", ("comfyui-api-graph/v1",), ("t2v",)
    )
    executor.capabilities = lambda: {
        "capability_schema_version": 2,
        "model_digests": [],
        "ready_workflow_digests": [],
        "workflow_readiness": [],
    }
    events: list[str] = []

    class FakeGateway:
        announced: dict[str, Any] | None = None

        def announce(self, capabilities: dict[str, Any]) -> None:
            events.append("announce")
            self.announced = capabilities

        def poll_lease(self) -> Any:
            raise AssertionError("policyless Worker must not claim inference")

    gateway = FakeGateway()

    class FakeCore:
        def capabilities(self) -> dict[str, Any]:
            return {
                "executors": [
                    {
                        "type": "comfyui",
                        "capabilities": executor.capabilities(),
                    }
                ]
            }

        def resume_pending(self, _gateway: Any) -> None:
            events.append("resume_upload")
            return None

    class FakeMaintenance:
        enabled = True

        def recover_pending_update(self, **_kwargs: Any) -> None:
            events.append("recover_update")
            return None

        def run_one(self) -> None:
            events.append("maintenance")
            return None

    exit_code = run(
        [
            "serve",
            "--once",
            "--json",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: executor,
        gateway_factory=lambda *_arguments: gateway,  # type: ignore[arg-type,return-value]
        core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
        maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
    )

    assert exit_code == EXIT_OK
    assert events == [
        "recover_update",
        "announce",
        "resume_upload",
        "maintenance",
    ]
    assert gateway.announced is not None
    assert gateway.announced["maintenance_actions"] == [
        "worker_update",
        "model_install",
        "capability_install",
        "node_pack_install",
    ]
    assert gateway.announced["executors"][0]["capabilities"] == {
        "capability_schema_version": 2,
        "model_digests": [],
        "ready_workflow_digests": [],
        "workflow_readiness": [],
    }
    assert json.loads(capsys.readouterr().out)["mode"] == "maintenance_only"


def test_comfyui_capability_probe_failure_keeps_v2_fail_closed() -> None:
    executor = FakeExecutor()
    executor.descriptor = lambda: ExecutorDescriptor(
        "comfyui", "1.2.0", ("comfyui-api-graph/v1",), ("t2v",)
    )
    executor.capabilities = lambda: (_ for _ in ()).throw(RuntimeError("probe failed"))

    status = _executor_status(executor)

    assert status["ok"] is False
    assert status["executor"]["health"] == "capability_probe_failed"
    assert status["executor"]["capabilities"] == {
        "capability_schema_version": 2,
        "model_digests": [],
        "ready_workflow_digests": [],
        "workflow_readiness": [],
    }

    executor.capabilities = lambda: {}
    invalid_status = _executor_status(executor)

    assert invalid_status["ok"] is False
    assert invalid_status["executor"]["health"] == "capability_probe_failed"
    assert invalid_status["executor"]["capabilities"]["capability_schema_version"] == 2


def test_cold_comfyui_worker_stays_online_while_model_probe_is_blocked(
    tmp_path: Path,
    capsys: Any,
    monkeypatch: Any,
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    renewed = threading.Event()
    announcements: list[dict[str, Any]] = []
    announce_attempts = 0

    class SlowComfyExecutor(FakeExecutor):
        requires_execution_policy = True
        execution_policy_configured = False

        def descriptor(self) -> ExecutorDescriptor:
            return ExecutorDescriptor("comfyui", "1.2.0", ("comfyui-api-graph/v1",), ("t2v",))

        def capabilities(self) -> dict[str, Any]:
            assert renewed.wait(timeout=1), "startup liveness was not renewed"
            return {
                "capability_schema_version": 2,
                "model_digests": ["sha256:" + "a" * 64],
                "ready_workflow_digests": [],
                "workflow_readiness": [],
            }

    class FakeGateway:
        def announce(self, capabilities: dict[str, Any]) -> None:
            nonlocal announce_attempts
            announce_attempts += 1
            if announce_attempts == 1:
                raise RuntimeError("transient startup transport failure")
            announcements.append(capabilities)
            if announcements:
                renewed.set()

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            return None

    class FakeMaintenance:
        enabled = True

        def recover_pending_update(self, **_kwargs: Any) -> None:
            return None

        def run_one(self) -> None:
            return None

    monkeypatch.setattr(worker_main_module, "_STARTUP_ANNOUNCE_INTERVAL_SECONDS", 0.001)

    exit_code = run(
        [
            "serve",
            "--once",
            "--json",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: SlowComfyExecutor(),
        gateway_factory=lambda *_arguments: FakeGateway(),  # type: ignore[arg-type,return-value]
        core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
        maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
    )

    assert exit_code == EXIT_OK
    assert announce_attempts >= 3
    assert len(announcements) >= 2
    assert announcements[0]["executors"][0]["capabilities"] == {
        "capability_schema_version": 2,
        "model_digests": [],
        "ready_workflow_digests": [],
        "workflow_readiness": [],
    }
    assert announcements[-1]["executors"][0]["capabilities"]["model_digests"] == [
        "sha256:" + "a" * 64
    ]
    assert json.loads(capsys.readouterr().out)["mode"] == "maintenance_only"


def test_ready_snapshot_is_not_replaced_by_empty_readiness_on_next_loop(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    stop_handler: list[Any] = []
    monkeypatch.setattr(
        worker_main_module.signal,
        "signal",
        lambda _signal, handler: stop_handler.append(handler),
    )
    executor = FakeExecutor()
    executor.requires_execution_policy = True
    executor.execution_policy_configured = False
    executor.descriptor = lambda: ExecutorDescriptor(
        "comfyui", "1.2.0", ("comfyui-api-graph/v1",), ("t2v",)
    )
    ready_digest = "sha256:" + "a" * 64
    executor.capabilities = lambda: {
        "capability_schema_version": 2,
        "model_digests": [ready_digest],
        "ready_workflow_digests": [ready_digest],
        "workflow_readiness": [
            {
                "workflow_ref": "vgen/test@1.0.0",
                "workflow_digest": ready_digest,
                "state": "ready",
                "missing_model_digests": [],
                "missing_node_classes": [],
            }
        ],
    }
    announcements: list[dict[str, Any]] = []

    class FakeGateway:
        def announce(self, capabilities: dict[str, Any]) -> None:
            announcements.append(capabilities)
            if len(announcements) == 3:
                stop_handler[-1](0, None)

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            return None

    class FakeMaintenance:
        enabled = True

        def recover_pending_update(self, **_kwargs: Any) -> None:
            return None

        def run_one(self) -> None:
            return None

    exit_code = run(
        [
            "serve",
            "--json",
            "--interval",
            "0.001",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: executor,
        gateway_factory=lambda *_arguments: FakeGateway(),  # type: ignore[arg-type,return-value]
        core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
        maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
    )

    assert exit_code == EXIT_OK
    reported = [item["executors"][0]["capabilities"] for item in announcements]
    assert reported[0]["workflow_readiness"] == []
    assert reported[1]["ready_workflow_digests"] == [ready_digest]
    assert reported[2]["ready_workflow_digests"] == [ready_digest]


def test_serve_retries_spooled_upload_before_polling_new_lease(tmp_path: Path, capsys: Any) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )

    class FakeGateway:
        def announce(self, capabilities: dict[str, Any]) -> None:
            return None

        def poll_lease(self) -> Any:
            raise AssertionError("new work must not be polled before upload recovery")

    gateway = FakeGateway()

    class FakeCore:
        def capabilities(self) -> dict[str, Any]:
            return {"executors": []}

        def resume_pending(self, actual_gateway: Any) -> Any:
            assert actual_gateway is gateway
            return SimpleNamespace(succeeded=True, failure=None)

    assert (
        run(
            [
                "serve",
                "--once",
                "--json",
                "--gateway-url",
                "https://gateway.example.test",
                "--credentials-file",
                str(credential_file),
            ],
            executor_factory=lambda _arguments: FakeExecutor(),
            gateway_factory=lambda _arguments, _credentials, _session: gateway,  # type: ignore[arg-type,return-value]
            core_factory=lambda _arguments, _executor, _session: FakeCore(),  # type: ignore[return-value]
        )
        == EXIT_OK
    )
    assert json.loads(capsys.readouterr().out)["mode"] == "upload_resumed"


def test_unhealthy_executor_still_announces_and_runs_maintenance(
    tmp_path: Path, capsys: Any
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    owner_root = DeviceKeys.generate()
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials(
            "wrk_test",
            DeviceKeys.generate(),
            "short-session",
            owner_root_signing_public_key=b64url_encode(owner_root.signing_public_bytes()),
        ),
    )
    events: list[str] = []
    executor = FakeExecutor(healthy=False)
    executor.descriptor = lambda: ExecutorDescriptor(
        "comfyui", "1.2.0", ("comfyui-api-graph/v1",), ("t2v",)
    )
    executor.requires_execution_policy = True
    executor.execution_policy_configured = True

    class FakeGateway:
        def announce(self, capabilities: dict[str, Any]) -> None:
            events.append("announce")
            assert capabilities["maintenance_actions"] == [
                "worker_update",
                "model_install",
                "capability_install",
                "node_pack_install",
            ]
            assert capabilities["executors"][0]["capabilities"] == {
                "capability_schema_version": 2,
                "model_digests": [],
                "ready_workflow_digests": [],
                "workflow_readiness": [],
            }

        def poll_lease(self) -> Any:
            raise AssertionError("inference must not be leased while the executor is unhealthy")

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            events.append("resume_upload")
            return None

    class FakeMaintenance:
        enabled = True

        def recover_pending_update(self, **_kwargs: Any) -> None:
            events.append("recover_update")
            return None

        def run_one(self) -> MaintenanceOutcome:
            events.append("maintenance")
            return MaintenanceOutcome("maintenance_models_installed", True, job_id="mtn_test")

    exit_code = run(
        [
            "serve",
            "--once",
            "--json",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: executor,
        gateway_factory=lambda *_arguments: FakeGateway(),  # type: ignore[arg-type,return-value]
        core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
        maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
    )

    assert exit_code == EXIT_UNAVAILABLE
    assert events == [
        "recover_update",
        "announce",
        "resume_upload",
        "maintenance",
    ]
    status = json.loads(capsys.readouterr().out)
    assert status["mode"] == "maintenance_models_installed"
    assert status["maintenance_succeeded"] is True


def test_pending_update_requests_supervisor_restart_before_other_work(
    tmp_path: Path, capsys: Any
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    events: list[str] = []

    class FakeMaintenance:
        def recover_pending_update(self, **_kwargs: Any) -> MaintenanceOutcome:
            events.append("recover_update")
            return MaintenanceOutcome(
                "maintenance_update_restart", True, restart_required=True, job_id="mtn_test"
            )

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            raise AssertionError("upload recovery must wait for the target runtime")

    assert (
        run(
            [
                "serve",
                "--once",
                "--json",
                "--gateway-url",
                "https://gateway.example.test",
                "--credentials-file",
                str(credential_file),
            ],
            executor_factory=lambda _arguments: FakeExecutor(),
            gateway_factory=lambda *_arguments: SimpleNamespace(),  # type: ignore[arg-type,return-value]
            core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
            maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
        )
        == EXIT_UPDATE_RESTART
    )
    assert events == ["recover_update"]
    assert json.loads(capsys.readouterr().out)["mode"] == "maintenance_update_restart"


def test_completed_old_target_yields_to_newer_supervisor_base(
    tmp_path: Path, capsys: Any, monkeypatch: Any
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    events: list[str] = []

    class FakeMaintenance:
        def recover_pending_update(self, **_kwargs: Any) -> MaintenanceOutcome:
            events.append("recover_update")
            return MaintenanceOutcome("maintenance_update_activated", True, job_id="mtn_test")

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            raise AssertionError("the newer base must start before other work")

    monkeypatch.setattr(worker_main_module, "__version__", "0.13.9")
    monkeypatch.setenv("VGEN_WORKER_SUPERVISOR_BASE_VERSION", "0.13.10")

    assert (
        run(
            [
                "serve",
                "--once",
                "--json",
                "--gateway-url",
                "https://gateway.example.test",
                "--credentials-file",
                str(credential_file),
            ],
            executor_factory=lambda _arguments: FakeExecutor(),
            gateway_factory=lambda *_arguments: SimpleNamespace(),  # type: ignore[arg-type,return-value]
            core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
            maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
        )
        == EXIT_UPDATE_RESTART
    )
    assert events == ["recover_update"]
    status = json.loads(capsys.readouterr().out)
    assert status["mode"] == "maintenance_update_superseded"
    assert status["maintenance_succeeded"] is True


def test_pending_activation_uses_main_gateway_announce_callback(
    tmp_path: Path, capsys: Any
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    executor = FakeExecutor()
    executor.requires_execution_policy = True
    executor.execution_policy_configured = False
    executor.descriptor = lambda: ExecutorDescriptor(
        "comfyui", "1.2.0", ("comfyui-api-graph/v1",), ("t2v",)
    )
    executor.capabilities = lambda: {
        "capability_schema_version": 2,
        "model_digests": ["sha256:" + "a" * 64],
        "ready_workflow_digests": [],
        "workflow_readiness": [],
    }
    announcements: list[dict[str, Any]] = []

    class FakeGateway:
        def announce(self, capabilities: dict[str, Any]) -> None:
            announcements.append(capabilities)

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            return None

    class FakeMaintenance:
        enabled = True

        def recover_pending_update(self, **callbacks: Any) -> MaintenanceOutcome:
            capabilities = callbacks["activation_probe"]()
            callbacks["activation_announce"](capabilities)
            return MaintenanceOutcome("maintenance_update_activated", True, job_id="mtn_test")

        def run_one(self) -> None:
            return None

    exit_code = run(
        [
            "serve",
            "--once",
            "--json",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: executor,
        gateway_factory=lambda *_arguments: FakeGateway(),  # type: ignore[arg-type,return-value]
        core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
        maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
    )

    assert exit_code == EXIT_OK
    assert len(announcements) == 2
    assert announcements[0]["executors"][0]["capabilities"]["model_digests"] == []
    assert announcements[-1]["executors"][0]["capabilities"]["model_digests"] == [
        "sha256:" + "a" * 64
    ]
    assert json.loads(capsys.readouterr().out)["maintenance_succeeded"] is True


def test_pending_update_cleanup_does_not_block_worker_announce(tmp_path: Path, capsys: Any) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    events: list[str] = []

    class FakeGateway:
        def announce(self, _capabilities: dict[str, Any]) -> None:
            events.append("announce")

        def poll_lease(self) -> None:
            events.append("poll")
            return None

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            events.append("resume_upload")
            return None

    class FakeMaintenance:
        enabled = True

        def recover_pending_update(self, **_kwargs: Any) -> MaintenanceOutcome:
            events.append("recover_update")
            return MaintenanceOutcome("maintenance_update_cleanup_pending", True, job_id="mtn_test")

        def run_one(self) -> None:
            events.append("maintenance")
            return None

    assert (
        run(
            [
                "serve",
                "--once",
                "--json",
                "--gateway-url",
                "https://gateway.example.test",
                "--credentials-file",
                str(credential_file),
            ],
            executor_factory=lambda _arguments: FakeExecutor(),
            gateway_factory=lambda *_arguments: FakeGateway(),  # type: ignore[arg-type,return-value]
            core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
            maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
        )
        == EXIT_OK
    )
    assert events == [
        "recover_update",
        "announce",
        "resume_upload",
        "announce",
        "maintenance",
        "poll",
    ]
    status = json.loads(capsys.readouterr().out)
    assert status["maintenance_succeeded"] is True


def test_failed_target_activation_requests_supervisor_rollback(tmp_path: Path, capsys: Any) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )

    class FakeMaintenance:
        def recover_pending_update(self, **_kwargs: Any) -> MaintenanceOutcome:
            return MaintenanceOutcome(
                "maintenance_update_activation_failed",
                False,
                rollback_required=True,
                job_id="mtn_test",
            )

    assert (
        run(
            [
                "serve",
                "--once",
                "--json",
                "--gateway-url",
                "https://gateway.example.test",
                "--credentials-file",
                str(credential_file),
            ],
            executor_factory=lambda _arguments: FakeExecutor(),
            gateway_factory=lambda *_arguments: SimpleNamespace(),  # type: ignore[arg-type,return-value]
            core_factory=lambda *_arguments: SimpleNamespace(),  # type: ignore[arg-type,return-value]
            maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
        )
        == EXIT_UPDATE_ROLLBACK
    )
    assert json.loads(capsys.readouterr().out)["mode"] == ("maintenance_update_activation_failed")


def test_foreground_serve_uses_builtin_supervisor(tmp_path: Path, monkeypatch: Any) -> None:
    calls: list[tuple[list[str], Path]] = []

    def fake_supervisor(argv: list[str], *, work_root: Path) -> int:
        calls.append((argv, work_root))
        return 23

    monkeypatch.setattr("vgen.worker.main.supervise_worker", fake_supervisor)

    assert run_entrypoint(["serve", "--work-root", str(tmp_path), "--json"]) == 23
    assert calls == [(["serve", "--work-root", str(tmp_path), "--json"], tmp_path)]
