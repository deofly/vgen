from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from vgen.crypto import DeviceKeys
from vgen.executors import ExecutorDescriptor, ExecutorHealth
from vgen.worker import LeaseReference, WorkerCredentials, save_worker_credentials_file
from vgen.worker.main import (
    EXIT_CONFIG,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_UPDATE_RESTART,
    run,
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
    assert gateway.announced == {"executors": [{"type": "fake"}]}


def test_worker_refuses_credentials_pinned_to_another_gateway(
    tmp_path: Path, capsys: Any
) -> None:
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


def test_authenticated_serve_rejects_policy_required_executor_without_local_policy(
    tmp_path: Path,
    capsys: Any,
) -> None:
    credential_file = tmp_path / "worker-credentials.json"
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    executor = FakeExecutor()
    executor.requires_execution_policy = True
    executor.execution_policy_configured = False

    exit_code = run(
        [
            "serve",
            "--once",
            "--gateway-url",
            "https://gateway.example.test",
            "--credentials-file",
            str(credential_file),
        ],
        executor_factory=lambda _arguments: executor,
        gateway_factory=lambda *_arguments: (_ for _ in ()).throw(
            AssertionError("Gateway must not be contacted without a local policy")
        ),
    )

    assert exit_code == EXIT_CONFIG
    assert "requires --comfy-policy-file" in capsys.readouterr().err


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
    save_worker_credentials_file(
        credential_file,
        WorkerCredentials("wrk_test", DeviceKeys.generate(), "short-session"),
    )
    events: list[str] = []

    class FakeGateway:
        def announce(self, capabilities: dict[str, Any]) -> None:
            events.append("announce")
            assert capabilities["executors"][0]["capabilities"] == {}

        def poll_lease(self) -> Any:
            raise AssertionError("inference must not be leased while the executor is unhealthy")

    class FakeCore:
        def resume_pending(self, _gateway: Any) -> None:
            events.append("resume_upload")
            return None

    class FakeMaintenance:
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
        executor_factory=lambda _arguments: FakeExecutor(healthy=False),
        gateway_factory=lambda *_arguments: FakeGateway(),  # type: ignore[arg-type,return-value]
        core_factory=lambda *_arguments: FakeCore(),  # type: ignore[arg-type,return-value]
        maintenance_factory=lambda *_arguments: FakeMaintenance(),  # type: ignore[arg-type,return-value]
    )

    assert exit_code == EXIT_UNAVAILABLE
    assert events == ["recover_update", "announce", "resume_upload", "maintenance"]
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
