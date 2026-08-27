from __future__ import annotations

import hashlib
import io
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest
import requests

from vgen.artifacts import ArtifactAdapterRegistry, LocalArtifactAdapter
from vgen.crypto import (
    DeviceKeys,
    b64url_decode,
    decrypt_stream,
    encrypt_payload,
    encrypt_stream,
    generate_task_data_key,
    task_aad,
    verify_http_request,
    verify_message,
    wrap_task_key,
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
from vgen.protocol import ErrorCode, RetryAction, VGenError
from vgen.worker import (
    GatewayUnavailableError,
    GatewayV1Client,
    LeaseLostError,
    LeaseReference,
    WorkerCore,
    WorkerCredentials,
    WorkerFailureReport,
)


def response(status: int, value: Any | None = None) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = b"" if value is None else json.dumps(value).encode("utf-8")
    return result


class RecordingSession:
    def __init__(self, lease: Mapping[str, Any] | None = None) -> None:
        self.lease = lease
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.lease_delivered = False

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.requests.append((method, url, kwargs))
        path = urlparse(url).path
        if path.endswith("/lease"):
            if self.lease_delivered or self.lease is None:
                return response(204)
            self.lease_delivered = True
            return response(200, self.lease)
        if path.endswith("/finish"):
            return response(200, {"state": "succeeded"})
        if path.endswith("/heartbeat"):
            return response(200, {"ok": True, "expires_at": 4_000_000_000})
        raise AssertionError(f"unexpected path: {path}")


class LegacyFinishSession(RecordingSession):
    def __init__(self) -> None:
        super().__init__()
        self.finish_count = 0

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        path = urlparse(url).path
        if not path.endswith("/finish"):
            return super().request(method, url, **kwargs)
        self.requests.append((method, url, kwargs))
        self.finish_count += 1
        if self.finish_count == 1:
            return response(
                422,
                {
                    "error": {
                        "code": int(ErrorCode.USAGE_REPORT_INVALID),
                        "details": {"reason": "failure_code_unregistered"},
                    }
                },
            )
        return response(200, {"state": "failed"})


class FakeEncryptedExecutor:
    def descriptor(self) -> ExecutorDescriptor:
        return ExecutorDescriptor("fake", "1.0.0", ("opaque/v1",), ("i2v",))

    def health(self) -> ExecutorHealth:
        return ExecutorHealth(True, "ready")

    def capabilities(self) -> Mapping[str, Any]:
        return {"gpu_count": 1}

    def execute(self, request: ExecutionRequest, context: ExecutionContext) -> ExecutionResult:
        assert request.payload == b'{"prompt":"private prompt"}'
        assert request.inputs[0].path.read_bytes() == b"private first frame"
        context.progress(0.5, "sampling")
        output = context.work_dir / "private-result.bin"
        output.write_bytes(b"private generated result")
        return ExecutionResult(
            (ExecutionArtifact("primary", output, "application/octet-stream"),),
            usage=UsageMetrics(gpu_active_ms=1250, denoise_steps=8),
            executor_run_id="run_private",
        )

    def cancel(self, handle: str | None = None) -> None:
        return None


def encrypted_lease(tmp_path: Path, keys: DeviceKeys) -> tuple[dict[str, Any], bytes]:
    task_key = generate_task_data_key()
    payload_aad = task_aad(
        workspace_id="wsp_contract",
        task_id="tsk_contract",
        attempt_id="atm_contract",
        artifact_id="payload",
        key_version=3,
    )
    payload = encrypt_payload(task_key, b'{"prompt":"private prompt"}', aad=payload_aad)
    wrapped = wrap_task_key(keys.encryption_public_key, task_key, aad=payload_aad)

    input_aad = task_aad(
        workspace_id="wsp_contract",
        task_id="tsk_contract",
        attempt_id="atm_contract",
        artifact_id="art_input",
        key_version=3,
    )
    encrypted_input = tmp_path / "encrypted-input.vgen"
    with io.BytesIO(b"private first frame") as source, encrypted_input.open("wb") as target:
        encrypt_stream(source, target, task_key, aad=input_aad)
    input_bytes = encrypted_input.read_bytes()
    output = tmp_path / "encrypted-output.vgen"
    return (
        {
            "lease_id": "lea_contract",
            "task_id": "tsk_contract",
            "attempt_id": "atm_contract",
            "fencing_token": 9,
            "expires_at": 4_000_000_000,
            "workspace_id": "wsp_contract",
            "executor_type": "fake",
            "payload_format": "opaque/v1",
            "operation": "i2v",
            "key_version": 3,
            "workflow_digest": "sha256:" + "a" * 64,
            "encrypted_payload": json.dumps(payload.to_dict()),
            "encrypted_tdk_envelope": json.dumps(wrapped.to_dict()),
            "artifacts": [
                {
                    "id": "art_input",
                    "kind": "first_frame",
                    "media_metadata": {
                        "filename": "first-frame.png",
                        "media_type": "image/png",
                    },
                }
            ],
            "artifact_download_tickets": [
                {
                    "artifact_id": "art_input",
                    "name": "first_frame",
                    "ticket": {
                        "url": encrypted_input.as_uri(),
                        "method": "GET",
                        "expected_size": len(input_bytes),
                        "expected_sha256": hashlib.sha256(input_bytes).hexdigest(),
                    },
                }
            ],
            "output_upload_tickets": [
                {
                    "artifact_id": "art_output",
                    "name": "primary",
                    "filename": "result.bin",
                    "media_type": "application/octet-stream",
                    "kind": "video",
                    "store_type": "local",
                    "object_ref": "objects/result-contract",
                    "ticket": {"url": output.as_uri(), "method": "PUT"},
                }
            ],
        },
        task_key,
    )


def test_gateway_wire_is_decrypted_only_in_worker_and_results_are_reencrypted(
    tmp_path: Path,
) -> None:
    keys = DeviceKeys.generate()
    wire, task_key = encrypted_lease(tmp_path, keys)
    serialized_wire = json.dumps(wire)
    assert "private prompt" not in serialized_wire
    assert "private first frame" not in serialized_wire

    session = RecordingSession(wire)
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    lease = client.poll_lease()
    assert lease is not None
    assert lease.payload.data == b'{"prompt":"private prompt"}'
    core = WorkerCore(
        ExecutorRegistry(FakeEncryptedExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        work_root=tmp_path / "work",
    )
    outcome = core.process(lease, client)
    assert outcome.succeeded

    output_path = tmp_path / "encrypted-output.vgen"
    assert b"private generated result" not in output_path.read_bytes()
    output_aad = task_aad(
        workspace_id="wsp_contract",
        task_id="tsk_contract",
        attempt_id="atm_contract",
        artifact_id="art_output",
        key_version=3,
    )
    plaintext = io.BytesIO()
    with output_path.open("rb") as encrypted:
        decrypt_stream(encrypted, plaintext, task_key, aad=output_aad)
    assert plaintext.getvalue() == b"private generated result"

    for method, url, kwargs in session.requests:
        body = kwargs["data"]
        headers = kwargs["headers"]
        assert headers["Vgen-Protocol-Version"] == "1"
        verify_http_request(
            keys.signing_public_key,
            method=method,
            path=urlparse(url).path,
            body=body,
            headers=headers,
            expected_key_id=keys.key_id,
        )
        assert "private prompt" not in body.decode("utf-8")
        assert "file://" not in body.decode("utf-8")
    finish_body = json.loads(session.requests[-1][2]["data"])
    assert finish_body["fencing_token"] == 9
    assert finish_body["metrics"]["gpu_active_ms"] == 1250
    assert finish_body["output_artifacts"][0]["object_ref"] == "objects/result-contract"
    assert finish_body["output_artifacts"][0]["media_metadata"] == {
        "media_type": "application/octet-stream"
    }
    assert finish_body["worker_signature"]


def test_cancel_failure_signs_measured_usage_for_gateway_billing() -> None:
    keys = DeviceKeys.generate()
    session = RecordingSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    reference = LeaseReference("lea_cancel", "tsk_cancel", "atm_cancel", "wrk_contract", 11)
    client.fail(
        reference,
        WorkerFailureReport(
            code=ErrorCode.EXECUTION_CANCELLED,
            name="EXECUTION_CANCELLED",
            message="Execution was cancelled.",
            retry_action=RetryAction.NONE,
            responsibility="consumer",
            occurred_after_start=True,
            usage=UsageMetrics(
                executor_wall_ms=1_250,
                gpu_active_ms=1_100,
                gpu_count=1,
                input_bytes=256,
            ),
        ),
    )

    finish_body = json.loads(session.requests[-1][2]["data"])
    assert finish_body["succeeded"] is False
    assert finish_body["failure_code"] == int(ErrorCode.EXECUTION_CANCELLED)
    assert finish_body["responsibility"] == "consumer"
    assert finish_body["metrics"] == {
        "executor_wall_ms": 1_250,
        "gpu_active_ms": 1_100,
        "gpu_count": 1,
        "input_bytes": 256,
        "output_bytes": 0,
    }
    signature = finish_body.pop("worker_signature")
    assert verify_message(
        keys.signing_public_key,
        json.dumps(
            {
                "attempt_id": reference.attempt_id,
                "task_id": reference.task_id,
                "worker_id": reference.worker_id,
                **finish_body,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
        b64url_decode(signature, expected_length=64),
        context=b"vgen-worker-finish-v1",
    )


def test_worker_binds_system_oom_diagnostics_and_drops_native_usage() -> None:
    keys = DeviceKeys.generate()
    session = RecordingSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    reference = LeaseReference("lea_oom", "tsk_oom", "atm_oom", "wrk_contract", 12)
    client.fail(
        reference,
        WorkerFailureReport(
            code=ErrorCode.SYSTEM_OUT_OF_MEMORY,
            name="SYSTEM_OUT_OF_MEMORY",
            message="System memory exhausted.",
            retry_action=RetryAction.ANOTHER_WORKER,
            responsibility="provider",
            occurred_after_start=True,
            details={
                "reason": "system_out_of_memory",
                "component": "sampler",
                "phase": "executing",
                "status_code": 507,
                "prompt": "private prompt",
            },
            usage=UsageMetrics(native={"private_prompt_bits": 12345}),
        ),
    )

    finish_body = json.loads(session.requests[-1][2]["data"])
    assert finish_body["failure_code"] == int(ErrorCode.SYSTEM_OUT_OF_MEMORY)
    assert finish_body["responsibility"] == "provider"
    assert finish_body["safe_failure_details"] == {
        "reason": "system_out_of_memory",
        "component": "sampler",
    }
    assert "native" not in finish_body["metrics"]


def test_system_oom_finish_falls_back_only_for_a_legacy_gateway_registry() -> None:
    keys = DeviceKeys.generate()
    session = LegacyFinishSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    reference = LeaseReference("lea_oom", "tsk_oom", "atm_oom", "wrk_contract", 12)

    client.fail(
        reference,
        WorkerFailureReport(
            code=ErrorCode.SYSTEM_OUT_OF_MEMORY,
            name="SYSTEM_OUT_OF_MEMORY",
            message="System memory exhausted.",
            retry_action=RetryAction.ANOTHER_WORKER,
            responsibility="provider",
            occurred_after_start=True,
            details={"reason": "system_out_of_memory", "component": "sampler"},
            usage=UsageMetrics(executor_wall_ms=42),
        ),
    )

    assert session.finish_count == 2
    first = json.loads(session.requests[0][2]["data"])
    fallback = json.loads(session.requests[1][2]["data"])
    assert first["failure_code"] == int(ErrorCode.SYSTEM_OUT_OF_MEMORY)
    assert first["responsibility"] == "provider"
    assert fallback["failure_code"] == int(ErrorCode.INTERNAL_ERROR)
    assert fallback["responsibility"] == "platform"
    assert fallback["safe_failure_details"] == {}
    assert (
        session.requests[0][2]["headers"]["Idempotency-Key"]
        == (session.requests[1][2]["headers"]["Idempotency-Key"])
    )
    for request_body in (first, fallback):
        signature = request_body.pop("worker_signature")
        assert verify_message(
            keys.signing_public_key,
            json.dumps(
                {
                    "attempt_id": reference.attempt_id,
                    "task_id": reference.task_id,
                    "worker_id": reference.worker_id,
                    **request_body,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            b64url_decode(signature, expected_length=64),
            context=b"vgen-worker-finish-v1",
        )


def test_retry_unwraps_for_current_attempt_but_decrypts_original_content(
    tmp_path: Path,
) -> None:
    keys = DeviceKeys.generate()
    wire, task_key = encrypted_lease(tmp_path, keys)
    wire["lease_id"] = "lea_retry"
    wire["attempt_id"] = "atm_retry"
    wire["content_attempt_id"] = "atm_contract"
    retry_wrap_aad = task_aad(
        workspace_id="wsp_contract",
        task_id="tsk_contract",
        attempt_id="atm_retry",
        artifact_id="payload",
        key_version=3,
    )
    wire["encrypted_tdk_envelope"] = json.dumps(
        wrap_task_key(keys.encryption_public_key, task_key, aad=retry_wrap_aad).to_dict()
    )
    session = RecordingSession(wire)
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    lease = client.poll_lease()
    assert lease is not None
    assert lease.crypto is not None
    assert lease.crypto.content_attempt_id == "atm_contract"
    core = WorkerCore(
        ExecutorRegistry(FakeEncryptedExecutor()),
        ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,))),
        work_root=tmp_path / "work-retry",
    )
    assert core.process(lease, client).succeeded

    retry_output_aad = task_aad(
        workspace_id="wsp_contract",
        task_id="tsk_contract",
        attempt_id="atm_retry",
        artifact_id="art_output",
        key_version=3,
    )
    plaintext = io.BytesIO()
    with (tmp_path / "encrypted-output.vgen").open("rb") as encrypted:
        decrypt_stream(encrypted, plaintext, task_key, aad=retry_output_aad)
    assert plaintext.getvalue() == b"private generated result"


def test_late_fencing_error_maps_to_lease_lost() -> None:
    class LateSession:
        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            return response(
                409,
                {
                    "error": {
                        "code": 310001,
                        "request_id": "req_late",
                        "retry": {"after_ms": None},
                    }
                },
            )

    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=LateSession(),  # type: ignore[arg-type]
    )
    reference = LeaseReference("lea_1", "tsk_1", "atm_1", "wrk_contract", 5)
    with pytest.raises(LeaseLostError):
        client.heartbeat(reference, ProgressEvent(0.5, "sampling"))


def test_attempt_heartbeat_reports_progress_when_enabled() -> None:
    session = RecordingSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=session,  # type: ignore[arg-type]
        report_progress=True,
    )
    reference = LeaseReference("lea_1", "tsk_1", "atm_1", "wrk_contract", 5)

    client.heartbeat(reference, ProgressEvent(0.57, "sampling"))

    body = json.loads(session.requests[-1][2]["data"])
    assert body["progress"] == {"fraction": 0.57, "stage": "sampling"}


def test_mark_started_preserves_gateway_cancellation_directive() -> None:
    class CancelAtStartSession(RecordingSession):
        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            self.requests.append((method, url, kwargs))
            return response(
                200,
                {"ok": True, "cancelled": True, "expires_at": 4_000_000_000},
            )

    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=CancelAtStartSession(),  # type: ignore[arg-type]
    )
    reference = LeaseReference("lea_1", "tsk_1", "atm_1", "wrk_contract", 5)

    directive = client.mark_started(reference)

    assert directive.cancelled is True
    assert directive.lease_expires_at == 4_000_000_000


def test_invalid_encrypted_payload_is_safely_failed_before_execution(tmp_path: Path) -> None:
    keys = DeviceKeys.generate()
    wire, _task_key = encrypted_lease(tmp_path, keys)
    payload = json.loads(wire["encrypted_payload"])
    first = payload["ciphertext"][0]
    payload["ciphertext"] = ("A" if first != "A" else "B") + payload["ciphertext"][1:]
    wire["encrypted_payload"] = json.dumps(payload)
    session = RecordingSession(wire)
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    with pytest.raises(VGenError) as caught:
        client.poll_lease()
    assert getattr(caught.value, "code", None) == 400001
    finish_body = json.loads(session.requests[-1][2]["data"])
    assert finish_body["succeeded"] is False
    assert finish_body["failure_code"] == 400001
    assert finish_body["responsibility"] == "platform"
    assert "ciphertext" not in json.dumps(finish_body)


def test_network_failure_maps_to_local_700001() -> None:
    class OfflineSession:
        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            raise requests.ConnectionError("sensitive upstream diagnostics")

    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=OfflineSession(),  # type: ignore[arg-type]
    )
    with pytest.raises(GatewayUnavailableError) as caught:
        client.announce({"executors": []})
    assert caught.value.code == 700001
    assert "sensitive" not in str(caught.value)


def test_expired_short_session_is_refreshed_with_worker_key_challenge() -> None:
    keys = DeviceKeys.generate()

    class RefreshSession:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict[str, Any]]] = []
            self.heartbeat_calls = 0

        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            self.requests.append((method, url, kwargs))
            path = urlparse(url).path
            if path.endswith("/workers/wrk_contract/heartbeat"):
                self.heartbeat_calls += 1
                if self.heartbeat_calls == 1:
                    return response(
                        401,
                        {
                            "error": {
                                "code": 100002,
                                "request_id": "req_expired",
                                "retry": {"after_ms": None},
                            }
                        },
                    )
                return response(200, {"ok": True})
            if path.endswith("/auth/challenges"):
                return response(
                    200,
                    {
                        "challenge_id": "chl_worker",
                        "challenge": "signed one time worker challenge",
                        "principal_type": "worker",
                    },
                )
            if path.endswith("/auth/sessions"):
                body = json.loads(kwargs["data"])
                assert body["principal_type"] == "worker"
                assert body["worker_id"] == "wrk_contract"
                assert verify_message(
                    keys.signing_public_key,
                    b"signed one time worker challenge",
                    b64url_decode(body["signature"], expected_length=64),
                )
                return response(
                    200,
                    {
                        "principal_type": "worker",
                        "worker_id": "wrk_contract",
                        "session_token": "refreshed-short-session",
                        "expires_at": 4_000_000_000,
                    },
                )
            raise AssertionError(path)

    session = RefreshSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", keys, "expired-short-session"),
        session=session,  # type: ignore[arg-type]
    )
    assert client.announce({"executors": []})["ok"] is True
    heartbeat_requests = [
        item
        for item in session.requests
        if urlparse(item[1]).path.endswith("/workers/wrk_contract/heartbeat")
    ]
    assert heartbeat_requests[0][2]["headers"]["Authorization"] == ("Bearer expired-short-session")
    assert heartbeat_requests[1][2]["headers"]["Authorization"] == (
        "Bearer refreshed-short-session"
    )
    assert all(
        request[2]["headers"]["Vgen-Protocol-Version"] == "1" for request in session.requests
    )


def test_gateway_maintenance_claim_heartbeat_complete_and_relative_ticket() -> None:
    class MaintenanceSession:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict[str, Any]]] = []

        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            self.requests.append((method, url, kwargs))
            path = urlparse(url).path
            if path.endswith("/claim"):
                return response(
                    200,
                    {
                        "id": "mtn_test",
                        "artifact": {
                            "store_type": "local",
                            "expected_size": 12,
                            "expected_sha256": "a" * 64,
                        },
                        "artifact_download_ticket": {
                            "url": "/api/v1/artifacts/transfer/art_test",
                            "method": "GET",
                            "headers": {"Vgen-Artifact-Ticket": "redacted"},
                            "expected_size": 12,
                            "expected_sha256": "a" * 64,
                        },
                    },
                )
            if path.endswith("/heartbeat"):
                return response(200, {"ok": True})
            if path.endswith("/complete"):
                return response(200, {"state": "succeeded"})
            raise AssertionError(path)

    session = MaintenanceSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=session,  # type: ignore[arg-type]
    )
    job = client.claim_maintenance(ttl_seconds=60)
    assert job is not None
    ticket = client.maintenance_artifact_ticket(job)
    assert ticket.url == "https://gateway.example.test/api/v1/artifacts/transfer/art_test"
    assert ticket.expected_size == 12
    assert ticket.expected_sha256 == "a" * 64
    client.heartbeat_maintenance(
        "mtn_test",
        fencing_token=2,
        state="restarting",
        progress={"stage": "activating", "completed_bytes": 0, "total_bytes": None},
        adopt_restart_session=True,
    )
    client.complete_maintenance(
        "mtn_test",
        fencing_token=2,
        succeeded=True,
        result={
            "kind": "worker_update",
            "status": "activated",
            "target_version": "0.2.0",
            "artifact_sha256": "a" * 64,
        },
    )

    paths = [urlparse(item[1]).path for item in session.requests]
    assert paths == [
        "/api/v1/workers/wrk_contract/maintenance-jobs/claim",
        "/api/v1/workers/wrk_contract/maintenance-jobs/mtn_test/heartbeat",
        "/api/v1/workers/wrk_contract/maintenance-jobs/mtn_test/complete",
    ]
    assert session.requests[0][2]["headers"]["Idempotency-Key"].startswith(
        "worker-maintenance-claim-"
    )
    assert json.loads(session.requests[1][2]["data"])["adopt_restart_session"] is True


def test_maintenance_claim_falls_back_for_legacy_gateway_and_reprobes() -> None:
    class LegacyThenUpgradedSession:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict[str, Any]]] = []
            self.upgraded = False

        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            self.requests.append((method, url, kwargs))
            body = json.loads(kwargs["data"])
            if "supported_actions" in body and not self.upgraded:
                return response(
                    422,
                    {"error": {"code": int(ErrorCode.VALIDATION_FAILED)}},
                )
            return response(204)

    session = LegacyThenUpgradedSession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=session,  # type: ignore[arg-type]
    )

    assert client.claim_maintenance(ttl_seconds=60) is None
    assert [json.loads(item[2]["data"]) for item in session.requests] == [
        {
                "supported_actions": [
                    "worker_update",
                    "model_install",
                    "capability_install",
                    "node_pack_install",
                ],
            "ttl_seconds": 60,
        },
        {"ttl_seconds": 60},
    ]
    assert (
        session.requests[0][2]["headers"]["Idempotency-Key"]
        != session.requests[1][2]["headers"]["Idempotency-Key"]
    )

    assert client.claim_maintenance(ttl_seconds=60) is None
    assert json.loads(session.requests[-1][2]["data"]) == {"ttl_seconds": 60}

    session.upgraded = True
    client._maintenance_actions_retry_at = 0.0
    assert client.claim_maintenance(ttl_seconds=60) is None
    assert "supported_actions" in json.loads(session.requests[-1][2]["data"])


def test_legacy_claim_ambiguous_response_keeps_key_and_body_bound() -> None:
    class AmbiguousLegacySession:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict[str, Any]]] = []

        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            self.requests.append((method, url, kwargs))
            body = json.loads(kwargs["data"])
            if len(self.requests) == 1:
                assert "supported_actions" in body
                return response(
                    422,
                    {"error": {"code": int(ErrorCode.VALIDATION_FAILED)}},
                )
            if len(self.requests) == 2:
                assert body == {"ttl_seconds": 60}
                raise requests.ConnectionError("response lost after cached claim")
            return response(204)

    session = AmbiguousLegacySession()
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
        session=session,  # type: ignore[arg-type]
    )

    with pytest.raises(GatewayUnavailableError):
        client.claim_maintenance(ttl_seconds=60)
    legacy_key = session.requests[1][2]["headers"]["Idempotency-Key"]

    # Even if the negotiation re-probe deadline passes, an ambiguous request
    # must first be replayed with its exact canonical body and key.
    client._maintenance_actions_retry_at = 0.0
    assert client.claim_maintenance(ttl_seconds=60) is None
    assert json.loads(session.requests[2][2]["data"]) == {"ttl_seconds": 60}
    assert session.requests[2][2]["headers"]["Idempotency-Key"] == legacy_key

    assert client.claim_maintenance(ttl_seconds=60) is None
    assert "supported_actions" in json.loads(session.requests[3][2]["data"])
    assert session.requests[3][2]["headers"]["Idempotency-Key"] != legacy_key


def test_local_maintenance_ticket_must_share_gateway_origin() -> None:
    client = GatewayV1Client(
        "https://gateway.example.test",
        WorkerCredentials("wrk_contract", DeviceKeys.generate(), "short-session"),
    )
    job = {
        "artifact": {
            "store_type": "local",
            "expected_size": 12,
            "expected_sha256": "a" * 64,
        },
        "artifact_download_ticket": {
            "url": "https://storage.example.test/api/v1/artifacts/transfer/art_test",
            "method": "GET",
            "expected_size": 12,
            "expected_sha256": "a" * 64,
        },
    }

    with pytest.raises(VGenError) as raised:
        client.maintenance_artifact_ticket(job)

    assert raised.value.code == ErrorCode.SOURCE_NOT_ALLOWED
