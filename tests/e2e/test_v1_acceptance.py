from __future__ import annotations

import io
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    build_allocation_proof_payload,
    canonical_json,
    decrypt_payload,
    decrypt_stream,
    encrypt_payload,
    encrypt_stream,
    encrypted_stream_size,
    generate_task_data_key,
    generate_workspace_data_key,
    issue_device_certificate,
    sign_allocation_proof,
    sign_key_manifest,
    sign_message,
    task_aad,
    unwrap_task_key,
    wrap_task_key,
    wrap_task_key_for_workspace,
)
from vgen.gateway.app import create_app
from vgen.protocol import ErrorCode
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_user_registration_claim,
    build_workspace_recipient_admission_manifest,
    sign_user_registration_claim,
)


@dataclass(frozen=True, slots=True)
class Actor:
    user_id: str
    device_id: str
    identity: IdentityKeys
    device: DeviceKeys
    headers: dict[str, str]
    certificate: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RegisteredWorker:
    worker_id: str
    owner: Actor
    keys: DeviceKeys
    headers: dict[str, str]


def _identity() -> IdentityKeys:
    return IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())


def _user_registration_material(
    *,
    identity: IdentityKeys,
    device: DeviceKeys,
    device_id: str,
    certificate: dict[str, Any],
    invite_id: str,
    display_name: str,
    device_name: str,
) -> tuple[dict[str, Any], str]:
    claim = build_user_registration_claim(
        invite_id=invite_id,
        display_name=display_name,
        root_key_id=identity.root_key_id,
        root_signing_public_key=b64url_encode(identity.signing_public_bytes()),
        root_encryption_public_key=b64url_encode(identity.encryption_public_bytes()),
        device_id=device_id,
        device_name=device_name,
        device_signing_public_key=b64url_encode(device.signing_public_bytes()),
        device_encryption_public_key=b64url_encode(device.encryption_public_bytes()),
        device_certificate=certificate,
    )
    return claim, sign_user_registration_claim(device.signing_private_key, claim)


def _signed_user_admission(
    *,
    owner: Actor,
    workspace_id: str,
    enrollment: dict[str, Any],
    claim: dict[str, Any],
    proof_signature: str,
) -> dict[str, Any]:
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner.user_id,
        owner_root_key_id=owner.identity.root_key_id,
        subject_user_id=str(enrollment["subject_user_id"]),
        enrollment_id=str(enrollment["id"]),
        registration_claim=claim,
        registration_proof_signature=proof_signature,
        issued_at=int(claim["device_certificate"]["payload"]["issued_at"]),
    )
    return sign_key_manifest(owner.identity, manifest)


def _bootstrap(client: TestClient) -> Actor:
    identity = _identity()
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(identity, device, device_id=device_id).to_dict()
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_code": "acceptance-bootstrap",
            "display_name": "Owner A",
            "root_signing_public_key": b64url_encode(identity.signing_public_bytes()),
            "root_encryption_public_key": b64url_encode(identity.encryption_public_bytes()),
            "device_id": device_id,
            "device_name": "owner-a-device",
            "device_signing_public_key": b64url_encode(device.signing_public_bytes()),
            "device_encryption_public_key": b64url_encode(device.encryption_public_bytes()),
            "device_certificate": certificate,
        },
    )
    assert response.status_code == 200, response.text
    value = response.json()
    return Actor(
        user_id=value["user"]["id"],
        device_id=device_id,
        identity=identity,
        device=device,
        headers={"Authorization": f"Bearer {value['session']['token']}"},
        certificate=certificate,
    )


def _enroll_user(
    client: TestClient,
    *,
    admin: Actor,
    workspace_id: str,
    display_name: str,
    method: str = "direct_invite",
) -> tuple[Actor, dict[str, Any]]:
    invite_response = client.post(
        f"/api/v1/workspaces/{workspace_id}/invites",
        json={"kind": "user", "method": method},
        headers=admin.headers,
    )
    assert invite_response.status_code == 200, invite_response.text
    invite = invite_response.json()

    identity = _identity()
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(identity, device, device_id=device_id).to_dict()
    claim, proof_signature = _user_registration_material(
        identity=identity,
        device=device,
        device_id=device_id,
        certificate=certificate,
        invite_id=invite["enrollment"]["id"],
        display_name=display_name,
        device_name=f"{display_name}-device",
    )
    response = client.post(
        "/api/v1/auth/enroll",
        json={
            "invite_id": invite["enrollment"]["id"],
            "secret": invite["secret"],
            "claim": claim,
            "proof_signature": proof_signature,
        },
    )
    assert response.status_code == 200, response.text
    value = response.json()
    challenge = client.post(
        "/api/v1/auth/challenges",
        json={"principal_type": "device", "device_id": device_id},
    ).json()
    session = client.post(
        "/api/v1/auth/sessions",
        json={
            "principal_type": "device",
            "device_id": device_id,
            "challenge_id": challenge["challenge_id"],
            "signature": b64url_encode(
                sign_message(device.signing_private_key, challenge["challenge"].encode())
            ),
        },
    )
    assert session.status_code == 200, session.text
    actor = Actor(
        user_id=value["user"]["id"],
        device_id=device_id,
        identity=identity,
        device=device,
        headers={"Authorization": f"Bearer {session.json()['session_token']}"},
        certificate=certificate,
    )
    return actor, {
        "invite": invite,
        "enrollment": value["enrollment"],
        "claim": claim,
        "proof_signature": proof_signature,
        "certificate": certificate,
    }


def _worker_certificate(owner: Actor, keys: DeviceKeys) -> str:
    return json.dumps(
        sign_key_manifest(
            owner.identity,
            {
                "version": 1,
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": owner.identity.root_key_id,
                "worker_key_id": keys.key_id,
                "worker_signing_public_key": b64url_encode(keys.signing_public_bytes()),
                "worker_encryption_public_key": b64url_encode(keys.encryption_public_bytes()),
                "issued_at": int(time.time()),
            },
        ),
        separators=(",", ":"),
    )


def _register_worker(
    client: TestClient,
    *,
    owner: Actor,
    admin: Actor,
    workspace_id: str,
    pool_id: str,
    name: str,
    announce: bool = True,
) -> RegisteredWorker:
    keys = DeviceKeys.generate()
    response = client.post(
        "/api/v1/workers",
        json={
            "name": name,
            "manager_broker_id": None,
            "signing_public_key": b64url_encode(keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(keys.encryption_public_bytes()),
            "certificate": _worker_certificate(owner, keys),
            "executor_type": "fake",
            "executor_version": "acceptance-1",
            "capabilities": {},
            "capacity": 1,
        },
        headers=owner.headers,
    )
    assert response.status_code == 200, response.text
    worker = response.json()
    assert worker["owner_user_id"] == owner.user_id
    assert worker["manager_broker_id"] is None

    challenge_response = client.post(
        "/api/v1/auth/challenges",
        json={"principal_type": "worker", "worker_id": worker["id"]},
    )
    assert challenge_response.status_code == 200, challenge_response.text
    challenge = challenge_response.json()
    session_response = client.post(
        "/api/v1/auth/sessions",
        json={
            "principal_type": "worker",
            "worker_id": worker["id"],
            "challenge_id": challenge["challenge_id"],
            "signature": b64url_encode(
                sign_message(
                    keys.signing_private_key,
                    challenge["challenge"].encode(),
                )
            ),
        },
    )
    assert session_response.status_code == 200, session_response.text
    worker_headers = {"Authorization": f"Bearer {session_response.json()['session_token']}"}

    offer = client.post(
        f"/api/v1/workers/{worker['id']}/offer",
        json={"pool_id": pool_id},
        headers=owner.headers,
    )
    assert offer.status_code == 200, offer.text
    allocation = offer.json()
    proof = sign_allocation_proof(
        admin.identity,
        build_allocation_proof_payload(
            allocation_id=allocation["id"],
            workspace_id=allocation["workspace_id"],
            pool_id=allocation["pool_id"],
            worker_id=worker["id"],
            worker_signing_public_key=worker["signing_public_key"],
            worker_encryption_public_key=worker["encryption_public_key"],
            worker_certificate=worker["certificate"],
            owner_consent_at=allocation["owner_consent_at"],
            approver_root_key_id=admin.identity.root_key_id,
        ),
    )
    approval = client.post(
        f"/api/v1/worker-allocations/{allocation['id']}/approve",
        json={"proof": proof},
        headers=admin.headers,
    )
    assert approval.status_code == 200, approval.text
    assert approval.json()["status"] == "active"

    proposal = client.post(
        f"/api/v1/workers/{worker['id']}/rates",
        json={
            "workspace_id": workspace_id,
            "rate_microtokens_per_gpu_second": 1_000_000,
        },
        headers=owner.headers,
    )
    assert proposal.status_code == 200, proposal.text
    approved_rate = client.post(
        f"/api/v1/rates/{proposal.json()['id']}/approve",
        headers=admin.headers,
    )
    assert approved_rate.status_code == 200, approved_rate.text

    registered = RegisteredWorker(worker["id"], owner, keys, worker_headers)
    if announce:
        _announce_worker(client, registered)
    return registered


def _announce_worker(
    client: TestClient,
    worker: RegisteredWorker,
    *,
    executor_capabilities: dict[str, Any] | None = None,
) -> None:
    response = client.post(
        f"/api/v1/workers/{worker.worker_id}/heartbeat",
        json={
            "capabilities": {
                "executors": [
                    {
                        "type": "fake",
                        "version": "1.2.0",
                        "payload_formats": ["opaque/v1"],
                        "operations": ["text-to-video", "image-to-video"],
                        "max_concurrency": 1,
                        "capabilities": executor_capabilities or {"model_digests": []},
                    }
                ]
            }
        },
        headers=worker.headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "active"


def _prepare(
    client: TestClient,
    *,
    actor: Actor,
    workspace_id: str,
    pool_id: str,
    input_size: int | None = None,
    public_requirements: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "workspace_id": workspace_id,
        "pool_id": pool_id,
        "workflow_ref": "vgen/acceptance-fake@1.0.0",
        "workflow_digest": "sha256:" + "a" * 64,
        "executor_type": "fake",
        "client_channel": "cli",
        "public_requirements": public_requirements
        or {
            "operation": "text-to-video" if input_size is None else "image-to-video",
            "payload_format": "opaque/v1",
        },
    }
    if input_size is not None:
        body["input_artifacts"] = [
            {
                "kind": "first_frame",
                "encrypted_size": input_size,
                "media_metadata": {"media_type": "image/png"},
            }
        ]
    response = client.post("/api/v1/tasks/prepare", json=body, headers=actor.headers)
    assert response.status_code == 200, response.text
    return response.json()


def _commit_encrypted_payload(
    client: TestClient,
    *,
    actor: Actor,
    prepared: dict[str, Any],
    worker: RegisteredWorker,
    plaintext: bytes,
    task_key: bytes | None = None,
) -> bytes:
    key = task_key or generate_task_data_key()
    aad = task_aad(
        workspace_id=prepared["workspace_id"],
        task_id=prepared["id"],
        attempt_id=prepared["attempt_id"],
        artifact_id="payload",
        key_version=1,
    )
    encrypted_payload = encrypt_payload(key, plaintext, aad=aad)
    worker_envelope = wrap_task_key(worker.keys.encryption_public_key, key, aad=aad)
    reader_envelope = wrap_task_key_for_workspace(generate_workspace_data_key(), key, aad=aad)
    response = client.post(
        f"/api/v1/tasks/{prepared['id']}/commit",
        json={
            "encrypted_payload": json.dumps(encrypted_payload.to_dict(), separators=(",", ":")),
            "worker_tdk_envelope": json.dumps(worker_envelope.to_dict(), separators=(",", ":")),
            "reader_envelope": json.dumps(reader_envelope.to_dict(), separators=(",", ":")),
            "key_algorithm": worker_envelope.algorithm,
            "artifacts": [],
        },
        headers=actor.headers,
    )
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "committed"
    return key


def _finish_body(
    *,
    worker: RegisteredWorker,
    lease: dict[str, Any],
    fencing_token: int,
    output_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "fencing_token": fencing_token,
        "succeeded": True,
        "output_artifacts": output_artifacts or [],
        "metrics": {"gpu_active_ms": 10},
        "worker_signature": None,
        "failure_code": None,
        "responsibility": "none",
        "safe_failure_details": {},
    }
    report = {
        "attempt_id": lease["attempt_id"],
        "task_id": lease["task_id"],
        "worker_id": worker.worker_id,
        **{key: value for key, value in body.items() if key != "worker_signature"},
    }
    body["worker_signature"] = b64url_encode(
        sign_message(
            worker.keys.signing_private_key,
            canonical_json(report),
            context=b"vgen-worker-finish-v1",
        )
    )
    return body


def _failed_finish_body(
    *,
    worker: RegisteredWorker,
    lease: dict[str, Any],
    failure_code: ErrorCode,
    responsibility: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "fencing_token": lease["fencing_token"],
        "succeeded": False,
        "output_artifacts": [],
        "metrics": {"gpu_active_ms": 10, "gpu_count": 1},
        "worker_signature": None,
        "failure_code": int(failure_code),
        "responsibility": responsibility,
        "safe_failure_details": {"reason": failure_code.name.lower()},
    }
    report = {
        "attempt_id": lease["attempt_id"],
        "task_id": lease["task_id"],
        "worker_id": worker.worker_id,
        **{key: value for key, value in body.items() if key != "worker_signature"},
    }
    body["worker_signature"] = b64url_encode(
        sign_message(
            worker.keys.signing_private_key,
            canonical_json(report),
            context=b"vgen-worker-finish-v1",
        )
    )
    return body


class FakeEncryptedExecutor:
    def execute(self, prompt: bytes, first_frame: bytes) -> bytes:
        assert prompt == b'{"prompt":"PRIVATE_PROMPT_91a4f6"}'
        assert first_frame == b"PRIVATE_INPUT_12d9aa"
        return b"PRIVATE_OUTPUT_e34b08"


def test_user_without_broker_and_cross_user_pool_scheduling(tmp_path: Path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        owner_a = _bootstrap(client)
        assert client.get("/api/v1/brokers", headers=owner_a.headers).json() == []
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Shared Workspace"},
            headers=owner_a.headers,
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Shared Pool"},
            headers=owner_a.headers,
        ).json()
        owner_b, _ = _enroll_user(
            client,
            admin=owner_a,
            workspace_id=workspace["id"],
            display_name="User B",
        )
        assert client.get("/api/v1/brokers", headers=owner_b.headers).json() == []

        worker_b = _register_worker(
            client,
            owner=owner_b,
            admin=owner_a,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="worker-b",
            announce=False,
        )
        worker_a = _register_worker(
            client,
            owner=owner_a,
            admin=owner_a,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="worker-a",
            announce=False,
        )
        _announce_worker(client, worker_b)
        _announce_worker(client, worker_a)

        allocations = client.get(
            f"/api/v1/workspaces/{workspace['id']}/worker-allocations",
            headers=owner_a.headers,
        ).json()
        assert {item["worker_id"] for item in allocations} == {
            worker_a.worker_id,
            worker_b.worker_id,
        }
        assert {item["status"] for item in allocations} == {"active"}

        prepared = _prepare(
            client,
            actor=owner_b,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
        )
        assert prepared["worker"]["id"] == worker_a.worker_id
        attempt = app.state.db.fetchone(
            "SELECT provider_user_id FROM task_attempts WHERE id=?",
            (prepared["attempt_id"],),
        )
        task = app.state.db.fetchone(
            "SELECT consumer_user_id FROM tasks WHERE id=?", (prepared["id"],)
        )
        assert task["consumer_user_id"] == owner_b.user_id
        assert attempt["provider_user_id"] == owner_a.user_id


def test_retry_attempts_on_two_workers_have_independent_usage_entries(tmp_path: Path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        owner = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Metered Retry Workspace"},
            headers=owner.headers,
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Metered Retry Pool"},
            headers=owner.headers,
        ).json()
        workers = [
            _register_worker(
                client,
                owner=owner,
                admin=owner,
                workspace_id=workspace["id"],
                pool_id=pool["id"],
                name=f"metered-worker-{index}",
                announce=False,
            )
            for index in range(3)
        ]
        by_id = {worker.worker_id: worker for worker in workers}
        model_digest = "sha256:" + "b" * 64
        # Only the first Worker is initially eligible. The two later
        # heartbeats deliberately sort ahead of it but lack the required model.
        _announce_worker(
            client,
            workers[0],
            executor_capabilities={"model_digests": [model_digest]},
        )
        _announce_worker(client, workers[1])
        _announce_worker(client, workers[2])

        prepared = _prepare(
            client,
            actor=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            public_requirements={
                "operation": "text-to-video",
                "payload_format": "opaque/v1",
                "model_digests": [model_digest],
            },
        )
        first_worker = by_id[prepared["worker"]["id"]]
        assert first_worker.worker_id == workers[0].worker_id
        task_key = _commit_encrypted_payload(
            client,
            actor=owner,
            prepared=prepared,
            worker=first_worker,
            plaintext=b'{"prompt":"metered retry"}',
        )
        first_lease_response = client.post(
            f"/api/v1/workers/{first_worker.worker_id}/lease",
            json={"ttl_seconds": 60},
            headers=first_worker.headers,
        )
        assert first_lease_response.status_code == 200, first_lease_response.text
        first_lease = first_lease_response.json()
        assert (
            client.post(
                f"/api/v1/attempts/{first_lease['attempt_id']}/heartbeat",
                json={"fencing_token": first_lease["fencing_token"], "started": True},
                headers=first_worker.headers,
            ).status_code
            == 200
        )
        failed = client.post(
            f"/api/v1/attempts/{first_lease['attempt_id']}/finish",
            json=_failed_finish_body(
                worker=first_worker,
                lease=first_lease,
                failure_code=ErrorCode.GPU_OUT_OF_MEMORY,
                responsibility="provider",
            ),
            headers=first_worker.headers,
        )
        assert failed.status_code == 200, failed.text

        no_eligible_retry = client.post(
            f"/api/v1/tasks/{prepared['id']}/retry",
            json={},
            headers=owner.headers,
        )
        assert no_eligible_retry.status_code == 503, no_eligible_retry.text
        assert no_eligible_retry.json()["error"]["code"] == int(ErrorCode.NO_ELIGIBLE_WORKER)

        # Make one replacement eligible, then announce an incompatible Worker
        # last. Retry must reuse the complete requirements matcher, skip the
        # newest incompatible candidate, and never fall back to the old Worker.
        _announce_worker(
            client,
            workers[1],
            executor_capabilities={"model_digests": [model_digest]},
        )
        _announce_worker(client, workers[2])
        retry_response = client.post(
            f"/api/v1/tasks/{prepared['id']}/retry",
            json={},
            headers=owner.headers,
        )
        assert retry_response.status_code == 200, retry_response.text
        retry = retry_response.json()
        second_worker = by_id[retry["worker"]["id"]]
        assert second_worker.worker_id == workers[1].worker_id
        replacement_envelope = wrap_task_key(
            second_worker.keys.encryption_public_key,
            task_key,
            aad=task_aad(
                workspace_id=workspace["id"],
                task_id=prepared["id"],
                attempt_id=retry["attempt_id"],
                key_version=1,
            ),
        )
        rekeyed = client.post(
            f"/api/v1/tasks/{prepared['id']}/rekey",
            json={
                "replacement_worker_id": second_worker.worker_id,
                "worker_tdk_envelope": json.dumps(
                    replacement_envelope.to_dict(), separators=(",", ":")
                ),
                "key_algorithm": replacement_envelope.algorithm,
            },
            headers=owner.headers,
        )
        assert rekeyed.status_code == 200, rekeyed.text

        second_lease_response = client.post(
            f"/api/v1/workers/{second_worker.worker_id}/lease",
            json={"ttl_seconds": 60},
            headers=second_worker.headers,
        )
        assert second_lease_response.status_code == 200, second_lease_response.text
        second_lease = second_lease_response.json()
        assert (
            client.post(
                f"/api/v1/attempts/{second_lease['attempt_id']}/heartbeat",
                json={"fencing_token": second_lease["fencing_token"], "started": True},
                headers=second_worker.headers,
            ).status_code
            == 200
        )
        completed = client.post(
            f"/api/v1/attempts/{second_lease['attempt_id']}/finish",
            json=_finish_body(
                worker=second_worker,
                lease=second_lease,
                fencing_token=second_lease["fencing_token"],
            ),
            headers=second_worker.headers,
        )
        assert completed.status_code == 200, completed.text

        usage_response = client.get(
            f"/api/v1/workspaces/{workspace['id']}/usage",
            headers=owner.headers,
        )
        assert usage_response.status_code == 200, usage_response.text
        usage = [entry for entry in usage_response.json() if entry["task_id"] == prepared["id"]]
        assert len(usage) == 2
        assert {entry["attempt_id"] for entry in usage} == {
            first_lease["attempt_id"],
            second_lease["attempt_id"],
        }
        assert {entry["worker_id"] for entry in usage} == {
            first_worker.worker_id,
            second_worker.worker_id,
        }
        by_attempt = {entry["attempt_id"]: entry for entry in usage}
        assert by_attempt[first_lease["attempt_id"]]["billable"] == 0
        assert by_attempt[first_lease["attempt_id"]]["total_microtokens"] == 0
        assert by_attempt[second_lease["attempt_id"]]["billable"] == 1
        assert by_attempt[second_lease["attempt_id"]]["total_microtokens"] == 10_000


def test_enrollment_policies_expiry_reuse_approval_and_rejection(
    tmp_path: Path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        admin = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Invite Workspace"},
            headers=admin.headers,
        ).json()

        direct_user, direct_flow = _enroll_user(
            client,
            admin=admin,
            workspace_id=workspace["id"],
            display_name="Direct User",
        )
        assert direct_flow["enrollment"]["state"] == "active"
        assert workspace["id"] in {
            item["id"]
            for item in client.get("/api/v1/workspaces", headers=direct_user.headers).json()
        }

        reused_identity = _identity()
        reused_device = DeviceKeys.generate()
        reused_device_id = new_id("device")
        reused_certificate = issue_device_certificate(
            reused_identity, reused_device, device_id=reused_device_id
        ).to_dict()
        reused_claim, reused_proof = _user_registration_material(
            identity=reused_identity,
            device=reused_device,
            device_id=reused_device_id,
            certificate=reused_certificate,
            invite_id=direct_flow["invite"]["enrollment"]["id"],
            display_name="Invite Reuser",
            device_name="reused-device",
        )
        reused = client.post(
            "/api/v1/auth/enroll",
            json={
                "invite_id": direct_flow["invite"]["enrollment"]["id"],
                "secret": direct_flow["invite"]["secret"],
                "claim": reused_claim,
                "proof_signature": reused_proof,
            },
        )
        # The original recipient may safely retry the exact registration after
        # a lost response. Reusing the same Invite for different identity
        # material is therefore reported as a semantic idempotency conflict,
        # not mistaken for that allowed retry.
        assert reused.status_code == 409, reused.text
        assert reused.json()["error"]["code"] == 600002

        revoked_direct = client.post(
            f"/api/v1/enrollments/{direct_flow['enrollment']['id']}/revoke",
            headers=admin.headers,
        )
        assert revoked_direct.status_code == 200, revoked_direct.text
        assert revoked_direct.json()["state"] == "revoked"
        assert client.get("/api/v1/workspaces", headers=direct_user.headers).json() == []

        revocable_invite = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "workspace_member", "method": "direct_invite"},
            headers=admin.headers,
        ).json()
        revoked_invite = client.post(
            f"/api/v1/enrollments/{revocable_invite['enrollment']['id']}/revoke",
            headers=admin.headers,
        )
        assert revoked_invite.status_code == 200, revoked_invite.text
        assert revoked_invite.json()["state"] == "revoked"
        assert direct_user.certificate is not None
        revoked_member_claim, revoked_member_proof = _user_registration_material(
            identity=direct_user.identity,
            device=direct_user.device,
            device_id=direct_user.device_id,
            certificate=direct_user.certificate,
            invite_id=revocable_invite["enrollment"]["id"],
            display_name="Direct User",
            device_name="Direct User-device",
        )
        revoked_claim = client.post(
            "/api/v1/enrollments/claim",
            json={
                "invite_id": revocable_invite["enrollment"]["id"],
                "secret": revocable_invite["secret"],
                "claim": revoked_member_claim,
                "proof_signature": revoked_member_proof,
            },
            headers=direct_user.headers,
        )
        assert revoked_claim.status_code == 400, revoked_claim.text
        assert revoked_claim.json()["error"]["code"] == 240001

        pending_user, pending_flow = _enroll_user(
            client,
            admin=admin,
            workspace_id=workspace["id"],
            display_name="Pending User",
            method="invite_approval",
        )
        assert pending_flow["enrollment"]["state"] == "pending"
        assert client.get("/api/v1/workspaces", headers=pending_user.headers).json() == []
        rejected = client.post(
            f"/api/v1/enrollments/{pending_flow['enrollment']['id']}/decision",
            json={"approve": False},
            headers=admin.headers,
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["state"] == "rejected"

        approved_user, approved_flow = _enroll_user(
            client,
            admin=admin,
            workspace_id=workspace["id"],
            display_name="Approved User",
            method="invite_approval",
        )
        approved_admission = _signed_user_admission(
            owner=admin,
            workspace_id=workspace["id"],
            enrollment=approved_flow["enrollment"],
            claim=approved_flow["claim"],
            proof_signature=approved_flow["proof_signature"],
        )
        approved = client.post(
            f"/api/v1/enrollments/{approved_flow['enrollment']['id']}/decision",
            json={"approve": True, "signed_admission": approved_admission},
            headers=admin.headers,
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["state"] == "active"
        assert workspace["id"] in {
            item["id"]
            for item in client.get("/api/v1/workspaces", headers=approved_user.headers).json()
        }

        application_workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Apply Workspace"},
            headers=admin.headers,
        ).json()
        assert direct_user.certificate is not None
        application_id = new_id("application")
        application_claim, application_proof = _user_registration_material(
            identity=direct_user.identity,
            device=direct_user.device,
            device_id=direct_user.device_id,
            certificate=direct_user.certificate,
            invite_id=application_id,
            display_name="Direct User",
            device_name="Direct User-device",
        )
        application = client.post(
            "/api/v1/applications",
            json={
                "application_id": application_id,
                "workspace_id": application_workspace["id"],
                "kind": "workspace_member",
                "relationship": "member",
                "claim": application_claim,
                "proof_signature": application_proof,
            },
            headers=direct_user.headers,
        )
        assert application.status_code == 200, application.text
        assert application.json()["method"] == "apply_approval"
        assert application.json()["state"] == "pending"
        application_admission = _signed_user_admission(
            owner=admin,
            workspace_id=application_workspace["id"],
            enrollment=application.json(),
            claim=application_claim,
            proof_signature=application_proof,
        )
        decision = client.post(
            f"/api/v1/enrollments/{application.json()['id']}/decision",
            json={"approve": True, "signed_admission": application_admission},
            headers=admin.headers,
        )
        assert decision.status_code == 200, decision.text
        assert application_workspace["id"] in {
            item["id"]
            for item in client.get("/api/v1/workspaces", headers=direct_user.headers).json()
        }

        assert pending_user.certificate is not None
        rejected_application_id = new_id("application")
        rejected_application_claim, rejected_application_proof = (
            _user_registration_material(
                identity=pending_user.identity,
                device=pending_user.device,
                device_id=pending_user.device_id,
                certificate=pending_user.certificate,
                invite_id=rejected_application_id,
                display_name="Pending User",
                device_name="Pending User-device",
            )
        )
        rejected_application = client.post(
            "/api/v1/applications",
            json={
                "application_id": rejected_application_id,
                "workspace_id": application_workspace["id"],
                "kind": "workspace_member",
                "relationship": "member",
                "claim": rejected_application_claim,
                "proof_signature": rejected_application_proof,
            },
            headers=pending_user.headers,
        )
        assert rejected_application.status_code == 200, rejected_application.text
        rejected_application_decision = client.post(
            f"/api/v1/enrollments/{rejected_application.json()['id']}/decision",
            json={"approve": False},
            headers=admin.headers,
        )
        assert rejected_application_decision.status_code == 200
        assert rejected_application_decision.json()["state"] == "rejected"

        expiring = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "workspace_member", "method": "direct_invite"},
            headers=admin.headers,
        ).json()
        app.state.db.execute(
            "UPDATE enrollments SET expires_at=0 WHERE id=?",
            (expiring["enrollment"]["id"],),
        )
        expired_claim, expired_proof = _user_registration_material(
            identity=direct_user.identity,
            device=direct_user.device,
            device_id=direct_user.device_id,
            certificate=direct_user.certificate,
            invite_id=expiring["enrollment"]["id"],
            display_name="Direct User",
            device_name="Direct User-device",
        )
        expired = client.post(
            "/api/v1/enrollments/claim",
            json={
                "invite_id": expiring["enrollment"]["id"],
                "secret": expiring["secret"],
                "claim": expired_claim,
                "proof_signature": expired_proof,
            },
            headers=direct_user.headers,
        )
        assert expired.status_code == 400
        assert expired.json()["error"]["code"] == 240001

        closed_workspace = client.post(
            "/api/v1/workspaces",
            json={
                "name": "Closed Workspace",
                "enrollment_policy": {
                    "workspace_member": "closed",
                    "service": "closed",
                    "broker_device": "closed",
                    "worker_allocation": "closed",
                },
            },
            headers=admin.headers,
        ).json()
        closed_application_id = new_id("application")
        closed_claim, closed_proof = _user_registration_material(
            identity=direct_user.identity,
            device=direct_user.device,
            device_id=direct_user.device_id,
            certificate=direct_user.certificate,
            invite_id=closed_application_id,
            display_name="Direct User",
            device_name="Direct User-device",
        )
        closed = client.post(
            "/api/v1/applications",
            json={
                "application_id": closed_application_id,
                "workspace_id": closed_workspace["id"],
                "kind": "workspace_member",
                "claim": closed_claim,
                "proof_signature": closed_proof,
            },
            headers=direct_user.headers,
        )
        assert closed.status_code == 403
        assert closed.json()["error"]["code"] == 240003


def test_worker_leave_revoke_and_fencing_reject_late_result(tmp_path: Path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        owner = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Worker Lifecycle"},
            headers=owner.headers,
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Lifecycle Pool"},
            headers=owner.headers,
        ).json()
        worker = _register_worker(
            client,
            owner=owner,
            admin=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="draining-worker",
        )
        prepared = _prepare(
            client,
            actor=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
        )
        _commit_encrypted_payload(
            client,
            actor=owner,
            prepared=prepared,
            worker=worker,
            plaintext=b'{"prompt":"lifecycle"}',
        )
        lease_response = client.post(
            f"/api/v1/workers/{worker.worker_id}/lease",
            json={"ttl_seconds": 60},
            headers=worker.headers,
        )
        assert lease_response.status_code == 200, lease_response.text
        lease = lease_response.json()
        running = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/heartbeat",
            json={
                "fencing_token": lease["fencing_token"],
                "started": True,
                "progress": {"fraction": 0.5, "stage": "fake"},
            },
            headers=worker.headers,
        )
        assert running.status_code == 200, running.text

        leave = client.post(
            f"/api/v1/workers/{worker.worker_id}/leave",
            json={"force": False},
            headers=owner.headers,
        )
        assert leave.status_code == 200, leave.text
        assert leave.json()["status"] == "draining"
        assert (
            app.state.db.fetchone(
                "SELECT state FROM task_attempts WHERE id=?", (lease["attempt_id"],)
            )["state"]
            == "running"
        )

        late_body = _finish_body(
            worker=worker,
            lease=lease,
            fencing_token=lease["fencing_token"] + 1,
        )
        late = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/finish",
            json=late_body,
            headers=worker.headers,
        )
        assert late.status_code == 409, late.text
        assert late.json()["error"]["code"] == 310001

        completed = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/finish",
            json=_finish_body(
                worker=worker,
                lease=lease,
                fencing_token=lease["fencing_token"],
            ),
            headers=worker.headers,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "succeeded"
        assert (
            app.state.db.fetchone("SELECT status FROM workers WHERE id=?", (worker.worker_id,))[
                "status"
            ]
            == "revoked"
        )

        force_worker = _register_worker(
            client,
            owner=owner,
            admin=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="force-revoked-worker",
        )
        revoked = client.post(
            f"/api/v1/workers/{force_worker.worker_id}/revoke",
            headers=owner.headers,
        )
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["status"] == "revoked"
        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "worker", "worker_id": force_worker.worker_id},
        )
        assert challenge.status_code == 401

        idle_worker = _register_worker(
            client,
            owner=owner,
            admin=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="idle-graceful-worker",
        )
        graceful = client.post(
            f"/api/v1/workers/{idle_worker.worker_id}/leave",
            json={"force": False},
            headers=owner.headers,
        )
        assert graceful.status_code == 200, graceful.text
        assert graceful.json()["status"] == "revoked"
        assert (
            app.state.db.fetchone(
                "SELECT revoked_at FROM sessions WHERE principal_type='worker' AND principal_id=?",
                (idle_worker.worker_id,),
            )["revoked_at"]
            is not None
        )
        idle_challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "worker", "worker_id": idle_worker.worker_id},
        )
        assert idle_challenge.status_code == 401


def test_expired_lease_requires_rekey_and_worker_session_is_scoped(
    tmp_path: Path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        owner = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Lease Expiry"},
            headers=owner.headers,
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Lease Pool"},
            headers=owner.headers,
        ).json()
        worker = _register_worker(
            client,
            owner=owner,
            admin=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="lease-expiry-worker",
        )

        forbidden = client.post(
            "/api/v1/workspaces",
            json={"name": "Worker Must Not Create This"},
            headers=worker.headers,
        )
        assert forbidden.status_code == 403, forbidden.text
        assert forbidden.json()["error"]["code"] in {120001, 120002}

        prepared = _prepare(
            client,
            actor=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
        )
        _commit_encrypted_payload(
            client,
            actor=owner,
            prepared=prepared,
            worker=worker,
            plaintext=b'{"prompt":"expire lease"}',
        )
        lease = client.post(
            f"/api/v1/workers/{worker.worker_id}/lease",
            json={"ttl_seconds": 60},
            headers=worker.headers,
        ).json()
        app.state.db.execute(
            "UPDATE leases SET expires_at=0 WHERE attempt_id=?",
            (lease["attempt_id"],),
        )
        swept = client.post(
            f"/api/v1/workers/{worker.worker_id}/lease",
            json={"ttl_seconds": 60},
            headers=worker.headers,
        )
        assert swept.status_code == 204, swept.text
        task = client.get(f"/api/v1/tasks/{prepared['id']}", headers=owner.headers)
        assert task.status_code == 200, task.text
        assert task.json()["state"] == "rekey_required"
        assert task.json()["attempts"][0]["state"] == "expired"


def test_scheduler_enforces_public_executor_and_resource_requirements(
    tmp_path: Path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        owner = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Capability Matching"},
            headers=owner.headers,
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Capability Pool"},
            headers=owner.headers,
        ).json()
        worker = _register_worker(
            client,
            owner=owner,
            admin=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="capability-worker",
            announce=False,
        )
        model_digest = "sha256:" + "b" * 64
        _announce_worker(
            client,
            worker,
            executor_capabilities={
                "model_digests": [model_digest],
                "vram_bytes": 24_000_000_000,
                "runtime_version": "0.30.1",
            },
        )

        base = {
            "workspace_id": workspace["id"],
            "pool_id": pool["id"],
            "workflow_ref": "vgen/requirements@1.0.0",
            "workflow_digest": "sha256:" + "c" * 64,
            "executor_type": "fake",
            "client_channel": "api",
        }
        rejected_requirements = (
            {
                "operation": "unsupported-operation",
                "payload_format": "opaque/v1",
                "model_digests": [model_digest],
                "min_vram_bytes": 16_000_000_000,
            },
            {
                "operation": "text-to-video",
                "payload_format": "unsupported/v9",
                "model_digests": [model_digest],
                "min_vram_bytes": 16_000_000_000,
            },
            {
                "operation": "text-to-video",
                "payload_format": "opaque/v1",
                "executor_min_version": "2.0.0",
                "model_digests": [model_digest],
                "min_vram_bytes": 16_000_000_000,
            },
            {
                "operation": "text-to-video",
                "payload_format": "opaque/v1",
                "runtime_min_version": "0.31.0",
                "model_digests": [model_digest],
                "min_vram_bytes": 16_000_000_000,
            },
            {
                "operation": "text-to-video",
                "payload_format": "opaque/v1",
                "model_digests": ["sha256:" + "d" * 64],
                "min_vram_bytes": 16_000_000_000,
            },
            {
                "operation": "text-to-video",
                "payload_format": "opaque/v1",
                "model_digests": [model_digest],
                "min_vram_bytes": 32_000_000_000,
            },
        )
        for requirements in rejected_requirements:
            rejected = client.post(
                "/api/v1/tasks/prepare",
                json={**base, "public_requirements": requirements},
                headers=owner.headers,
            )
            assert rejected.status_code == 503, (requirements, rejected.text)
            assert rejected.json()["error"]["code"] == 220001

        accepted = client.post(
            "/api/v1/tasks/prepare",
            json={
                **base,
                "public_requirements": {
                    "operation": "text-to-video",
                    "payload_format": "opaque/v1",
                    "executor_min_version": "1.1.0",
                    "runtime_min_version": "0.30.0",
                    "model_digests": [model_digest],
                    "min_vram_bytes": 16_000_000_000,
                },
            },
            headers=owner.headers,
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["worker"]["id"] == worker.worker_id


def test_gateway_database_and_artifact_store_never_persist_plaintext(
    tmp_path: Path,
    caplog,
) -> None:
    database_path = tmp_path / "gateway.db"
    artifact_root = tmp_path / "artifacts"
    app = create_app(
        database_path=str(database_path),
        bootstrap_code="acceptance-bootstrap",
        require_request_signatures=False,
        artifact_root=str(artifact_root),
    )
    prompt = b'{"prompt":"PRIVATE_PROMPT_91a4f6"}'
    first_frame = b"PRIVATE_INPUT_12d9aa"
    expected_output = b"PRIVATE_OUTPUT_e34b08"
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        owner = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Encrypted Tasks"},
            headers=owner.headers,
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Encrypted Pool"},
            headers=owner.headers,
        ).json()
        worker = _register_worker(
            client,
            owner=owner,
            admin=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            name="encrypted-worker",
        )
        prepared = _prepare(
            client,
            actor=owner,
            workspace_id=workspace["id"],
            pool_id=pool["id"],
            input_size=encrypted_stream_size(len(first_frame)),
        )
        task_key = generate_task_data_key()
        input_ticket = prepared["artifact_tickets"][0]
        input_ciphertext = io.BytesIO()
        encrypt_stream(
            io.BytesIO(first_frame),
            input_ciphertext,
            task_key,
            aad=task_aad(
                workspace_id=workspace["id"],
                task_id=prepared["id"],
                attempt_id=prepared["attempt_id"],
                artifact_id=input_ticket["artifact_id"],
                key_version=1,
            ),
        )
        uploaded = client.put(
            input_ticket["url"],
            headers=input_ticket["headers"],
            content=input_ciphertext.getvalue(),
        )
        assert uploaded.status_code == 204, uploaded.text
        _commit_encrypted_payload(
            client,
            actor=owner,
            prepared=prepared,
            worker=worker,
            plaintext=prompt,
            task_key=task_key,
        )

        lease_response = client.post(
            f"/api/v1/workers/{worker.worker_id}/lease",
            json={"ttl_seconds": 60},
            headers=worker.headers,
        )
        assert lease_response.status_code == 200, lease_response.text
        lease = lease_response.json()
        payload_aad = task_aad(
            workspace_id=workspace["id"],
            task_id=prepared["id"],
            attempt_id=prepared["attempt_id"],
            artifact_id="payload",
            key_version=1,
        )
        opened_task_key = unwrap_task_key(
            worker.keys.encryption_private_key,
            json.loads(lease["encrypted_tdk_envelope"]),
            aad=payload_aad,
        )
        opened_prompt = decrypt_payload(
            opened_task_key,
            json.loads(lease["encrypted_payload"]),
            aad=payload_aad,
        )
        download_ticket = lease["artifact_download_tickets"][0]
        downloaded = client.get(download_ticket["url"], headers=download_ticket["headers"])
        assert downloaded.status_code == 200, downloaded.text
        opened_input = io.BytesIO()
        decrypt_stream(
            io.BytesIO(downloaded.content),
            opened_input,
            opened_task_key,
            aad=task_aad(
                workspace_id=workspace["id"],
                task_id=prepared["id"],
                attempt_id=prepared["attempt_id"],
                artifact_id=input_ticket["artifact_id"],
                key_version=1,
            ),
        )
        fake_output = FakeEncryptedExecutor().execute(opened_prompt, opened_input.getvalue())
        assert fake_output == expected_output

        output_ticket = lease["output_upload_tickets"][0]
        encrypted_output = io.BytesIO()
        encrypt_stream(
            io.BytesIO(fake_output),
            encrypted_output,
            opened_task_key,
            aad=task_aad(
                workspace_id=workspace["id"],
                task_id=prepared["id"],
                attempt_id=prepared["attempt_id"],
                artifact_id=output_ticket["artifact_id"],
                key_version=1,
            ),
        )
        output_upload = client.put(
            output_ticket["url"],
            headers=output_ticket["headers"],
            content=encrypted_output.getvalue(),
        )
        assert output_upload.status_code == 204, output_upload.text
        output_artifact = {
            "artifact_id": output_ticket["artifact_id"],
            "kind": "video",
            "store_type": None,
            "object_ref": None,
            "content_digest": None,
            "encrypted_size": None,
            "media_metadata": {},
        }
        finished = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/finish",
            json=_finish_body(
                worker=worker,
                lease=lease,
                fencing_token=lease["fencing_token"],
                output_artifacts=[output_artifact],
            ),
            headers=worker.headers,
        )
        assert finished.status_code == 200, finished.text

    for path in tmp_path.rglob("*"):
        if not path.is_file():
            continue
        persisted = path.read_bytes()
        assert prompt not in persisted, path
        assert first_frame not in persisted, path
        assert expected_output not in persisted, path
    assert prompt.decode() not in caplog.text
    assert first_frame.decode() not in caplog.text
    assert expected_output.decode() not in caplog.text
