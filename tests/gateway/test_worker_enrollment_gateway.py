from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    build_allocation_proof_payload,
    canonical_json,
    sign_allocation_proof,
    sign_http_request,
    sign_key_manifest,
    sign_message,
)
from vgen.gateway.app import create_app
from vgen.gateway.openapi import idempotency_cache_mode

WORKER_ENROLLMENT_CONTEXT = b"vgen-worker-enrollment-v1"


def _claim(worker: DeviceKeys, invite_id: str, *, name: str = "gpu-host") -> dict[str, Any]:
    return {
        "version": 1,
        "kind": "vgen-worker-enrollment-claim",
        "invite_id": invite_id,
        "worker_key_id": worker.key_id,
        "name": name,
        "signing_public_key": b64url_encode(worker.signing_public_bytes()),
        "encryption_public_key": b64url_encode(worker.encryption_public_bytes()),
        "executor_type": "comfyui",
        "executor_version": "1.1.0",
        "capabilities": {"gpu": {"vram_bytes": 24_000_000_000}},
        "capacity": 1,
    }


def _claim_signature(worker: DeviceKeys, claim: dict[str, Any]) -> str:
    return b64url_encode(
        sign_message(
            worker.signing_private_key,
            canonical_json(claim),
            context=WORKER_ENROLLMENT_CONTEXT,
        )
    )


def _owner_certificate(
    owner: IdentityKeys,
    claim: dict[str, Any],
    *,
    issued_at: int | None = None,
) -> dict[str, Any]:
    return sign_key_manifest(
        owner,
        {
            "version": 1,
            "kind": "vgen-worker-owner-certificate",
            "owner_root_key_id": owner.root_key_id,
            "worker_key_id": claim["worker_key_id"],
            "worker_signing_public_key": claim["signing_public_key"],
            "worker_encryption_public_key": claim["encryption_public_key"],
            "issued_at": int(time.time()) if issued_at is None else issued_at,
        },
    )


def _allocation_proof(
    owner: IdentityKeys,
    claim: dict[str, Any],
    allocation: dict[str, Any],
    certificate: dict[str, Any],
    *,
    issued_at: int | None = None,
) -> dict[str, Any]:
    return sign_allocation_proof(
        owner,
        build_allocation_proof_payload(
            allocation_id=allocation["id"],
            workspace_id=allocation["workspace_id"],
            pool_id=allocation["pool_id"],
            worker_id=allocation["worker_id"],
            worker_signing_public_key=claim["signing_public_key"],
            worker_encryption_public_key=claim["encryption_public_key"],
            worker_certificate=certificate,
            owner_consent_at=allocation["owner_consent_at"],
            approver_root_key_id=owner.root_key_id,
            issued_at=issued_at,
        ),
    )


def _setup(tmp_path):
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    client = TestClient(app)
    client.headers.update({"Vgen-Protocol-Version": "1"})
    boot, headers, owner, _ = bootstrap_identity(client)
    workspace = client.post(
        "/api/v1/workspaces", json={"name": "Worker enrollment"}, headers=headers
    ).json()
    pool = client.post(
        f"/api/v1/workspaces/{workspace['id']}/pools",
        json={"name": "GPU"},
        headers=headers,
    ).json()
    return app, client, boot, headers, owner, workspace, pool


def _invite(client: TestClient, headers: dict[str, str], workspace: dict, pool: dict):
    response = client.post(
        f"/api/v1/workspaces/{workspace['id']}/worker-invites",
        json={
            "method": "invite_approval",
            "pool_id": pool["id"],
            "name": "Windows GPU Worker",
            "executor_type": "comfyui",
            "executor_version": "1.1.0",
            "capacity": 1,
            "rate_microtokens_per_gpu_second": 1_250_000,
            "traffic_microtokens_per_gib": 0,
            "ttl_seconds": 1800,
        },
        headers={**headers, "Idempotency-Key": "worker-invite-test"},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    invite_id, secret = data["invite_uri"].removeprefix("vgen://join/").split("#", 1)
    assert data["enrollment"]["id"] == invite_id
    assert "secret" not in data
    assert "invite_secret_hash" not in data["enrollment"]
    return data, invite_id, secret


def test_worker_invite_claim_signed_status_and_atomic_approval(tmp_path) -> None:
    app, client, boot, headers, owner, workspace, pool = _setup(tmp_path)
    with client:
        _, invite_id, secret = _invite(client, headers, workspace, pool)
        stored_invite = app.state.db.fetchone(
            "SELECT * FROM enrollments WHERE id=?", (invite_id,)
        )
        assert stored_invite is not None
        assert stored_invite["invite_secret_hash"] == hashlib.sha256(secret.encode()).hexdigest()
        assert secret not in str(dict(stored_invite))
        assert (
            app.state.db.fetchone(
                "SELECT COUNT(*) AS n FROM idempotency_records WHERE path LIKE '%worker-invite%'"
            )["n"]
            == 0
        )

        worker = DeviceKeys.generate()
        claim = _claim(worker, invite_id)
        bad_proof = _claim_signature(DeviceKeys.generate(), claim)
        rejected_proof = client.post(
            "/api/v1/worker-enrollments/claim",
            json={
                "invite_id": invite_id,
                "secret": secret,
                "claim": claim,
                "proof_signature": bad_proof,
            },
        )
        assert rejected_proof.status_code == 401
        assert rejected_proof.json()["error"]["code"] == 100003
        assert app.state.db.fetchone(
            "SELECT state FROM enrollments WHERE id=?", (invite_id,)
        )["state"] == "issued"

        claim_body = {
            "invite_id": invite_id,
            "secret": secret,
            "claim": claim,
            "proof_signature": _claim_signature(worker, claim),
        }
        claimed = client.post(
            "/api/v1/worker-enrollments/claim",
            json=claim_body,
            headers={"Idempotency-Key": f"worker-enrollment:{invite_id}:{worker.key_id}"},
        )
        assert claimed.status_code == 200, claimed.text
        pending = claimed.json()
        assert pending["enrollment"]["state"] == "pending"
        assert pending["enrollment"]["worker_key_id"] == worker.key_id
        assert "claim" not in pending["enrollment"]
        assert "proof_signature" not in pending["enrollment"]
        assert pending["allocation"]["worker_id"] == pending["enrollment"]["subject_id"]
        assert app.state.db.fetchone(
            "SELECT id FROM workers WHERE id=?", (pending["allocation"]["worker_id"],)
        ) is None
        assert (
            app.state.db.fetchone(
                "SELECT COUNT(*) AS n FROM idempotency_records WHERE path='/api/v1/worker-enrollments/claim'"
            )["n"]
            == 0
        )
        assert secret not in json.dumps(pending, sort_keys=True)

        retried = client.post("/api/v1/worker-enrollments/claim", json=claim_body)
        assert retried.status_code == 200
        assert retried.json()["allocation"]["id"] == pending["allocation"]["id"]
        changed_claim = _claim(worker, invite_id, name="different-name")
        changed = client.post(
            "/api/v1/worker-enrollments/claim",
            json={
                **claim_body,
                "claim": changed_claim,
                "proof_signature": _claim_signature(worker, changed_claim),
            },
        )
        assert changed.status_code == 409
        assert changed.json()["error"]["code"] == 600002

        status_path = f"/api/v1/worker-enrollments/{invite_id}"
        unsigned = client.get(status_path)
        assert unsigned.status_code == 401
        assert unsigned.json()["error"]["code"] == 100003
        signed_headers = sign_http_request(
            worker,
            method="GET",
            path=status_path,
        ).to_headers()
        worker_status = client.get(status_path, headers=signed_headers)
        assert worker_status.status_code == 200, worker_status.text
        assert worker_status.headers["cache-control"] == "no-store"
        assert worker_status.headers["vary"] == (
            "Authorization, Content-Digest, Signature-Input, Signature"
        )
        assert "claim" not in worker_status.json()["enrollment"]
        replay = client.get(status_path, headers=signed_headers)
        assert replay.status_code == 409
        assert replay.json()["error"]["code"] == 100004

        admin_status = client.get(status_path, headers=headers)
        assert admin_status.status_code == 200, admin_status.text
        assert admin_status.headers["cache-control"] == "no-store"
        review = admin_status.json()
        assert review["enrollment"]["claim"] == claim
        assert review["enrollment"]["proof_signature"] == claim_body["proof_signature"]

        certificate = _owner_certificate(owner, claim)
        allocation_proof = _allocation_proof(
            owner, claim, review["allocation"], certificate
        )
        decision_body = {
            "approve": True,
            "owner_certificate": json.dumps(certificate, separators=(",", ":")),
            "allocation_proof": allocation_proof,
        }
        approved = client.post(
            f"{status_path}/decision", json=decision_body, headers=headers
        )
        assert approved.status_code == 200, approved.text
        active = approved.json()
        assert active["enrollment"]["state"] == "active"
        assert active["worker"]["status"] == "offline"
        assert active["worker"]["owner_user_id"] == boot["user"]["id"]
        assert active["worker"]["signing_public_key"] == claim["signing_public_key"]
        assert active["allocation"]["status"] == "active"
        rate = app.state.db.fetchone(
            "SELECT * FROM rate_cards WHERE worker_id=? AND workspace_id=? AND status='approved'",
            (active["worker"]["id"], workspace["id"]),
        )
        assert rate is not None
        assert rate["rate_microtokens_per_gpu_second"] == 1_250_000
        assert rate["traffic_microtokens_per_gib"] == 0
        assert secret not in json.dumps(active, sort_keys=True)
        assert "invite_secret_hash" not in json.dumps(active, sort_keys=True)

        same_decision = client.post(
            f"{status_path}/decision", json=decision_body, headers=headers
        )
        assert same_decision.status_code == 200, same_decision.text
        conflicting_decision = json.loads(json.dumps(decision_body))
        conflicting_decision["allocation_proof"]["payload"]["issued_at"] += 1
        conflict = client.post(
            f"{status_path}/decision", json=conflicting_decision, headers=headers
        )
        assert conflict.status_code == 409
        assert conflict.json()["error"]["code"] == 600002

        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "worker", "worker_id": active["worker"]["id"]},
        )
        assert challenge.status_code == 200, challenge.text
        session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "worker",
                "worker_id": active["worker"]["id"],
                "challenge_id": challenge.json()["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        worker.signing_private_key,
                        challenge.json()["challenge"].encode(),
                    )
                ),
            },
        )
        assert session.status_code == 200, session.text


def test_worker_enrollment_reject_expiry_and_timestamp_bounds(tmp_path) -> None:
    app, client, _, headers, owner, workspace, pool = _setup(tmp_path)
    with client:
        _, expired_id, expired_secret = _invite(client, headers, workspace, pool)
        app.state.db.execute(
            "UPDATE enrollments SET expires_at=0 WHERE id=?", (expired_id,)
        )
        expired_worker = DeviceKeys.generate()
        expired_claim = _claim(expired_worker, expired_id)
        expired = client.post(
            "/api/v1/worker-enrollments/claim",
            json={
                "invite_id": expired_id,
                "secret": expired_secret,
                "claim": expired_claim,
                "proof_signature": _claim_signature(expired_worker, expired_claim),
            },
        )
        assert expired.status_code == 400
        assert expired.json()["error"]["code"] == 240001

        _, invite_id, secret = _invite(client, headers, workspace, pool)
        worker = DeviceKeys.generate()
        claim = _claim(worker, invite_id)
        claim_response = client.post(
            "/api/v1/worker-enrollments/claim",
            json={
                "invite_id": invite_id,
                "secret": secret,
                "claim": claim,
                "proof_signature": _claim_signature(worker, claim),
            },
        )
        assert claim_response.status_code == 200
        pending = claim_response.json()
        claimed_at = int(pending["enrollment"]["claimed_at"])

        old_certificate = _owner_certificate(owner, claim, issued_at=claimed_at - 301)
        old_certificate_decision = client.post(
            f"/api/v1/worker-enrollments/{invite_id}/decision",
            json={
                "approve": True,
                "owner_certificate": json.dumps(old_certificate, separators=(",", ":")),
                "allocation_proof": _allocation_proof(
                    owner, claim, pending["allocation"], old_certificate
                ),
            },
            headers=headers,
        )
        assert old_certificate_decision.status_code == 401
        assert old_certificate_decision.json()["error"]["code"] == 110002
        assert app.state.db.fetchone(
            "SELECT state FROM enrollments WHERE id=?", (invite_id,)
        )["state"] == "pending"

        certificate = _owner_certificate(owner, claim)
        old_proof = _allocation_proof(
            owner,
            claim,
            pending["allocation"],
            certificate,
            issued_at=claimed_at - 301,
        )
        old_proof_decision = client.post(
            f"/api/v1/worker-enrollments/{invite_id}/decision",
            json={
                "approve": True,
                "owner_certificate": json.dumps(certificate, separators=(",", ":")),
                "allocation_proof": old_proof,
            },
            headers=headers,
        )
        assert old_proof_decision.status_code == 422
        assert old_proof_decision.json()["error"]["code"] == 230004
        assert app.state.db.fetchone(
            "SELECT id FROM workers WHERE signing_public_key=?",
            (claim["signing_public_key"],),
        ) is None

        rejected = client.post(
            f"/api/v1/worker-enrollments/{invite_id}/decision",
            json={"approve": False},
            headers=headers,
        )
        assert rejected.status_code == 200, rejected.text
        assert rejected.json()["enrollment"]["state"] == "rejected"
        repeated = client.post(
            f"/api/v1/worker-enrollments/{invite_id}/decision",
            json={"approve": False},
            headers=headers,
        )
        assert repeated.status_code == 200
        changed_claim = _claim(worker, invite_id, name="claim-after-rejection")
        changed = client.post(
            "/api/v1/worker-enrollments/claim",
            json={
                "invite_id": invite_id,
                "secret": secret,
                "claim": changed_claim,
                "proof_signature": _claim_signature(worker, changed_claim),
            },
        )
        assert changed.status_code == 409
        assert changed.json()["error"]["code"] == 600002


def test_worker_enrollment_secret_routes_disable_response_replay_cache(tmp_path) -> None:
    assert (
        idempotency_cache_mode("/api/v1/workspaces/wsp_example/worker-invites")
        == "disabled"
    )
    assert idempotency_cache_mode("/api/v1/worker-enrollments/claim") == "disabled"
    assert idempotency_cache_mode("/api/v1/worker-enrollments/inv_example/decision") == "plain"

    app = create_app(
        database_path=str(tmp_path / "openapi.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "openapi-artifacts"),
    )
    schema = app.openapi()
    status_operation = schema["paths"][
        "/api/v1/worker-enrollments/{enrollment_id}"
    ]["get"]
    assert status_operation["security"] == [
        {"VGenSession": []},
        {"VGenWorkerEnrollmentSignature": []},
    ]
    conditional_headers = status_operation["x-vgen-conditional-required-headers"]
    assert conditional_headers["VGenSession"] == ["Authorization"]
    assert conditional_headers["VGenWorkerEnrollmentSignature"] == [
        "Content-Digest",
        "Signature-Input",
        "Signature",
    ]
    parameter_names = {
        parameter["$ref"].rsplit("/", 1)[-1]
        for parameter in status_operation["parameters"]
        if "$ref" in parameter
    }
    for name in (
        "WorkerEnrollmentContentDigest",
        "WorkerEnrollmentSignatureInput",
        "WorkerEnrollmentSignature",
    ):
        assert name in parameter_names
        assert schema["components"]["parameters"][name]["required"] is False
    assert "ContentDigest" not in parameter_names
    assert "SignatureInput" not in parameter_names
    assert "Signature" not in parameter_names
    claim_schema = schema["components"]["schemas"]["WorkerEnrollmentClaimRequest"]
    assert claim_schema["properties"]["secret"]["writeOnly"] is True
