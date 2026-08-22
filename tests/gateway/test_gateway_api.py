from __future__ import annotations

import hashlib
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    build_allocation_proof_payload,
    canonical_json,
    issue_device_certificate,
    sign_allocation_proof,
    sign_http_request,
    sign_key_manifest,
    sign_message,
)
from vgen.gateway.app import create_app
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_user_registration_claim,
    sign_user_registration_claim,
)


def public_keys() -> tuple[str, str]:
    signing = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    encryption = (
        X25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return b64url_encode(signing), b64url_encode(encryption)


def bootstrap_identity(
    client: TestClient,
) -> tuple[dict, dict[str, str], IdentityKeys, DeviceKeys]:
    identity = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(identity, device, device_id=device_id).to_dict()
    root_sign = b64url_encode(identity.signing_public_bytes())
    root_enc = b64url_encode(identity.encryption_public_bytes())
    device_sign = b64url_encode(device.signing_public_bytes())
    device_enc = b64url_encode(device.encryption_public_bytes())
    response = client.post(
        "/api/v1/auth/bootstrap",
        json={
            "bootstrap_code": "test-bootstrap",
            "display_name": "Operator",
            "root_signing_public_key": root_sign,
            "root_encryption_public_key": root_enc,
            "device_id": device_id,
            "device_name": "operator-laptop",
            "device_signing_public_key": device_sign,
            "device_encryption_public_key": device_enc,
            "device_certificate": certificate,
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return data, {"Authorization": f"Bearer {data['session']['token']}"}, identity, device


def bootstrap(client: TestClient) -> tuple[dict, dict[str, str]]:
    data, headers, _, _ = bootstrap_identity(client)
    return data, headers


def worker_owner_certificate(identity: IdentityKeys, worker: DeviceKeys) -> str:
    return json.dumps(
        sign_key_manifest(
            identity,
            {
                "version": 1,
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": identity.root_key_id,
                "worker_key_id": worker.key_id,
                "worker_signing_public_key": b64url_encode(worker.signing_public_bytes()),
                "worker_encryption_public_key": b64url_encode(worker.encryption_public_bytes()),
                "issued_at": int(time.time()),
            },
        ),
        separators=(",", ":"),
    )


def device_enrollment_proof(keys: DeviceKeys, invite_id: str, device_id: str) -> str:
    return b64url_encode(
        sign_message(
            keys.signing_private_key,
            canonical_json({"version": 1, "invite_id": invite_id, "device_id": device_id}),
            context=b"vgen-device-enrollment-v1",
        )
    )


def user_enrollment_proof(keys: DeviceKeys, claim: dict) -> str:
    return sign_user_registration_claim(keys.signing_private_key, claim)


def test_bootstrap_workspace_pool_and_idempotency(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers = bootstrap(client)
        health = client.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["journal_mode"] == "wal"

        write_headers = {**headers, "Idempotency-Key": "create-workspace-1"}
        first = client.post("/api/v1/workspaces", json={"name": "Studio"}, headers=write_headers)
        second = client.post("/api/v1/workspaces", json={"name": "Studio"}, headers=write_headers)
        assert first.status_code == second.status_code == 200
        assert first.json()["id"] == second.json()["id"]
        assert second.headers["Idempotency-Replayed"] == "true"

        conflict = client.post(
            "/api/v1/workspaces", json={"name": "Different"}, headers=write_headers
        )
        assert conflict.status_code == 409
        assert conflict.json()["error"]["code"] == 600002

        workspace_id = first.json()["id"]
        pool = client.post(
            f"/api/v1/workspaces/{workspace_id}/pools",
            json={"name": "GPU", "policy": {"trusted_workers_only": True}},
            headers=headers,
        )
        assert pool.status_code == 200, pool.text
        assert pool.json()["workspace_id"] == workspace_id
        assert boot["user"]["is_operator"] == 1


def test_broker_heartbeat_reports_runtime_version(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers = bootstrap(client)
        broker_response = client.post(
            "/api/v1/brokers",
            json={"name": "Home", "device_id": boot["device"]["id"]},
            headers=headers,
        )
        assert broker_response.status_code == 200, broker_response.text
        broker = broker_response.json()
        broker_device_id = broker["broker_device"]["id"]

        legacy = client.post(
            f"/api/v1/broker-devices/{broker_device_id}/heartbeat",
            json={"broker_id": broker["id"], "status": "online", "journal_pending": 0},
            headers=headers,
        )
        assert legacy.status_code == 200, legacy.text
        assert legacy.json()["runtime_version"] is None

        heartbeat = client.post(
            f"/api/v1/broker-devices/{broker_device_id}/heartbeat",
            json={
                "broker_id": broker["id"],
                "status": "online",
                "runtime_version": "0.4.0",
                "protocol_version": "1",
                "build_commit": "abcdef1234567",
                "journal_pending": 2,
            },
            headers=headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text
        listed = client.get("/api/v1/brokers", headers=headers).json()
        device = listed[0]["devices"][0]
        assert device["runtime_version"] == "0.4.0"
        assert device["protocol_version"] == "1"
        assert device["build_commit"] == "abcdef1234567"
        assert device["journal_pending"] == 2
        assert device["heartbeat_at"] is not None


def test_worker_task_attempt_and_usage_ledger(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        _, user_headers, owner_identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Studio"}, headers=user_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "Shared GPU"},
            headers=user_headers,
        ).json()

        worker_keys = DeviceKeys.generate()
        worker_sign = b64url_encode(worker_keys.signing_public_bytes())
        worker_enc = b64url_encode(worker_keys.encryption_public_bytes())
        registration = {
            "name": "gpu-01",
            "signing_public_key": worker_sign,
            "encryption_public_key": worker_enc,
            "certificate": worker_owner_certificate(owner_identity, worker_keys),
            "executor_type": "comfyui",
            "executor_version": "1",
            "capabilities": {"gpu": {"vram_bytes": 24_000_000_000}},
        }
        tampered = dict(registration)
        tampered["encryption_public_key"] = public_keys()[1]
        rejected = client.post("/api/v1/workers", json=tampered, headers=user_headers)
        assert rejected.status_code == 401
        assert rejected.json()["error"]["code"] == 110002

        registration_headers = {**user_headers, "Idempotency-Key": "worker-owner-key-1"}
        response = client.post(
            "/api/v1/workers",
            json=registration,
            headers=registration_headers,
        )
        assert response.status_code == 200, response.text
        worker = response.json()
        assert "session" not in worker
        replayed_registration = client.post(
            "/api/v1/workers", json=registration, headers=registration_headers
        )
        assert replayed_registration.status_code == 200
        assert replayed_registration.json()["id"] == worker["id"]
        assert replayed_registration.headers["Idempotency-Replayed"] == "true"
        assert (
            app.state.db.fetchone(
                "SELECT COUNT(*) AS n FROM sessions WHERE principal_type='worker'"
            )["n"]
            == 0
        )
        cached_worker = app.state.db.fetchone(
            "SELECT response_body FROM idempotency_records WHERE path='/api/v1/workers'"
        )
        assert cached_worker is not None
        assert b'"token"' not in bytes(cached_worker["response_body"])
        worker_challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "worker", "worker_id": worker["id"]},
        )
        assert worker_challenge.status_code == 200, worker_challenge.text
        challenge_data = worker_challenge.json()
        refreshed = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "worker",
                "worker_id": worker["id"],
                "challenge_id": challenge_data["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        worker_keys.signing_private_key,
                        challenge_data["challenge"].encode(),
                    )
                ),
            },
        )
        assert refreshed.status_code == 200, refreshed.text
        worker_headers = {"Authorization": f"Bearer {refreshed.json()['session_token']}"}
        privilege_escalation = client.post(
            "/api/v1/workspaces", json={"name": "forbidden"}, headers=worker_headers
        )
        assert privilege_escalation.status_code == 403
        assert privilege_escalation.json()["error"]["code"] == 120001

        offered = client.post(
            f"/api/v1/workers/{worker['id']}/offer",
            json={"pool_id": pool["id"]},
            headers=user_headers,
        )
        assert offered.status_code == 200, offered.text
        allocation = offered.json()
        proof = sign_allocation_proof(
            owner_identity,
            build_allocation_proof_payload(
                allocation_id=allocation["id"],
                workspace_id=allocation["workspace_id"],
                pool_id=allocation["pool_id"],
                worker_id=worker["id"],
                worker_signing_public_key=registration["signing_public_key"],
                worker_encryption_public_key=registration["encryption_public_key"],
                worker_certificate=registration["certificate"],
                owner_consent_at=allocation["owner_consent_at"],
                approver_root_key_id=owner_identity.root_key_id,
            ),
        )
        tampered_proof = json.loads(json.dumps(proof))
        tampered_proof["payload"]["pool_id"] = "pol_gateway_substitution"
        rejected_approval = client.post(
            f"/api/v1/worker-allocations/{allocation['id']}/approve",
            json={"proof": tampered_proof},
            headers=user_headers,
        )
        assert rejected_approval.status_code == 422
        assert rejected_approval.json()["error"]["code"] == 230004
        approved = client.post(
            f"/api/v1/worker-allocations/{allocation['id']}/approve",
            json={"proof": proof},
            headers=user_headers,
        )
        assert approved.status_code == 200, approved.text

        rate = client.post(
            f"/api/v1/workers/{worker['id']}/rates",
            json={
                "workspace_id": workspace["id"],
                "rate_microtokens_per_gpu_second": 1_000_000,
            },
            headers=user_headers,
        )
        assert rate.status_code == 200, rate.text
        assert (
            client.post(
                f"/api/v1/rates/{rate.json()['id']}/approve", headers=user_headers
            ).status_code
            == 200
        )

        offline_prepare = client.post(
            "/api/v1/tasks/prepare",
            json={
                "workspace_id": workspace["id"],
                "pool_id": pool["id"],
                "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
                "workflow_digest": "sha256:" + "a" * 64,
                "executor_type": "comfyui",
            },
            headers=user_headers,
        )
        assert offline_prepare.status_code == 503
        assert offline_prepare.json()["error"]["code"] == 220001
        announced = client.post(
            f"/api/v1/workers/{worker['id']}/heartbeat",
            json={
                "capabilities": {
                    "executors": [
                        {
                            "type": "comfyui",
                            "version": "1",
                            "payload_formats": ["opaque/v1"],
                            "operations": ["text-to-video"],
                            "max_concurrency": 1,
                            "capabilities": {"models": []},
                        }
                    ]
                }
            },
            headers=worker_headers,
        )
        assert announced.status_code == 200, announced.text
        assert announced.json()["status"] == "active"
        limited_token, _ = app.state.db.create_session(
            principal_type="worker",
            principal_id=worker["id"],
            user_id=worker["owner_user_id"],
            scopes=["worker:heartbeat"],
        )
        cross_scope = client.post(
            f"/api/v1/workers/{worker['id']}/lease",
            json={"ttl_seconds": 60},
            headers={"Authorization": f"Bearer {limited_token}"},
        )
        assert cross_scope.status_code == 403
        assert cross_scope.json()["error"]["code"] == 120002

        abandoned_payload = {
            "workspace_id": workspace["id"],
            "pool_id": pool["id"],
            "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
            "workflow_digest": "sha256:" + "b" * 64,
            "executor_type": "comfyui",
            "reservation_ttl_seconds": 15,
        }
        abandoned_headers = {**user_headers, "Idempotency-Key": "expired-prepare"}
        abandoned = client.post(
            "/api/v1/tasks/prepare", json=abandoned_payload, headers=abandoned_headers
        )
        assert abandoned.status_code == 200, abandoned.text
        app.state.db.execute(
            "UPDATE tasks SET reservation_expires_at=0 WHERE id=?", (abandoned.json()["id"],)
        )
        expired_replay = client.post(
            "/api/v1/tasks/prepare", json=abandoned_payload, headers=abandoned_headers
        )
        assert expired_replay.status_code == 409
        assert expired_replay.json()["error"]["code"] == 310003

        prepare_payload = {
            "workspace_id": workspace["id"],
            "pool_id": pool["id"],
            "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
            "workflow_digest": "sha256:" + "a" * 64,
            "executor_type": "comfyui",
            "client_channel": "cli",
            "public_requirements": {"operation": "text-to-video"},
            "input_artifacts": [{"kind": "first_frame", "encrypted_size": len(b"encrypted-input")}],
        }
        prepare_headers = {**user_headers, "Idempotency-Key": "prepare-lost-response"}
        prepared = client.post(
            "/api/v1/tasks/prepare", json=prepare_payload, headers=prepare_headers
        )
        assert prepared.status_code == 200, prepared.text
        task = prepared.json()
        task_count = app.state.db.fetchone("SELECT COUNT(*) AS n FROM tasks")["n"]
        replayed_prepare = client.post(
            "/api/v1/tasks/prepare", json=prepare_payload, headers=prepare_headers
        )
        assert replayed_prepare.status_code == 200, replayed_prepare.text
        assert replayed_prepare.headers["Idempotency-Replayed"] == "true"
        assert replayed_prepare.json()["id"] == task["id"]
        assert app.state.db.fetchone("SELECT COUNT(*) AS n FROM tasks")["n"] == task_count
        assert (
            replayed_prepare.json()["artifact_tickets"][0]["headers"]["Vgen-Artifact-Ticket"]
            != task["artifact_tickets"][0]["headers"]["Vgen-Artifact-Ticket"]
        )
        task = replayed_prepare.json()
        cached_prepare = bytes(
            app.state.db.fetchone(
                """SELECT response_body FROM idempotency_records
                   WHERE path='/api/v1/tasks/prepare'"""
            )["response_body"]
        )
        assert b"/api/v1/artifacts/transfer/" not in cached_prepare
        assert b'"url"' not in cached_prepare
        assert b"Vgen-Artifact-Ticket" not in cached_prepare
        assert task["worker"]["id"] == worker["id"]
        assert task["worker"]["owner_root_signing_public_key"] == b64url_encode(
            owner_identity.signing_public_bytes()
        )
        assert task["worker"]["certificate"] == registration["certificate"]
        assert task["allocation"]["proof"] == proof
        assert task["allocation"]["admin_root_signing_public_key"] == b64url_encode(
            owner_identity.signing_public_bytes()
        )
        assert task["attempt_id"].startswith("atm_")
        input_ticket = task["artifact_tickets"][0]
        assert input_ticket["url"].endswith("/" + input_ticket["artifact_id"])
        assert input_ticket["headers"]["Vgen-Artifact-Ticket"] not in input_ticket["url"]
        assert (
            app.state.db.fetchone("SELECT state FROM tasks WHERE id=?", (abandoned.json()["id"],))[
                "state"
            ]
            == "expired"
        )
        missing_capability = client.put(input_ticket["url"], content=b"encrypted-input")
        assert missing_capability.status_code == 403
        uploaded = client.put(
            input_ticket["url"],
            headers=input_ticket["headers"],
            content=b"encrypted-input",
        )
        assert uploaded.status_code == 204, uploaded.text
        reused_upload = client.put(
            input_ticket["url"], headers=input_ticket["headers"], content=b"replacement"
        )
        assert reused_upload.status_code == 409
        assert reused_upload.json()["error"]["code"] == 100004

        committed = client.post(
            f"/api/v1/tasks/{task['id']}/commit",
            json={
                "encrypted_payload": "encrypted-payload",
                "worker_tdk_envelope": "encrypted-task-key",
                "reader_envelope": "encrypted-reader-key",
                "key_algorithm": "HPKE-Base-X25519-HKDF-SHA256-ChaCha20Poly1305",
                "artifacts": [],
            },
            headers=user_headers,
        )
        assert committed.status_code == 200, committed.text
        assert committed.json()["state"] == "committed"

        lease_path = f"/api/v1/workers/{worker['id']}/lease"
        lease_headers = {**worker_headers, "Idempotency-Key": "lease-lost-response"}
        leased = client.post(lease_path, json={"ttl_seconds": 60}, headers=lease_headers)
        assert leased.status_code == 200, leased.text
        lease = leased.json()
        replayed_lease = client.post(lease_path, json={"ttl_seconds": 60}, headers=lease_headers)
        assert replayed_lease.status_code == 200, replayed_lease.text
        assert replayed_lease.headers["Idempotency-Replayed"] == "true"
        assert replayed_lease.json()["attempt_id"] == lease["attempt_id"]
        assert replayed_lease.json()["lease_id"] == lease["lease_id"]
        assert (
            replayed_lease.json()["artifact_download_tickets"][0]["headers"]["Vgen-Artifact-Ticket"]
            != lease["artifact_download_tickets"][0]["headers"]["Vgen-Artifact-Ticket"]
        )
        assert (
            replayed_lease.json()["output_upload_tickets"][0]["headers"]["Vgen-Artifact-Ticket"]
            != lease["output_upload_tickets"][0]["headers"]["Vgen-Artifact-Ticket"]
        )
        lease = replayed_lease.json()
        cached_lease = bytes(
            app.state.db.fetchone(
                "SELECT response_body FROM idempotency_records WHERE path=?", (lease_path,)
            )["response_body"]
        )
        assert b"/api/v1/artifacts/transfer/" not in cached_lease
        assert b'"url"' not in cached_lease
        assert b"Vgen-Artifact-Ticket" not in cached_lease
        assert lease["attempt_id"] == task["attempt_id"]
        assert "graph" not in lease
        assert lease["encrypted_payload"] == "encrypted-payload"
        input_download = lease["artifact_download_tickets"][0]
        downloaded_input = client.get(input_download["url"], headers=input_download["headers"])
        assert downloaded_input.content == b"encrypted-input"

        heartbeat = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/heartbeat",
            json={"fencing_token": lease["fencing_token"], "started": True},
            headers=worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text

        refreshed_tickets = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/artifact-tickets",
            headers={**worker_headers, "Idempotency-Key": "must-not-cache-capability"},
        )
        assert refreshed_tickets.status_code == 200, refreshed_tickets.text
        assert refreshed_tickets.headers["Cache-Control"] == "no-store"
        assert (
            app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM idempotency_records
                   WHERE path LIKE '/api/v1/attempts/%/artifact-tickets'"""
            )["n"]
            == 0
        )
        output_ticket = refreshed_tickets.json()["output_upload_tickets"][0]
        uploaded_output = client.put(
            output_ticket["url"],
            headers=output_ticket["headers"],
            content=b"encrypted-video",
        )
        assert uploaded_output.status_code == 204, uploaded_output.text

        finish_body = {
            "fencing_token": lease["fencing_token"],
            "succeeded": True,
            "metrics": {
                "gpu_active_ms": 2500,
                "gateway_wall_ms": 2700,
                "egress_bytes": 4096,
                "output_frames": 81,
            },
            "responsibility": "none",
            "output_artifacts": [
                {
                    "artifact_id": output_ticket["artifact_id"],
                    "kind": "video",
                    "store_type": None,
                    "object_ref": None,
                    "content_digest": None,
                    "encrypted_size": None,
                    "media_metadata": {"frames": 81},
                }
            ],
            "failure_code": None,
            "safe_failure_details": {},
        }
        finish_signed = {
            "attempt_id": lease["attempt_id"],
            "task_id": lease["task_id"],
            "worker_id": worker["id"],
            **finish_body,
        }
        finish_body["worker_signature"] = b64url_encode(
            sign_message(
                worker_keys.signing_private_key,
                canonical_json(finish_signed),
                context=b"vgen-worker-finish-v1",
            )
        )
        finished = client.post(
            f"/api/v1/attempts/{lease['attempt_id']}/finish",
            json=finish_body,
            headers=worker_headers,
        )
        assert finished.status_code == 200, finished.text
        assert finished.json()["state"] == "succeeded"
        lost_lease_replay = client.post(lease_path, json={"ttl_seconds": 60}, headers=lease_headers)
        assert lost_lease_replay.status_code == 409
        assert lost_lease_replay.json()["error"]["code"] == 310001

        usage = client.get(f"/api/v1/workspaces/{workspace['id']}/usage", headers=user_headers)
        assert usage.status_code == 200, usage.text
        entries = usage.json()
        assert len(entries) == 1
        assert entries[0]["worker_id"] == worker["id"]
        assert entries[0]["client_channel"] == "cli"
        assert entries[0]["compute_microtokens"] == 2_500_000
        assert entries[0]["billable"] == 1
        task_view = client.get(f"/api/v1/tasks/{task['id']}", headers=user_headers).json()
        output = next(item for item in task_view["artifacts"] if item["state"] == "available")
        downloaded_output = client.get(
            output["download_ticket"]["url"],
            headers=output["download_ticket"]["headers"],
        )
        assert downloaded_output.content == b"encrypted-video"
        app.state.db.execute("UPDATE tasks SET state='failed' WHERE id=?", (task["id"],))
        retry = client.post(f"/api/v1/tasks/{task['id']}/retry", headers=user_headers)
        assert retry.status_code == 503, retry.text
        assert retry.json()["error"]["code"] == 220001
        revoked = client.post(f"/api/v1/workers/{worker['id']}/revoke", headers=user_headers)
        assert revoked.status_code == 200, revoked.text
        rejected_refresh = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "worker", "worker_id": worker["id"]},
        )
        assert rejected_refresh.status_code == 401


def test_running_cancel_is_acknowledged_and_billed_once_end_to_end(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, user_headers, _, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Cancellation"}, headers=user_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=user_headers,
        ).json()

        worker_keys = DeviceKeys.generate()
        worker = app.state.repository.create_worker(
            owner_user_id=boot["user"]["id"],
            manager_broker_id=None,
            name="cancel-worker",
            signing_public_key=b64url_encode(worker_keys.signing_public_bytes()),
            encryption_public_key=b64url_encode(worker_keys.encryption_public_bytes()),
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        worker_token, _ = app.state.db.create_session(
            principal_type="worker",
            principal_id=worker["id"],
            user_id=boot["user"]["id"],
            scopes=["worker:heartbeat", "worker:complete"],
        )
        worker_headers = {"Authorization": f"Bearer {worker_token}"}

        task_id = new_id("task")
        attempt_id = new_id("attempt")
        lease_id = new_id("lease")
        stamp = time.time()
        fencing_token = int(stamp * 1_000_000)
        rate_snapshot = json.dumps(
            {
                "rate_microtokens_per_gpu_second": 1_000_000,
                "traffic_microtokens_per_gib": 0,
                "workflow_multiplier_ppm": 1_000_000,
                "formula_version": 1,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        app.state.db.execute(
            """INSERT INTO tasks
               (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
                consumer_principal_id,client_channel,workflow_ref,workflow_digest,
                executor_type,public_requirements,content_key_version,assigned_worker_id,
                state,priority,created_at,committed_at,updated_at)
               VALUES (?,?,?,?,? ,?,'api','vgen/test@1.0.0',?,'fake','{}',1,?,
                       'running',0,?,?,?)""",
            (
                task_id,
                workspace["id"],
                pool["id"],
                boot["user"]["id"],
                "device",
                boot["device"]["id"],
                "sha256:" + "c" * 64,
                worker["id"],
                stamp - 2,
                stamp - 2,
                stamp - 1,
            ),
        )
        app.state.db.execute(
            """INSERT INTO task_attempts
               (id,task_id,attempt_number,worker_id,provider_user_id,executor_type,
                executor_version,state,rate_snapshot,fencing_token,reserved_at,leased_at,
                started_at)
               VALUES (?,?,1,?,?,'fake','1','running',?,?,?,?,?)""",
            (
                attempt_id,
                task_id,
                worker["id"],
                boot["user"]["id"],
                rate_snapshot,
                fencing_token,
                stamp - 2,
                stamp - 1.8,
                stamp - 1.5,
            ),
        )
        app.state.db.execute(
            """INSERT INTO leases
               (id,attempt_id,worker_id,fencing_token,encrypted_tdk_envelope,
                issued_at,expires_at,heartbeat_at)
               VALUES (?,?,?,?,'{}',?,?,?)""",
            (
                lease_id,
                attempt_id,
                worker["id"],
                fencing_token,
                stamp - 1.8,
                stamp + 60,
                stamp,
            ),
        )

        cancelled = client.post(f"/api/v1/tasks/{task_id}/cancel", headers=user_headers)
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["state"] == "cancelled"
        directive = client.post(
            f"/api/v1/attempts/{attempt_id}/heartbeat",
            json={"fencing_token": fencing_token, "ttl_seconds": 60},
            headers=worker_headers,
        )
        assert directive.status_code == 200, directive.text
        assert directive.json()["cancelled"] is True

        finish_body = {
            "fencing_token": fencing_token,
            "succeeded": False,
            "output_artifacts": [],
            "metrics": {"executor_wall_ms": 1_200, "gpu_count": 1},
            "failure_code": 320008,
            "responsibility": "consumer",
            "safe_failure_details": {},
        }
        finish_body["worker_signature"] = b64url_encode(
            sign_message(
                worker_keys.signing_private_key,
                canonical_json(
                    {
                        "attempt_id": attempt_id,
                        "task_id": task_id,
                        "worker_id": worker["id"],
                        **finish_body,
                    }
                ),
                context=b"vgen-worker-finish-v1",
            )
        )
        finish_headers = {**worker_headers, "Idempotency-Key": "cancel-finish-once"}
        finished = client.post(
            f"/api/v1/attempts/{attempt_id}/finish",
            json=finish_body,
            headers=finish_headers,
        )
        repeated = client.post(
            f"/api/v1/attempts/{attempt_id}/finish",
            json=finish_body,
            headers=finish_headers,
        )
        assert finished.status_code == repeated.status_code == 200
        assert finished.json()["state"] == "cancelled"
        assert repeated.headers["Idempotency-Replayed"] == "true"

        usage = client.get(f"/api/v1/workspaces/{workspace['id']}/usage", headers=user_headers)
        assert usage.status_code == 200, usage.text
        assert len(usage.json()) == 1
        assert usage.json()[0]["attempt_id"] == attempt_id
        assert usage.json()[0]["billable"] == 1
        assert usage.json()[0]["compute_microtokens"] == 1_200_000
        assert (
            app.state.db.fetchone(
                "SELECT COUNT(*) AS count FROM usage_ledger WHERE attempt_id=?", (attempt_id,)
            )["count"]
            == 1
        )

        late_success = {
            **finish_body,
            "succeeded": True,
            "failure_code": None,
            "responsibility": "none",
        }
        late_success.pop("worker_signature")
        late_success["worker_signature"] = b64url_encode(
            sign_message(
                worker_keys.signing_private_key,
                canonical_json(
                    {
                        "attempt_id": attempt_id,
                        "task_id": task_id,
                        "worker_id": worker["id"],
                        **late_success,
                    }
                ),
                context=b"vgen-worker-finish-v1",
            )
        )
        fenced = client.post(
            f"/api/v1/attempts/{attempt_id}/finish",
            json=late_success,
            headers={**worker_headers, "Idempotency-Key": "late-success-new-mutation"},
        )
        assert fenced.status_code == 409
        assert fenced.json()["error"]["code"] == 310001
        task = client.get(f"/api/v1/tasks/{task_id}", headers=user_headers).json()
        assert task["state"] == "cancelled"
        assert task["attempts"][0]["state"] == "cancelled"


def test_workspace_admin_can_append_one_usage_reversal_via_api(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers = bootstrap(client)
        owner_id = boot["user"]["id"]
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Billing"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()
        worker = app.state.repository.create_worker(
            owner_user_id=owner_id,
            manager_broker_id=None,
            name="billing-worker",
            signing_public_key="billing-reversal-signing-key",
            encryption_public_key="billing-reversal-encryption-key",
            certificate=None,
            executor_type="fake",
            executor_version="1",
            capabilities={},
            capacity=1,
        )
        task_id = new_id("task")
        attempt_id = new_id("attempt")
        ledger_id = new_id("usage_ledger")
        stamp = time.time()
        app.state.db.execute(
            """INSERT INTO tasks
               (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
                consumer_principal_id,client_channel,workflow_ref,workflow_digest,
                executor_type,public_requirements,content_key_version,state,priority,
                created_at,finished_at,updated_at)
               VALUES (?,?,?,?,?,?,'api','vgen/test@1.0.0',?,'fake','{}',1,
                       'succeeded',0,?,?,?)""",
            (
                task_id,
                workspace["id"],
                pool["id"],
                owner_id,
                "device",
                boot["device"]["id"],
                hashlib.sha256(task_id.encode()).hexdigest(),
                stamp,
                stamp,
                stamp,
            ),
        )
        app.state.db.execute(
            """INSERT INTO task_attempts
               (id,task_id,attempt_number,worker_id,provider_user_id,executor_type,
                executor_version,state,responsibility,rate_snapshot,fencing_token,
                reserved_at,finished_at)
               VALUES (?,?,1,?,?,'fake','1','succeeded','consumer','{}',1,?,?)""",
            (attempt_id, task_id, worker["id"], owner_id, stamp, stamp),
        )
        app.state.db.execute(
            """INSERT INTO usage_ledger
               (id,attempt_id,entry_type,metrics,rate_snapshot,compute_microtokens,
                traffic_microtokens,total_microtokens,billable,responsibility,
                formula_version,integrity_hash,created_at)
               VALUES (?,?,'charge','{}','{}',11,2,13,1,'consumer',1,?,?)""",
            (ledger_id, attempt_id, hashlib.sha256(ledger_id.encode()).hexdigest(), stamp),
        )

        invalid = client.post(
            f"/api/v1/workspaces/{workspace['id']}/usage/{ledger_id}/reversal",
            json={"reason_code": "operator-written free-form explanation"},
            headers=owner_headers,
        )
        assert invalid.status_code == 422
        assert invalid.json()["error"]["code"] == 600001

        reversal_headers = {**owner_headers, "Idempotency-Key": "reverse-charge-1"}
        first = client.post(
            f"/api/v1/workspaces/{workspace['id']}/usage/{ledger_id}/reversal",
            json={"reason_code": "platform_fault"},
            headers=reversal_headers,
        )
        replay = client.post(
            f"/api/v1/workspaces/{workspace['id']}/usage/{ledger_id}/reversal",
            json={"reason_code": "platform_fault"},
            headers=reversal_headers,
        )
        assert first.status_code == replay.status_code == 200
        assert replay.headers["Idempotency-Replayed"] == "true"
        assert first.json()["id"] == replay.json()["id"]
        assert first.json()["total_microtokens"] == -13
        assert first.json()["reversal_reason_code"] == "platform_fault"

        semantic_retry = client.post(
            f"/api/v1/workspaces/{workspace['id']}/usage/{ledger_id}/reversal",
            json={"reason_code": "duplicate_charge"},
            headers=owner_headers,
        )
        assert semantic_retry.status_code == 200
        assert semantic_retry.json()["id"] == first.json()["id"]
        assert semantic_retry.json()["reversal_reason_code"] == "platform_fault"

        usage = client.get(
            f"/api/v1/workspaces/{workspace['id']}/usage", headers=owner_headers
        ).json()
        related = [entry for entry in usage if entry["attempt_id"] == attempt_id]
        assert len(related) == 2
        assert sum(entry["total_microtokens"] for entry in related) == 0


def test_standard_error_envelope_and_secret_not_stored(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        protocol_error = client.get("/api/v1/workspaces")
        assert protocol_error.status_code == 400
        assert protocol_error.json()["error"]["code"] == 600003
        client.headers.update({"Vgen-Protocol-Version": "1"})
        response = client.get("/api/v1/workspaces")
        assert response.status_code == 401
        error = response.json()["error"]
        assert error["code"] == 100001
        assert error["name"] == "AUTHENTICATION_REQUIRED"
        assert error["request_id"].startswith("req_")
        assert response.headers["X-Request-ID"] == error["request_id"]


def test_device_session_revalidates_persisted_certificate(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, _, identity, device = bootstrap_identity(client)
        device_id = boot["device"]["id"]
        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": device_id},
        ).json()
        expired = issue_device_certificate(
            identity,
            device,
            device_id=device_id,
            issued_at=int(time.time()) - 60,
            expires_at=int(time.time()) - 1,
        ).to_dict()
        app.state.db.execute(
            "UPDATE devices SET certificate=? WHERE id=?",
            (json.dumps(expired, separators=(",", ":")), device_id),
        )
        rejected = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "device",
                "device_id": device_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        device.signing_private_key,
                        challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert rejected.status_code == 401
        assert rejected.json()["error"]["code"] == 110002


def test_mutation_signature_and_nonce_replay_protection(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=True,
        artifact_root=str(tmp_path / "artifacts"),
    )
    identity = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(identity, device, device_id=device_id).to_dict()
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        response = client.post(
            "/api/v1/auth/bootstrap",
            json={
                "bootstrap_code": "test-bootstrap",
                "display_name": "Operator",
                "root_signing_public_key": b64url_encode(identity.signing_public_bytes()),
                "root_encryption_public_key": b64url_encode(identity.encryption_public_bytes()),
                "device_id": device_id,
                "device_name": "signed-device",
                "device_signing_public_key": b64url_encode(device.signing_public_bytes()),
                "device_encryption_public_key": b64url_encode(device.encryption_public_bytes()),
                "device_certificate": certificate,
            },
        )
        assert response.status_code == 200, response.text
        session_token = response.json()["session_token"]
        body = b'{"name":"Signed Workspace"}'
        signed = sign_http_request(
            device,
            method="POST",
            path="/api/v1/workspaces",
            body=body,
        ).to_headers()
        headers = {
            "Authorization": f"Bearer {session_token}",
            "Content-Type": "application/json",
            **signed,
        }
        created = client.post("/api/v1/workspaces", content=body, headers=headers)
        assert created.status_code == 200, created.text
        replayed = client.post("/api/v1/workspaces", content=body, headers=headers)
        assert replayed.status_code == 409
        assert replayed.json()["error"]["code"] == 100004

        cached_body = b'{"name":"Idempotent Signed Workspace"}'
        cached_signature = sign_http_request(
            device,
            method="POST",
            path="/api/v1/workspaces",
            body=cached_body,
        ).to_headers()
        cached_headers = {
            "Authorization": f"Bearer {session_token}",
            "Content-Type": "application/json",
            "Idempotency-Key": "signed-workspace-1",
            **cached_signature,
        }
        cached = client.post("/api/v1/workspaces", content=cached_body, headers=cached_headers)
        assert cached.status_code == 200, cached.text
        unsigned_replay = client.post(
            "/api/v1/workspaces",
            content=cached_body,
            headers={
                "Authorization": f"Bearer {session_token}",
                "Content-Type": "application/json",
                "Idempotency-Key": "signed-workspace-1",
            },
        )
        assert unsigned_replay.status_code == 401
        assert unsigned_replay.json()["error"]["code"] == 100003


def test_direct_device_invite_and_revoke(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Devices"}, headers=headers
        ).json()
        invite = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "broker_device", "method": "direct_invite"},
            headers=headers,
        )
        assert invite.status_code == 200, invite.text
        invited = invite.json()
        new_device = DeviceKeys.generate()
        new_device_id = new_id("device")
        certificate = issue_device_certificate(
            identity, new_device, device_id=new_device_id
        ).to_dict()
        enrolled = client.post(
            "/api/v1/devices/enroll",
            json={
                "invite_id": invited["enrollment"]["id"],
                "secret": invited["secret"],
                "root_signing_public_key": b64url_encode(identity.signing_public_bytes()),
                "root_encryption_public_key": b64url_encode(identity.encryption_public_bytes()),
                "device_id": new_device_id,
                "device_name": "replacement",
                "device_certificate": certificate,
                "proof_signature": device_enrollment_proof(
                    new_device, invited["enrollment"]["id"], new_device_id
                ),
            },
        )
        assert enrolled.status_code == 200, enrolled.text
        assert enrolled.json()["user_id"] == boot["user"]["id"]
        assert enrolled.json()["login_required"] is True
        assert "session_token" not in enrolled.json()

        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": new_device_id},
        ).json()
        wrong_device = DeviceKeys.generate()
        rejected_session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "device",
                "device_id": new_device_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        wrong_device.signing_private_key,
                        challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert rejected_session.status_code == 401
        assert rejected_session.json()["error"]["code"] == 100003

        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": new_device_id},
        ).json()
        accepted_session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "device",
                "device_id": new_device_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        new_device.signing_private_key,
                        challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert accepted_session.status_code == 200, accepted_session.text
        revoked = client.post(f"/api/v1/devices/{new_device_id}/revoke", headers=headers)
        assert revoked.status_code == 200, revoked.text
        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": new_device_id},
        )
        assert challenge.status_code == 401


def test_generic_claim_is_membership_only_and_preserves_dedicated_invites(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, root, device = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Typed enrollment"}, headers=headers
        ).json()

        certificate = boot["device"]["certificate"]
        if isinstance(certificate, str):
            certificate = json.loads(certificate)

        def registration_proof(invite_id: str) -> tuple[dict, str]:
            claim = build_user_registration_claim(
                invite_id=invite_id,
                display_name=str(boot["user"]["display_name"]),
                root_key_id=root.root_key_id,
                root_signing_public_key=b64url_encode(root.signing_public_bytes()),
                root_encryption_public_key=b64url_encode(root.encryption_public_bytes()),
                device_id=str(boot["device_id"]),
                device_name=str(boot["device"]["name"]),
                device_signing_public_key=b64url_encode(device.signing_public_bytes()),
                device_encryption_public_key=b64url_encode(device.encryption_public_bytes()),
                device_certificate=certificate,
            )
            return claim, user_enrollment_proof(device, claim)

        dedicated_invites = [
            client.post(
                f"/api/v1/workspaces/{workspace['id']}/invites",
                json={"kind": "user", "method": "direct_invite"},
                headers=headers,
            ).json(),
            client.post(
                f"/api/v1/workspaces/{workspace['id']}/invites",
                json={
                    "kind": "service",
                    "method": "direct_invite",
                    "scopes": ["task:submit"],
                },
                headers=headers,
            ).json(),
            client.post(
                f"/api/v1/workspaces/{workspace['id']}/invites",
                json={"kind": "broker_device", "method": "direct_invite"},
                headers=headers,
            ).json(),
        ]
        for invite in dedicated_invites:
            claim, proof_signature = registration_proof(invite["enrollment"]["id"])
            rejected = client.post(
                "/api/v1/enrollments/claim",
                json={
                    "invite_id": invite["enrollment"]["id"],
                    "secret": invite["secret"],
                    "claim": claim,
                    "proof_signature": proof_signature,
                },
                headers=headers,
            )
            assert rejected.status_code == 400, rejected.text
            assert rejected.json()["error"]["code"] == 240001
            enrollment = app.state.db.fetchone(
                "SELECT state FROM enrollments WHERE id=?",
                (invite["enrollment"]["id"],),
            )
            assert enrollment["state"] == "issued"

        membership = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "workspace_member", "method": "direct_invite"},
            headers=headers,
        ).json()
        confused_claim = client.post(
            "/api/v1/enrollments/claim",
            json={
                "invite_id": membership["enrollment"]["id"],
                "secret": membership["secret"],
                "subject_id": new_id("worker"),
                "claim": {"kind": "service"},
            },
            headers=headers,
        )
        assert confused_claim.status_code == 422
        assert confused_claim.json()["error"]["code"] == 600001
        membership_claim, membership_proof = registration_proof(
            membership["enrollment"]["id"]
        )
        claimed = client.post(
            "/api/v1/enrollments/claim",
            json={
                "invite_id": membership["enrollment"]["id"],
                "secret": membership["secret"],
                "claim": membership_claim,
                "proof_signature": membership_proof,
            },
            headers=headers,
        )
        assert claimed.status_code == 200, claimed.text
        assert claimed.json()["kind"] == "workspace_member"
        assert claimed.json()["state"] == "active"

        unsupported_worker_invite = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "worker_allocation", "method": "direct_invite"},
            headers=headers,
        )
        assert unsupported_worker_invite.status_code == 422
        assert unsupported_worker_invite.json()["error"]["code"] == 600001


def test_generic_claim_cannot_activate_legacy_allocation_for_another_users_worker(
    tmp_path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        _, owner_headers, owner_root, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "No worker invites"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()

        worker_keys = DeviceKeys.generate()
        worker = client.post(
            "/api/v1/workers",
            json={
                "name": "owner-worker",
                "signing_public_key": b64url_encode(worker_keys.signing_public_bytes()),
                "encryption_public_key": b64url_encode(worker_keys.encryption_public_bytes()),
                "certificate": worker_owner_certificate(owner_root, worker_keys),
                "executor_type": "fake",
            },
            headers=owner_headers,
        )
        assert worker.status_code == 200, worker.text

        attacker_invite = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "user", "method": "direct_invite"},
            headers=owner_headers,
        ).json()
        attacker_root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
        attacker_device = DeviceKeys.generate()
        attacker_device_id = new_id("device")
        attacker_claim = build_user_registration_claim(
            invite_id=attacker_invite["enrollment"]["id"],
            display_name="Attacker",
            root_key_id=attacker_root.root_key_id,
            root_signing_public_key=b64url_encode(attacker_root.signing_public_bytes()),
            root_encryption_public_key=b64url_encode(attacker_root.encryption_public_bytes()),
            device_id=attacker_device_id,
            device_name="attacker-device",
            device_signing_public_key=b64url_encode(attacker_device.signing_public_bytes()),
            device_encryption_public_key=b64url_encode(attacker_device.encryption_public_bytes()),
            device_certificate=issue_device_certificate(
                attacker_root, attacker_device, device_id=attacker_device_id
            ).to_dict(),
        )
        attacker = client.post(
            "/api/v1/auth/enroll",
            json={
                "invite_id": attacker_invite["enrollment"]["id"],
                "secret": attacker_invite["secret"],
                "claim": attacker_claim,
                "proof_signature": user_enrollment_proof(attacker_device, attacker_claim),
            },
        )
        assert attacker.status_code == 200, attacker.text
        attacker_challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": attacker_device_id},
        ).json()
        attacker_session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "device",
                "device_id": attacker_device_id,
                "challenge_id": attacker_challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        attacker_device.signing_private_key,
                        attacker_challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert attacker_session.status_code == 200, attacker_session.text
        attacker_headers = {"Authorization": f"Bearer {attacker_session.json()['session_token']}"}

        # Simulate an issued credential persisted by an older alpha build.
        # Even legacy rows are rejected by the now membership-only claim path.
        legacy_invite_id = new_id("invite")
        legacy_secret = "legacy-worker-invite-secret-000001"
        stamp = time.time()
        app.state.db.execute(
            """INSERT INTO enrollments
               (id,kind,method,state,workspace_id,pool_id,issuer_user_id,
                invite_secret_hash,expires_at,created_at,updated_at)
               VALUES (?,'worker_allocation','direct_invite','issued',?,?,?,?,?,?,?)""",
            (
                legacy_invite_id,
                workspace["id"],
                pool["id"],
                attacker.json()["user"]["id"],
                hashlib.sha256(legacy_secret.encode()).hexdigest(),
                stamp + 300,
                stamp,
                stamp,
            ),
        )
        legacy_claim = {**attacker_claim, "invite_id": legacy_invite_id}
        rejected = client.post(
            "/api/v1/enrollments/claim",
            json={
                "invite_id": legacy_invite_id,
                "secret": legacy_secret,
                "claim": legacy_claim,
                "proof_signature": user_enrollment_proof(attacker_device, legacy_claim),
            },
            headers=attacker_headers,
        )
        assert rejected.status_code == 400, rejected.text
        assert rejected.json()["error"]["code"] == 240001
        assert (
            app.state.db.fetchone("SELECT state FROM enrollments WHERE id=?", (legacy_invite_id,))[
                "state"
            ]
            == "issued"
        )
        assert (
            app.state.db.fetchone(
                "SELECT 1 FROM worker_allocations WHERE worker_id=? AND pool_id=?",
                (worker.json()["id"], pool["id"]),
            )
            is None
        )


def test_device_invite_rejects_forged_certificate_and_key_possession(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, root, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Device proof"}, headers=headers
        ).json()
        invited = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "broker_device", "method": "direct_invite"},
            headers=headers,
        ).json()
        new_device = DeviceKeys.generate()
        new_device_id = new_id("device")

        mismatched_certificate = issue_device_certificate(
            root, new_device, device_id=new_id("device")
        ).to_dict()
        base_payload = {
            "invite_id": invited["enrollment"]["id"],
            "secret": invited["secret"],
            "root_signing_public_key": boot["user"]["root_signing_public_key"],
            "root_encryption_public_key": boot["user"]["root_encryption_public_key"],
            "device_id": new_device_id,
            "device_name": "new-device",
            "proof_signature": device_enrollment_proof(
                new_device, invited["enrollment"]["id"], new_device_id
            ),
        }
        forged_certificate = client.post(
            "/api/v1/devices/enroll",
            json={**base_payload, "device_certificate": mismatched_certificate},
        )
        assert forged_certificate.status_code == 401
        assert forged_certificate.json()["error"]["code"] == 110002

        valid_certificate = issue_device_certificate(
            root, new_device, device_id=new_device_id
        ).to_dict()
        impostor = DeviceKeys.generate()
        forged_possession = client.post(
            "/api/v1/devices/enroll",
            json={
                **base_payload,
                "device_certificate": valid_certificate,
                "proof_signature": device_enrollment_proof(
                    impostor, invited["enrollment"]["id"], new_device_id
                ),
            },
        )
        assert forged_possession.status_code == 401
        assert forged_possession.json()["error"]["code"] == 100003

        enrollment = app.state.db.fetchone(
            "SELECT state FROM enrollments WHERE id=?",
            (invited["enrollment"]["id"],),
        )
        assert enrollment["state"] == "issued"
        assert app.state.db.fetchone("SELECT 1 FROM devices WHERE id=?", (new_device_id,)) is None

        enrolled = client.post(
            "/api/v1/devices/enroll",
            json={**base_payload, "device_certificate": valid_certificate},
        )
        assert enrolled.status_code == 200, enrolled.text
        assert enrolled.json()["login_required"] is True
