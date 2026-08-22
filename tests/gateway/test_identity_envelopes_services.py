from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from vgen.crypto import (
    HPKE_ALGORITHM,
    DeviceKeys,
    IdentityKeys,
    b64url_decode,
    b64url_encode,
    canonical_json,
    issue_device_certificate,
    sign_key_manifest,
    sign_message,
    unwrap_workspace_key,
    workspace_key_aad,
    wrap_workspace_key,
)
from vgen.gateway.app import create_app
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_user_registration_claim,
    build_workspace_recipient_admission_manifest,
    sign_user_registration_claim,
)


def _bootstrap(
    client: TestClient,
) -> tuple[dict, dict[str, str], IdentityKeys, DeviceKeys]:
    root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(root, device, device_id=device_id).to_dict()
    response = client.post(
        "/api/v1/auth/bootstrap",
        headers={"Idempotency-Key": "must-not-cache-bootstrap-session"},
        json={
            "bootstrap_code": "test-bootstrap",
            "display_name": "Operator",
            "root_signing_public_key": b64url_encode(root.signing_public_bytes()),
            "root_encryption_public_key": b64url_encode(root.encryption_public_bytes()),
            "device_id": device_id,
            "device_name": "old-device",
            "device_signing_public_key": b64url_encode(device.signing_public_bytes()),
            "device_encryption_public_key": b64url_encode(device.encryption_public_bytes()),
            "device_certificate": certificate,
        },
    )
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    data = response.json()
    return data, {"Authorization": f"Bearer {data['session_token']}"}, root, device


def _device_enrollment_proof(keys: DeviceKeys, invite_id: str, device_id: str) -> str:
    return b64url_encode(
        sign_message(
            keys.signing_private_key,
            canonical_json({"version": 1, "invite_id": invite_id, "device_id": device_id}),
            context=b"vgen-device-enrollment-v1",
        )
    )


def _user_enrollment_proof(keys: DeviceKeys, claim: dict) -> str:
    return sign_user_registration_claim(keys.signing_private_key, claim)


def _owner_self_admission(
    client: TestClient,
    *,
    headers: dict[str, str],
    boot: dict,
    root: IdentityKeys,
    device: DeviceKeys,
    workspace_id: str,
) -> dict:
    certificate = boot["device"]["certificate"]
    if isinstance(certificate, str):
        certificate = json.loads(certificate)
    claim = build_user_registration_claim(
        invite_id=f"workspace-owner-self:{workspace_id}",
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
    proof = _user_enrollment_proof(device, claim)
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=str(boot["user_id"]),
        owner_root_key_id=root.root_key_id,
        subject_user_id=str(boot["user_id"]),
        enrollment_id=None,
        registration_claim=claim,
        registration_proof_signature=proof,
        issued_at=int(certificate["payload"]["issued_at"]),
    )
    response = client.post(
        f"/api/v1/workspaces/{workspace_id}/recipient-admissions",
        headers=headers,
        json={
            "enrollment_id": None,
            "signed_admission": sign_key_manifest(root, manifest),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _workspace_grant(
    *,
    root: IdentityKeys,
    workspace_id: str,
    recipient: dict,
    workspace_key: bytes,
    key_version: int = 1,
    rotation_id: str | None = None,
    recipient_set_digest: str | None = None,
) -> dict:
    recipient_type = str(recipient["recipient_type"])
    recipient_id = str(recipient["recipient_id"])
    aad = workspace_key_aad(
        workspace_id=workspace_id,
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        key_version=key_version,
        recipient_binding_digest=str(recipient["recipient_binding_digest"]),
    )
    envelope = wrap_workspace_key(
        b64url_decode(str(recipient["encryption_public_key"]), expected_length=32),
        workspace_key,
        aad=aad,
    ).to_dict()
    manifest = {
        "version": 1,
        "kind": "vgen-workspace-key-envelope",
        "workspace_id": workspace_id,
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": HPKE_ALGORITHM,
        "envelope_sha256": hashlib.sha256(canonical_json(envelope)).hexdigest(),
        "recipient_public_key_sha256": recipient["recipient_key_sha256"],
        "recipient_admission_sha256": recipient["admission_digest"],
        "recipient_binding_digest": recipient["recipient_binding_digest"],
        "signer_root_key_id": root.root_key_id,
        "issued_at": int(time.time()),
    }
    if rotation_id is not None:
        manifest["rotation_id"] = rotation_id
        manifest["recipient_set_digest"] = recipient_set_digest
    return {
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": HPKE_ALGORITHM,
        "envelope": envelope,
        "signed_manifest": sign_key_manifest(root, manifest),
    }


def _legacy_workspace_grant(
    *,
    root: IdentityKeys,
    workspace_id: str,
    recipient_type: str,
    recipient_id: str,
    recipient_public_key: bytes,
    workspace_key: bytes,
    key_version: int = 1,
) -> dict:
    aad = workspace_key_aad(
        workspace_id=workspace_id,
        recipient_type=recipient_type,
        recipient_id=recipient_id,
        key_version=key_version,
    )
    envelope = wrap_workspace_key(recipient_public_key, workspace_key, aad=aad).to_dict()
    manifest = {
        "version": 1,
        "kind": "vgen-workspace-key-envelope",
        "workspace_id": workspace_id,
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": HPKE_ALGORITHM,
        "envelope_sha256": hashlib.sha256(canonical_json(envelope)).hexdigest(),
        "signer_root_key_id": root.root_key_id,
        "issued_at": int(time.time()),
    }
    return {
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": HPKE_ALGORITHM,
        "envelope": envelope,
        "signed_manifest": sign_key_manifest(root, manifest),
    }


def test_workspace_key_rotation_is_atomic_idempotent_and_retains_history(tmp_path: Path) -> None:
    database_path = tmp_path / "gateway.db"
    app = create_app(
        database_path=str(database_path),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, root, device = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Rotating"}, headers=headers
        ).json()
        workspace_id = workspace["id"]
        _owner_self_admission(
            client,
            headers=headers,
            boot=boot,
            root=root,
            device=device,
            workspace_id=workspace_id,
        )
        pool = client.post(
            f"/api/v1/workspaces/{workspace_id}/pools",
            json={"name": "History"},
            headers=headers,
        ).json()
        user_id = boot["user_id"]
        old_key = b"1" * 32
        for recipient_type, recipient_id in (
            ("user_recovery", user_id),
            ("device", boot["device_id"]),
        ):
            recipient_response = client.get(
                f"/api/v1/workspaces/{workspace_id}/key-recipients/"
                f"{recipient_type}/{recipient_id}",
                headers=headers,
            )
            assert recipient_response.status_code == 200, recipient_response.text
            grant = _workspace_grant(
                root=root,
                workspace_id=workspace_id,
                recipient=recipient_response.json(),
                workspace_key=old_key,
            )
            response = client.post(
                f"/api/v1/workspaces/{workspace_id}/key-envelopes",
                json=grant,
                headers=headers,
            )
            assert response.status_code == 200, response.text

        old_task_id = new_id("task")
        stamp = time.time()
        app.state.db.execute(
            """INSERT INTO tasks
               (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
                consumer_principal_id,client_channel,workflow_ref,workflow_digest,
                executor_type,public_requirements,content_key_version,state,created_at,updated_at)
               VALUES (?,?,?,?,? ,?,?,?,?,?,'{}',1,'expired',?,?)""",
            (
                old_task_id,
                workspace_id,
                pool["id"],
                user_id,
                "device",
                boot["device_id"],
                "cli",
                "test/history@1.0.0",
                "sha256:" + "0" * 64,
                "fake",
                stamp,
                stamp,
            ),
        )

        snapshot_response = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-rotation/recipients",
            headers=headers,
        )
        assert snapshot_response.status_code == 200, snapshot_response.text
        snapshot = snapshot_response.json()
        assert snapshot["current_key_version"] == 1
        assert len(snapshot["recipients"]) == 2
        rotation_id = "wkr_abcdefghijklmnop"
        new_key = b"2" * 32
        grants = [
            _workspace_grant(
                root=root,
                workspace_id=workspace_id,
                recipient=recipient,
                workspace_key=new_key,
                key_version=2,
                rotation_id=rotation_id,
                recipient_set_digest=snapshot["recipient_set_digest"],
            )
            for recipient in snapshot["recipients"]
        ]
        payload = {
            "rotation_id": rotation_id,
            "expected_key_version": 1,
            "new_key_version": 2,
            "recipient_set_digest": snapshot["recipient_set_digest"],
            "envelopes": grants,
        }

        incomplete = client.post(
            f"/api/v1/workspaces/{workspace_id}/key-rotations",
            json={**payload, "envelopes": grants[:-1]},
            headers=headers,
        )
        assert incomplete.status_code == 409, incomplete.text
        assert incomplete.json()["error"]["code"] == 400002
        assert (
            app.state.db.fetchone("SELECT key_version FROM workspaces WHERE id=?", (workspace_id,))[
                "key_version"
            ]
            == 1
        )
        assert (
            app.state.db.fetchone(
                "SELECT COUNT(*) AS n FROM key_envelopes WHERE workspace_id=? AND key_version=2",
                (workspace_id,),
            )["n"]
            == 0
        )

        activated = client.post(
            f"/api/v1/workspaces/{workspace_id}/key-rotations",
            json=payload,
            headers=headers,
        )
        assert activated.status_code == 200, activated.text
        assert activated.json()["key_version"] == 2
        assert activated.json()["old_envelopes_retained"] is True

        replay = client.post(
            f"/api/v1/workspaces/{workspace_id}/key-rotations",
            json=payload,
            headers=headers,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["idempotent_replay"] is True
        counts = app.state.db.fetchall(
            """SELECT key_version,COUNT(*) AS n FROM key_envelopes
               WHERE workspace_id=? AND task_id IS NULL
               GROUP BY key_version ORDER BY key_version""",
            (workspace_id,),
        )
        assert [(row["key_version"], row["n"]) for row in counts] == [(1, 2), (2, 2)]
        assert (
            app.state.db.fetchone(
                "SELECT content_key_version FROM tasks WHERE id=?", (old_task_id,)
            )["content_key_version"]
            == 1
        )
        audit = app.state.db.fetchone(
            """SELECT safe_details FROM audit_events
               WHERE workspace_id=? AND action='workspace.key_rotated'""",
            (workspace_id,),
        )
        assert audit is not None
        assert new_key not in audit["safe_details"].encode()


def test_device_migration_and_workspace_envelopes_never_store_plaintext(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "gateway.db"
    app = create_app(
        database_path=str(database_path),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, old_headers, root, old_device = _bootstrap(client)
        user_id = boot["user_id"]
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Encrypted"}, headers=old_headers
        ).json()
        workspace_id = workspace["id"]
        _owner_self_admission(
            client,
            headers=old_headers,
            boot=boot,
            root=root,
            device=old_device,
            workspace_id=workspace_id,
        )
        workspace_key = b"wdk-plaintext-must-never-leak!!!"  # exactly 32 bytes
        assert len(workspace_key) == 32

        recovery_recipient = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-recipients/user_recovery/{user_id}",
            headers=old_headers,
        )
        assert recovery_recipient.status_code == 200, recovery_recipient.text
        recovery_grant = _workspace_grant(
            root=root,
            workspace_id=workspace_id,
            recipient=recovery_recipient.json(),
            workspace_key=workspace_key,
        )
        assert (
            client.post(
                f"/api/v1/workspaces/{workspace_id}/key-envelopes",
                json=recovery_grant,
                headers=old_headers,
            ).status_code
            == 200
        )
        old_device_id = boot["device_id"]
        old_device_recipient = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-recipients/device/{old_device_id}",
            headers=old_headers,
        )
        assert old_device_recipient.status_code == 200, old_device_recipient.text
        assert (
            client.post(
                f"/api/v1/workspaces/{workspace_id}/key-envelopes",
                json=_workspace_grant(
                    root=root,
                    workspace_id=workspace_id,
                    recipient=old_device_recipient.json(),
                    workspace_key=workspace_key,
                ),
                headers=old_headers,
            ).status_code
            == 200
        )

        new_device = DeviceKeys.generate()
        new_device_id = new_id("device")
        new_certificate = issue_device_certificate(
            root, new_device, device_id=new_device_id
        ).to_dict()
        challenge = client.post(
            "/api/v1/auth/device-recovery/challenges",
            headers={"Idempotency-Key": "must-not-cache-recovery-challenge"},
            json={
                "root_signing_public_key": b64url_encode(root.signing_public_bytes()),
                "device_id": new_device_id,
            },
        ).json()
        proof = canonical_json(
            {
                "version": 1,
                "challenge_id": challenge["challenge_id"],
                "challenge": challenge["challenge"],
                "device_id": new_device_id,
                "device_name": "new-device",
                "device_signing_public_key": b64url_encode(new_device.signing_public_bytes()),
                "device_encryption_public_key": b64url_encode(new_device.encryption_public_bytes()),
                "root_signing_public_key": b64url_encode(root.signing_public_bytes()),
                "root_encryption_public_key": b64url_encode(root.encryption_public_bytes()),
            }
        )
        recovered = client.post(
            "/api/v1/auth/device-recovery/complete",
            headers={"Idempotency-Key": "must-not-cache-recovery-session"},
            json={
                "challenge_id": challenge["challenge_id"],
                "root_signing_public_key": b64url_encode(root.signing_public_bytes()),
                "root_encryption_public_key": b64url_encode(root.encryption_public_bytes()),
                "device_id": new_device_id,
                "device_name": "new-device",
                "device_signing_public_key": b64url_encode(new_device.signing_public_bytes()),
                "device_encryption_public_key": b64url_encode(new_device.encryption_public_bytes()),
                "device_certificate": new_certificate,
                "root_signature": b64url_encode(
                    sign_message(
                        root.signing_private_key,
                        proof,
                        context=b"vgen-device-recovery-root-v1",
                    )
                ),
                "device_signature": b64url_encode(
                    sign_message(
                        new_device.signing_private_key,
                        proof,
                        context=b"vgen-device-recovery-device-v1",
                    )
                ),
            },
        )
        assert recovered.status_code == 200, recovered.text
        assert recovered.headers["Cache-Control"] == "no-store"
        assert (
            app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM idempotency_records
                   WHERE path LIKE '/api/v1/auth/%'"""
            )["n"]
            == 0
        )
        new_headers = {"Authorization": f"Bearer {recovered.json()['session_token']}"}
        recovery = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-envelopes/user_recovery/{user_id}",
            headers=new_headers,
        )
        assert recovery.status_code == 200, recovery.text
        item = recovery.json()["items"][0]
        assert (
            unwrap_workspace_key(
                root.encryption_private_key,
                item["envelope"],
                aad=workspace_key_aad(
                    workspace_id=workspace_id,
                    recipient_type="user_recovery",
                    recipient_id=user_id,
                    key_version=1,
                    recipient_binding_digest=item["signed_manifest"]["manifest"][
                        "recipient_binding_digest"
                    ],
                ),
            )
            == workspace_key
        )

        new_device_recipient = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-recipients/device/{new_device_id}",
            headers=new_headers,
        )
        assert new_device_recipient.status_code == 200, new_device_recipient.text
        assert (
            client.post(
                f"/api/v1/workspaces/{workspace_id}/key-envelopes",
                json=_workspace_grant(
                    root=root,
                    workspace_id=workspace_id,
                    recipient=new_device_recipient.json(),
                    workspace_key=workspace_key,
                ),
                headers=new_headers,
            ).status_code
            == 200
        )
        assert (
            client.post(f"/api/v1/devices/{old_device_id}/revoke", headers=new_headers).status_code
            == 200
        )
        assert client.get("/api/v1/workspaces", headers=old_headers).status_code == 401

        stored = app.state.db.fetchall(
            "SELECT envelope FROM key_envelopes WHERE workspace_id=?", (workspace_id,)
        )
        assert stored and all(workspace_key not in row["envelope"].encode() for row in stored)

    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(database_path) + suffix)
        if candidate.exists():
            assert workspace_key not in candidate.read_bytes()


def test_service_scope_isolation_envelope_access_and_enrollment_revoke(
    tmp_path: Path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, admin_headers, root, admin_device = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "API"}, headers=admin_headers
        ).json()
        workspace_id = workspace["id"]
        invite = client.post(
            f"/api/v1/workspaces/{workspace_id}/invites",
            json={
                "kind": "service",
                "method": "direct_invite",
                "scopes": ["task:read"],
            },
            headers=admin_headers,
        )
        assert invite.status_code == 200, invite.text
        service_keys = DeviceKeys.generate()
        claim = {
            "version": 1,
            "invite_id": invite.json()["enrollment"]["id"],
            "name": "read-api",
            "signing_public_key": b64url_encode(service_keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(service_keys.encryption_public_bytes()),
        }
        enrolled = client.post(
            "/api/v1/auth/services/enroll",
            json={
                "invite_id": claim["invite_id"],
                "name": claim["name"],
                "signing_public_key": claim["signing_public_key"],
                "encryption_public_key": claim["encryption_public_key"],
                "secret": invite.json()["secret"],
                "proof_signature": b64url_encode(
                    sign_message(
                        service_keys.signing_private_key,
                        canonical_json(claim),
                        context=b"vgen-service-enrollment-v1",
                    )
                ),
            },
        )
        assert enrolled.status_code == 200, enrolled.text
        service_id = enrolled.json()["service"]["id"]
        _owner_self_admission(
            client,
            headers=admin_headers,
            boot=boot,
            root=root,
            device=admin_device,
            workspace_id=workspace_id,
        )
        rotation_recipients = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-rotation/recipients",
            headers=admin_headers,
        )
        assert rotation_recipients.status_code == 200, rotation_recipients.text
        assert all(
            recipient["recipient_type"] != "service"
            for recipient in rotation_recipients.json()["recipients"]
        )
        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "service", "service_id": service_id},
        ).json()
        session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "service",
                "service_id": service_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        service_keys.signing_private_key,
                        challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert session.status_code == 200, session.text
        service_headers = {"Authorization": f"Bearer {session.json()['session_token']}"}
        assert (
            client.get(
                "/api/v1/tasks",
                params={"workspace_id": workspace_id},
                headers=service_headers,
            ).status_code
            == 200
        )
        denied_submit = client.post(
            "/api/v1/tasks/prepare",
            json={
                "workspace_id": workspace_id,
                "pool_id": new_id("pool"),
                "workflow_ref": "vgen/example@1.0.0",
                "workflow_digest": "sha256:" + "0" * 64,
                "executor_type": "comfyui",
                "public_requirements": {},
                "client_channel": "api",
            },
            headers=service_headers,
        )
        assert denied_submit.status_code == 403
        assert denied_submit.json()["error"]["code"] == 120002
        assert (
            client.post(
                "/api/v1/workspaces", json={"name": "forbidden"}, headers=service_headers
            ).status_code
            == 403
        )

        workspace_key = b"s" * 32
        grant = _legacy_workspace_grant(
            root=root,
            workspace_id=workspace_id,
            recipient_type="service",
            recipient_id=service_id,
            recipient_public_key=service_keys.encryption_public_bytes(),
            workspace_key=workspace_key,
        )
        rejected_grant = client.post(
            f"/api/v1/workspaces/{workspace_id}/key-envelopes",
            json=grant,
            headers=admin_headers,
        )
        assert rejected_grant.status_code == 404, rejected_grant.text
        assert rejected_grant.json()["error"]["code"] == 400005
        assert (
            rejected_grant.json()["error"]["details"]["reason"]
            == "SERVICE_RECIPIENT_ADMISSION_UNSUPPORTED"
        )

        stamp = time.time()
        signed_manifest = grant["signed_manifest"]
        app.state.db.execute(
            """INSERT INTO key_envelopes
               (id,workspace_id,task_id,recipient_type,recipient_id,key_version,
                algorithm,envelope,created_at)
               VALUES (?,?,NULL,'service',?,?,?,?,?)""",
            (
                new_id("key_envelope"),
                workspace_id,
                service_id,
                1,
                HPKE_ALGORITHM,
                json.dumps(grant["envelope"], sort_keys=True, separators=(",", ":")),
                stamp,
            ),
        )
        app.state.db.execute(
            """INSERT INTO key_manifests
               (id,subject_type,subject_id,key_version,manifest,signature,
                signer_user_id,created_at)
               VALUES (?,'workspace_key_envelope',?,1,?,?,?,?)""",
            (
                new_id("key_manifest"),
                f"{workspace_id}:service:{service_id}",
                json.dumps(signed_manifest["manifest"], sort_keys=True, separators=(",", ":")),
                signed_manifest["signature"],
                boot["user_id"],
                stamp,
            ),
        )
        own_envelope = client.get(
            f"/api/v1/workspaces/{workspace_id}/key-envelopes/service/{service_id}",
            headers=service_headers,
        )
        assert own_envelope.status_code == 200, own_envelope.text
        historical_item = own_envelope.json()["items"][0]
        assert historical_item["envelope"] != workspace_key.decode()
        assert (
            unwrap_workspace_key(
                service_keys.encryption_private_key,
                historical_item["envelope"],
                aad=workspace_key_aad(
                    workspace_id=workspace_id,
                    recipient_type="service",
                    recipient_id=service_id,
                    key_version=1,
                ),
            )
            == workspace_key
        )

        enrollment_id = invite.json()["enrollment"]["id"]
        first_revoke = client.post(
            f"/api/v1/enrollments/{enrollment_id}/revoke", headers=admin_headers
        )
        second_revoke = client.post(
            f"/api/v1/enrollments/{enrollment_id}/revoke", headers=admin_headers
        )
        assert first_revoke.status_code == second_revoke.status_code == 200
        assert second_revoke.json()["state"] == "revoked"
        assert (
            client.get(
                "/api/v1/tasks",
                params={"workspace_id": workspace_id},
                headers=service_headers,
            ).status_code
            == 401
        )


def test_invite_approval_activates_user_and_device_relationships(tmp_path: Path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, admin_headers, operator_root, _ = _bootstrap(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Approvals"}, headers=admin_headers
        ).json()
        workspace_id = workspace["id"]

        user_invite = client.post(
            f"/api/v1/workspaces/{workspace_id}/invites",
            json={"kind": "user", "method": "invite_approval"},
            headers=admin_headers,
        ).json()
        member_root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
        member_device = DeviceKeys.generate()
        member_device_id = new_id("device")
        member_certificate = issue_device_certificate(
            member_root, member_device, device_id=member_device_id
        ).to_dict()
        member_claim = build_user_registration_claim(
            invite_id=user_invite["enrollment"]["id"],
            display_name="Member",
            root_key_id=member_root.root_key_id,
            root_signing_public_key=b64url_encode(member_root.signing_public_bytes()),
            root_encryption_public_key=b64url_encode(member_root.encryption_public_bytes()),
            device_id=member_device_id,
            device_name="member-device",
            device_signing_public_key=b64url_encode(member_device.signing_public_bytes()),
            device_encryption_public_key=b64url_encode(member_device.encryption_public_bytes()),
            device_certificate=member_certificate,
        )
        member_proof = _user_enrollment_proof(member_device, member_claim)
        claimed_user = client.post(
            "/api/v1/auth/enroll",
            json={
                "invite_id": user_invite["enrollment"]["id"],
                "secret": user_invite["secret"],
                "claim": member_claim,
                "proof_signature": member_proof,
            },
        )
        assert claimed_user.status_code == 200, claimed_user.text
        member_challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": member_device_id},
        ).json()
        member_session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "device",
                "device_id": member_device_id,
                "challenge_id": member_challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        member_device.signing_private_key,
                        member_challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert member_session.status_code == 200, member_session.text
        member_headers = {"Authorization": f"Bearer {member_session.json()['session_token']}"}
        assert client.get("/api/v1/workspaces", headers=member_headers).json() == []
        approved_user = client.post(
            f"/api/v1/enrollments/{user_invite['enrollment']['id']}/decision",
            json={
                "approve": True,
                "signed_admission": sign_key_manifest(
                    operator_root,
                    build_workspace_recipient_admission_manifest(
                        workspace_id=workspace_id,
                        owner_user_id=boot["user"]["id"],
                        owner_root_key_id=operator_root.root_key_id,
                        subject_user_id=claimed_user.json()["user"]["id"],
                        enrollment_id=user_invite["enrollment"]["id"],
                        registration_claim=member_claim,
                        registration_proof_signature=member_proof,
                        issued_at=int(time.time()),
                    ),
                ),
            },
            headers=admin_headers,
        )
        assert approved_user.status_code == 200, approved_user.text
        assert [
            item["id"] for item in client.get("/api/v1/workspaces", headers=member_headers).json()
        ] == [workspace_id]

        device_invite = client.post(
            f"/api/v1/workspaces/{workspace_id}/invites",
            json={"kind": "broker_device", "method": "invite_approval"},
            headers=admin_headers,
        ).json()
        replacement = DeviceKeys.generate()
        replacement_id = new_id("device")
        replacement_certificate = issue_device_certificate(
            operator_root, replacement, device_id=replacement_id
        ).to_dict()
        pending_device = client.post(
            "/api/v1/devices/enroll",
            json={
                "invite_id": device_invite["enrollment"]["id"],
                "secret": device_invite["secret"],
                "root_signing_public_key": boot["user"]["root_signing_public_key"],
                "root_encryption_public_key": boot["user"]["root_encryption_public_key"],
                "device_id": replacement_id,
                "device_name": "approved-device",
                "device_certificate": replacement_certificate,
                "proof_signature": _device_enrollment_proof(
                    replacement, device_invite["enrollment"]["id"], replacement_id
                ),
            },
        )
        assert pending_device.status_code == 200, pending_device.text
        assert pending_device.json()["approval_required"] is True
        assert "session_token" not in pending_device.json()
        assert (
            client.post(
                f"/api/v1/enrollments/{device_invite['enrollment']['id']}/decision",
                json={"approve": True},
                headers=admin_headers,
            ).status_code
            == 200
        )
        challenge = client.post(
            "/api/v1/auth/challenges",
            json={"principal_type": "device", "device_id": replacement_id},
        ).json()
        replacement_session = client.post(
            "/api/v1/auth/sessions",
            json={
                "principal_type": "device",
                "device_id": replacement_id,
                "challenge_id": challenge["challenge_id"],
                "signature": b64url_encode(
                    sign_message(
                        replacement.signing_private_key,
                        challenge["challenge"].encode(),
                    )
                ),
            },
        )
        assert replacement_session.status_code == 200, replacement_session.text

        # Active relationship revocation is idempotent and revokes its session.
        replacement_headers = {
            "Authorization": f"Bearer {replacement_session.json()['session_token']}"
        }
        assert (
            client.post(
                f"/api/v1/enrollments/{device_invite['enrollment']['id']}/revoke",
                headers=admin_headers,
            ).status_code
            == 200
        )
        assert client.get("/api/v1/workspaces", headers=replacement_headers).status_code == 401
