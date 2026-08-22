from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity, user_enrollment_proof
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    issue_device_certificate,
)
from vgen.gateway.app import create_app
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import build_user_registration_claim


def test_user_enrollment_exact_retry_recovers_a_lost_response_without_duplicate_identity(
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
        _, owner_headers, _, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces",
            json={"name": "Shared studio"},
            headers=owner_headers,
        ).json()
        invitation = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={
                "kind": "user",
                "method": "direct_invite",
                "relationship": "member",
            },
            headers=owner_headers,
        ).json()
        invite_id = invitation["enrollment"]["id"]
        secret = invitation["secret"]

        root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
        device = DeviceKeys.generate()
        device_id = new_id("device")
        certificate = issue_device_certificate(root, device, device_id=device_id).to_dict()
        registration_claim = build_user_registration_claim(
            invite_id=invite_id,
            display_name="Second user",
            root_key_id=root.root_key_id,
            root_signing_public_key=b64url_encode(root.signing_public_bytes()),
            root_encryption_public_key=b64url_encode(root.encryption_public_bytes()),
            device_id=device_id,
            device_name="second-mac",
            device_signing_public_key=b64url_encode(device.signing_public_bytes()),
            device_encryption_public_key=b64url_encode(device.encryption_public_bytes()),
            device_certificate=certificate,
        )
        payload = {
            "invite_id": invite_id,
            "secret": secret,
            "claim": registration_claim,
            "proof_signature": user_enrollment_proof(device, registration_claim),
        }

        first = client.post("/api/v1/auth/enroll", json=payload)
        assert first.status_code == 200, first.text
        first_value = first.json()
        assert first_value["enrollment"]["state"] == "active"
        assert "invite_secret_hash" not in first_value["enrollment"]

        # This is the same request after the first successful response was lost.
        retried = client.post("/api/v1/auth/enroll", json=payload)
        assert retried.status_code == 200, retried.text
        retried_value = retried.json()
        assert retried_value["user"]["id"] == first_value["user"]["id"]
        assert retried_value["device"]["id"] == first_value["device"]["id"]
        assert retried_value["enrollment"]["id"] == invite_id

        user_id = first_value["user"]["id"]
        assert app.state.db.fetchone(
            "SELECT COUNT(*) AS n FROM users WHERE root_signing_public_key=?",
            (registration_claim["root_signing_public_key"],),
        )["n"] == 1
        assert app.state.db.fetchone(
            "SELECT COUNT(*) AS n FROM devices WHERE id=? AND user_id=?",
            (device_id, user_id),
        )["n"] == 1
        assert app.state.db.fetchone(
            "SELECT COUNT(*) AS n FROM memberships WHERE workspace_id=? AND user_id=?",
            (workspace["id"], user_id),
        )["n"] == 1

        changed_claim = {**registration_claim, "display_name": "Gateway substituted identity"}
        changed = client.post(
            "/api/v1/auth/enroll",
            json={
                **payload,
                "claim": changed_claim,
                "proof_signature": user_enrollment_proof(device, changed_claim),
            },
        )
        assert changed.status_code == 409
        assert changed.json()["error"]["code"] == 600002

        stored = app.state.db.fetchone("SELECT * FROM enrollments WHERE id=?", (invite_id,))
        assert stored is not None
        claim_record = json.loads(stored["claim"])
        assert claim_record["registration_claim"]["device_id"] == device_id
        assert claim_record["proof_signature"] == payload["proof_signature"]
        assert "secret" not in json.dumps(claim_record, sort_keys=True)
        assert secret.encode() not in (tmp_path / "gateway.db").read_bytes()
        assert app.state.db.fetchone(
            "SELECT COUNT(*) AS n FROM idempotency_records WHERE path='/api/v1/auth/enroll'"
        )["n"] == 0
