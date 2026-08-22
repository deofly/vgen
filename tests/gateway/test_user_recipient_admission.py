from __future__ import annotations

from copy import deepcopy
from time import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    issue_device_certificate,
    sign_key_manifest,
)
from vgen.gateway.app import create_app
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_user_registration_claim,
    build_workspace_recipient_admission_manifest,
    sign_user_registration_claim,
)


def _claim(identity: IdentityKeys, device: DeviceKeys, invite_id: str) -> dict[str, object]:
    device_id = new_id("device")
    certificate = issue_device_certificate(identity, device, device_id=device_id).to_dict()
    claim = build_user_registration_claim(
        invite_id=invite_id,
        display_name="Joining User",
        root_key_id=identity.root_key_id,
        root_signing_public_key=b64url_encode(identity.signing_public_bytes()),
        root_encryption_public_key=b64url_encode(identity.encryption_public_bytes()),
        device_id=device_id,
        device_name="Joining Mac",
        device_signing_public_key=b64url_encode(device.signing_public_bytes()),
        device_encryption_public_key=b64url_encode(device.encryption_public_bytes()),
        device_certificate=certificate,
    )
    return {
        "claim": claim,
        "proof_signature": sign_user_registration_claim(device.signing_private_key, claim),
    }


def _admission(
    owner: IdentityKeys,
    *,
    owner_user_id: str,
    workspace_id: str,
    subject_user_id: str,
    enrollment_id: str | None,
    registration: dict[str, object],
    issued_at: int | None = None,
) -> dict[str, object]:
    claim = registration["claim"]
    assert isinstance(claim, dict)
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
        owner_root_key_id=owner.root_key_id,
        subject_user_id=subject_user_id,
        enrollment_id=enrollment_id,
        registration_claim=claim,
        registration_proof_signature=str(registration["proof_signature"]),
        issued_at=int(time()) if issued_at is None else issued_at,
    )
    return sign_key_manifest(owner, manifest)


def test_user_approval_requires_owner_admission_and_semantic_retry_is_safe(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Admission test"}, headers=owner_headers
        ).json()
        invitation = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={
                "kind": "user",
                "method": "invite_approval",
                "relationship": "member",
            },
            headers=owner_headers,
        ).json()
        enrollment_id = invitation["enrollment"]["id"]
        joining_root = IdentityKeys(
            Ed25519PrivateKey.generate(), X25519PrivateKey.generate()
        )
        joining_device = DeviceKeys.generate()
        registration = _claim(joining_root, joining_device, enrollment_id)
        enrolled = client.post(
            "/api/v1/auth/enroll",
            json={
                "invite_id": enrollment_id,
                "secret": invitation["secret"],
                **registration,
            },
        )
        assert enrolled.status_code == 200, enrolled.text
        enrollment = enrolled.json()["enrollment"]
        assert enrollment["claim"] == registration["claim"]
        assert enrollment["proof_signature"] == registration["proof_signature"]

        missing = client.post(
            f"/api/v1/enrollments/{enrollment_id}/decision",
            json={"approve": True},
            headers=owner_headers,
        )
        assert missing.status_code == 401
        assert missing.json()["error"]["code"] == 100003

        signed = _admission(
            owner,
            owner_user_id=boot["user"]["id"],
            workspace_id=workspace["id"],
            subject_user_id=enrolled.json()["user"]["id"],
            enrollment_id=enrollment_id,
            registration=registration,
        )
        tampered = deepcopy(signed)
        tampered["manifest"]["root_encryption_public_key"] = b64url_encode(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        )
        rejected = client.post(
            f"/api/v1/enrollments/{enrollment_id}/decision",
            json={"approve": True, "signed_admission": tampered},
            headers=owner_headers,
        )
        assert rejected.status_code == 401

        approved = client.post(
            f"/api/v1/enrollments/{enrollment_id}/decision",
            json={"approve": True, "signed_admission": signed},
            headers=owner_headers,
        )
        assert approved.status_code == 200, approved.text
        assert approved.json()["state"] == "active"

        # A retry may carry a fresh admission timestamp/signature, but it may
        # never replace the immutable identity semantics already pinned.
        retry = _admission(
            owner,
            owner_user_id=boot["user"]["id"],
            workspace_id=workspace["id"],
            subject_user_id=enrolled.json()["user"]["id"],
            enrollment_id=enrollment_id,
            registration=registration,
            issued_at=int(signed["manifest"]["issued_at"]) + 1,
        )
        replay = client.post(
            f"/api/v1/workspaces/{workspace['id']}/recipient-admissions",
            json={"enrollment_id": enrollment_id, "signed_admission": retry},
            headers=owner_headers,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["signed_admission"] == signed


def test_owner_can_issue_wdk_recipient_invite(tmp_path) -> None:
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
            "/api/v1/workspaces", json={"name": "Owner only"}, headers=owner_headers
        ).json()
        # The public contract still permits Owner-issued recipient Invites.
        created = client.post(
            f"/api/v1/workspaces/{workspace['id']}/invites",
            json={"kind": "workspace_member", "method": "direct_invite"},
            headers=owner_headers,
        )
        assert created.status_code == 200
