from __future__ import annotations

import hashlib
from copy import deepcopy
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from vgen.cli.client import VgenClientError
from vgen.cli.identity_store import DeviceIdentity
from vgen.cli.user_enrollment import (
    UserEnrollmentError,
    ensure_owner_self_admission,
    identity_registration_claim,
    require_enrollment_claim,
    verify_recipient_bundle,
)
from vgen.cli.workspace_authorities import WorkspaceAuthorityStore
from vgen.cli.workspace_envelopes import (
    LegacyOwnerMigrationRequired,
    migrate_legacy_workspace_owner,
    require_local_workspace_owner,
)
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    canonical_json,
    issue_device_certificate,
    sign_key_manifest,
)
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_workspace_recipient_admission_manifest,
    user_verification_code,
    verify_user_registration_claim,
    workspace_recipient_admission_digest,
)


def _identity(alias: str = "owner") -> DeviceIdentity:
    root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    device = DeviceKeys.generate()
    device_id = new_id("device")
    certificate = issue_device_certificate(root, device, device_id=device_id)
    return DeviceIdentity(
        alias=alias,
        root_key_id=root.root_key_id,
        root_signing_public_key=b64url_encode(root.signing_public_bytes()),
        root_encryption_public_key=b64url_encode(root.encryption_public_bytes()),
        root_keys=root,
        device_id=device_id,
        device_keys=device,
        certificate=certificate,
    )


def _device_for_root(root: IdentityKeys, alias: str) -> DeviceIdentity:
    device = DeviceKeys.generate()
    device_id = new_id("device")
    return DeviceIdentity(
        alias=alias,
        root_key_id=root.root_key_id,
        root_signing_public_key=b64url_encode(root.signing_public_bytes()),
        root_encryption_public_key=b64url_encode(root.encryption_public_bytes()),
        root_keys=root,
        device_id=device_id,
        device_keys=device,
        certificate=issue_device_certificate(root, device, device_id=device_id),
    )


def _admitted_user_bundle() -> tuple[
    DeviceIdentity, dict[str, object], dict[str, object], str, str
]:
    owner = _identity()
    subject = _identity("subject")
    workspace_id = new_id("workspace")
    owner_user_id = new_id("user")
    subject_user_id = new_id("user")
    enrollment_id = new_id("invite")
    claim, proof = identity_registration_claim(
        subject,
        invite_id=enrollment_id,
        display_name="Subject",
        device_name="Subject Mac",
    )
    admission_manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
        owner_root_key_id=owner.root_key_id,
        subject_user_id=subject_user_id,
        enrollment_id=enrollment_id,
        registration_claim=claim,
        registration_proof_signature=proof,
        issued_at=int(subject.certificate.payload["issued_at"]),
    )
    admission = sign_key_manifest(owner.root_keys, admission_manifest)
    admission_digest = workspace_recipient_admission_digest(admission)
    key_digest = hashlib.sha256(
        subject.root_keys.encryption_public_bytes()
    ).hexdigest()
    binding = {
        "recipient_type": "user_recovery",
        "recipient_id": subject_user_id,
        "subject_user_id": subject_user_id,
        "encryption_public_key": subject.root_encryption_public_key,
        "recipient_key_sha256": key_digest,
        "admission_digest": admission_digest,
    }
    recipient = {
        **binding,
        "recipient_binding_digest": hashlib.sha256(canonical_json(binding)).hexdigest(),
        "signed_admission": admission,
        "admission_signer_user_id": owner_user_id,
        "admission_signer_root_signing_public_key": owner.root_signing_public_key,
    }
    enrollment = {
        "id": enrollment_id,
        "kind": "workspace_member",
        "method": "direct_invite",
        "state": "active",
        "workspace_id": workspace_id,
        "issuer_user_id": owner_user_id,
        "subject_user_id": subject_user_id,
        "subject_id": subject.device_id,
        "claim": claim,
        "proof_signature": proof,
    }
    return owner, recipient, enrollment, workspace_id, owner_user_id


def test_full_user_claim_and_code_reject_any_key_or_proof_substitution() -> None:
    subject = _identity("subject")
    claim, proof = identity_registration_claim(
        subject,
        invite_id=new_id("invite"),
        display_name="Subject",
        device_name="Subject Mac",
    )
    assert verify_user_registration_claim(claim, proof)

    tampered_root = dict(claim)
    tampered_root["root_encryption_public_key"] = b64url_encode(
        X25519PrivateKey.generate().public_key().public_bytes_raw()
    )
    assert not verify_user_registration_claim(tampered_root, proof)

    tampered_device = dict(claim)
    tampered_device["device_encryption_public_key"] = b64url_encode(
        X25519PrivateKey.generate().public_key().public_bytes_raw()
    )
    assert not verify_user_registration_claim(tampered_device, proof)
    assert not verify_user_registration_claim(claim, b64url_encode(b"x" * 64))


def test_verification_code_mismatch_refuses_owner_admission() -> None:
    _, _, enrollment, workspace_id, owner_user_id = _admitted_user_bundle()
    with pytest.raises(UserEnrollmentError, match="does not match"):
        require_enrollment_claim(
            enrollment,
            workspace_id=workspace_id,
            enrollment_id=str(enrollment["id"]),
            verification_code="0000-0000-0000-0000-0000",
            owner_user_id=owner_user_id,
        )
    claim = enrollment["claim"]
    assert isinstance(claim, dict)
    require_enrollment_claim(
        enrollment,
        workspace_id=workspace_id,
        enrollment_id=str(enrollment["id"]),
        verification_code=user_verification_code(claim),
        owner_user_id=owner_user_id,
    )


@pytest.mark.parametrize("field", ["encryption_public_key", "signed_admission"])
def test_gateway_recipient_key_or_admission_substitution_is_rejected(field: str) -> None:
    owner, recipient, _, workspace_id, owner_user_id = _admitted_user_bundle()
    tampered = deepcopy(recipient)
    if field == "encryption_public_key":
        tampered[field] = b64url_encode(
            X25519PrivateKey.generate().public_key().public_bytes_raw()
        )
    else:
        assert isinstance(tampered[field], dict)
        tampered[field]["manifest"]["subject_user_id"] = new_id("user")
    with pytest.raises(UserEnrollmentError, match="substituted or unverifiable"):
        verify_recipient_bundle(
            tampered,
            owner,
            workspace_id=workspace_id,
            owner_user_id=owner_user_id,
        )


def test_verified_recipient_bundle_binds_raw_key_and_admission_digest() -> None:
    owner, recipient, _, workspace_id, owner_user_id = _admitted_user_bundle()
    verified = verify_recipient_bundle(
        recipient,
        owner,
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
    )
    assert verified["encryption_public_key"] == recipient["encryption_public_key"]
    assert verified["recipient_key_sha256"] == recipient["recipient_key_sha256"]
    assert verified["admission_digest"] == recipient["admission_digest"]

    with pytest.raises(UserEnrollmentError, match="substituted or unverifiable"):
        verify_recipient_bundle(
            recipient,
            owner,
            workspace_id=workspace_id,
            owner_user_id=owner_user_id,
            expected_recipient_type="device",
            expected_recipient_id="dev_expected",
        )


def test_future_owner_device_reuses_genesis_admission_without_replacing_it() -> None:
    root = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    original = _device_for_root(root, "original")
    recovered = _device_for_root(root, "recovered")
    workspace_id = new_id("workspace")
    owner_user_id = new_id("user")
    claim, proof = identity_registration_claim(
        original,
        invite_id=f"workspace-owner-self:{workspace_id}",
        display_name="Owner",
        device_name="Original",
    )
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
        owner_root_key_id=root.root_key_id,
        subject_user_id=owner_user_id,
        enrollment_id=None,
        registration_claim=claim,
        registration_proof_signature=proof,
        issued_at=int(original.certificate.payload["issued_at"]),
    )
    signed = sign_key_manifest(root, manifest)
    existing = {
        "workspace_id": workspace_id,
        "subject_user_id": owner_user_id,
        "admission_digest": workspace_recipient_admission_digest(signed),
        "signed_admission": signed,
        "admission_signer_user_id": owner_user_id,
        "admission_signer_root_signing_public_key": original.root_signing_public_key,
    }

    class ExistingAdmissionGateway:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def request(self, method: str, path: str, **_kwargs):  # type: ignore[no-untyped-def]
            self.calls.append((method, path))
            if method == "GET" and path.endswith(f"/{owner_user_id}"):
                return existing
            raise AssertionError((method, path))

    gateway = ExistingAdmissionGateway()
    result = ensure_owner_self_admission(
        gateway,  # type: ignore[arg-type]
        recovered,
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
    )
    assert result == existing
    assert gateway.calls == [
        (
            "GET",
            f"/api/v1/workspaces/{workspace_id}/recipient-admissions/{owner_user_id}",
        )
    ]


def test_legacy_owner_requires_explicit_migration_before_key_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    workspace_id = new_id("workspace")
    owner_user_id = new_id("user")

    class MemoryKeyring:
        def __init__(self) -> None:
            self.values: dict[tuple[str, str], str] = {}

        def set_password(self, service: str, username: str, password: str) -> None:
            self.values[(service, username)] = password

        def get_password(self, service: str, username: str) -> str | None:
            return self.values.get((service, username))

    authority_store = WorkspaceAuthorityStore(backend=MemoryKeyring())
    monkeypatch.setattr(
        "vgen.cli.workspace_envelopes.WorkspaceAuthorityStore",
        lambda: authority_store,
    )

    class LegacyGateway:
        profile = SimpleNamespace(
            user_id=owner_user_id,
            endpoint="https://gateway.example",
        )

        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []

        def request(self, method: str, path: str, **kwargs):  # type: ignore[no-untyped-def]
            self.calls.append((method, path))
            if method == "GET" and "/recipient-admissions/" in path:
                raise VgenClientError(
                    400005,
                    "KEY_RECIPIENT_NOT_FOUND",
                    "not found",
                    status_code=404,
                )
            if method == "GET" and path == "/api/v1/workspaces":
                return [{"id": workspace_id, "owner_user_id": owner_user_id}]
            if method == "POST" and path.endswith("/recipient-admissions"):
                body = kwargs["json_body"]
                return {
                    "workspace_id": workspace_id,
                    "subject_user_id": owner_user_id,
                    "signed_admission": body["signed_admission"],
                }
            raise AssertionError((method, path))

    gateway = LegacyGateway()
    with pytest.raises(LegacyOwnerMigrationRequired, match="owner-migrate"):
        require_local_workspace_owner(
            gateway,  # type: ignore[arg-type]
            identity,
            workspace_id=workspace_id,
        )
    assert authority_store.load_owner(workspace_id) is None

    migrated = migrate_legacy_workspace_owner(
        gateway,  # type: ignore[arg-type]
        identity,
        workspace_id=workspace_id,
    )
    assert migrated["migrated"] is True
    assert migrated["source"] == "explicit_legacy_owner_tofu"
    assert authority_store.load_owner(workspace_id) is not None
    assert (
        require_local_workspace_owner(
            gateway,  # type: ignore[arg-type]
            identity,
            workspace_id=workspace_id,
        )
        == owner_user_id
    )
