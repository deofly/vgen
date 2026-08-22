from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import vgen.cli.workspace_envelopes as cli_workspace_envelopes
from vgen.cli.client import VgenClientError
from vgen.cli.identity_store import DeviceIdentity
from vgen.cli.user_enrollment import identity_registration_claim
from vgen.cli.workspace_authorities import WorkspaceAuthorityStore
from vgen.cli.workspace_envelopes import (
    initialize_workspace_keys,
    rotate_workspace_key,
    sync_service_workspace_key,
    sync_workspace_key,
)
from vgen.cli.workspace_keys import WorkspaceKeyStore
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    canonical_json,
    issue_device_certificate,
    sign_key_manifest,
    unwrap_workspace_key,
    workspace_key_aad,
    wrap_workspace_key,
)
from vgen.protocol.ids import new_id
from vgen.protocol.user_enrollment import (
    build_workspace_recipient_admission_manifest,
    workspace_recipient_admission_digest,
)


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


@pytest.fixture(autouse=True)
def isolated_mutation_authority_store(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = MemoryKeyring()
    monkeypatch.setattr(
        cli_workspace_envelopes,
        "WorkspaceAuthorityStore",
        lambda: WorkspaceAuthorityStore(backend=backend),
    )


def identity_for(root: IdentityKeys, *, alias: str) -> DeviceIdentity:
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


def root_identity() -> IdentityKeys:
    return IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())


def owner_admission_record(
    owner: DeviceIdentity,
    *,
    workspace_id: str,
    owner_user_id: str,
) -> dict[str, Any]:
    claim, proof = identity_registration_claim(
        owner,
        invite_id=f"workspace-owner-self:{workspace_id}",
        display_name="Workspace Owner",
        device_name="Owner Device",
    )
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
        owner_root_key_id=owner.root_key_id,
        subject_user_id=owner_user_id,
        enrollment_id=None,
        registration_claim=claim,
        registration_proof_signature=proof,
        issued_at=int(owner.certificate.payload["issued_at"]),
    )
    signed = sign_key_manifest(owner.root_keys, manifest)
    return {
        "workspace_id": workspace_id,
        "subject_user_id": owner_user_id,
        "admission_digest": workspace_recipient_admission_digest(signed),
        "signed_admission": signed,
        "admission_signer_user_id": owner_user_id,
        "admission_signer_root_signing_public_key": owner.root_signing_public_key,
    }


def admitted_recipient(
    admission: dict[str, Any],
    *,
    recipient_type: str,
    recipient_id: str,
    subject_user_id: str,
    encryption_public_key: str,
    device_certificate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    key_digest = hashlib.sha256(
        cli_workspace_envelopes.b64url_decode(encryption_public_key, expected_length=32)
    ).hexdigest()
    binding: dict[str, Any] = {
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "subject_user_id": subject_user_id,
        "encryption_public_key": encryption_public_key,
        "recipient_key_sha256": key_digest,
        "admission_digest": admission["admission_digest"],
    }
    if device_certificate is not None:
        binding["device_certificate_sha256"] = hashlib.sha256(
            canonical_json(device_certificate)
        ).hexdigest()
    return {
        **binding,
        "recipient_binding_digest": hashlib.sha256(canonical_json(binding)).hexdigest(),
        **({"device_certificate": device_certificate} if device_certificate is not None else {}),
        "signed_admission": admission["signed_admission"],
        "admission_signer_user_id": admission["admission_signer_user_id"],
        "admission_signer_root_signing_public_key": admission[
            "admission_signer_root_signing_public_key"
        ],
    }


def legacy_envelope_item(
    *,
    root: IdentityKeys,
    signer_user_id: str,
    workspace_id: str,
    recipient_type: str,
    recipient_id: str,
    recipient_public_key: bytes,
    workspace_key: bytes,
    key_version: int = 1,
) -> dict[str, Any]:
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
        "algorithm": cli_workspace_envelopes.HPKE_ALGORITHM,
        "envelope_sha256": hashlib.sha256(canonical_json(envelope)).hexdigest(),
        "signer_root_key_id": root.root_key_id,
        "issued_at": 1,
    }
    return {
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": cli_workspace_envelopes.HPKE_ALGORITHM,
        "envelope": envelope,
        "signed_manifest": sign_key_manifest(root, manifest),
        "signer_user_id": signer_user_id,
        "signer_root_signing_public_key": b64url_encode(root.signing_public_bytes()),
        "signer_workspace_role": "owner",
    }


class EnvelopeGateway:
    def __init__(self, *, user_id: str, root: IdentityKeys, workspace_id: str) -> None:
        self.user_id = user_id
        self.root = root
        self.workspace_id = workspace_id
        self.profile = SimpleNamespace(user_id=user_id)
        self.admission: dict[str, Any] | None = None
        self.recipients: dict[tuple[str, str], dict[str, Any]] = {
            ("user_recovery", user_id): {
                "encryption_public_key": b64url_encode(root.encryption_public_bytes())
            }
        }
        self.envelopes: dict[tuple[str, str], dict[str, Any]] = {}
        self.key_version = 1

    def add_device(self, identity: DeviceIdentity) -> None:
        self.recipients[("device", identity.device_id)] = {
            "encryption_public_key": b64url_encode(
                identity.device_keys.encryption_public_bytes()
            ),
            "device_certificate": identity.certificate.to_dict(),
        }

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if method == "GET" and path == "/api/v1/workspaces":
            return [
                {
                    "id": self.workspace_id,
                    "owner_user_id": self.user_id,
                    "key_version": self.key_version,
                }
            ]
        if method == "GET" and "/recipient-admissions/" in path:
            if self.admission is None:
                raise VgenClientError(
                    400005,
                    "KEY_RECIPIENT_NOT_FOUND",
                    "recipient admission not found",
                    status_code=404,
                )
            return self.admission
        if method == "POST" and path.endswith("/recipient-admissions"):
            signed = kwargs["json_body"]["signed_admission"]
            self.admission = {
                "workspace_id": self.workspace_id,
                "subject_user_id": self.user_id,
                "admission_digest": workspace_recipient_admission_digest(signed),
                "signed_admission": signed,
                "admission_signer_user_id": self.user_id,
                "admission_signer_root_signing_public_key": b64url_encode(
                    self.root.signing_public_bytes()
                ),
            }
            return self.admission
        if "/key-recipients/" in path:
            recipient_type, recipient_id = path.rsplit("/", 2)[-2:]
            assert self.admission is not None
            recipient = self.recipients[(recipient_type, recipient_id)]
            return {
                **admitted_recipient(
                    self.admission,
                    recipient_type=recipient_type,
                    recipient_id=recipient_id,
                    subject_user_id=self.user_id,
                    encryption_public_key=recipient["encryption_public_key"],
                    device_certificate=recipient.get("device_certificate"),
                ),
                "key_version": self.key_version,
            }
        if method == "POST" and path.endswith("/key-envelopes"):
            payload = dict(kwargs["json_body"])
            payload.update(
                {
                    "signer_user_id": self.user_id,
                    "signer_root_signing_public_key": b64url_encode(
                        self.root.signing_public_bytes()
                    ),
                    "signer_workspace_role": "owner",
                }
            )
            self.envelopes[(payload["recipient_type"], payload["recipient_id"])] = payload
            return {"id": new_id("key_envelope"), "stored": True}
        if method == "GET" and "/key-envelopes/" in path:
            recipient_type, recipient_id = path.rsplit("/", 2)[-2:]
            item = self.envelopes.get((recipient_type, recipient_id))
            return {"items": [item] if item else []}
        raise AssertionError((method, path, kwargs))


class RotationGateway:
    def __init__(
        self,
        recipients: list[dict[str, Any]],
        *,
        workspace_id: str,
        user_id: str,
        admission: dict[str, Any],
        recipient_set_digest: str | None = None,
        fail: bool = False,
    ) -> None:
        self.recipients = sorted(
            recipients, key=lambda value: (value["recipient_type"], value["recipient_id"])
        )
        self.workspace_id = workspace_id
        self.user_id = user_id
        self.admission = admission
        self.profile = SimpleNamespace(user_id=user_id)
        self.recipient_set_digest = recipient_set_digest or hashlib.sha256(
            canonical_json(self.recipients)
        ).hexdigest()
        self.fail = fail
        self.mutation: dict[str, Any] | None = None

    def request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        if method == "GET" and path == "/api/v1/workspaces":
            return [
                {
                    "id": self.workspace_id,
                    "owner_user_id": self.user_id,
                    "key_version": 1,
                }
            ]
        if method == "GET" and "/recipient-admissions/" in path:
            return self.admission
        if method == "POST" and path.endswith("/recipient-admissions"):
            return self.admission
        if method == "GET" and path.endswith("/key-rotation/recipients"):
            return {
                "current_key_version": 1,
                "next_key_version": 2,
                "recipient_set_digest": self.recipient_set_digest,
                "recipients": self.recipients,
            }
        if method == "POST" and path.endswith("/key-rotations"):
            self.mutation = kwargs["json_body"]
            if self.fail:
                raise RuntimeError("rotation rejected")
            return {
                "workspace_id": path.split("/")[4],
                "rotation_id": self.mutation["rotation_id"],
                "previous_key_version": 1,
                "key_version": 2,
                "recipient_count": len(self.recipients),
                "old_envelopes_retained": True,
                "idempotent_replay": False,
            }
        raise AssertionError((method, path, kwargs))


def test_new_device_sync_verifies_root_manifest_before_keychain_write() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    old_device = identity_for(root, alias="old")
    new_device = identity_for(root, alias="new")
    gateway = EnvelopeGateway(user_id=user_id, root=root, workspace_id=workspace_id)
    gateway.add_device(old_device)
    gateway.add_device(new_device)
    old_keyring = MemoryKeyring()
    new_keyring = MemoryKeyring()
    initialize_workspace_keys(
        gateway,  # type: ignore[arg-type]
        old_device,
        {"id": workspace_id, "owner_user_id": user_id, "key_version": 1},
        store=WorkspaceKeyStore(backend=old_keyring),
    )
    result = sync_workspace_key(
        gateway,  # type: ignore[arg-type]
        new_device,
        workspace_id=workspace_id,
        user_id=user_id,
        store=WorkspaceKeyStore(backend=new_keyring),
        authority_store=WorkspaceAuthorityStore(backend=MemoryKeyring()),
    )
    assert result["source"] == "user_recovery"
    assert result["signer_trust"] == "local_user_root"
    assert result["device_envelope_created"] is False
    assert ("device", new_device.device_id) not in gateway.envelopes
    assert WorkspaceKeyStore(backend=old_keyring).load(workspace_id, 1) == WorkspaceKeyStore(
        backend=new_keyring
    ).load(workspace_id, 1)


def test_tampered_manifest_never_reaches_keychain() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    old_device = identity_for(root, alias="old")
    new_device = identity_for(root, alias="new")
    gateway = EnvelopeGateway(user_id=user_id, root=root, workspace_id=workspace_id)
    gateway.add_device(old_device)
    gateway.add_device(new_device)
    initialize_workspace_keys(
        gateway,  # type: ignore[arg-type]
        old_device,
        {"id": workspace_id, "owner_user_id": user_id, "key_version": 1},
        store=WorkspaceKeyStore(backend=MemoryKeyring()),
    )
    gateway.envelopes[("user_recovery", user_id)]["signed_manifest"]["manifest"]["key_version"] = 2
    destination = MemoryKeyring()
    with pytest.raises(ValueError, match="signature or binding"):
        sync_workspace_key(
            gateway,  # type: ignore[arg-type]
            new_device,
            workspace_id=workspace_id,
            user_id=user_id,
            store=WorkspaceKeyStore(backend=destination),
            authority_store=WorkspaceAuthorityStore(backend=MemoryKeyring()),
        )
    assert destination.values == {}


def test_service_sync_only_opens_its_admin_signed_service_envelope() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    service_id = new_id("service")
    service_keys = DeviceKeys.generate()
    gateway = EnvelopeGateway(user_id=user_id, root=root, workspace_id=workspace_id)
    workspace_key = b"w" * 32
    gateway.envelopes[("service", service_id)] = legacy_envelope_item(
        root=root,
        signer_user_id=user_id,
        workspace_id=workspace_id,
        recipient_type="service",
        recipient_id=service_id,
        recipient_public_key=service_keys.encryption_public_bytes(),
        workspace_key=workspace_key,
    )
    destination = MemoryKeyring()
    authorities = WorkspaceAuthorityStore(backend=MemoryKeyring())
    authorities.pin(
        workspace_id=workspace_id,
        user_id=user_id,
        root_signing_public_key=b64url_encode(root.signing_public_bytes()),
        root_key_id=root.root_key_id,
        source="test",
    )

    result = sync_service_workspace_key(
        gateway,  # type: ignore[arg-type]
        service_keys,
        workspace_id=workspace_id,
        service_id=service_id,
        store=WorkspaceKeyStore(backend=destination),
        authority_store=authorities,
    )

    assert result["source"] == "service"
    assert WorkspaceKeyStore(backend=destination).load(workspace_id, 1) == workspace_key


def test_service_sync_rejects_gateway_substitution_of_admin_key_and_signature() -> None:
    trusted = root_identity()
    attacker = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    service_id = new_id("service")
    service_keys = DeviceKeys.generate()
    gateway = EnvelopeGateway(user_id=user_id, root=trusted, workspace_id=workspace_id)
    gateway.envelopes[("service", service_id)] = legacy_envelope_item(
        root=trusted,
        signer_user_id=user_id,
        workspace_id=workspace_id,
        recipient_type="service",
        recipient_id=service_id,
        recipient_public_key=service_keys.encryption_public_bytes(),
        workspace_key=b"w" * 32,
    )
    item = gateway.envelopes[("service", service_id)]
    forged_manifest = dict(item["signed_manifest"]["manifest"])
    forged_manifest["signer_root_key_id"] = attacker.root_key_id
    item["signed_manifest"] = sign_key_manifest(attacker, forged_manifest)
    item["signer_root_signing_public_key"] = b64url_encode(attacker.signing_public_bytes())
    authorities = WorkspaceAuthorityStore(backend=MemoryKeyring())
    authorities.pin(
        workspace_id=workspace_id,
        user_id=user_id,
        root_signing_public_key=b64url_encode(trusted.signing_public_bytes()),
        root_key_id=trusted.root_key_id,
        source="signed_invite_fragment",
    )

    with pytest.raises(RuntimeError, match="substituted"):
        sync_service_workspace_key(
            gateway,  # type: ignore[arg-type]
            service_keys,
            workspace_id=workspace_id,
            service_id=service_id,
            store=WorkspaceKeyStore(backend=MemoryKeyring()),
            authority_store=authorities,
        )


def test_rotation_wraps_every_snapshot_recipient_before_saving_local_key() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    admin = identity_for(root, alias="admin")
    admission = owner_admission_record(
        admin, workspace_id=workspace_id, owner_user_id=user_id
    )
    recovery_recipient = admitted_recipient(
        admission,
        recipient_type="user_recovery",
        recipient_id=user_id,
        subject_user_id=user_id,
        encryption_public_key=b64url_encode(root.encryption_public_bytes()),
    )
    device_recipient = admitted_recipient(
        admission,
        recipient_type="device",
        recipient_id=admin.device_id,
        subject_user_id=user_id,
        encryption_public_key=b64url_encode(admin.device_keys.encryption_public_bytes()),
        device_certificate=admin.certificate.to_dict(),
    )
    recipients = [
        recovery_recipient,
        device_recipient,
    ]
    gateway = RotationGateway(
        recipients,
        workspace_id=workspace_id,
        user_id=user_id,
        admission=admission,
    )
    keyring = MemoryKeyring()

    result = rotate_workspace_key(
        gateway,  # type: ignore[arg-type]
        admin,
        workspace_id=workspace_id,
        expected_key_version=1,
        store=WorkspaceKeyStore(backend=keyring),
    )

    assert result["key_version"] == 2
    assert result["local_key_saved"] is True
    assert gateway.mutation is not None
    assert len(gateway.mutation["envelopes"]) == 2
    assert {item["recipient_type"] for item in gateway.mutation["envelopes"]} == {
        "device",
        "user_recovery",
    }
    workspace_key = WorkspaceKeyStore(backend=keyring).load(workspace_id, 2)
    raw_mutation = json.dumps(gateway.mutation, sort_keys=True).encode()
    assert workspace_key not in raw_mutation
    device_grant = next(
        item for item in gateway.mutation["envelopes"] if item["recipient_type"] == "device"
    )
    assert (
        unwrap_workspace_key(
            admin.device_keys.encryption_private_key,
            device_grant["envelope"],
            aad=workspace_key_aad(
                workspace_id=workspace_id,
                recipient_type="device",
                recipient_id=admin.device_id,
                key_version=2,
                recipient_binding_digest=device_recipient["recipient_binding_digest"],
            ),
        )
        == workspace_key
    )


def test_rotation_rejects_rehashed_gateway_recipient_key_substitution() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    admin = identity_for(root, alias="admin")
    admission = owner_admission_record(
        admin, workspace_id=workspace_id, owner_user_id=user_id
    )
    recipient = admitted_recipient(
        admission,
        recipient_type="user_recovery",
        recipient_id=user_id,
        subject_user_id=user_id,
        encryption_public_key=b64url_encode(root.encryption_public_bytes()),
    )
    substituted_key = X25519PrivateKey.generate().public_key().public_bytes_raw()
    substituted = dict(recipient)
    substituted["encryption_public_key"] = b64url_encode(substituted_key)
    substituted["recipient_key_sha256"] = hashlib.sha256(substituted_key).hexdigest()
    substituted_binding = {
        field: substituted[field]
        for field in (
            "recipient_type",
            "recipient_id",
            "subject_user_id",
            "encryption_public_key",
            "recipient_key_sha256",
            "admission_digest",
        )
    }
    substituted["recipient_binding_digest"] = hashlib.sha256(
        canonical_json(substituted_binding)
    ).hexdigest()
    recipients = [substituted]
    substituted_snapshot_digest = hashlib.sha256(canonical_json(recipients)).hexdigest()
    gateway = RotationGateway(
        recipients,
        workspace_id=workspace_id,
        user_id=user_id,
        admission=admission,
        recipient_set_digest=substituted_snapshot_digest,
    )
    keyring = MemoryKeyring()

    with pytest.raises(ValueError, match="substituted or unverifiable"):
        rotate_workspace_key(
            gateway,  # type: ignore[arg-type]
            admin,
            workspace_id=workspace_id,
            store=WorkspaceKeyStore(backend=keyring),
        )

    assert gateway.mutation is None
    assert keyring.values == {}


def test_failed_rotation_does_not_persist_unactivated_key() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    admin = identity_for(root, alias="admin")
    admission = owner_admission_record(
        admin, workspace_id=workspace_id, owner_user_id=user_id
    )
    gateway = RotationGateway(
        [
            admitted_recipient(
                admission,
                recipient_type="user_recovery",
                recipient_id=user_id,
                subject_user_id=user_id,
                encryption_public_key=b64url_encode(root.encryption_public_bytes()),
            )
        ],
        workspace_id=workspace_id,
        user_id=user_id,
        admission=admission,
        fail=True,
    )
    keyring = MemoryKeyring()

    with pytest.raises(RuntimeError, match="rotation rejected"):
        rotate_workspace_key(
            gateway,  # type: ignore[arg-type]
            admin,
            workspace_id=workspace_id,
            store=WorkspaceKeyStore(backend=keyring),
        )

    assert keyring.values == {}


def test_historical_key_sync_does_not_try_to_publish_an_old_device_envelope() -> None:
    root = root_identity()
    user_id = new_id("user")
    workspace_id = new_id("workspace")
    old_device = identity_for(root, alias="old")
    new_device = identity_for(root, alias="new")
    gateway = EnvelopeGateway(user_id=user_id, root=root, workspace_id=workspace_id)
    gateway.add_device(old_device)
    gateway.add_device(new_device)
    old_keyring = MemoryKeyring()
    initialize_workspace_keys(
        gateway,  # type: ignore[arg-type]
        old_device,
        {"id": workspace_id, "owner_user_id": user_id, "key_version": 1},
        store=WorkspaceKeyStore(backend=old_keyring),
    )
    gateway.key_version = 2
    destination = MemoryKeyring()

    result = sync_workspace_key(
        gateway,  # type: ignore[arg-type]
        new_device,
        workspace_id=workspace_id,
        user_id=user_id,
        key_version=1,
        store=WorkspaceKeyStore(backend=destination),
        authority_store=WorkspaceAuthorityStore(backend=MemoryKeyring()),
    )

    assert result["key_version"] == 1
    assert result["historical_version"] is False
    assert result["device_envelope_created"] is False
    assert ("device", new_device.device_id) not in gateway.envelopes
    assert WorkspaceKeyStore(backend=destination).load(workspace_id, 1) == WorkspaceKeyStore(
        backend=old_keyring
    ).load(workspace_id, 1)
