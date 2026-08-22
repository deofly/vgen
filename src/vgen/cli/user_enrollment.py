"""Client-side User enrollment verification and Owner admission helpers."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping
from typing import Any

from vgen.crypto import (
    b64url_decode,
    canonical_json,
    sign_key_manifest,
    verify_device_certificate,
)
from vgen.protocol.user_enrollment import (
    build_user_registration_claim,
    build_workspace_recipient_admission_manifest,
    normalize_user_verification_code,
    sign_user_registration_claim,
    user_verification_code,
    verify_user_registration_claim,
    verify_workspace_recipient_admission,
    workspace_recipient_admission_digest,
)

from .client import GatewayClient, VgenClientError
from .identity_store import DeviceIdentity


class UserEnrollmentError(ValueError):
    pass


def verify_existing_owner_admission(
    existing: Mapping[str, Any],
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    owner_user_id: str,
) -> bool:
    try:
        signed = existing["signed_admission"]
        manifest = signed["manifest"]
        return bool(
            existing.get("workspace_id") == workspace_id
            and existing.get("subject_user_id") == owner_user_id
            and existing.get("admission_signer_user_id") == owner_user_id
            and existing.get("admission_signer_root_signing_public_key")
            == identity.root_signing_public_key
            and existing.get("admission_digest")
            == workspace_recipient_admission_digest(signed)
            and verify_workspace_recipient_admission(
                signed,
                identity.root_signing_public_key,
                workspace_id=workspace_id,
                owner_user_id=owner_user_id,
                subject_user_id=owner_user_id,
            )
            and manifest.get("enrollment_id") is None
            and manifest.get("root_signing_public_key")
            == identity.root_signing_public_key
            and manifest.get("root_encryption_public_key")
            == identity.root_encryption_public_key
        )
    except (KeyError, TypeError, ValueError):
        return False


def identity_registration_claim(
    identity: DeviceIdentity,
    *,
    invite_id: str,
    display_name: str,
    device_name: str,
) -> tuple[dict[str, Any], str]:
    certificate = identity.certificate.to_dict()
    claim = build_user_registration_claim(
        invite_id=invite_id,
        display_name=display_name,
        root_key_id=identity.root_key_id,
        root_signing_public_key=identity.root_signing_public_key,
        root_encryption_public_key=identity.root_encryption_public_key,
        device_id=identity.device_id,
        device_name=device_name,
        device_signing_public_key=str(certificate["payload"]["signing_public_key"]),
        device_encryption_public_key=str(certificate["payload"]["encryption_public_key"]),
        device_certificate=certificate,
    )
    proof = sign_user_registration_claim(identity.device_keys.signing_private_key, claim)
    return claim, proof


def require_enrollment_claim(
    enrollment: Mapping[str, Any],
    *,
    workspace_id: str,
    enrollment_id: str,
    verification_code: str,
    owner_user_id: str | None = None,
) -> tuple[dict[str, Any], str, str]:
    claim = enrollment.get("claim")
    proof = enrollment.get("proof_signature")
    subject_user_id = str(enrollment.get("subject_user_id") or "")
    valid = bool(
        enrollment.get("kind") in {"user", "workspace_member"}
        and str(enrollment.get("id")) == enrollment_id
        and str(enrollment.get("workspace_id")) == workspace_id
        and (
            owner_user_id is None
            or str(enrollment.get("issuer_user_id")) == owner_user_id
            or enrollment.get("method") == "apply_approval"
        )
        and enrollment.get("state") in {"pending", "active"}
        and isinstance(claim, Mapping)
        and isinstance(proof, str)
        and claim.get("invite_id") == enrollment_id
        and claim.get("device_id") == enrollment.get("subject_id")
        and subject_user_id
        and verify_user_registration_claim(
            claim,
            proof,
            require_certificate_time_valid=False,
        )
    )
    if not valid:
        raise UserEnrollmentError("Gateway returned an invalid User enrollment claim.")
    expected = user_verification_code(claim)
    try:
        presented = normalize_user_verification_code(verification_code)
    except ValueError as exc:
        raise UserEnrollmentError(str(exc)) from exc
    if not secrets.compare_digest(expected, presented):
        raise UserEnrollmentError(
            "User verification code does not match; refusing to admit this encryption key."
        )
    return dict(claim), proof, subject_user_id


def sign_enrollment_admission(
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    owner_user_id: str,
    enrollment: Mapping[str, Any],
    verification_code: str,
) -> dict[str, Any]:
    enrollment_id = str(enrollment.get("id") or "")
    claim, proof, subject_user_id = require_enrollment_claim(
        enrollment,
        workspace_id=workspace_id,
        enrollment_id=enrollment_id,
        verification_code=verification_code,
        owner_user_id=owner_user_id,
    )
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
        owner_root_key_id=identity.root_key_id,
        subject_user_id=subject_user_id,
        enrollment_id=enrollment_id,
        registration_claim=claim,
        registration_proof_signature=proof,
        issued_at=int(claim["device_certificate"]["payload"]["issued_at"]),
    )
    return sign_key_manifest(identity.root_keys, manifest)


def ensure_owner_self_admission(
    client: GatewayClient,
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    owner_user_id: str,
    display_name: str = "Workspace Owner",
    device_name: str = "Owner Device",
) -> dict[str, Any]:
    if not owner_user_id:
        raise UserEnrollmentError("Workspace Owner User ID is required.")
    try:
        existing = client.request(
            "GET",
            f"/api/v1/workspaces/{workspace_id}/recipient-admissions/{owner_user_id}",
        )
    except VgenClientError as exc:
        if exc.code != 400005 and exc.status_code != 404:
            raise
    else:
        if not verify_existing_owner_admission(
            existing,
            identity,
            workspace_id=workspace_id,
            owner_user_id=owner_user_id,
        ):
            raise UserEnrollmentError(
                "Stored Workspace Owner admission does not match the local root identity."
            )
        return dict(existing)
    claim, proof = identity_registration_claim(
        identity,
        invite_id=f"workspace-owner-self:{workspace_id}",
        display_name=display_name,
        device_name=device_name,
    )
    manifest = build_workspace_recipient_admission_manifest(
        workspace_id=workspace_id,
        owner_user_id=owner_user_id,
        owner_root_key_id=identity.root_key_id,
        subject_user_id=owner_user_id,
        enrollment_id=None,
        registration_claim=claim,
        registration_proof_signature=proof,
        issued_at=int(claim["device_certificate"]["payload"]["issued_at"]),
    )
    signed = sign_key_manifest(identity.root_keys, manifest)
    return client.request(
        "POST",
        f"/api/v1/workspaces/{workspace_id}/recipient-admissions",
        json_body={"enrollment_id": None, "signed_admission": signed},
        idempotency_key=f"workspace-owner-admission:{workspace_id}:{owner_user_id}",
    )


def verify_recipient_bundle(
    recipient: Mapping[str, Any],
    identity: DeviceIdentity,
    *,
    workspace_id: str,
    owner_user_id: str,
    expected_recipient_type: str | None = None,
    expected_recipient_id: str | None = None,
) -> dict[str, str]:
    """Verify one Gateway recipient against the local Owner root."""

    try:
        signed = recipient["signed_admission"]
        signer_user_id = str(recipient["admission_signer_user_id"])
        signer_public = str(recipient["admission_signer_root_signing_public_key"])
        subject_user_id = str(recipient["subject_user_id"])
        recipient_type = str(recipient["recipient_type"])
        recipient_id = str(recipient["recipient_id"])
        encryption_public_key = str(recipient["encryption_public_key"])
        admission_valid = (
            isinstance(signed, Mapping)
            and signer_user_id == owner_user_id
            and signer_public == identity.root_signing_public_key
            and verify_workspace_recipient_admission(
                signed,
                signer_public,
                workspace_id=workspace_id,
                owner_user_id=owner_user_id,
                subject_user_id=subject_user_id,
            )
        )
        manifest = signed["manifest"]
        claim = manifest["registration_claim"]
        admission_digest = workspace_recipient_admission_digest(signed)
        key_digest = hashlib.sha256(
            b64url_decode(encryption_public_key, expected_length=32)
        ).hexdigest()
        common_valid = (
            admission_valid
            and (
                expected_recipient_type is None
                or recipient_type == expected_recipient_type
            )
            and (expected_recipient_id is None or recipient_id == expected_recipient_id)
            and recipient.get("admission_digest") == admission_digest
            and recipient.get("recipient_key_sha256") == key_digest
        )
        binding: dict[str, Any] = {
            "recipient_type": recipient_type,
            "recipient_id": recipient_id,
            "subject_user_id": subject_user_id,
            "encryption_public_key": encryption_public_key,
            "recipient_key_sha256": key_digest,
            "admission_digest": admission_digest,
        }
        if recipient_type == "user_recovery":
            recipient_valid = bool(
                recipient_id == subject_user_id
                and encryption_public_key == claim["root_encryption_public_key"]
            )
        elif recipient_type == "device":
            certificate = recipient["device_certificate"]
            payload = certificate["payload"]
            certificate_digest = hashlib.sha256(canonical_json(certificate)).hexdigest()
            binding["device_certificate_sha256"] = certificate_digest
            recipient_valid = bool(
                recipient.get("device_certificate_sha256") == certificate_digest
                and payload.get("device_id") == recipient_id
                and payload.get("encryption_public_key") == encryption_public_key
                and verify_device_certificate(
                    certificate,
                    b64url_decode(str(claim["root_signing_public_key"]), expected_length=32),
                )
            )
        else:
            raise UserEnrollmentError(
                "Service WDK recipients are disabled until equivalent admission proof exists."
            )
        binding_digest = hashlib.sha256(canonical_json(binding)).hexdigest()
        if (
            not common_valid
            or not recipient_valid
            or recipient.get("recipient_binding_digest") != binding_digest
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, UserEnrollmentError):
            raise
        raise UserEnrollmentError(
            "Gateway returned a substituted or unverifiable Workspace key recipient."
        ) from exc
    return {
        "encryption_public_key": encryption_public_key,
        "recipient_key_sha256": key_digest,
        "admission_digest": admission_digest,
        "recipient_binding_digest": binding_digest,
    }


__all__ = [
    "UserEnrollmentError",
    "ensure_owner_self_admission",
    "identity_registration_claim",
    "require_enrollment_claim",
    "sign_enrollment_admission",
    "verify_recipient_bundle",
    "verify_existing_owner_admission",
]
