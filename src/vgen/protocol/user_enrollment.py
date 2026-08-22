"""End-to-end verifiable User enrollment and Workspace admission material.

The Gateway is a transport and persistence service for these objects.  It is
not a trust anchor: a joining Device proves possession of its key and its root
certificate chain, then the Workspace Owner signs the admission only after an
out-of-band verification-code comparison.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from vgen.crypto import (
    b64url_decode,
    b64url_encode,
    canonical_json,
    root_signing_key_id,
    sign_message,
    verify_device_certificate,
    verify_key_manifest,
    verify_message,
)

USER_ENROLLMENT_CONTEXT = b"vgen-user-enrollment-v1"
USER_VERIFICATION_CODE_CONTEXT = b"vgen-user-enrollment-verification-code-v1\x00"
USER_CLAIM_KIND = "vgen-user-enrollment-claim"
WORKSPACE_RECIPIENT_ADMISSION_KIND = "vgen-workspace-recipient-admission"

_CLAIM_FIELDS = frozenset(
    {
        "version",
        "kind",
        "invite_id",
        "display_name",
        "root_key_id",
        "root_signing_public_key",
        "root_encryption_public_key",
        "device_id",
        "device_name",
        "device_signing_public_key",
        "device_encryption_public_key",
        "device_certificate",
    }
)
_ADMISSION_FIELDS = frozenset(
    {
        "version",
        "kind",
        "workspace_id",
        "owner_user_id",
        "owner_root_key_id",
        "subject_user_id",
        "subject_device_id",
        "enrollment_id",
        "claim_sha256",
        "root_key_id",
        "root_signing_public_key",
        "root_encryption_public_key",
        "device_signing_public_key",
        "device_encryption_public_key",
        "device_certificate_sha256",
        "registration_claim",
        "registration_proof_signature",
        "issued_at",
    }
)


def build_user_registration_claim(
    *,
    invite_id: str,
    display_name: str,
    root_key_id: str,
    root_signing_public_key: str,
    root_encryption_public_key: str,
    device_id: str,
    device_name: str,
    device_signing_public_key: str,
    device_encryption_public_key: str,
    device_certificate: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the one canonical public claim signed by the joining Device."""

    return {
        "version": 1,
        "kind": USER_CLAIM_KIND,
        "invite_id": invite_id,
        "display_name": display_name.strip(),
        "root_key_id": root_key_id,
        "root_signing_public_key": root_signing_public_key,
        "root_encryption_public_key": root_encryption_public_key,
        "device_id": device_id,
        "device_name": device_name.strip(),
        "device_signing_public_key": device_signing_public_key,
        "device_encryption_public_key": device_encryption_public_key,
        "device_certificate": dict(device_certificate),
    }


def sign_user_registration_claim(signing_private_key: Any, claim: Mapping[str, Any]) -> str:
    return b64url_encode(
        sign_message(
            signing_private_key,
            canonical_json(dict(claim)),
            context=USER_ENROLLMENT_CONTEXT,
        )
    )


def verify_user_registration_claim(
    claim: Mapping[str, Any],
    proof_signature: str,
    *,
    require_certificate_time_valid: bool = True,
) -> bool:
    """Verify the complete claim, root-issued Device certificate and proof."""

    try:
        if set(claim) != _CLAIM_FIELDS:
            return False
        root_signing = b64url_decode(
            str(claim["root_signing_public_key"]), expected_length=32
        )
        b64url_decode(str(claim["root_encryption_public_key"]), expected_length=32)
        device_signing = b64url_decode(
            str(claim["device_signing_public_key"]), expected_length=32
        )
        b64url_decode(str(claim["device_encryption_public_key"]), expected_length=32)
        certificate = claim["device_certificate"]
        if not isinstance(certificate, Mapping):
            return False
        certificate_payload = certificate.get("payload")
        shape_is_valid = (
            claim["version"] == 1
            and claim["kind"] == USER_CLAIM_KIND
            and isinstance(claim["invite_id"], str)
            and bool(claim["invite_id"])
            and isinstance(claim["display_name"], str)
            and bool(claim["display_name"].strip())
            and len(claim["display_name"]) <= 120
            and isinstance(claim["device_id"], str)
            and bool(claim["device_id"])
            and isinstance(claim["device_name"], str)
            and bool(claim["device_name"].strip())
            and len(claim["device_name"]) <= 120
            and claim["root_key_id"] == root_signing_key_id(root_signing)
            and isinstance(certificate_payload, Mapping)
            and certificate_payload.get("root_key_id") == claim["root_key_id"]
            and certificate_payload.get("device_id") == claim["device_id"]
            and certificate_payload.get("signing_public_key")
            == claim["device_signing_public_key"]
            and certificate_payload.get("encryption_public_key")
            == claim["device_encryption_public_key"]
            and verify_device_certificate(
                certificate,
                root_signing,
                require_time_valid=require_certificate_time_valid,
            )
        )
        return bool(
            shape_is_valid
            and verify_message(
                device_signing,
                canonical_json(dict(claim)),
                b64url_decode(proof_signature, expected_length=64),
                context=USER_ENROLLMENT_CONTEXT,
            )
        )
    except (KeyError, TypeError, ValueError):
        return False


def user_claim_digest(claim: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(claim))).hexdigest()


def user_verification_code(claim: Mapping[str, Any]) -> str:
    """Return an 80-bit public fingerprint suitable for voice/chat comparison."""

    digest = hashlib.sha256(
        USER_VERIFICATION_CODE_CONTEXT + canonical_json(dict(claim))
    ).hexdigest()[:20].upper()
    return "-".join(digest[index : index + 4] for index in range(0, 20, 4))


def normalize_user_verification_code(value: str) -> str:
    compact = "".join(character for character in value.strip().upper() if character != "-")
    if len(compact) != 20 or any(character not in "0123456789ABCDEF" for character in compact):
        raise ValueError(
            "User verification code must contain five groups of four hexadecimal characters."
        )
    return "-".join(compact[index : index + 4] for index in range(0, 20, 4))


def build_workspace_recipient_admission_manifest(
    *,
    workspace_id: str,
    owner_user_id: str,
    owner_root_key_id: str,
    subject_user_id: str,
    enrollment_id: str | None,
    registration_claim: Mapping[str, Any],
    registration_proof_signature: str,
    issued_at: int,
) -> dict[str, Any]:
    """Build the Owner-signed admission persisted for one User in a Workspace."""

    claim = dict(registration_claim)
    return {
        "version": 1,
        "kind": WORKSPACE_RECIPIENT_ADMISSION_KIND,
        "workspace_id": workspace_id,
        "owner_user_id": owner_user_id,
        "owner_root_key_id": owner_root_key_id,
        "subject_user_id": subject_user_id,
        "subject_device_id": claim["device_id"],
        "enrollment_id": enrollment_id,
        "claim_sha256": user_claim_digest(claim),
        "root_key_id": claim["root_key_id"],
        "root_signing_public_key": claim["root_signing_public_key"],
        "root_encryption_public_key": claim["root_encryption_public_key"],
        "device_signing_public_key": claim["device_signing_public_key"],
        "device_encryption_public_key": claim["device_encryption_public_key"],
        "device_certificate_sha256": hashlib.sha256(
            canonical_json(claim["device_certificate"])
        ).hexdigest(),
        "registration_claim": claim,
        "registration_proof_signature": registration_proof_signature,
        "issued_at": issued_at,
    }


def verify_workspace_recipient_admission(
    signed_admission: Mapping[str, Any],
    owner_root_signing_public_key: str,
    *,
    workspace_id: str,
    owner_user_id: str,
    subject_user_id: str | None = None,
    enrollment_id: str | None = None,
) -> bool:
    """Verify the Owner signature and all duplicated claim bindings."""

    try:
        if set(signed_admission) != {"manifest", "signer_key_id", "signature"}:
            return False
        owner_public = b64url_decode(owner_root_signing_public_key, expected_length=32)
        manifest = signed_admission["manifest"]
        if not isinstance(manifest, Mapping):
            return False
        if set(manifest) != _ADMISSION_FIELDS:
            return False
        claim = manifest["registration_claim"]
        proof = manifest["registration_proof_signature"]
        if not isinstance(claim, Mapping) or not isinstance(proof, str):
            return False
        certificate = claim["device_certificate"]
        valid = (
            verify_key_manifest(signed_admission, owner_public)
            and signed_admission.get("signer_key_id") == root_signing_key_id(owner_public)
            and manifest.get("version") == 1
            and manifest.get("kind") == WORKSPACE_RECIPIENT_ADMISSION_KIND
            and manifest.get("workspace_id") == workspace_id
            and manifest.get("owner_user_id") == owner_user_id
            and manifest.get("owner_root_key_id") == root_signing_key_id(owner_public)
            and (
                subject_user_id is None
                or manifest.get("subject_user_id") == subject_user_id
            )
            and (enrollment_id is None or manifest.get("enrollment_id") == enrollment_id)
            and (
                manifest.get("enrollment_id") is None
                or manifest.get("enrollment_id") == claim.get("invite_id")
            )
            and manifest.get("subject_device_id") == claim.get("device_id")
            and manifest.get("claim_sha256") == user_claim_digest(claim)
            and manifest.get("root_key_id") == claim.get("root_key_id")
            and manifest.get("root_signing_public_key")
            == claim.get("root_signing_public_key")
            and manifest.get("root_encryption_public_key")
            == claim.get("root_encryption_public_key")
            and manifest.get("device_signing_public_key")
            == claim.get("device_signing_public_key")
            and manifest.get("device_encryption_public_key")
            == claim.get("device_encryption_public_key")
            and manifest.get("device_certificate_sha256")
            == hashlib.sha256(canonical_json(certificate)).hexdigest()
            and isinstance(manifest.get("issued_at"), int)
            and not isinstance(manifest.get("issued_at"), bool)
            and int(manifest["issued_at"]) > 0
            and verify_user_registration_claim(
                claim,
                proof,
                require_certificate_time_valid=False,
            )
        )
        return bool(valid)
    except (KeyError, TypeError, ValueError):
        return False


def workspace_recipient_admission_digest(signed_admission: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(dict(signed_admission))).hexdigest()


__all__ = [
    "USER_CLAIM_KIND",
    "USER_ENROLLMENT_CONTEXT",
    "WORKSPACE_RECIPIENT_ADMISSION_KIND",
    "build_user_registration_claim",
    "build_workspace_recipient_admission_manifest",
    "normalize_user_verification_code",
    "sign_user_registration_claim",
    "user_claim_digest",
    "user_verification_code",
    "verify_user_registration_claim",
    "verify_workspace_recipient_admission",
    "workspace_recipient_admission_digest",
]
