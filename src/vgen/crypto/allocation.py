"""Workspace-signed Worker allocation proofs.

The Worker owner certificate proves ownership of a Worker key pair. An
allocation proof is a separate authorization statement from a Workspace
owner/admin: it binds that certified Worker to one Workspace and one Pool.
Clients verify both statements before wrapping a Task Data Key for a Worker.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .encoding import b64url_decode, b64url_encode, canonical_json
from .identity import IdentityKeys, sign_message, verify_message

ALLOCATION_PROOF_CONTEXT = b"vgen-workspace-allocation-proof-v1"
ALLOCATION_PROOF_KIND = "vgen-workspace-worker-allocation"


def root_signing_key_id(public_key: bytes) -> str:
    """Return the stable VGen root key id for a raw Ed25519 public key."""

    if len(public_key) != 32:
        raise ValueError("root signing public key must contain 32 bytes")
    digest = hashlib.sha256(b"vgen-root-key-id-v1\x00" + public_key).digest()
    return "root_" + b64url_encode(digest[:20])


def worker_certificate_digest(certificate: Mapping[str, Any] | str) -> str:
    """Hash a Worker owner certificate using canonical JSON."""

    if isinstance(certificate, str):
        try:
            value = json.loads(certificate)
        except json.JSONDecodeError as exc:
            raise ValueError("Worker owner certificate is not valid JSON") from exc
    else:
        value = dict(certificate)
    if not isinstance(value, dict):
        raise ValueError("Worker owner certificate must be a JSON object")
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def build_allocation_proof_payload(
    *,
    allocation_id: str,
    workspace_id: str,
    pool_id: str,
    worker_id: str,
    worker_signing_public_key: str,
    worker_encryption_public_key: str,
    worker_certificate: Mapping[str, Any] | str,
    owner_consent_at: float,
    approver_root_key_id: str,
    issued_at: int | None = None,
) -> dict[str, Any]:
    """Build the exact authorization statement an admin must sign."""

    if owner_consent_at <= 0:
        raise ValueError("allocation owner consent timestamp is required")
    return {
        "version": 1,
        "kind": ALLOCATION_PROOF_KIND,
        "allocation_id": allocation_id,
        "workspace_id": workspace_id,
        "pool_id": pool_id,
        "worker_id": worker_id,
        "worker_signing_public_key": worker_signing_public_key,
        "worker_encryption_public_key": worker_encryption_public_key,
        "worker_certificate_digest": worker_certificate_digest(worker_certificate),
        # Milliseconds avoid cross-language floating point serialization drift.
        "owner_consent_at_ms": int(round(owner_consent_at * 1000)),
        "approver_root_key_id": approver_root_key_id,
        "issued_at": int(time.time()) if issued_at is None else int(issued_at),
    }


def sign_allocation_proof(
    identity: IdentityKeys,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Sign an allocation statement with a User recovery/root signing key."""

    value = dict(payload)
    if value.get("approver_root_key_id") != identity.root_key_id:
        raise ValueError("allocation proof approver does not match the signing root key")
    return {
        "payload": value,
        "signer_key_id": identity.root_key_id,
        "signature": b64url_encode(
            sign_message(
                identity.signing_private_key,
                canonical_json(value),
                context=ALLOCATION_PROOF_CONTEXT,
            )
        ),
    }


def verify_allocation_proof(
    proof: Mapping[str, Any],
    root_signing_public_key: Ed25519PublicKey | bytes,
    *,
    expected: Mapping[str, Any] | None = None,
    now: int | None = None,
    max_future_seconds: int = 300,
) -> bool:
    """Verify signature, schema and caller-supplied allocation bindings."""

    public_bytes = (
        root_signing_public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if isinstance(root_signing_public_key, Ed25519PublicKey)
        else root_signing_public_key
    )
    try:
        if len(public_bytes) != 32:
            return False
        payload = dict(proof["payload"])
        signature = b64url_decode(str(proof["signature"]), expected_length=64)
        signer_key_id = str(proof["signer_key_id"])
        issued_at = int(payload["issued_at"])
        owner_consent_at_ms = int(payload["owner_consent_at_ms"])
        schema_valid = (
            payload["version"] == 1
            and payload["kind"] == ALLOCATION_PROOF_KIND
            and bool(payload["allocation_id"])
            and bool(payload["workspace_id"])
            and bool(payload["pool_id"])
            and bool(payload["worker_id"])
            and bool(payload["worker_signing_public_key"])
            and bool(payload["worker_encryption_public_key"])
            and str(payload["worker_certificate_digest"]).startswith("sha256:")
            and owner_consent_at_ms > 0
            and payload["approver_root_key_id"] == signer_key_id
            and signer_key_id == root_signing_key_id(public_bytes)
        )
    except (KeyError, TypeError, ValueError):
        return False
    if not schema_valid:
        return False
    current = int(time.time()) if now is None else int(now)
    if issued_at > current + max_future_seconds:
        return False
    if expected is not None and any(payload.get(key) != value for key, value in expected.items()):
        return False
    return verify_message(
        public_bytes,
        canonical_json(payload),
        signature,
        context=ALLOCATION_PROOF_CONTEXT,
    )
