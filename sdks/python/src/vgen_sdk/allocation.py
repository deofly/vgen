"""Workspace-signed Worker allocation proof primitives."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .encoding import b64url_decode, canonical_json
from .keys import root_signing_key_id, verify_message

ALLOCATION_PROOF_CONTEXT = b"vgen-workspace-allocation-proof-v1"
ALLOCATION_PROOF_KIND = "vgen-workspace-worker-allocation"


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
    """Build the exact allocation authorization statement an admin signs."""

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
        "owner_consent_at_ms": int(round(owner_consent_at * 1000)),
        "approver_root_key_id": approver_root_key_id,
        "issued_at": int(time.time()) if issued_at is None else int(issued_at),
    }


def verify_allocation_proof(
    proof: Mapping[str, Any],
    root_signing_public_key: Ed25519PublicKey | bytes,
    *,
    expected: Mapping[str, Any] | None = None,
    now: int | None = None,
    max_future_seconds: int = 300,
) -> bool:
    """Verify an allocation signature, schema, time, and expected bindings.

    ``root_signing_public_key`` must come from the application's trusted
    Workspace authority configuration, never from the untrusted proof.
    """

    if max_future_seconds < 0:
        raise ValueError("max_future_seconds must not be negative")

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
        raw_signature = proof["signature"]
        signer_key_id = proof["signer_key_id"]
        issued_at = payload["issued_at"]
        owner_consent_at_ms = payload["owner_consent_at_ms"]
        if not isinstance(raw_signature, str) or not isinstance(signer_key_id, str):
            return False
        signature = b64url_decode(raw_signature, expected_length=64)
        digest = payload["worker_certificate_digest"]
        schema_valid = (
            isinstance(payload["version"], int)
            and not isinstance(payload["version"], bool)
            and payload["version"] == 1
            and payload["kind"] == ALLOCATION_PROOF_KIND
            and all(
                isinstance(payload[field], str) and bool(payload[field])
                for field in (
                    "allocation_id",
                    "workspace_id",
                    "pool_id",
                    "worker_id",
                    "worker_signing_public_key",
                    "worker_encryption_public_key",
                )
            )
            and isinstance(digest, str)
            and len(digest) == 71
            and digest.startswith("sha256:")
            and all(character in "0123456789abcdef" for character in digest[7:])
            and isinstance(issued_at, int)
            and not isinstance(issued_at, bool)
            and isinstance(owner_consent_at_ms, int)
            and not isinstance(owner_consent_at_ms, bool)
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
