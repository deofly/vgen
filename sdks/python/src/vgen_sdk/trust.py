"""Worker certificate binding checks using application-supplied trust roots."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .encoding import b64url_decode
from .keys import device_key_id, root_signing_key_id, verify_key_manifest

WORKER_OWNER_CERTIFICATE_KIND = "vgen-worker-owner-certificate"


def _root_public_bytes(public_key: Ed25519PublicKey | bytes) -> bytes:
    if isinstance(public_key, bytes):
        if len(public_key) != 32:
            raise ValueError("root signing public key must contain 32 bytes")
        return public_key
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def verify_worker_owner_certificate(
    worker: Mapping[str, Any],
    trusted_owner_root_public_key: Ed25519PublicKey | bytes,
    *,
    now: int | None = None,
    max_future_seconds: int = 300,
) -> bool:
    """Verify the Worker's owner certificate and bind both Worker public keys.

    The trusted root key is an explicit caller input. A root key included in
    the untrusted Worker response is checked for consistency but never used as
    the source of trust.
    """

    if max_future_seconds < 0:
        raise ValueError("max_future_seconds must not be negative")
    try:
        root_bytes = _root_public_bytes(trusted_owner_root_public_key)
        expected_root_key_id = root_signing_key_id(root_bytes)
        raw_certificate = worker["certificate"]
        certificate = (
            json.loads(raw_certificate)
            if isinstance(raw_certificate, str)
            else dict(raw_certificate)
        )
        signing_public_key = str(worker["signing_public_key"])
        encryption_public_key = str(worker["encryption_public_key"])
        signing_public_bytes = b64url_decode(signing_public_key, expected_length=32)
        b64url_decode(encryption_public_key, expected_length=32)
        presented_root = worker.get("owner_root_signing_public_key")
        if (
            presented_root is not None
            and b64url_decode(str(presented_root), expected_length=32) != root_bytes
        ):
            return False
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return False
    if not verify_key_manifest(certificate, root_bytes):
        return False
    manifest = certificate.get("manifest")
    if not isinstance(manifest, dict):
        return False
    issued_at = manifest.get("issued_at")
    version = manifest.get("version")
    current = int(time.time()) if now is None else int(now)
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != 1
        or not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or issued_at > current + max_future_seconds
    ):
        return False
    expected = {
        "kind": WORKER_OWNER_CERTIFICATE_KIND,
        "owner_root_key_id": expected_root_key_id,
        "worker_key_id": device_key_id(signing_public_bytes),
        "worker_signing_public_key": signing_public_key,
        "worker_encryption_public_key": encryption_public_key,
    }
    return all(manifest.get(key) == value for key, value in expected.items())
