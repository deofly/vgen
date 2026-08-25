"""End-to-end signed Worker maintenance intents.

The authenticated HTTP request proves which Device asked the Gateway to queue a
maintenance job.  This signed object survives that hop so the Worker can also
verify the owner's certified Device authorization before installing a runtime
or model file.  The potentially larger maintenance specification is bound by a
canonical SHA-256 digest and is not duplicated inside the signature envelope.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .encoding import b64url_decode, b64url_encode, canonical_json
from .identity import (
    DeviceCertificate,
    DeviceKeys,
    sign_message,
    verify_device_certificate,
    verify_message,
)

MAINTENANCE_INTENT_CONTEXT = b"vgen-worker-maintenance-intent-v1"
MAINTENANCE_INTENT_KIND = "vgen-worker-maintenance-intent"
MAINTENANCE_ACTIONS = frozenset(
    {"worker_update", "model_install", "capability_install"}
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PAYLOAD_FIELDS = frozenset(
    {
        "version",
        "kind",
        "action",
        "worker_id",
        "broker_id",
        "device_id",
        "spec_digest",
        "issued_at",
        "expires_at",
        "nonce",
    }
)
_INTENT_FIELDS = frozenset({"payload", "device_certificate", "signature"})
_MAX_CLOCK_SKEW_SECONDS = 300


def maintenance_spec_digest(spec: Mapping[str, Any]) -> str:
    """Return the canonical digest bound into a maintenance authorization."""

    if not isinstance(spec, Mapping):
        raise TypeError("maintenance spec must be a mapping")
    return "sha256:" + hashlib.sha256(canonical_json(dict(spec))).hexdigest()


def build_maintenance_intent_payload(
    *,
    worker_id: str,
    broker_id: str,
    kind: str,
    spec: Mapping[str, Any],
    device_id: str,
    issued_at: int,
    expires_at: int,
    nonce: str,
) -> dict[str, Any]:
    """Build the exact, versioned statement signed by a Broker Device."""

    issued = _strict_integer(issued_at, "maintenance intent issued_at")
    expiry = _strict_integer(expires_at, "maintenance intent expires_at")
    if expiry <= issued:
        raise ValueError("maintenance intent expiry must be after issue time")
    _required_text(worker_id, "maintenance intent worker_id")
    _required_text(broker_id, "maintenance intent broker_id")
    _required_text(device_id, "maintenance intent device_id")
    _validate_action(kind)
    _validate_nonce(nonce)
    return {
        "version": 1,
        "kind": MAINTENANCE_INTENT_KIND,
        "action": kind,
        "worker_id": worker_id,
        "broker_id": broker_id,
        "device_id": device_id,
        "spec_digest": maintenance_spec_digest(spec),
        "issued_at": issued,
        "expires_at": expiry,
        "nonce": nonce,
    }


def sign_maintenance_intent(
    device_keys: DeviceKeys,
    device_certificate: DeviceCertificate | Mapping[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Sign an exact maintenance payload with the certified Device key."""

    cert = (
        device_certificate
        if isinstance(device_certificate, DeviceCertificate)
        else DeviceCertificate.from_dict(device_certificate)
    )
    value = dict(payload)
    if not _valid_payload_schema(value):
        raise ValueError("maintenance intent payload is invalid")
    try:
        certificate_key = b64url_decode(
            str(cert.payload["signing_public_key"]), expected_length=32
        )
        certificate_device_id = str(cert.payload["device_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("maintenance intent device certificate is invalid") from exc
    if certificate_key != device_keys.signing_public_bytes():
        raise ValueError("maintenance intent Device key does not match its certificate")
    if certificate_device_id != value["device_id"]:
        raise ValueError("maintenance intent Device ID does not match its certificate")
    return {
        "payload": value,
        "device_certificate": cert.to_dict(),
        "signature": b64url_encode(
            sign_message(
                device_keys.signing_private_key,
                canonical_json(value),
                context=MAINTENANCE_INTENT_CONTEXT,
            )
        ),
    }


def verify_maintenance_intent(
    intent: Mapping[str, Any],
    root_public_key: Ed25519PublicKey | bytes | str,
    *,
    expected_worker_id: str,
    expected_broker_id: str,
    expected_kind: str,
    expected_spec: Mapping[str, Any],
    now: int | None = None,
) -> bool:
    """Verify the certificate, signature, time window and every caller binding.

    Malformed untrusted wire values return ``False`` rather than escaping parser
    exceptions into a Worker maintenance loop.
    """

    try:
        if not isinstance(intent, Mapping) or set(intent) != _INTENT_FIELDS:
            return False
        payload_value = intent["payload"]
        certificate_value = intent["device_certificate"]
        if not isinstance(payload_value, Mapping) or not isinstance(
            certificate_value, Mapping
        ):
            return False
        payload = dict(payload_value)
        if not _valid_payload_schema(payload):
            return False
        current = int(time.time()) if now is None else _strict_integer(now, "current time")
        issued = _strict_integer(payload["issued_at"], "maintenance intent issued_at")
        expiry = _strict_integer(payload["expires_at"], "maintenance intent expires_at")
        if issued > current + _MAX_CLOCK_SKEW_SECONDS or current >= expiry or expiry <= issued:
            return False
        if (
            payload["worker_id"] != expected_worker_id
            or payload["broker_id"] != expected_broker_id
            or payload["action"] != expected_kind
            or payload["spec_digest"] != maintenance_spec_digest(expected_spec)
        ):
            return False
        certificate = DeviceCertificate.from_dict(certificate_value)
        decoded_root_key = (
            b64url_decode(root_public_key, expected_length=32)
            if isinstance(root_public_key, str)
            else root_public_key
        )
        if not verify_device_certificate(certificate, decoded_root_key, now=current):
            return False
        if certificate.payload.get("device_id") != payload["device_id"]:
            return False
        device_public_key = b64url_decode(
            str(certificate.payload["signing_public_key"]), expected_length=32
        )
        signature = b64url_decode(str(intent["signature"]), expected_length=64)
        return verify_message(
            device_public_key,
            canonical_json(payload),
            signature,
            context=MAINTENANCE_INTENT_CONTEXT,
        )
    except Exception:
        # This is an untrusted wire-verification boundary used by a long-lived
        # Worker loop. Any malformed Mapping implementation, key object, codec,
        # or crypto backend failure must fail closed rather than escape.
        return False


def _valid_payload_schema(payload: Mapping[str, Any]) -> bool:
    try:
        issued = _strict_integer(payload["issued_at"], "maintenance intent issued_at")
        expiry = _strict_integer(payload["expires_at"], "maintenance intent expires_at")
        return (
            set(payload) == _PAYLOAD_FIELDS
            and type(payload["version"]) is int
            and payload["version"] == 1
            and payload["kind"] == MAINTENANCE_INTENT_KIND
            and _valid_text(payload["worker_id"])
            and _valid_text(payload["broker_id"])
            and _valid_text(payload["device_id"])
            and payload["action"] in MAINTENANCE_ACTIONS
            and isinstance(payload["spec_digest"], str)
            and bool(_DIGEST.fullmatch(payload["spec_digest"]))
            and expiry > issued
            and _valid_nonce(payload["nonce"])
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _strict_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{label} must be an integer")
    return value


def _valid_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 256 and "\x00" not in value


def _required_text(value: Any, label: str) -> None:
    if not _valid_text(value):
        raise ValueError(f"{label} must be a non-empty bounded string")


def _validate_action(value: str) -> None:
    if value not in MAINTENANCE_ACTIONS:
        raise ValueError("unsupported maintenance action")


def _valid_nonce(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 16 <= len(value) <= 128
        and all(character.isascii() and (character.isalnum() or character in "-_") for character in value)
    )


def _validate_nonce(value: str) -> None:
    if not _valid_nonce(value):
        raise ValueError("maintenance intent nonce is invalid")
