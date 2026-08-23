"""Service signing and encryption keys compatible with VGen ``DeviceKeys``."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .encoding import b64url_decode, b64url_encode, canonical_json

SIGNATURE_CONTEXT = b"vgen-message-signature-v1"
MANIFEST_CONTEXT = b"vgen-key-manifest-v1"


def _raw_private(key: Ed25519PrivateKey | X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def device_key_id(signing_public_key: bytes) -> str:
    """Derive the stable key ID used by VGen Services, Devices, and Workers."""

    if not isinstance(signing_public_key, bytes) or len(signing_public_key) != 32:
        raise ValueError("device signing public key must contain 32 bytes")
    digest = hashlib.sha256(b"vgen-device-key-id-v1\x00" + signing_public_key).digest()
    return "devkey_" + b64url_encode(digest[:20])


def root_signing_key_id(public_key: bytes) -> str:
    """Derive the stable VGen root key ID for a raw Ed25519 public key."""

    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("root signing public key must contain 32 bytes")
    digest = hashlib.sha256(b"vgen-root-key-id-v1\x00" + public_key).digest()
    return "root_" + b64url_encode(digest[:20])


def _signed_message(context: bytes, message: bytes) -> bytes:
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not context or b"\x00" in context:
        raise ValueError("signature context must be non-empty and contain no NUL")
    return context + b"\x00" + message


def sign_message(
    private_key: Ed25519PrivateKey | bytes,
    message: bytes,
    *,
    context: bytes = SIGNATURE_CONTEXT,
) -> bytes:
    """Create a domain-separated Ed25519 signature."""

    key = (
        Ed25519PrivateKey.from_private_bytes(private_key)
        if isinstance(private_key, bytes)
        else private_key
    )
    return key.sign(_signed_message(context, message))


def verify_message(
    public_key: Ed25519PublicKey | bytes,
    message: bytes,
    signature: bytes,
    *,
    context: bytes = SIGNATURE_CONTEXT,
) -> bool:
    """Verify a domain-separated Ed25519 signature."""

    key = (
        Ed25519PublicKey.from_public_bytes(public_key)
        if isinstance(public_key, bytes)
        else public_key
    )
    try:
        key.verify(signature, _signed_message(context, message))
    except InvalidSignature:
        return False
    return True


def verify_key_manifest(
    signed_manifest: Mapping[str, Any],
    root_signing_public_key: Ed25519PublicKey | bytes,
) -> bool:
    """Verify a root-signed VGen key manifest.

    The trusted root key is supplied by the application; this function never
    accepts a trust root from the manifest itself.
    """

    if not isinstance(signed_manifest, Mapping):
        return False
    try:
        root_public = (
            Ed25519PublicKey.from_public_bytes(root_signing_public_key)
            if isinstance(root_signing_public_key, bytes)
            else root_signing_public_key
        )
        root_public_bytes = _raw_public(root_public)
        payload = dict(signed_manifest["manifest"])
        signature = b64url_decode(str(signed_manifest["signature"]), expected_length=64)
        if signed_manifest["signer_key_id"] != root_signing_key_id(root_public_bytes):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return verify_message(
        root_public,
        canonical_json(payload),
        signature,
        context=MANIFEST_CONTEXT,
    )


@dataclass(frozen=True, slots=True)
class DeviceKeys:
    """Independent Ed25519 signing and X25519 encryption key pair.

    The wire representation and ``key_id`` are byte-for-byte compatible with
    the existing VGen ``DeviceKeys`` type. Private values are omitted from
    ``repr``.
    """

    signing_private_key: Ed25519PrivateKey = field(repr=False)
    encryption_private_key: X25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls) -> DeviceKeys:
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(
        cls,
        *,
        signing_private_key: bytes,
        encryption_private_key: bytes,
    ) -> DeviceKeys:
        return cls(
            Ed25519PrivateKey.from_private_bytes(signing_private_key),
            X25519PrivateKey.from_private_bytes(encryption_private_key),
        )

    @property
    def signing_public_key(self) -> Ed25519PublicKey:
        return self.signing_private_key.public_key()

    @property
    def encryption_public_key(self) -> X25519PublicKey:
        return self.encryption_private_key.public_key()

    @property
    def key_id(self) -> str:
        return device_key_id(self.signing_public_bytes())

    def signing_public_bytes(self) -> bytes:
        return _raw_public(self.signing_public_key)

    def encryption_public_bytes(self) -> bytes:
        return _raw_public(self.encryption_public_key)

    def signing_private_bytes(self) -> bytes:
        return _raw_private(self.signing_private_key)

    def encryption_private_bytes(self) -> bytes:
        return _raw_private(self.encryption_private_key)

    def sign(self, message: bytes, *, context: bytes = SIGNATURE_CONTEXT) -> bytes:
        return sign_message(self.signing_private_key, message, context=context)

    def to_bytes(self) -> bytes:
        """Serialize keys using ``vgen-device-keys`` version 1."""

        return serialize_device_keys(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> DeviceKeys:
        return deserialize_device_keys(data)


def serialize_device_keys(device: DeviceKeys) -> bytes:
    """Serialize keys without performing filesystem I/O."""

    return canonical_json(
        {
            "format": "vgen-device-keys",
            "version": 1,
            "key_id": device.key_id,
            "signing_private_key": b64url_encode(device.signing_private_bytes()),
            "encryption_private_key": b64url_encode(device.encryption_private_bytes()),
        }
    )


def deserialize_device_keys(data: bytes) -> DeviceKeys:
    """Load and integrity-check ``vgen-device-keys`` version 1 bytes."""

    try:
        value = json.loads(data.decode("utf-8"))
        version = value["version"]
        if (
            value["format"] != "vgen-device-keys"
            or not isinstance(version, int)
            or isinstance(version, bool)
            or version != 1
        ):
            raise ValueError("unsupported VGen device key format")
        device = DeviceKeys.from_private_bytes(
            signing_private_key=b64url_decode(
                str(value["signing_private_key"]), expected_length=32
            ),
            encryption_private_key=b64url_decode(
                str(value["encryption_private_key"]), expected_length=32
            ),
        )
        if not secrets.compare_digest(device.key_id, str(value["key_id"])):
            raise ValueError("VGen device key ID mismatch")
        return device
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid VGen device key data") from exc
