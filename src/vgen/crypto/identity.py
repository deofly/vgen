"""BIP-39 recovery identities and per-device signing/encryption keys.

Long-lived recovery material is used only to derive a root Ed25519 signing key
and X25519 recovery key. Runtime devices get independent random keys and a
root-signed certificate, so loss of one device does not require changing the
stable user identity.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .encoding import b64url_decode, b64url_encode, canonical_json

IDENTITY_DOMAIN = b"vgen-identity-v1"
SIGNATURE_CONTEXT = b"vgen-message-signature-v1"
DEVICE_CERT_CONTEXT = b"vgen-device-certificate-v1"
MANIFEST_CONTEXT = b"vgen-key-manifest-v1"
RECOVERY_FILE_VERSION = 1


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


def _derive(master_seed: bytes, label: bytes) -> bytes:
    if len(master_seed) < 32:
        raise ValueError("identity master seed must contain at least 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=IDENTITY_DOMAIN,
        info=IDENTITY_DOMAIN + b"\x00" + label,
    ).derive(master_seed)


def _key_id(signing_public_key: bytes) -> str:
    digest = hashlib.sha256(b"vgen-root-key-id-v1\x00" + signing_public_key).digest()
    return "root_" + b64url_encode(digest[:20])


def device_key_id(signing_public_key: bytes) -> str:
    """Derive the stable public Worker/Device key identifier."""

    if not isinstance(signing_public_key, bytes) or len(signing_public_key) != 32:
        raise ValueError("device signing public key must contain 32 bytes")
    digest = hashlib.sha256(b"vgen-device-key-id-v1\x00" + signing_public_key).digest()
    return "devkey_" + b64url_encode(digest[:20])


def _signed_message(context: bytes, message: bytes) -> bytes:
    if not context or b"\x00" in context:
        raise ValueError("signature context must be non-empty and contain no NUL")
    return context + b"\x00" + message


def sign_message(
    private_key: Ed25519PrivateKey | bytes,
    message: bytes,
    *,
    context: bytes = SIGNATURE_CONTEXT,
) -> bytes:
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


@dataclass(frozen=True, slots=True)
class IdentityKeys:
    """Derived user recovery/root keys; private values are omitted from repr."""

    signing_private_key: Ed25519PrivateKey = field(repr=False)
    encryption_private_key: X25519PrivateKey = field(repr=False)

    @property
    def signing_public_key(self) -> Ed25519PublicKey:
        return self.signing_private_key.public_key()

    @property
    def encryption_public_key(self) -> X25519PublicKey:
        return self.encryption_private_key.public_key()

    @property
    def root_key_id(self) -> str:
        return _key_id(self.signing_public_bytes())

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

    def public_manifest(self) -> dict[str, Any]:
        return {
            "version": 1,
            "root_key_id": self.root_key_id,
            "signing_algorithm": "Ed25519",
            "signing_public_key": b64url_encode(self.signing_public_bytes()),
            "encryption_algorithm": "X25519",
            "encryption_public_key": b64url_encode(self.encryption_public_bytes()),
        }


@dataclass(frozen=True, slots=True)
class IdentityBundle:
    mnemonic: str = field(repr=False)
    keys: IdentityKeys

    @property
    def recovery_words(self) -> tuple[str, ...]:
        return tuple(self.mnemonic.split())


@dataclass(frozen=True, slots=True)
class DeviceKeys:
    signing_private_key: Ed25519PrivateKey = field(repr=False)
    encryption_private_key: X25519PrivateKey = field(repr=False)

    @classmethod
    def generate(cls) -> DeviceKeys:
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

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


@dataclass(frozen=True, slots=True)
class DeviceCertificate:
    payload: Mapping[str, Any]
    signature: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "payload", dict(self.payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": dict(self.payload),
            "signature": b64url_encode(self.signature),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeviceCertificate:
        return cls(
            payload=dict(value["payload"]),
            signature=b64url_decode(str(value["signature"]), expected_length=64),
        )


def derive_identity_keys(master_seed: bytes) -> IdentityKeys:
    """Derive domain-separated root keys from BIP-39 seed material."""

    return IdentityKeys(
        signing_private_key=Ed25519PrivateKey.from_private_bytes(
            _derive(master_seed, b"user-root-signing-key")
        ),
        encryption_private_key=X25519PrivateKey.from_private_bytes(
            _derive(master_seed, b"user-recovery-encryption-key")
        ),
    )


def _mnemonic_engine():  # type: ignore[no-untyped-def]
    try:
        from mnemonic import Mnemonic
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise RuntimeError("identity mnemonics require the 'mnemonic>=0.21' package") from exc
    return Mnemonic("english")


def identity_init(*, passphrase: str = "") -> IdentityBundle:
    """Generate a machine-random 24-word identity recovery phrase."""

    engine = _mnemonic_engine()
    words = engine.generate(strength=256)
    return IdentityBundle(
        mnemonic=words,
        keys=derive_identity_keys(engine.to_seed(words, passphrase=passphrase)),
    )


def identity_recover(mnemonic: str, *, passphrase: str = "") -> IdentityKeys:
    """Recover the deterministic root keys after validating BIP-39 checksum."""

    normalized = " ".join(mnemonic.strip().split())
    engine = _mnemonic_engine()
    if len(normalized.split()) != 24 or not engine.check(normalized):
        raise ValueError("recovery phrase must be a valid 24-word English BIP-39 mnemonic")
    return derive_identity_keys(engine.to_seed(normalized, passphrase=passphrase))


def export_recovery_file(mnemonic: str) -> bytes:
    """Serialize recovery entropy for an explicitly requested plaintext file.

    The caller must require an explicit dangerous option and create the output
    with mode 0600. This function performs no filesystem I/O.
    """

    normalized = " ".join(mnemonic.strip().split())
    engine = _mnemonic_engine()
    if len(normalized.split()) != 24 or not engine.check(normalized):
        raise ValueError("recovery phrase must be a valid 24-word English BIP-39 mnemonic")
    entropy = bytes(engine.to_entropy(normalized))
    body = {
        "format": "vgen-identity-recovery",
        "version": RECOVERY_FILE_VERSION,
        "entropy": b64url_encode(entropy),
        "checksum": hashlib.sha256(b"vgen-recovery-file-v1\x00" + entropy).hexdigest(),
    }
    return canonical_json(body) + b"\n"


def identity_recover_file(data: bytes, *, passphrase: str = "") -> IdentityKeys:
    try:
        body = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid VGen recovery file") from exc
    if body.get("format") != "vgen-identity-recovery" or body.get("version") != 1:
        raise ValueError("unsupported VGen recovery file")
    entropy = b64url_decode(str(body.get("entropy", "")), expected_length=32)
    expected = hashlib.sha256(b"vgen-recovery-file-v1\x00" + entropy).hexdigest()
    if not secrets.compare_digest(str(body.get("checksum", "")), expected):
        raise ValueError("VGen recovery file checksum mismatch")
    engine = _mnemonic_engine()
    return identity_recover(engine.to_mnemonic(entropy), passphrase=passphrase)


def issue_device_certificate(
    identity: IdentityKeys,
    device: DeviceKeys,
    *,
    device_id: str,
    issued_at: int | None = None,
    expires_at: int | None = None,
    serial: str | None = None,
) -> DeviceCertificate:
    issued = int(time.time()) if issued_at is None else int(issued_at)
    expiry = issued + 365 * 24 * 60 * 60 if expires_at is None else int(expires_at)
    if expiry <= issued:
        raise ValueError("device certificate expiry must be after issue time")
    payload = {
        "version": 1,
        "device_id": device_id,
        "root_key_id": identity.root_key_id,
        "serial": serial or b64url_encode(secrets.token_bytes(16)),
        "issued_at": issued,
        "expires_at": expiry,
        "signing_algorithm": "Ed25519",
        "signing_public_key": b64url_encode(device.signing_public_bytes()),
        "encryption_algorithm": "X25519",
        "encryption_public_key": b64url_encode(device.encryption_public_bytes()),
    }
    signature = identity.sign(canonical_json(payload), context=DEVICE_CERT_CONTEXT)
    return DeviceCertificate(payload=payload, signature=signature)


def verify_device_certificate(
    certificate: DeviceCertificate | Mapping[str, Any],
    root_signing_public_key: Ed25519PublicKey | bytes,
    *,
    now: int | None = None,
    require_time_valid: bool = True,
) -> bool:
    cert = (
        certificate
        if isinstance(certificate, DeviceCertificate)
        else DeviceCertificate.from_dict(certificate)
    )
    root_public = (
        Ed25519PublicKey.from_public_bytes(root_signing_public_key)
        if isinstance(root_signing_public_key, bytes)
        else root_signing_public_key
    )
    try:
        payload = cert.payload
        valid_schema = (
            payload["version"] == 1
            and bool(payload["device_id"])
            and payload["root_key_id"] == _key_id(_raw_public(root_public))
            and payload["signing_algorithm"] == "Ed25519"
            and payload["encryption_algorithm"] == "X25519"
        )
        b64url_decode(str(payload["signing_public_key"]), expected_length=32)
        b64url_decode(str(payload["encryption_public_key"]), expected_length=32)
    except (KeyError, TypeError, ValueError):
        return False
    if not valid_schema or not verify_message(
        root_public,
        canonical_json(dict(cert.payload)),
        cert.signature,
        context=DEVICE_CERT_CONTEXT,
    ):
        return False
    if not require_time_valid:
        return True
    current = int(time.time()) if now is None else int(now)
    try:
        return int(cert.payload["issued_at"]) <= current < int(cert.payload["expires_at"])
    except (KeyError, TypeError, ValueError):
        return False


def sign_key_manifest(identity: IdentityKeys, manifest: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(manifest)
    return {
        "manifest": payload,
        "signer_key_id": identity.root_key_id,
        "signature": b64url_encode(
            identity.sign(canonical_json(payload), context=MANIFEST_CONTEXT)
        ),
    }


def verify_key_manifest(
    signed_manifest: Mapping[str, Any],
    root_signing_public_key: Ed25519PublicKey | bytes,
) -> bool:
    root_public = (
        Ed25519PublicKey.from_public_bytes(root_signing_public_key)
        if isinstance(root_signing_public_key, bytes)
        else root_signing_public_key
    )
    try:
        payload = dict(signed_manifest["manifest"])
        signature = b64url_decode(str(signed_manifest["signature"]), expected_length=64)
        if signed_manifest["signer_key_id"] != _key_id(_raw_public(root_public)):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return verify_message(
        root_public,
        canonical_json(payload),
        signature,
        context=MANIFEST_CONTEXT,
    )


def serialize_device_keys(device: DeviceKeys) -> bytes:
    """Serialize device keys for storage in an OS keyring, without filesystem I/O."""

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
    try:
        value = json.loads(data.decode("utf-8"))
        if value["format"] != "vgen-device-keys" or value["version"] != 1:
            raise ValueError("unsupported VGen device key format")
        device = DeviceKeys(
            signing_private_key=Ed25519PrivateKey.from_private_bytes(
                b64url_decode(str(value["signing_private_key"]), expected_length=32)
            ),
            encryption_private_key=X25519PrivateKey.from_private_bytes(
                b64url_decode(str(value["encryption_private_key"]), expected_length=32)
            ),
        )
        if not secrets.compare_digest(device.key_id, str(value["key_id"])):
            raise ValueError("VGen device key ID mismatch")
        return device
    except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid VGen device key data") from exc
