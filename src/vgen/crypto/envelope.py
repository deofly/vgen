"""Task payload encryption and RFC 9180 HPKE key envelopes.

Payloads use libsodium XChaCha20-Poly1305. Each random task data key is wrapped
independently for the assigned Worker and authorized readers with HPKE Base mode
using DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from vgen.protocol.errors import ErrorCode, VGenError

from .encoding import b64url_decode, b64url_encode, canonical_json

TASK_DATA_KEY_BYTES = 32
XCHACHA_NONCE_BYTES = 24
PAYLOAD_ALGORITHM = "XChaCha20-Poly1305-IETF"
HPKE_ALGORITHM = "HPKE-Base-X25519-HKDF-SHA256-ChaCha20Poly1305"

_HPKE_VERSION = b"HPKE-v1"
_KEM_ID = 0x0020
_KDF_ID = 0x0001
_AEAD_ID = 0x0003
_NSECRET = 32
_NK = 32
_NN = 12
_KEM_SUITE_ID = b"KEM" + _KEM_ID.to_bytes(2, "big")
_HPKE_SUITE_ID = (
    b"HPKE" + _KEM_ID.to_bytes(2, "big") + _KDF_ID.to_bytes(2, "big") + _AEAD_ID.to_bytes(2, "big")
)
_TASK_WRAP_INFO = b"vgen-task-key-wrap-v1"
_WORKSPACE_KEY_WRAP_INFO = b"vgen-workspace-key-wrap-v1"
_WORKSPACE_READER_AAD = b"vgen-workspace-reader-envelope-v1"


def generate_task_data_key() -> bytes:
    return secrets.token_bytes(TASK_DATA_KEY_BYTES)


def generate_workspace_data_key() -> bytes:
    return secrets.token_bytes(TASK_DATA_KEY_BYTES)


def _require_bytes(name: str, value: bytes, length: int | None = None) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must contain {length} bytes")


def _labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    labeled_ikm = _HPKE_VERSION + suite_id + label + ikm
    return hmac.new(salt, labeled_ikm, hashlib.sha256).digest()


def _labeled_expand(
    prk: bytes,
    suite_id: bytes,
    label: bytes,
    info: bytes,
    length: int,
) -> bytes:
    if length < 0 or length > 0xFFFF:
        raise ValueError("HPKE output length is out of range")
    labeled_info = length.to_bytes(2, "big") + _HPKE_VERSION + suite_id + label + info
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=labeled_info,
    ).derive(prk)


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(b"", _KEM_SUITE_ID, b"eae_prk", dh)
    return _labeled_expand(
        eae_prk,
        _KEM_SUITE_ID,
        b"shared_secret",
        kem_context,
        _NSECRET,
    )


def _key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(b"", _HPKE_SUITE_ID, b"psk_id_hash", b"")
    info_hash = _labeled_extract(b"", _HPKE_SUITE_ID, b"info_hash", info)
    key_schedule_context = b"\x00" + psk_id_hash + info_hash  # Base mode
    secret = _labeled_extract(shared_secret, _HPKE_SUITE_ID, b"secret", b"")
    key = _labeled_expand(secret, _HPKE_SUITE_ID, b"key", key_schedule_context, _NK)
    base_nonce = _labeled_expand(
        secret,
        _HPKE_SUITE_ID,
        b"base_nonce",
        key_schedule_context,
        _NN,
    )
    return key, base_nonce


def _x25519_public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _coerce_x25519_public(value: X25519PublicKey | bytes) -> X25519PublicKey:
    if isinstance(value, X25519PublicKey):
        return value
    _require_bytes("recipient public key", value, 32)
    return X25519PublicKey.from_public_bytes(value)


def _coerce_x25519_private(value: X25519PrivateKey | bytes) -> X25519PrivateKey:
    if isinstance(value, X25519PrivateKey):
        return value
    _require_bytes("recipient private key", value, 32)
    return X25519PrivateKey.from_private_bytes(value)


@dataclass(frozen=True, slots=True)
class HpkeCiphertext:
    encapsulated_key: bytes
    ciphertext: bytes
    algorithm: str = HPKE_ALGORITHM

    def __post_init__(self) -> None:
        _require_bytes("HPKE encapsulated key", self.encapsulated_key, 32)
        _require_bytes("HPKE ciphertext", self.ciphertext)
        if self.algorithm != HPKE_ALGORITHM:
            raise ValueError("unsupported HPKE algorithm")

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "encapsulated_key": b64url_encode(self.encapsulated_key),
            "ciphertext": b64url_encode(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> HpkeCiphertext:
        return cls(
            algorithm=str(value["algorithm"]),
            encapsulated_key=b64url_decode(str(value["encapsulated_key"]), expected_length=32),
            ciphertext=b64url_decode(str(value["ciphertext"])),
        )


def hpke_seal(
    recipient_public_key: X25519PublicKey | bytes,
    plaintext: bytes,
    *,
    info: bytes,
    aad: bytes = b"",
) -> HpkeCiphertext:
    """Encrypt one plaintext using RFC 9180 HPKE Base mode."""

    _require_bytes("plaintext", plaintext)
    _require_bytes("HPKE info", info)
    _require_bytes("HPKE AAD", aad)
    recipient = _coerce_x25519_public(recipient_public_key)
    ephemeral = X25519PrivateKey.generate()
    encapsulated_key = _x25519_public_bytes(ephemeral.public_key())
    recipient_bytes = _x25519_public_bytes(recipient)
    try:
        dh = ephemeral.exchange(recipient)
    except ValueError as exc:
        raise ValueError("invalid X25519 recipient public key") from exc
    shared_secret = _extract_and_expand(dh, encapsulated_key + recipient_bytes)
    key, nonce = _key_schedule(shared_secret, info)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return HpkeCiphertext(encapsulated_key=encapsulated_key, ciphertext=ciphertext)


def hpke_open(
    recipient_private_key: X25519PrivateKey | bytes,
    sealed: HpkeCiphertext | Mapping[str, Any],
    *,
    info: bytes,
    aad: bytes = b"",
) -> bytes:
    """Open one RFC 9180 HPKE Base-mode ciphertext."""

    wrapped = sealed if isinstance(sealed, HpkeCiphertext) else HpkeCiphertext.from_dict(sealed)
    _require_bytes("HPKE info", info)
    _require_bytes("HPKE AAD", aad)
    recipient = _coerce_x25519_private(recipient_private_key)
    sender = X25519PublicKey.from_public_bytes(wrapped.encapsulated_key)
    recipient_bytes = _x25519_public_bytes(recipient.public_key())
    try:
        dh = recipient.exchange(sender)
        shared_secret = _extract_and_expand(dh, wrapped.encapsulated_key + recipient_bytes)
        key, nonce = _key_schedule(shared_secret, info)
        return ChaCha20Poly1305(key).decrypt(nonce, wrapped.ciphertext, aad)
    except (InvalidTag, ValueError) as exc:
        raise VGenError(ErrorCode.DECRYPTION_FAILED) from exc


@dataclass(frozen=True, slots=True)
class PayloadCiphertext:
    nonce: bytes
    ciphertext: bytes
    algorithm: str = PAYLOAD_ALGORITHM

    def __post_init__(self) -> None:
        _require_bytes("payload nonce", self.nonce, XCHACHA_NONCE_BYTES)
        _require_bytes("payload ciphertext", self.ciphertext)
        if self.algorithm != PAYLOAD_ALGORITHM:
            raise ValueError("unsupported payload encryption algorithm")

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "nonce": b64url_encode(self.nonce),
            "ciphertext": b64url_encode(self.ciphertext),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> PayloadCiphertext:
        return cls(
            algorithm=str(value["algorithm"]),
            nonce=b64url_decode(str(value["nonce"]), expected_length=XCHACHA_NONCE_BYTES),
            ciphertext=b64url_decode(str(value["ciphertext"])),
        )


def _xchacha_bindings():  # type: ignore[no-untyped-def]
    try:
        from nacl import bindings
        from nacl.exceptions import CryptoError
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise RuntimeError("XChaCha encryption requires the 'PyNaCl>=1.5' package") from exc
    return bindings, CryptoError


def encrypt_payload(key: bytes, plaintext: bytes, *, aad: bytes) -> PayloadCiphertext:
    _require_bytes("payload key", key, TASK_DATA_KEY_BYTES)
    _require_bytes("plaintext", plaintext)
    _require_bytes("payload AAD", aad)
    bindings, _ = _xchacha_bindings()
    nonce = secrets.token_bytes(XCHACHA_NONCE_BYTES)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)
    return PayloadCiphertext(nonce=nonce, ciphertext=ciphertext)


def decrypt_payload(
    key: bytes,
    sealed: PayloadCiphertext | Mapping[str, Any],
    *,
    aad: bytes,
) -> bytes:
    _require_bytes("payload key", key, TASK_DATA_KEY_BYTES)
    _require_bytes("payload AAD", aad)
    payload = (
        sealed if isinstance(sealed, PayloadCiphertext) else PayloadCiphertext.from_dict(sealed)
    )
    bindings, crypto_error = _xchacha_bindings()
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            payload.ciphertext, aad, payload.nonce, key
        )
    except crypto_error as exc:
        raise VGenError(ErrorCode.DECRYPTION_FAILED) from exc


def task_aad(
    *,
    workspace_id: str,
    task_id: str,
    attempt_id: str,
    artifact_id: str = "payload",
    key_version: int = 1,
) -> bytes:
    """Build the canonical AAD binding required for task or artifact content."""

    if key_version < 1:
        raise ValueError("key_version must be positive")
    return canonical_json(
        {
            "protocol_version": "v1",
            "workspace_id": workspace_id,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "artifact_id": artifact_id,
            "key_version": key_version,
        }
    )


def workspace_key_aad(
    *,
    workspace_id: str,
    recipient_type: str,
    recipient_id: str,
    key_version: int = 1,
    recipient_binding_digest: str | None = None,
) -> bytes:
    """Bind a Workspace Data Key envelope to one immutable recipient."""

    if not workspace_id or not recipient_type or not recipient_id:
        raise ValueError("workspace and recipient identifiers are required")
    if key_version < 1:
        raise ValueError("key_version must be positive")
    value = {
        "protocol_version": "v2" if recipient_binding_digest is not None else "v1",
        "workspace_id": workspace_id,
        "recipient_type": recipient_type,
        "recipient_id": recipient_id,
        "key_version": key_version,
    }
    if recipient_binding_digest is not None:
        if len(recipient_binding_digest) != 64 or any(
            character not in "0123456789abcdef" for character in recipient_binding_digest
        ):
            raise ValueError("recipient binding digest must be lowercase SHA-256")
        value["recipient_binding_digest"] = recipient_binding_digest
    return canonical_json(value)


def _wrap_info(aad: bytes) -> bytes:
    return _TASK_WRAP_INFO + b"\x00" + hashlib.sha256(aad).digest()


def wrap_task_key(
    recipient_public_key: X25519PublicKey | bytes,
    task_data_key: bytes,
    *,
    aad: bytes,
) -> HpkeCiphertext:
    _require_bytes("task data key", task_data_key, TASK_DATA_KEY_BYTES)
    return hpke_seal(
        recipient_public_key,
        task_data_key,
        info=_wrap_info(aad),
        aad=aad,
    )


def unwrap_task_key(
    recipient_private_key: X25519PrivateKey | bytes,
    wrapped: HpkeCiphertext | Mapping[str, Any],
    *,
    aad: bytes,
) -> bytes:
    key = hpke_open(
        recipient_private_key,
        wrapped,
        info=_wrap_info(aad),
        aad=aad,
    )
    _require_bytes("unwrapped task data key", key, TASK_DATA_KEY_BYTES)
    return key


def wrap_workspace_key(
    recipient_public_key: X25519PublicKey | bytes,
    workspace_data_key: bytes,
    *,
    aad: bytes,
) -> HpkeCiphertext:
    """Seal a Workspace Data Key for a recovery, device, or Service key."""

    _require_bytes("workspace data key", workspace_data_key, TASK_DATA_KEY_BYTES)
    return hpke_seal(
        recipient_public_key,
        workspace_data_key,
        info=_WORKSPACE_KEY_WRAP_INFO + b"\x00" + hashlib.sha256(aad).digest(),
        aad=aad,
    )


def unwrap_workspace_key(
    recipient_private_key: X25519PrivateKey | bytes,
    wrapped: HpkeCiphertext | Mapping[str, Any],
    *,
    aad: bytes,
) -> bytes:
    """Open a recipient-bound Workspace Data Key envelope."""

    key = hpke_open(
        recipient_private_key,
        wrapped,
        info=_WORKSPACE_KEY_WRAP_INFO + b"\x00" + hashlib.sha256(aad).digest(),
        aad=aad,
    )
    _require_bytes("workspace data key", key, TASK_DATA_KEY_BYTES)
    return key


def wrap_task_key_for_workspace(
    workspace_data_key: bytes,
    task_data_key: bytes,
    *,
    aad: bytes,
) -> PayloadCiphertext:
    """Create the reader envelope protected by a versioned Workspace Data Key."""

    _require_bytes("workspace data key", workspace_data_key, TASK_DATA_KEY_BYTES)
    _require_bytes("task data key", task_data_key, TASK_DATA_KEY_BYTES)
    return encrypt_payload(
        workspace_data_key,
        task_data_key,
        aad=_WORKSPACE_READER_AAD + b"\x00" + aad,
    )


def unwrap_task_key_for_workspace(
    workspace_data_key: bytes,
    wrapped: PayloadCiphertext | Mapping[str, Any],
    *,
    aad: bytes,
) -> bytes:
    _require_bytes("workspace data key", workspace_data_key, TASK_DATA_KEY_BYTES)
    key = decrypt_payload(
        workspace_data_key,
        wrapped,
        aad=_WORKSPACE_READER_AAD + b"\x00" + aad,
    )
    _require_bytes("unwrapped task data key", key, TASK_DATA_KEY_BYTES)
    return key


@dataclass(frozen=True, slots=True)
class TaskEnvelope:
    payload: PayloadCiphertext
    recipients: Mapping[str, HpkeCiphertext] = field(default_factory=dict)
    workspace_reader: PayloadCiphertext | None = None
    version: int = 1

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError("unsupported task envelope version")
        if not self.recipients:
            raise ValueError("task envelope requires at least one recipient")
        normalized: dict[str, HpkeCiphertext] = {}
        for recipient_id, wrapped in self.recipients.items():
            if not recipient_id:
                raise ValueError("task envelope recipient ID must not be empty")
            normalized[str(recipient_id)] = (
                wrapped
                if isinstance(wrapped, HpkeCiphertext)
                else HpkeCiphertext.from_dict(wrapped)
            )
        object.__setattr__(self, "recipients", normalized)
        if self.workspace_reader is not None and not isinstance(
            self.workspace_reader, PayloadCiphertext
        ):
            object.__setattr__(
                self,
                "workspace_reader",
                PayloadCiphertext.from_dict(self.workspace_reader),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "payload": self.payload.to_dict(),
            "recipients": {
                recipient_id: wrapped.to_dict()
                for recipient_id, wrapped in sorted(self.recipients.items())
            },
            "workspace_reader": (
                None if self.workspace_reader is None else self.workspace_reader.to_dict()
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> TaskEnvelope:
        recipients = value.get("recipients")
        if not isinstance(recipients, Mapping):
            raise ValueError("task envelope recipients must be an object")
        return cls(
            version=int(value.get("version", 0)),
            payload=PayloadCiphertext.from_dict(value["payload"]),
            recipients={
                str(recipient_id): HpkeCiphertext.from_dict(wrapped)
                for recipient_id, wrapped in recipients.items()
            },
            workspace_reader=(
                None
                if value.get("workspace_reader") is None
                else PayloadCiphertext.from_dict(value["workspace_reader"])
            ),
        )


def create_task_envelope(
    plaintext: bytes,
    recipients: Mapping[str, X25519PublicKey | bytes],
    *,
    aad: bytes,
    workspace_data_key: bytes | None = None,
) -> TaskEnvelope:
    """Encrypt a payload once and wrap its random key for every authorized reader."""

    if not recipients:
        raise ValueError("at least one task envelope recipient is required")
    key = generate_task_data_key()
    payload = encrypt_payload(key, plaintext, aad=aad)
    wrapped = {
        str(recipient_id): wrap_task_key(public_key, key, aad=aad)
        for recipient_id, public_key in recipients.items()
    }
    reader = (
        None
        if workspace_data_key is None
        else wrap_task_key_for_workspace(workspace_data_key, key, aad=aad)
    )
    return TaskEnvelope(payload=payload, recipients=wrapped, workspace_reader=reader)


def open_task_envelope(
    envelope: TaskEnvelope | Mapping[str, Any],
    *,
    recipient_id: str,
    recipient_private_key: X25519PrivateKey | bytes,
    aad: bytes,
) -> bytes:
    task = envelope if isinstance(envelope, TaskEnvelope) else TaskEnvelope.from_dict(envelope)
    try:
        wrapped = task.recipients[recipient_id]
    except KeyError as exc:
        raise VGenError(
            ErrorCode.RECIPIENT_KEY_UNAVAILABLE,
            details={"recipient_id": recipient_id},
        ) from exc
    key = unwrap_task_key(recipient_private_key, wrapped, aad=aad)
    return decrypt_payload(key, task.payload, aad=aad)


def open_task_envelope_with_workspace_key(
    envelope: TaskEnvelope | Mapping[str, Any],
    *,
    workspace_data_key: bytes,
    aad: bytes,
) -> bytes:
    task = envelope if isinstance(envelope, TaskEnvelope) else TaskEnvelope.from_dict(envelope)
    if task.workspace_reader is None:
        raise VGenError(ErrorCode.RECIPIENT_KEY_UNAVAILABLE)
    key = unwrap_task_key_for_workspace(
        workspace_data_key,
        task.workspace_reader,
        aad=aad,
    )
    return decrypt_payload(key, task.payload, aad=aad)
