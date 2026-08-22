"""VGen's constrained RFC 9421 HTTP Message Signature profile.

The profile uses the RFC 9421 ``Signature-Input`` and ``Signature`` field
syntax and Ed25519. It always covers method, the exact VGen request path
(including a raw query string when present), Content-Digest, created time,
nonce, key ID and algorithm. Keeping one fixed component set makes strict
verification and replay protection practical across the CLI and Gateway.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vgen.protocol.errors import ErrorCode, VGenError

from .encoding import b64url_encode
from .identity import DeviceKeys

SIGNATURE_LABEL = "sig1"
_COMPONENTS = '("@method" "@path" "content-digest")'
_KEY_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SIGNATURE_INPUT = re.compile(
    r"^(?P<label>[a-z][a-z0-9_]*)="
    r'(?P<params>\("@method" "@path" "content-digest"\);'
    r"created=(?P<created>[0-9]{1,12});"
    r'nonce="(?P<nonce>[A-Za-z0-9_-]{16,128})";'
    r'keyid="(?P<key_id>[A-Za-z0-9._:-]{1,128})";alg="ed25519")$'
)
_SIGNATURE = re.compile(r"^(?P<label>[a-z][a-z0-9_]*)=:(?P<value>[A-Za-z0-9+/]+={0,2}):$")
_CONTENT_DIGEST = re.compile(r"^sha-256=:(?P<value>[A-Za-z0-9+/]+={0,2}):$")


@dataclass(frozen=True, slots=True)
class RequestSignatureHeaders:
    content_digest: str
    signature_input: str
    signature: str

    def to_headers(self) -> dict[str, str]:
        return {
            "Content-Digest": self.content_digest,
            "Signature-Input": self.signature_input,
            "Signature": self.signature,
        }


@dataclass(frozen=True, slots=True)
class VerifiedRequestSignature:
    key_id: str
    created: int
    nonce: str


def _header(headers: Mapping[str, str], name: str) -> str:
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value.strip()
    raise VGenError(ErrorCode.SIGNATURE_INVALID, details={"missing_header": name})


def _validate_request(method: str, path: str, body: bytes) -> tuple[str, str]:
    if not isinstance(body, bytes):
        raise TypeError("HTTP body must be bytes")
    normalized_method = method.upper()
    if not re.fullmatch(r"[A-Z]+", normalized_method):
        raise ValueError("HTTP method is invalid")
    if (
        not path.startswith("/")
        or "#" in path
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in path)
    ):
        raise ValueError("HTTP path must be an ASCII absolute request target with percent encoding")
    return normalized_method, path


def _content_digest(body: bytes) -> str:
    encoded = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{encoded}:"


def _signature_params(*, created: int, nonce: str, key_id: str) -> str:
    return f'{_COMPONENTS};created={created};nonce="{nonce}";keyid="{key_id}";alg="ed25519"'


def _signature_base(
    *,
    method: str,
    path: str,
    content_digest: str,
    signature_params: str,
) -> bytes:
    return (
        f'"@method": {method}\n'
        f'"@path": {path}\n'
        f'"content-digest": {content_digest}\n'
        f'"@signature-params": {signature_params}'
    ).encode()


def sign_http_request(
    private_key: DeviceKeys | Ed25519PrivateKey | bytes,
    *,
    method: str,
    path: str,
    body: bytes = b"",
    key_id: str | None = None,
    created: int | None = None,
    nonce: str | None = None,
) -> RequestSignatureHeaders:
    """Return Content-Digest, Signature-Input and Signature request headers."""

    normalized_method, normalized_path = _validate_request(method, path, body)
    if isinstance(private_key, DeviceKeys):
        signing_key = private_key.signing_private_key
        resolved_key_id = private_key.key_id if key_id is None else key_id
    elif isinstance(private_key, bytes):
        signing_key = Ed25519PrivateKey.from_private_bytes(private_key)
        if key_id is None:
            raise ValueError("key_id is required for a raw private key")
        resolved_key_id = key_id
    else:
        signing_key = private_key
        if key_id is None:
            raise ValueError("key_id is required for an Ed25519 private key")
        resolved_key_id = key_id
    if not _KEY_ID.fullmatch(resolved_key_id):
        raise ValueError("HTTP signature key_id contains unsupported characters")
    issued_at = int(time.time()) if created is None else int(created)
    resolved_nonce = nonce or b64url_encode(secrets.token_bytes(24))
    if not _NONCE.fullmatch(resolved_nonce):
        raise ValueError("HTTP signature nonce is not canonical base64url")
    digest = _content_digest(body)
    params = _signature_params(
        created=issued_at,
        nonce=resolved_nonce,
        key_id=resolved_key_id,
    )
    signature = signing_key.sign(
        _signature_base(
            method=normalized_method,
            path=normalized_path,
            content_digest=digest,
            signature_params=params,
        )
    )
    return RequestSignatureHeaders(
        content_digest=digest,
        signature_input=f"{SIGNATURE_LABEL}={params}",
        signature=f"{SIGNATURE_LABEL}=:{base64.b64encode(signature).decode('ascii')}:",
    )


def verify_http_request(
    public_key: Ed25519PublicKey | bytes,
    *,
    method: str,
    path: str,
    body: bytes,
    headers: Mapping[str, str],
    expected_key_id: str | None = None,
    now: int | None = None,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 30,
    nonce_is_fresh: Callable[[str, int], bool] | None = None,
) -> VerifiedRequestSignature:
    """Strictly verify the VGen request-signature profile.

    ``nonce_is_fresh`` must atomically claim a nonce in the Gateway replay
    cache and return ``False`` if it was already present.
    """

    normalized_method, normalized_path = _validate_request(method, path, body)
    if max_age_seconds < 1 or max_future_skew_seconds < 0:
        raise ValueError("HTTP signature time limits are invalid")
    digest_header = _header(headers, "Content-Digest")
    input_header = _header(headers, "Signature-Input")
    signature_header = _header(headers, "Signature")

    digest_match = _CONTENT_DIGEST.fullmatch(digest_header)
    input_match = _SIGNATURE_INPUT.fullmatch(input_header)
    signature_match = _SIGNATURE.fullmatch(signature_header)
    if digest_match is None or input_match is None or signature_match is None:
        raise VGenError(ErrorCode.SIGNATURE_INVALID)
    if input_match.group("label") != signature_match.group("label"):
        raise VGenError(ErrorCode.SIGNATURE_INVALID)
    if input_match.group("label") != SIGNATURE_LABEL:
        raise VGenError(ErrorCode.SIGNATURE_INVALID)

    expected_digest = _content_digest(body)
    if not hmac.compare_digest(digest_header, expected_digest):
        raise VGenError(ErrorCode.SIGNATURE_INVALID)
    key_id = input_match.group("key_id")
    if expected_key_id is not None and not hmac.compare_digest(key_id, expected_key_id):
        raise VGenError(ErrorCode.SIGNATURE_INVALID)
    created = int(input_match.group("created"))
    current = int(time.time()) if now is None else int(now)
    if created > current + max_future_skew_seconds or current - created > max_age_seconds:
        raise VGenError(ErrorCode.SIGNATURE_INVALID, details={"reason": "signature_time"})

    try:
        signature = base64.b64decode(signature_match.group("value"), validate=True)
    except ValueError as exc:
        raise VGenError(ErrorCode.SIGNATURE_INVALID) from exc
    if len(signature) != 64:
        raise VGenError(ErrorCode.SIGNATURE_INVALID)
    verify_key = (
        Ed25519PublicKey.from_public_bytes(public_key)
        if isinstance(public_key, bytes)
        else public_key
    )
    try:
        verify_key.verify(
            signature,
            _signature_base(
                method=normalized_method,
                path=normalized_path,
                content_digest=digest_header,
                signature_params=input_match.group("params"),
            ),
        )
    except InvalidSignature as exc:
        raise VGenError(ErrorCode.SIGNATURE_INVALID) from exc

    nonce = input_match.group("nonce")
    if nonce_is_fresh is not None and not nonce_is_fresh(nonce, created):
        raise VGenError(ErrorCode.REPLAY_DETECTED)
    return VerifiedRequestSignature(key_id=key_id, created=created, nonce=nonce)
