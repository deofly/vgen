"""Authenticated streaming encryption for large task artifacts.

The framing is VGen-owned while every frame is authenticated by libsodium's
XChaCha20-Poly1305 secretstream construction. Callers should decrypt into a
temporary file and publish it only after this function returns successfully.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import BinaryIO

from vgen.protocol.errors import ErrorCode, VGenError

SECRETSTREAM_MAGIC = b"VGENSS01"
DEFAULT_CHUNK_SIZE = 1024 * 1024
MAX_FRAME_SIZE = 64 * 1024 * 1024


def encrypted_stream_size(
    plaintext_bytes: int,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> int:
    """Return the exact framed secretstream size without encrypting the file."""

    if plaintext_bytes < 0:
        raise ValueError("plaintext size cannot be negative")
    if chunk_size < 1 or chunk_size > MAX_FRAME_SIZE // 2:
        raise ValueError("stream chunk_size is out of range")
    bindings, _ = _bindings()
    chunks = max(1, (plaintext_bytes + chunk_size - 1) // chunk_size)
    return (
        len(SECRETSTREAM_MAGIC)
        + bindings.crypto_secretstream_xchacha20poly1305_HEADERBYTES
        + plaintext_bytes
        + chunks * (4 + bindings.crypto_secretstream_xchacha20poly1305_ABYTES)
    )


@dataclass(frozen=True, slots=True)
class StreamStats:
    plaintext_bytes: int
    ciphertext_bytes: int
    chunks: int


def _bindings():  # type: ignore[no-untyped-def]
    try:
        from nacl import bindings
        from nacl.exceptions import CryptoError
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise RuntimeError("artifact encryption requires the 'PyNaCl>=1.5' package") from exc
    return bindings, CryptoError


def _read_exact(source: BinaryIO, length: int) -> bytes:
    value = bytearray()
    while len(value) < length:
        part = source.read(length - len(value))
        if not part:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        value.extend(part)
    return bytes(value)


def _chunk_aad(aad: bytes, index: int) -> bytes:
    # A fixed-size digest keeps very large caller AAD from being repeated in
    # every frame while still binding the complete context and frame order.
    return hashlib.sha256(
        b"vgen-secretstream-frame-v1\x00" + aad + index.to_bytes(8, "big")
    ).digest()


def encrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    key: bytes,
    *,
    aad: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> StreamStats:
    """Encrypt *source* into framed secretstream bytes in *destination*."""

    bindings, _ = _bindings()
    if len(key) != bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES:
        raise ValueError(
            "secretstream key must contain "
            f"{bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES} bytes"
        )
    if not isinstance(aad, bytes):
        raise TypeError("stream AAD must be bytes")
    if chunk_size < 1 or chunk_size > MAX_FRAME_SIZE // 2:
        raise ValueError("stream chunk_size is out of range")

    state = bindings.crypto_secretstream_xchacha20poly1305_state()
    header = bindings.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    destination.write(SECRETSTREAM_MAGIC)
    destination.write(header)
    ciphertext_bytes = len(SECRETSTREAM_MAGIC) + len(header)
    plaintext_bytes = 0
    chunks = 0

    current = source.read(chunk_size)
    while True:
        following = source.read(chunk_size) if current else b""
        final = not following
        tag = (
            bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL
            if final
            else bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
        )
        encrypted = bindings.crypto_secretstream_xchacha20poly1305_push(
            state,
            current,
            _chunk_aad(aad, chunks),
            tag,
        )
        destination.write(struct.pack(">I", len(encrypted)))
        destination.write(encrypted)
        plaintext_bytes += len(current)
        ciphertext_bytes += 4 + len(encrypted)
        chunks += 1
        if final:
            break
        current = following

    return StreamStats(
        plaintext_bytes=plaintext_bytes,
        ciphertext_bytes=ciphertext_bytes,
        chunks=chunks,
    )


def decrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    key: bytes,
    *,
    aad: bytes,
    max_frame_size: int = MAX_FRAME_SIZE,
) -> StreamStats:
    """Verify and decrypt a VGen secretstream artifact."""

    bindings, crypto_error = _bindings()
    if len(key) != bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES:
        raise ValueError(
            "secretstream key must contain "
            f"{bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES} bytes"
        )
    if not isinstance(aad, bytes):
        raise TypeError("stream AAD must be bytes")
    if max_frame_size < bindings.crypto_secretstream_xchacha20poly1305_ABYTES:
        raise ValueError("max_frame_size is too small")

    if _read_exact(source, len(SECRETSTREAM_MAGIC)) != SECRETSTREAM_MAGIC:
        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
    header = _read_exact(source, bindings.crypto_secretstream_xchacha20poly1305_HEADERBYTES)
    state = bindings.crypto_secretstream_xchacha20poly1305_state()
    try:
        bindings.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key)
    except (crypto_error, ValueError) as exc:
        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED) from exc

    plaintext_bytes = 0
    ciphertext_bytes = len(SECRETSTREAM_MAGIC) + len(header)
    chunks = 0
    while True:
        length_bytes = source.read(4)
        if len(length_bytes) != 4:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        frame_length = struct.unpack(">I", length_bytes)[0]
        if (
            frame_length < bindings.crypto_secretstream_xchacha20poly1305_ABYTES
            or frame_length > max_frame_size
        ):
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        encrypted = _read_exact(source, frame_length)
        try:
            plaintext, tag = bindings.crypto_secretstream_xchacha20poly1305_pull(
                state,
                encrypted,
                _chunk_aad(aad, chunks),
            )
        except crypto_error as exc:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED) from exc
        if tag == bindings.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            destination.write(plaintext)
            plaintext_bytes += len(plaintext)
            ciphertext_bytes += 4 + frame_length
            chunks += 1
            if source.read(1):
                raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
            break
        if tag != bindings.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        destination.write(plaintext)
        plaintext_bytes += len(plaintext)
        ciphertext_bytes += 4 + frame_length
        chunks += 1

    return StreamStats(
        plaintext_bytes=plaintext_bytes,
        ciphertext_bytes=ciphertext_bytes,
        chunks=chunks,
    )
