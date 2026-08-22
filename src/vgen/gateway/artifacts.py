"""Executor-neutral encrypted artifact storage and opaque transfer tickets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import time
from collections.abc import AsyncIterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from vgen.protocol.errors import ErrorCode, VGenError
from vgen.protocol.ids import validate_id


@dataclass(frozen=True, slots=True)
class TransferTicket:
    artifact_id: str
    method: str
    url: str
    expires_at: float
    max_bytes: int
    headers: dict[str, str] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "method": self.method,
            "url": self.url,
            "expires_at": self.expires_at,
            "max_bytes": self.max_bytes,
            "headers": dict(self.headers or {}),
        }


@dataclass(frozen=True, slots=True)
class VerifiedTicket:
    artifact_id: str
    method: str
    expires_at: float
    max_bytes: int


class ArtifactStore(Protocol):
    store_type: str

    def issue_ticket(
        self, artifact_id: str, *, method: str, ttl_seconds: int, max_bytes: int
    ) -> TransferTicket: ...

    def verify_ticket(self, token: str, *, method: str) -> VerifiedTicket: ...

    def put(self, artifact_id: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]: ...

    async def put_chunks(
        self, artifact_id: str, chunks: AsyncIterable[bytes], *, max_bytes: int
    ) -> tuple[int, str]: ...

    def open(self, artifact_id: str) -> BinaryIO: ...

    def observe_upload(self, artifact_id: str, *, max_bytes: int) -> tuple[int, str | None]: ...


class LocalArtifactStore:
    """Stores ciphertext only; object paths are derived from canonical IDs."""

    store_type = "local"

    def __init__(self, root: str | Path, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("artifact ticket signing key must contain at least 32 bytes")
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._signing_key = bytes(signing_key)

    def _path(self, artifact_id: str) -> Path:
        if not validate_id(artifact_id, "artifact"):
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
        # No user-controlled path component reaches the filesystem.
        body = artifact_id.split("_", 1)[1]
        path = (self.root / body[:2] / f"{artifact_id}.ciphertext").resolve()
        if self.root not in path.parents:
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
        return path

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        try:
            return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (ValueError, TypeError) as exc:
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND) from exc

    def issue_ticket(
        self, artifact_id: str, *, method: str, ttl_seconds: int = 300, max_bytes: int
    ) -> TransferTicket:
        self._path(artifact_id)
        normalized = method.upper()
        if normalized not in ("GET", "PUT") or not 1 <= ttl_seconds <= 3600 or max_bytes < 0:
            raise ValueError("invalid artifact ticket policy")
        expires_at = time.time() + ttl_seconds
        payload = json.dumps(
            {
                "v": 1,
                "artifact_id": artifact_id,
                "method": normalized,
                "expires_at": expires_at,
                "max_bytes": max_bytes,
                "nonce": self._encode(secrets.token_bytes(16)),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        signature = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
        token = self._encode(payload) + "." + self._encode(signature)
        return TransferTicket(
            artifact_id=artifact_id,
            method=normalized,
            # Keep bearer material out of the request target. Reverse proxies
            # and default HTTP access logs routinely record paths, while this
            # dedicated header can be redacted with the other credentials.
            url=f"/api/v1/artifacts/transfer/{artifact_id}",
            expires_at=expires_at,
            max_bytes=max_bytes,
            headers={"Vgen-Artifact-Ticket": token},
        )

    def verify_ticket(self, token: str, *, method: str) -> VerifiedTicket:
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = self._decode(encoded_payload)
            signature = self._decode(encoded_signature)
            expected = hmac.new(self._signing_key, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("ticket signature")
            value = json.loads(payload)
            ticket = VerifiedTicket(
                artifact_id=str(value["artifact_id"]),
                method=str(value["method"]),
                expires_at=float(value["expires_at"]),
                max_bytes=int(value["max_bytes"]),
            )
            self._path(ticket.artifact_id)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND) from exc
        if ticket.method != method.upper() or ticket.expires_at <= time.time():
            raise VGenError(ErrorCode.PERMISSION_DENIED)
        return ticket

    def put(self, artifact_id: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        path = self._path(artifact_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        total = 0
        handle, temporary = tempfile.mkstemp(prefix="upload-", dir=path.parent)
        try:
            with os.fdopen(handle, "wb") as output:
                while True:
                    chunk = stream.read(min(1024 * 1024, max_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return total, digest.hexdigest()

    async def put_chunks(
        self, artifact_id: str, chunks: AsyncIterable[bytes], *, max_bytes: int
    ) -> tuple[int, str]:
        path = self._path(artifact_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        total = 0
        handle, temporary = tempfile.mkstemp(prefix="upload-", dir=path.parent)
        try:
            with os.fdopen(handle, "wb") as output:
                async for chunk in chunks:
                    total += len(chunk)
                    if total > max_bytes:
                        raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return total, digest.hexdigest()

    def open(self, artifact_id: str) -> BinaryIO:
        try:
            return self._path(artifact_id).open("rb")
        except FileNotFoundError as exc:
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND) from exc

    def observe_upload(self, artifact_id: str, *, max_bytes: int) -> tuple[int, str | None]:
        """Local uploads are observed and recorded by the transfer endpoint."""

        path = self._path(artifact_id)
        try:
            size = path.stat().st_size
        except FileNotFoundError as exc:
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND) from exc
        if size > max_bytes:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        return size, digest.hexdigest()


class OssArtifactStore:
    """Alibaba Cloud OSS ciphertext store using short-lived signed HTTP URLs.

    OSS credentials remain in the Gateway process. Clients and Workers receive
    only a single-object, single-method capability URL and generic HTTP headers.
    The URL is never persisted by this class or the Gateway repository.
    """

    store_type = "oss"

    def __init__(
        self,
        bucket: Any,
        *,
        key_prefix: str = "vgen/v1",
    ) -> None:
        prefix = key_prefix.strip("/")
        if not prefix or any(part in ("", ".", "..") for part in prefix.split("/")):
            raise ValueError("OSS artifact prefix is invalid")
        self._bucket = bucket
        self._key_prefix = prefix

    @classmethod
    def from_environment(cls) -> OssArtifactStore:
        """Create the Gateway-side OSS signer without exposing credentials."""

        endpoint = os.getenv("VGEN_OSS_ENDPOINT", "").strip()
        bucket_name = os.getenv("VGEN_OSS_BUCKET", "").strip()
        if not endpoint or not bucket_name:
            raise RuntimeError("VGEN_OSS_ENDPOINT and VGEN_OSS_BUCKET are required")
        if not endpoint.startswith("https://"):
            raise RuntimeError("VGEN_OSS_ENDPOINT must use HTTPS")
        try:
            import oss2
            from oss2.credentials import (
                EcsRamRoleCredentialsProvider,
                EnvironmentVariableCredentialsProvider,
            )
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError("OSS ArtifactStore requires the vgen[oss] extra") from exc

        role_name = os.getenv("VGEN_OSS_ECS_ROLE", "").strip()
        if role_name:
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", role_name):
                raise RuntimeError("VGEN_OSS_ECS_ROLE is invalid")
            auth_host = (
                "http://100.100.100.200/latest/meta-data/ram/security-credentials/" + role_name
            )
            provider = EcsRamRoleCredentialsProvider(auth_host)
        else:
            provider = EnvironmentVariableCredentialsProvider()
        auth = oss2.ProviderAuth(provider)
        bucket = oss2.Bucket(auth, endpoint, bucket_name)
        return cls(bucket, key_prefix=os.getenv("VGEN_OSS_PREFIX", "vgen/v1"))

    def _object_key(self, artifact_id: str) -> str:
        if not validate_id(artifact_id, "artifact"):
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
        body = artifact_id.split("_", 1)[1]
        return f"{self._key_prefix}/{body[:2]}/{artifact_id}.ciphertext"

    def issue_ticket(
        self,
        artifact_id: str,
        *,
        method: str,
        ttl_seconds: int = 300,
        max_bytes: int,
    ) -> TransferTicket:
        normalized = method.upper()
        if normalized not in ("GET", "PUT") or not 1 <= ttl_seconds <= 3600 or max_bytes < 0:
            raise ValueError("invalid artifact ticket policy")
        headers = (
            {
                "Content-Type": "application/octet-stream",
                # A direct OSS capability does not pass through the Gateway,
                # so its signed request must itself be single-use in effect.
                # OSS rejects a second PutObject for the same immutable key
                # when bucket versioning is disabled.
                "x-oss-forbid-overwrite": "true",
            }
            if normalized == "PUT"
            else {}
        )
        object_key = self._object_key(artifact_id)
        try:
            url = self._bucket.sign_url(
                normalized,
                object_key,
                ttl_seconds,
                headers=headers or None,
            )
        except Exception as exc:
            raise VGenError(ErrorCode.STORAGE_UNAVAILABLE) from exc
        if not str(url).startswith("https://"):
            raise VGenError(ErrorCode.STORAGE_UNAVAILABLE)
        return TransferTicket(
            artifact_id=artifact_id,
            method=normalized,
            url=str(url),
            expires_at=time.time() + ttl_seconds,
            max_bytes=max_bytes,
            headers=headers,
        )

    def observe_upload(self, artifact_id: str, *, max_bytes: int) -> tuple[int, str | None]:
        """HEAD a direct upload before changing Gateway artifact state."""

        try:
            result = self._bucket.head_object(self._object_key(artifact_id))
            size = int(result.content_length)
        except Exception as exc:
            raise VGenError(ErrorCode.STORAGE_UNAVAILABLE) from exc
        if size < 0 or size > max_bytes:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        # OSS ETag is not a protocol-level SHA-256, so do not mislabel it.
        return size, None

    def verify_ticket(self, token: str, *, method: str) -> VerifiedTicket:
        raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)

    def put(self, artifact_id: str, stream: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
        raise VGenError(ErrorCode.STORAGE_UNAVAILABLE)

    async def put_chunks(
        self, artifact_id: str, chunks: AsyncIterable[bytes], *, max_bytes: int
    ) -> tuple[int, str]:
        raise VGenError(ErrorCode.STORAGE_UNAVAILABLE)

    def open(self, artifact_id: str) -> BinaryIO:
        raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
