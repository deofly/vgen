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
import urllib.parse
from collections.abc import AsyncIterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
    provider: str | None = None
    endpoint: str | None = None
    credentials: dict[str, str] | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, object]:
        value: dict[str, object] = {
            "artifact_id": self.artifact_id,
            "method": self.method,
            "url": self.url,
            "expires_at": self.expires_at,
            "max_bytes": self.max_bytes,
            "headers": dict(self.headers or {}),
        }
        if self.provider is not None:
            value["provider"] = self.provider
        if self.endpoint is not None:
            value["endpoint"] = self.endpoint
        if self.credentials is not None:
            value["credentials"] = dict(self.credentials)
        return value


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


@dataclass(frozen=True, slots=True)
class StsCredentials:
    access_key_id: str
    access_key_secret: str
    security_token: str
    expires_at: float


class StsCredentialIssuer(Protocol):
    def assume_role(
        self, *, role_arn: str, session_name: str, policy: str, duration_seconds: int
    ) -> StsCredentials: ...


class AlibabaStsCredentialIssuer:
    """Assume a RAM role through the default Alibaba Cloud credential chain."""

    def __init__(self, client: Any) -> None:
        self._client = client

    @classmethod
    def from_environment(cls) -> AlibabaStsCredentialIssuer:
        try:
            from alibabacloud_credentials.client import Client as CredentialsClient
            from alibabacloud_sts20150401.client import Client as StsClient
            from alibabacloud_tea_openapi import models as open_api_models
        except ImportError as exc:  # pragma: no cover - optional extra
            raise RuntimeError("OSS ArtifactStore requires the vgen[oss] extra") from exc
        region = os.getenv("VGEN_STS_REGION", "cn-hangzhou").strip()
        endpoint = os.getenv("VGEN_STS_ENDPOINT", "sts.aliyuncs.com").strip()
        if not re.fullmatch(r"[a-z0-9-]{2,64}", region):
            raise RuntimeError("VGEN_STS_REGION is invalid")
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", endpoint):
            raise RuntimeError("VGEN_STS_ENDPOINT is invalid")
        config = open_api_models.Config(
            credential=CredentialsClient(), region_id=region, endpoint=endpoint
        )
        return cls(StsClient(config))

    def assume_role(
        self, *, role_arn: str, session_name: str, policy: str, duration_seconds: int
    ) -> StsCredentials:
        from alibabacloud_sts20150401 import models as sts_models

        response = self._client.assume_role(
            sts_models.AssumeRoleRequest(
                role_arn=role_arn,
                role_session_name=session_name,
                policy=policy,
                duration_seconds=duration_seconds,
            )
        )
        credentials = getattr(getattr(response, "body", None), "credentials", None)
        try:
            expiration = datetime.fromisoformat(
                str(credentials.expiration).replace("Z", "+00:00")
            ).astimezone(UTC)
            result = StsCredentials(
                access_key_id=str(credentials.access_key_id),
                access_key_secret=str(credentials.access_key_secret),
                security_token=str(credentials.security_token),
                expires_at=expiration.timestamp(),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise RuntimeError("STS AssumeRole returned invalid credentials") from exc
        if not all((result.access_key_id, result.access_key_secret, result.security_token)):
            raise RuntimeError("STS AssumeRole returned incomplete credentials")
        return result


class OssArtifactStore:
    """Issue object-scoped OSS STS credentials without proxying artifact bytes."""

    store_type = "oss"

    def __init__(
        self,
        issuer: StsCredentialIssuer,
        *,
        endpoint: str,
        bucket_name: str,
        transfer_role_arn: str,
        duration_seconds: int = 900,
        key_prefix: str = "vgen/v1",
    ) -> None:
        prefix = key_prefix.strip("/")
        if not prefix or any(part in ("", ".", "..") for part in prefix.split("/")):
            raise ValueError("OSS artifact prefix is invalid")
        if not 900 <= duration_seconds <= 3600:
            raise ValueError("OSS STS duration must be between 900 and 3600 seconds")
        self._issuer = issuer
        self._endpoint = endpoint.rstrip("/")
        self._bucket_name = bucket_name
        self._transfer_role_arn = transfer_role_arn
        self._duration_seconds = duration_seconds
        self._key_prefix = prefix

    @classmethod
    def from_environment(cls) -> OssArtifactStore:
        """Create an STS issuer; no long-lived AccessKey is accepted or stored."""

        endpoint = os.getenv("VGEN_OSS_ENDPOINT", "").strip()
        bucket_name = os.getenv("VGEN_OSS_BUCKET", "").strip()
        if not endpoint or not bucket_name:
            raise RuntimeError("VGEN_OSS_ENDPOINT and VGEN_OSS_BUCKET are required")
        parsed_endpoint = urllib.parse.urlsplit(endpoint)
        if (
            parsed_endpoint.scheme != "https"
            or not parsed_endpoint.hostname
            or parsed_endpoint.username is not None
            or parsed_endpoint.password is not None
            or parsed_endpoint.path not in {"", "/"}
            or parsed_endpoint.query
            or parsed_endpoint.fragment
        ):
            raise RuntimeError("VGEN_OSS_ENDPOINT must be a credential-free HTTPS origin")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}[a-z0-9]", bucket_name) is None:
            raise RuntimeError("VGEN_OSS_BUCKET is invalid")
        role_arn = os.getenv("VGEN_OSS_TRANSFER_ROLE_ARN", "").strip()
        if re.fullmatch(r"acs:ram::[0-9]{8,24}:role/[A-Za-z0-9_.@-]{1,64}", role_arn) is None:
            raise RuntimeError("VGEN_OSS_TRANSFER_ROLE_ARN is invalid")
        try:
            duration = int(os.getenv("VGEN_OSS_STS_DURATION_SECONDS", "900"))
        except ValueError as exc:
            raise RuntimeError("VGEN_OSS_STS_DURATION_SECONDS is invalid") from exc
        return cls(
            AlibabaStsCredentialIssuer.from_environment(),
            endpoint=endpoint,
            bucket_name=bucket_name,
            transfer_role_arn=role_arn,
            duration_seconds=duration,
            key_prefix=os.getenv("VGEN_OSS_PREFIX", "vgen/v1"),
        )

    def _object_key(self, artifact_id: str) -> str:
        if not validate_id(artifact_id, "artifact"):
            raise VGenError(ErrorCode.ARTIFACT_NOT_FOUND)
        body = artifact_id.split("_", 1)[1]
        return f"{self._key_prefix}/{body[:2]}/{artifact_id}.ciphertext"

    def _policy(self, object_key: str, method: str) -> str:
        actions = (
            ["oss:GetObject"]
            if method == "GET"
            else ["oss:PutObject", "oss:AbortMultipartUpload", "oss:ListParts"]
        )
        return json.dumps(
            {
                "Version": "1",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions,
                        "Resource": f"acs:oss:*:*:{self._bucket_name}/{object_key}",
                    }
                ],
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def verify_access(self) -> None:
        """Verify AssumeRole only; never PUT, HEAD, GET, or DELETE an OSS object."""

        object_key = f"{self._key_prefix}/.validation/{secrets.token_hex(8)}.ciphertext"
        try:
            self._issuer.assume_role(
                role_arn=self._transfer_role_arn,
                session_name="vgen-config-check",
                policy=self._policy(object_key, "GET"),
                duration_seconds=self._duration_seconds,
            )
        except Exception as exc:
            raise RuntimeError("OSS STS AssumeRole validation failed") from exc

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
        object_key = self._object_key(artifact_id)
        try:
            credentials = self._issuer.assume_role(
                role_arn=self._transfer_role_arn,
                session_name=f"vgen-{normalized.lower()}-{artifact_id[-20:]}",
                policy=self._policy(object_key, normalized),
                duration_seconds=self._duration_seconds,
            )
        except Exception as exc:
            raise VGenError(ErrorCode.STORAGE_UNAVAILABLE) from exc
        return TransferTicket(
            artifact_id=artifact_id,
            method=normalized,
            url=f"oss://{self._bucket_name}/{object_key}",
            expires_at=min(credentials.expires_at, time.time() + ttl_seconds),
            max_bytes=max_bytes,
            headers={},
            provider="oss_sts",
            endpoint=self._endpoint,
            credentials={
                "access_key_id": credentials.access_key_id,
                "access_key_secret": credentials.access_key_secret,
                "security_token": credentials.security_token,
            },
        )

    def observe_upload(self, artifact_id: str, *, max_bytes: int) -> tuple[int, str | None]:
        """HEAD the object using a GET-scoped STS token; no artifact bytes are transferred."""

        object_key = self._object_key(artifact_id)
        try:
            credentials = self._issuer.assume_role(
                role_arn=self._transfer_role_arn,
                session_name=f"vgen-head-{artifact_id[-20:]}",
                policy=self._policy(object_key, "GET"),
                duration_seconds=self._duration_seconds,
            )
            import oss2

            bucket = oss2.Bucket(
                oss2.StsAuth(
                    credentials.access_key_id,
                    credentials.access_key_secret,
                    credentials.security_token,
                ),
                self._endpoint,
                self._bucket_name,
            )
            size = int(bucket.head_object(object_key).content_length)
        except Exception as exc:
            raise VGenError(ErrorCode.STORAGE_UNAVAILABLE) from exc
        if size < 0 or size > max_bytes:
            raise VGenError(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
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
