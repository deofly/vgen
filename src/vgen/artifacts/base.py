"""Common artifact contracts used by workers and storage backends."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

ProgressCallback = Callable[[int, int | None], None]


def _immutable_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(value))


@dataclass(frozen=True)
class ArtifactDescriptor:
    """Stable metadata for an artifact, independent of where it is stored."""

    artifact_id: str
    filename: str
    media_type: str = "application/octet-stream"
    size_bytes: int | None = None
    sha256: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.artifact_id:
            raise ValueError("artifact_id is required")
        if not self.filename or Path(self.filename).name != self.filename:
            raise ValueError("filename must be a basename")
        if self.size_bytes is not None and self.size_bytes < 0:
            raise ValueError("size_bytes cannot be negative")
        if self.sha256 is not None:
            digest = self.sha256.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("sha256 must be a lowercase hexadecimal digest")
            object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "metadata", _immutable_mapping(self.metadata))


@dataclass(frozen=True)
class TransferTicket:
    """A short-lived, provider-neutral authorization to transfer one artifact.

    Signed HTTP, local ``file://`` and object-scoped ``oss://`` capabilities use
    the same shape. Secrets in ``url``, ``headers`` or ``credentials`` must never
    be copied into error reports.
    """

    url: str = field(repr=False)
    method: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    endpoint: str | None = None
    credentials: Mapping[str, str] = field(default_factory=dict, repr=False)
    expires_at: float | None = None
    expected_size: int | None = None
    expected_sha256: str | None = None
    media_type: str | None = None

    def __post_init__(self) -> None:
        parsed = urlparse(self.url)
        if not parsed.scheme:
            raise ValueError("transfer ticket URL must include a scheme")
        method = self.method.upper()
        if method not in {"GET", "PUT", "POST"}:
            raise ValueError("transfer ticket method must be GET, PUT, or POST")
        if self.expected_size is not None and self.expected_size < 0:
            raise ValueError("expected_size cannot be negative")
        digest = self.expected_sha256
        if digest is not None:
            digest = digest.lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("expected_sha256 must be a hexadecimal digest")
            object.__setattr__(self, "expected_sha256", digest)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))
        object.__setattr__(self, "credentials", MappingProxyType(dict(self.credentials)))


@dataclass(frozen=True)
class TransferReceipt:
    size_bytes: int
    sha256: str
    media_type: str | None = None


class ArtifactTransferError(Exception):
    """A safe transfer error which deliberately omits signed URLs/headers."""

    def __init__(
        self,
        operation: str,
        message: str,
        *,
        retryable: bool = True,
        status_code: int | None = None,
    ) -> None:
        lowered = message.casefold()
        unsafe_markers = (
            "://",
            "authorization",
            "bearer ",
            "credential",
            "signature=",
            "signed_url",
            "token=",
        )
        safe_message = (
            "Artifact transfer failed."
            if any(marker in lowered for marker in unsafe_markers)
            else message[:256]
        )
        super().__init__(safe_message)
        self.operation = operation
        self.retryable = retryable
        self.status_code = status_code


@runtime_checkable
class ArtifactTransport(Protocol):
    """Worker-side transport selected by ticket URL scheme."""

    @property
    def schemes(self) -> frozenset[str]: ...

    def download(
        self,
        ticket: TransferTicket,
        destination: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt: ...

    def upload(
        self,
        ticket: TransferTicket,
        source: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt: ...


@runtime_checkable
class ArtifactTicketIssuer(Protocol):
    """Gateway-side extension point for local, OSS, S3, or other backends."""

    def issue_download(self, artifact: ArtifactDescriptor) -> TransferTicket: ...

    def issue_upload(self, artifact: ArtifactDescriptor) -> TransferTicket: ...


class ArtifactAdapterRegistry:
    """Routes a provider-neutral ticket to the adapter for its URL scheme."""

    def __init__(self, *adapters: ArtifactTransport) -> None:
        self._adapters: dict[str, ArtifactTransport] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: ArtifactTransport) -> None:
        if not isinstance(adapter, ArtifactTransport):
            raise TypeError("adapter does not implement ArtifactTransport")
        if not adapter.schemes:
            raise ValueError("artifact adapter must support at least one scheme")
        for scheme in adapter.schemes:
            normalized = scheme.lower()
            if normalized in self._adapters:
                raise ValueError(f"artifact adapter already registered for {normalized}")
            self._adapters[normalized] = adapter

    def for_ticket(self, ticket: TransferTicket) -> ArtifactTransport:
        scheme = urlparse(ticket.url).scheme.lower()
        try:
            return self._adapters[scheme]
        except KeyError as exc:
            raise ArtifactTransferError(
                "resolve",
                f"No artifact adapter is installed for scheme '{scheme}'.",
                retryable=False,
            ) from exc

    def download(
        self,
        ticket: TransferTicket,
        destination: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        return self.for_ticket(ticket).download(ticket, destination, on_progress)

    def upload(
        self,
        ticket: TransferTicket,
        source: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        return self.for_ticket(ticket).upload(ticket, source, on_progress)


def file_digest(path: Path, chunk_size: int = 1024 * 1024) -> tuple[int, str]:
    """Return byte count and SHA-256 without loading a large artifact in memory."""

    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def validate_receipt(ticket: TransferTicket, receipt: TransferReceipt) -> None:
    if ticket.expected_size is not None and receipt.size_bytes != ticket.expected_size:
        raise ArtifactTransferError("verify", "Artifact size verification failed.", retryable=True)
    if ticket.expected_sha256 is not None and receipt.sha256 != ticket.expected_sha256:
        raise ArtifactTransferError(
            "verify", "Artifact digest verification failed.", retryable=True
        )


def validate_ticket_time(ticket: TransferTicket) -> None:
    if ticket.expires_at is not None and time.time() >= ticket.expires_at:
        raise ArtifactTransferError(
            "authorize", "Artifact transfer ticket has expired.", retryable=False
        )
