"""Generic signed-HTTP artifact transport.

OSS, S3 and most object stores can issue signed GET/PUT URLs, so workers do not
need provider SDKs or cloud credentials.  A backend-specific transport can still
be registered later when multipart or another protocol is required.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import BinaryIO

import requests

from .base import (
    ArtifactTransferError,
    ProgressCallback,
    TransferReceipt,
    TransferTicket,
    file_digest,
    validate_receipt,
    validate_ticket_time,
)


class _ProgressReader:
    def __init__(
        self,
        stream: BinaryIO,
        total: int,
        callback: ProgressCallback | None,
    ) -> None:
        self._stream = stream
        self._total = total
        self._callback = callback
        self._read = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._stream.read(size)
        self._read += len(chunk)
        if self._callback:
            self._callback(self._read, self._total)
        return chunk

    def __len__(self) -> int:
        return self._total


class HttpArtifactAdapter:
    schemes = frozenset({"http", "https"})

    def __init__(
        self,
        session: requests.Session | None = None,
        *,
        timeout: tuple[float, float] = (15.0, 300.0),
        chunk_size: int = 1024 * 1024,
    ) -> None:
        self._session = session or requests.Session()
        self._timeout = timeout
        self._chunk_size = chunk_size

    def download(
        self,
        ticket: TransferTicket,
        destination: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        if ticket.method != "GET":
            raise ArtifactTransferError(
                "download", "HTTP download ticket must use GET.", retryable=False
            )
        validate_ticket_time(ticket)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
        digest = hashlib.sha256()
        consumed = 0
        try:
            with self._session.request(
                "GET",
                ticket.url,
                headers=dict(ticket.headers),
                stream=True,
                allow_redirects=False,
                timeout=self._timeout,
            ) as response:
                if 300 <= response.status_code < 400:
                    raise ArtifactTransferError(
                        "download",
                        "Artifact download redirects are not allowed.",
                        retryable=False,
                        status_code=response.status_code,
                    )
                if response.status_code >= 400:
                    raise ArtifactTransferError(
                        "download",
                        "Artifact download endpoint rejected the request.",
                        retryable=response.status_code >= 500 or response.status_code == 429,
                        status_code=response.status_code,
                    )
                header_total = response.headers.get("Content-Length")
                total = int(header_total) if header_total and header_total.isdigit() else None
                with temp.open("wb") as stream:
                    for chunk in response.iter_content(chunk_size=self._chunk_size):
                        if not chunk:
                            continue
                        stream.write(chunk)
                        digest.update(chunk)
                        consumed += len(chunk)
                        if on_progress:
                            on_progress(consumed, total)
            receipt = TransferReceipt(consumed, digest.hexdigest(), ticket.media_type)
            validate_receipt(ticket, receipt)
            os.replace(temp, destination)
        except ArtifactTransferError:
            temp.unlink(missing_ok=True)
            raise
        except (requests.RequestException, OSError, ValueError) as exc:
            temp.unlink(missing_ok=True)
            raise ArtifactTransferError("download", "Artifact download failed.") from exc

        return receipt

    def upload(
        self,
        ticket: TransferTicket,
        source: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        if ticket.method not in {"PUT", "POST"}:
            raise ArtifactTransferError(
                "upload", "HTTP upload ticket must use PUT or POST.", retryable=False
            )
        validate_ticket_time(ticket)
        if not source.is_file():
            raise ArtifactTransferError("upload", "Artifact upload source does not exist.")
        size, digest = file_digest(source)
        receipt = TransferReceipt(size, digest, ticket.media_type)
        validate_receipt(ticket, receipt)
        headers = dict(ticket.headers)
        if ticket.media_type and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = ticket.media_type
        headers.setdefault("Content-Length", str(size))
        try:
            with (
                source.open("rb") as stream,
                self._session.request(
                    ticket.method,
                    ticket.url,
                    headers=headers,
                    data=_ProgressReader(stream, size, on_progress),
                    allow_redirects=False,
                    timeout=self._timeout,
                ) as response,
            ):
                if 300 <= response.status_code < 400:
                    raise ArtifactTransferError(
                        "upload",
                        "Artifact upload redirects are not allowed.",
                        retryable=False,
                        status_code=response.status_code,
                    )
                if response.status_code >= 400:
                    raise ArtifactTransferError(
                        "upload",
                        "Artifact upload endpoint rejected the request.",
                        retryable=response.status_code >= 500 or response.status_code == 429,
                        status_code=response.status_code,
                    )
        except ArtifactTransferError:
            raise
        except (requests.RequestException, OSError) as exc:
            raise ArtifactTransferError("upload", "Artifact upload failed.") from exc

        return receipt
