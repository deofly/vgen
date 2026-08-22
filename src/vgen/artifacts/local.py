"""Local filesystem artifact adapter, primarily for private deployments/tests."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname

from .base import (
    ArtifactTransferError,
    ProgressCallback,
    TransferReceipt,
    TransferTicket,
    file_digest,
    validate_receipt,
    validate_ticket_time,
)


class LocalArtifactAdapter:
    schemes = frozenset({"file"})

    def __init__(self, allowed_roots: tuple[Path, ...] = ()) -> None:
        self._allowed_roots = tuple(path.expanduser().resolve() for path in allowed_roots)

    def download(
        self,
        ticket: TransferTicket,
        destination: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        if ticket.method != "GET":
            raise ArtifactTransferError(
                "download", "Local download ticket must use GET.", retryable=False
            )
        validate_ticket_time(ticket)
        source = self._path(ticket)
        if not source.is_file():
            raise ArtifactTransferError("download", "Local artifact does not exist.")
        size, digest = file_digest(source)
        validate_receipt(ticket, TransferReceipt(size, digest, ticket.media_type))
        receipt = self._atomic_copy(source, destination, on_progress)
        return receipt

    def upload(
        self,
        ticket: TransferTicket,
        source: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        if ticket.method not in {"PUT", "POST"}:
            raise ArtifactTransferError(
                "upload", "Local upload ticket must use PUT or POST.", retryable=False
            )
        validate_ticket_time(ticket)
        if not source.is_file():
            raise ArtifactTransferError("upload", "Local upload source does not exist.")
        size, digest = file_digest(source)
        validate_receipt(ticket, TransferReceipt(size, digest, ticket.media_type))
        destination = self._path(ticket)
        receipt = self._atomic_copy(source, destination, on_progress)
        return receipt

    def _path(self, ticket: TransferTicket) -> Path:
        parsed = urlparse(ticket.url)
        if parsed.scheme.lower() != "file" or parsed.netloc not in {"", "localhost"}:
            raise ArtifactTransferError(
                "resolve", "Invalid local artifact ticket.", retryable=False
            )
        raw_path = url2pathname(unquote(parsed.path))
        # url2pathname leaves /C:/... on some non-Windows hosts; Path handles the
        # native form when this adapter runs on Windows.
        path = Path(raw_path).expanduser().resolve()
        if self._allowed_roots and not any(
            _is_relative_to(path, root) for root in self._allowed_roots
        ):
            raise ArtifactTransferError(
                "resolve",
                "Local artifact path is outside the configured roots.",
                retryable=False,
            )
        return path

    @staticmethod
    def _atomic_copy(
        source: Path,
        destination: Path,
        on_progress: ProgressCallback | None,
    ) -> TransferReceipt:
        source = source.resolve()
        destination = destination.expanduser().resolve()
        if source == destination:
            size, digest = file_digest(source)
            if on_progress:
                on_progress(size, size)
            return TransferReceipt(size, digest)

        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
        total = source.stat().st_size
        copied = 0
        try:
            with source.open("rb") as reader, temp.open("wb") as writer:
                while True:
                    chunk = reader.read(1024 * 1024)
                    if not chunk:
                        break
                    writer.write(chunk)
                    copied += len(chunk)
                    if on_progress:
                        on_progress(copied, total)
            shutil.copystat(source, temp)
            os.replace(temp, destination)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise ArtifactTransferError("transfer", "Local artifact transfer failed.") from exc

        size, digest = file_digest(destination)
        return TransferReceipt(size, digest)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
