"""Direct Alibaba Cloud OSS transfer using object-scoped STS credentials."""

from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path
from urllib.parse import unquote, urlparse

from .base import (
    ArtifactTransferError,
    ProgressCallback,
    TransferReceipt,
    TransferTicket,
    file_digest,
    validate_receipt,
    validate_ticket_time,
)


class OssStsArtifactAdapter:
    schemes = frozenset({"oss"})

    def __init__(self, *, multipart_threshold: int = 8 * 1024 * 1024) -> None:
        self._multipart_threshold = multipart_threshold

    @staticmethod
    def _bucket_and_key(ticket: TransferTicket) -> tuple[object, str]:
        parsed = urlparse(ticket.url)
        key = unquote(parsed.path.lstrip("/"))
        credentials = ticket.credentials
        if (
            parsed.scheme != "oss"
            or not parsed.netloc
            or not key
            or not ticket.endpoint
            or not ticket.endpoint.startswith("https://")
            or not credentials.get("access_key_id")
            or not credentials.get("access_key_secret")
            or not credentials.get("security_token")
        ):
            raise ArtifactTransferError(
                "authorize", "OSS STS transfer ticket is incomplete.", retryable=False
            )
        try:
            import oss2
        except ImportError as exc:  # pragma: no cover - optional extra
            raise ArtifactTransferError(
                "authorize", "OSS transfer support is not installed.", retryable=False
            ) from exc
        auth = oss2.StsAuth(
            credentials["access_key_id"],
            credentials["access_key_secret"],
            credentials["security_token"],
        )
        return oss2.Bucket(auth, ticket.endpoint, parsed.netloc), key

    def upload(
        self,
        ticket: TransferTicket,
        source: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        if ticket.method != "PUT":
            raise ArtifactTransferError("upload", "OSS upload ticket must use PUT.", retryable=False)
        validate_ticket_time(ticket)
        if not source.is_file():
            raise ArtifactTransferError("upload", "Artifact upload source does not exist.")
        size, digest = file_digest(source)
        receipt = TransferReceipt(size, digest, ticket.media_type)
        validate_receipt(ticket, receipt)
        bucket, key = self._bucket_and_key(ticket)
        try:
            import oss2

            with tempfile.TemporaryDirectory(prefix="vgen-oss-upload-") as checkpoint:
                oss2.resumable_upload(
                    bucket,
                    key,
                    str(source),
                    store=oss2.ResumableStore(root=checkpoint),
                    multipart_threshold=self._multipart_threshold,
                    progress_callback=on_progress,
                    headers={"x-oss-forbid-overwrite": "true"},
                )
        except ArtifactTransferError:
            raise
        except Exception as exc:
            raise ArtifactTransferError("upload", "OSS artifact upload failed.") from exc
        return receipt

    def download(
        self,
        ticket: TransferTicket,
        destination: Path,
        on_progress: ProgressCallback | None = None,
    ) -> TransferReceipt:
        if ticket.method != "GET":
            raise ArtifactTransferError(
                "download", "OSS download ticket must use GET.", retryable=False
            )
        validate_ticket_time(ticket)
        bucket, key = self._bucket_and_key(ticket)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
        try:
            import oss2

            with tempfile.TemporaryDirectory(prefix="vgen-oss-download-") as checkpoint:
                oss2.resumable_download(
                    bucket,
                    key,
                    str(temporary),
                    store=oss2.ResumableStore(root=checkpoint),
                    progress_callback=on_progress,
                )
            size, digest = file_digest(temporary)
            receipt = TransferReceipt(size, digest, ticket.media_type)
            validate_receipt(ticket, receipt)
            os.replace(temporary, destination)
            return receipt
        except ArtifactTransferError:
            temporary.unlink(missing_ok=True)
            raise
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            raise ArtifactTransferError("download", "OSS artifact download failed.") from exc
