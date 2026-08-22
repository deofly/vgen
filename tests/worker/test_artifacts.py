from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

import pytest

from vgen.artifacts import (
    ArtifactAdapterRegistry,
    ArtifactTransferError,
    HttpArtifactAdapter,
    LocalArtifactAdapter,
    TransferTicket,
    with_safe_media_extension,
)


class FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = body
        self.headers = headers or {"Content-Length": str(len(body))}

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def iter_content(self, chunk_size: int) -> list[bytes]:
        return [
            self.body[index : index + chunk_size] for index in range(0, len(self.body), chunk_size)
        ]


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []
        self.uploaded = b""

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        reader = kwargs.get("data")
        if reader is not None:
            chunks: list[bytes] = []
            while True:
                chunk = reader.read(3)
                if not chunk:
                    break
                chunks.append(chunk)
            self.uploaded = b"".join(chunks)
        return self.response


@pytest.mark.parametrize(
    ("filename", "media_type", "expected"),
    [
        ("output-00.bin", "video/mp4", "output-00.mp4"),
        ("output-00", "image/png", "output-00.png"),
        ("output-00.BIN", "Video/MP4", "output-00.mp4"),
        ("already.webm", "video/mp4", "already.webm"),
        ("output-00.bin", "application/x-private", "output-00.bin"),
        ("output-00.bin", "video/mp4;codecs=h264", "output-00.bin"),
    ],
)
def test_safe_media_extensions_are_allowlisted_and_preserve_specific_names(
    filename: str, media_type: str, expected: str
) -> None:
    assert with_safe_media_extension(filename, media_type) == expected


def test_safe_media_extension_rejects_non_basename() -> None:
    with pytest.raises(ValueError, match="basename"):
        with_safe_media_extension("private/output.bin", "video/mp4")


def test_local_adapter_round_trip_and_integrity(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    staged = tmp_path / "staged.bin"
    uploaded = tmp_path / "uploaded.bin"
    source.write_bytes(b"artifact-data")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    adapter = ArtifactAdapterRegistry(LocalArtifactAdapter((tmp_path,)))

    download = TransferTicket(source.as_uri(), "GET", expected_size=13, expected_sha256=digest)
    receipt = adapter.download(download, staged)
    assert receipt.sha256 == digest
    assert staged.read_bytes() == b"artifact-data"

    upload = TransferTicket(uploaded.as_uri(), "PUT", expected_size=13, expected_sha256=digest)
    adapter.upload(upload, staged)
    assert uploaded.read_bytes() == b"artifact-data"


def test_local_adapter_rejects_expired_and_out_of_root_tickets(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    adapter = LocalArtifactAdapter((tmp_path / "allowed",))
    with pytest.raises(ArtifactTransferError, match="expired"):
        adapter.download(
            TransferTicket(source.as_uri(), "GET", expires_at=time.time() - 1),
            tmp_path / "destination.bin",
        )
    with pytest.raises(ArtifactTransferError, match="outside"):
        adapter.download(TransferTicket(source.as_uri(), "GET"), tmp_path / "destination.bin")


def test_http_adapter_streams_without_exposing_signed_url(tmp_path: Path) -> None:
    secret_url = "https://objects.invalid/input?signature=super-secret"
    session = FakeSession(FakeResponse(body=b"downloaded"))
    adapter = HttpArtifactAdapter(session=session, chunk_size=3)
    destination = tmp_path / "download.bin"
    progress: list[tuple[int, int | None]] = []
    adapter.download(
        TransferTicket(
            secret_url,
            "GET",
            headers={"Authorization": "secret"},
            expected_sha256=hashlib.sha256(b"downloaded").hexdigest(),
        ),
        destination,
        lambda consumed, total: progress.append((consumed, total)),
    )
    assert destination.read_bytes() == b"downloaded"
    assert progress[-1] == (10, 10)
    assert "super-secret" not in repr(
        TransferTicket(secret_url, "GET", headers={"Authorization": "secret"})
    )

    source = tmp_path / "upload.bin"
    source.write_bytes(b"uploaded")
    upload_session = FakeSession(FakeResponse(status_code=200))
    upload_adapter = HttpArtifactAdapter(session=upload_session)
    upload_adapter.upload(TransferTicket(secret_url, "PUT"), source)
    assert upload_session.uploaded == b"uploaded"

    failing = HttpArtifactAdapter(session=FakeSession(FakeResponse(status_code=403)))
    with pytest.raises(ArtifactTransferError) as raised:
        failing.download(TransferTicket(secret_url, "GET"), tmp_path / "failed.bin")
    assert "super-secret" not in str(raised.value)


def test_http_digest_failure_does_not_publish_partial_file(tmp_path: Path) -> None:
    session = FakeSession(FakeResponse(body=b"corrupt"))
    destination = tmp_path / "result.bin"
    with pytest.raises(ArtifactTransferError, match="digest"):
        HttpArtifactAdapter(session=session).download(
            TransferTicket("https://objects.invalid/file", "GET", expected_sha256="0" * 64),
            destination,
        )
    assert not destination.exists()


@pytest.mark.parametrize(("method", "operation"), [("GET", "download"), ("PUT", "upload")])
def test_http_adapter_rejects_redirects(
    tmp_path: Path, method: str, operation: str
) -> None:
    session = FakeSession(
        FakeResponse(status_code=302, headers={"Location": "https://other.invalid/object"})
    )
    adapter = HttpArtifactAdapter(session=session)
    ticket = TransferTicket("https://objects.invalid/capability", method)

    if operation == "download":
        with pytest.raises(ArtifactTransferError, match="redirect"):
            adapter.download(ticket, tmp_path / "result.bin")
        assert not (tmp_path / "result.bin").exists()
    else:
        source = tmp_path / "source.bin"
        source.write_bytes(b"update")
        with pytest.raises(ArtifactTransferError, match="redirect"):
            adapter.upload(ticket, source)

    assert session.calls[0]["allow_redirects"] is False


def test_transfer_error_redacts_capability_urls_and_tokens() -> None:
    error = ArtifactTransferError(
        "upload",
        "PUT https://storage.example/object?token=secret failed",
    )
    assert str(error) == "Artifact transfer failed."
    assert "storage.example" not in repr(error)
