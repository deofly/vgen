from __future__ import annotations

import mimetypes
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

from vgen.artifacts import (
    ArtifactAdapterRegistry,
    HttpArtifactAdapter,
    OssStsArtifactAdapter,
    TransferReceipt,
    TransferTicket,
)
from vgen.crypto import decrypt_stream, encrypt_stream, encrypted_stream_size, task_aad


@dataclass(frozen=True, slots=True)
class LocalTaskInput:
    name: str
    path: Path
    media_type: str

    @classmethod
    def from_path(cls, name: str, value: str | Path) -> LocalTaskInput:
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"input artifact does not exist: {path}")
        return cls(
            name=name,
            path=path,
            media_type=mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        )

    def prepare_descriptor(self) -> dict[str, Any]:
        public_stem = "first-frame" if self.name == "image" else "last-frame"
        suffix = self.path.suffix.lower()
        if not suffix or len(suffix) > 10 or not suffix[1:].isalnum():
            suffix = ""
        return {
            "kind": self.name,
            "encrypted_size": encrypted_stream_size(self.path.stat().st_size),
            "media_metadata": {
                # Local basenames can contain names or project details. Only a
                # role-based transport filename is visible to the Gateway.
                "filename": public_stem + suffix,
                "media_type": self.media_type,
            },
        }


def _ticket(
    value: Mapping[str, Any],
    *,
    expected_size: int | None = None,
    expected_digest: str | None = None,
    media_type: str | None = None,
) -> TransferTicket:
    raw = value.get("ticket", value)
    if not isinstance(raw, Mapping):
        raise ValueError("artifact transfer ticket is invalid")
    digest = expected_digest
    if digest and digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    return TransferTicket(
        url=str(raw["url"]),
        method=str(raw["method"]),
        headers={str(key): str(item) for key, item in dict(raw.get("headers") or {}).items()},
        endpoint=(None if raw.get("endpoint") is None else str(raw["endpoint"])),
        credentials={
            str(key): str(item)
            for key, item in dict(raw.get("credentials") or {}).items()
        },
        expires_at=(None if raw.get("expires_at") is None else float(raw["expires_at"])),
        expected_size=expected_size,
        expected_sha256=digest,
        media_type=media_type,
    )


def encrypt_and_upload_inputs(
    inputs: list[LocalTaskInput],
    prepared_tickets: list[Mapping[str, Any]],
    *,
    task_data_key: bytes,
    workspace_id: str,
    task_id: str,
    content_attempt_id: str,
    key_version: int,
    session: requests.Session | None = None,
) -> list[dict[str, Any]]:
    """Encrypt local inputs and upload them through opaque provider-neutral tickets."""

    by_kind = {str(item.get("kind")): item for item in prepared_tickets}
    if len(by_kind) != len(prepared_tickets):
        raise ValueError("Gateway returned duplicate input artifact tickets")
    adapters = ArtifactAdapterRegistry(HttpArtifactAdapter(session), OssStsArtifactAdapter())
    bindings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="vgen-client-input-") as temporary:
        root = Path(temporary)
        for index, item in enumerate(inputs):
            try:
                raw_ticket = by_kind[item.name]
            except KeyError as exc:
                raise ValueError(f"Gateway did not return a ticket for input {item.name}") from exc
            artifact_id = str(raw_ticket.get("artifact_id") or "")
            if not artifact_id:
                raise ValueError("Gateway input ticket has no artifact_id")
            encrypted = root / f"{index:02d}.ciphertext"
            with item.path.open("rb") as source, encrypted.open("wb") as destination:
                encrypt_stream(
                    source,
                    destination,
                    task_data_key,
                    aad=task_aad(
                        workspace_id=workspace_id,
                        task_id=task_id,
                        attempt_id=content_attempt_id,
                        artifact_id=artifact_id,
                        key_version=key_version,
                    ),
                )
            receipt = adapters.upload(
                _ticket(
                    raw_ticket,
                    expected_size=encrypted.stat().st_size,
                    media_type="application/octet-stream",
                ),
                encrypted,
            )
            bindings.append(
                {
                    "input": item.name,
                    "artifact_id": artifact_id,
                    "encrypted_size": receipt.size_bytes,
                    "content_digest": f"sha256:{receipt.sha256}",
                }
            )
    return bindings


def download_and_decrypt_output(
    artifact: Mapping[str, Any],
    destination: Path,
    *,
    task_data_key: bytes,
    workspace_id: str,
    task_id: str,
    artifact_attempt_id: str,
    key_version: int,
    session: requests.Session | None = None,
) -> TransferReceipt:
    raw_ticket = artifact.get("download_ticket")
    if not isinstance(raw_ticket, Mapping):
        raise ValueError("output artifact has no download ticket")
    artifact_id = str(artifact.get("id") or "")
    if not artifact_id:
        raise ValueError("output artifact has no artifact_id")
    metadata = artifact.get("media_metadata")
    media_type = (
        str(metadata.get("media_type"))
        if isinstance(metadata, Mapping) and metadata.get("media_type")
        else "application/octet-stream"
    )
    adapters = ArtifactAdapterRegistry(HttpArtifactAdapter(session), OssStsArtifactAdapter())
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vgen-client-output-") as temporary:
        encrypted = Path(temporary) / "output.ciphertext"
        receipt = adapters.download(
            _ticket(
                raw_ticket,
                expected_size=(
                    None
                    if artifact.get("encrypted_size") is None
                    else int(artifact["encrypted_size"])
                ),
                expected_digest=(
                    None
                    if artifact.get("content_digest") is None
                    else str(artifact["content_digest"])
                ),
                media_type="application/octet-stream",
            ),
            encrypted,
        )
        temporary_output = destination.with_name(f".{destination.name}.part")
        try:
            with encrypted.open("rb") as source, temporary_output.open("wb") as output:
                decrypt_stream(
                    source,
                    output,
                    task_data_key,
                    aad=task_aad(
                        workspace_id=workspace_id,
                        task_id=task_id,
                        attempt_id=artifact_attempt_id,
                        artifact_id=artifact_id,
                        key_version=key_version,
                    ),
                )
            temporary_output.replace(destination)
        finally:
            temporary_output.unlink(missing_ok=True)
    return TransferReceipt(destination.stat().st_size, receipt.sha256, media_type)
