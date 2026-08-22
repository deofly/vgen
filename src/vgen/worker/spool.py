"""Durable encrypted-output spool for upload-only recovery.

Only ciphertext, public artifact metadata, lease fencing identifiers, and raw
usage measurements are persisted. Transfer tickets, task keys, payloads, and
executor plaintext never enter the journal.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vgen.executors import UsageMetrics

from .models import (
    LeaseReference,
    WorkerResult,
    WorkerResultArtifact,
)

_VERSION = 1
_MANIFEST = "upload-manifest.json"


class UploadJournalError(RuntimeError):
    """A safe local spool integrity/configuration error."""


@dataclass(frozen=True)
class PendingUpload:
    reference: LeaseReference
    result: WorkerResult
    files: Mapping[str, Path]
    pending_artifact_ids: frozenset[str]


class UploadJournal:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.root.chmod(0o700)

    def output_path(self, reference: LeaseReference, artifact_id: str) -> Path:
        directory = self._directory(reference.attempt_id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            directory.chmod(0o700)
        name = hashlib.sha256(artifact_id.encode("utf-8")).hexdigest() + ".ciphertext"
        return directory / name

    def save(
        self,
        reference: LeaseReference,
        result: WorkerResult,
        files: Mapping[str, Path],
        *,
        pending_artifact_ids: set[str] | frozenset[str] | None = None,
    ) -> PendingUpload:
        directory = self._directory(reference.attempt_id)
        expected_ids = {artifact.artifact_id for artifact in result.artifacts}
        if set(files) != expected_ids:
            raise UploadJournalError("Spool files do not match result artifacts.")
        normalized: dict[str, Path] = {}
        for artifact_id, path in files.items():
            resolved = path.resolve()
            if resolved.parent != directory or not resolved.is_file():
                raise UploadJournalError("Spool artifact is outside its attempt directory.")
            if os.name != "nt":
                resolved.chmod(0o600)
            normalized[artifact_id] = resolved
        pending = expected_ids if pending_artifact_ids is None else set(pending_artifact_ids)
        if not pending.issubset(expected_ids):
            raise UploadJournalError("Pending spool artifacts are invalid.")
        value = {
            "version": _VERSION,
            "reference": {
                "lease_id": reference.lease_id,
                "task_id": reference.task_id,
                "attempt_id": reference.attempt_id,
                "worker_id": reference.worker_id,
                "fencing_token": reference.fencing_token,
            },
            "result": _result_to_dict(result),
            "files": {artifact_id: path.name for artifact_id, path in sorted(normalized.items())},
            "pending_artifact_ids": sorted(pending),
        }
        self._write_manifest(directory, value)
        return PendingUpload(reference, result, normalized, frozenset(pending))

    def mark_uploaded(self, attempt_id: str, artifact_id: str) -> PendingUpload:
        pending = self.load(attempt_id)
        remaining = set(pending.pending_artifact_ids)
        remaining.discard(artifact_id)
        return self.save(
            pending.reference,
            pending.result,
            pending.files,
            pending_artifact_ids=remaining,
        )

    def load(self, attempt_id: str) -> PendingUpload:
        directory = self._directory(attempt_id)
        try:
            raw = json.loads((directory / _MANIFEST).read_text(encoding="utf-8"))
            if raw.get("version") != _VERSION:
                raise UploadJournalError("Unsupported upload spool manifest.")
            reference_value = raw["reference"]
            reference = LeaseReference(
                lease_id=str(reference_value["lease_id"]),
                task_id=str(reference_value["task_id"]),
                attempt_id=str(reference_value["attempt_id"]),
                worker_id=str(reference_value["worker_id"]),
                fencing_token=int(reference_value["fencing_token"]),
            )
            if reference.attempt_id != attempt_id:
                raise UploadJournalError("Upload spool attempt ID mismatch.")
            result = _result_from_dict(raw["result"])
            file_names = raw["files"]
            if not isinstance(file_names, dict):
                raise UploadJournalError("Invalid upload spool file table.")
            files: dict[str, Path] = {}
            for artifact in result.artifacts:
                name = str(file_names[artifact.artifact_id])
                if Path(name).name != name:
                    raise UploadJournalError("Invalid upload spool filename.")
                path = (directory / name).resolve()
                if path.parent != directory or not path.is_file():
                    raise UploadJournalError("Upload spool ciphertext is missing.")
                files[artifact.artifact_id] = path
            pending_ids = frozenset(str(item) for item in raw["pending_artifact_ids"])
            if not pending_ids.issubset(files):
                raise UploadJournalError("Invalid pending upload artifact list.")
            return PendingUpload(reference, result, files, pending_ids)
        except UploadJournalError:
            raise
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError) as exc:
            raise UploadJournalError("Invalid upload spool manifest.") from exc

    def list_pending(self) -> tuple[PendingUpload, ...]:
        values: list[PendingUpload] = []
        try:
            manifests = sorted(
                self.root.glob(f"*/{_MANIFEST}"), key=lambda path: path.stat().st_mtime
            )
        except OSError as exc:
            raise UploadJournalError("Upload spool cannot be listed.") from exc
        for manifest in manifests:
            try:
                raw = json.loads(manifest.read_text(encoding="utf-8"))
                attempt_id = str(raw["reference"]["attempt_id"])
                values.append(self.load(attempt_id))
            except (KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
                raise UploadJournalError("Invalid upload spool manifest.") from exc
        return tuple(values)

    def remove(self, attempt_id: str) -> None:
        pending = self.load(attempt_id)
        directory = self._directory(attempt_id)
        for path in pending.files.values():
            path.unlink(missing_ok=True)
        (directory / _MANIFEST).unlink(missing_ok=True)
        try:
            directory.rmdir()
        except OSError as exc:
            raise UploadJournalError("Upload spool directory could not be removed.") from exc

    def _directory(self, attempt_id: str) -> Path:
        name = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()
        return (self.root / name).resolve()

    @staticmethod
    def _write_manifest(directory: Path, value: Mapping[str, Any]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix="manifest-", dir=directory)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                Path(temporary).chmod(0o600)
            os.replace(temporary, directory / _MANIFEST)
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise


def _result_to_dict(result: WorkerResult) -> dict[str, Any]:
    usage = result.usage
    return {
        "artifacts": [
            {
                "artifact_id": artifact.artifact_id,
                "name": artifact.name,
                "filename": artifact.filename,
                "media_type": artifact.media_type,
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "kind": artifact.kind,
                "store_type": artifact.store_type,
                "object_ref": artifact.object_ref,
                "metadata": dict(artifact.metadata),
            }
            for artifact in result.artifacts
        ],
        "usage": {
            "executor_wall_ms": usage.executor_wall_ms,
            "gpu_active_ms": usage.gpu_active_ms,
            "gpu_count": usage.gpu_count,
            "input_bytes": usage.input_bytes,
            "output_bytes": usage.output_bytes,
            "frames": usage.frames,
            "duration_ms": usage.duration_ms,
            "denoise_steps": usage.denoise_steps,
            "native": dict(usage.native),
        },
        "executor_type": result.executor_type,
        "executor_version": result.executor_version,
        "executor_run_id": result.executor_run_id,
        "metadata": dict(result.metadata),
    }


def _result_from_dict(value: Mapping[str, Any]) -> WorkerResult:
    usage = value["usage"]
    return WorkerResult(
        artifacts=tuple(
            WorkerResultArtifact(
                artifact_id=str(artifact["artifact_id"]),
                name=str(artifact["name"]),
                filename=str(artifact["filename"]),
                media_type=str(artifact["media_type"]),
                size_bytes=int(artifact["size_bytes"]),
                sha256=str(artifact["sha256"]),
                kind=str(artifact["kind"]),
                store_type=str(artifact["store_type"]),
                object_ref=(
                    None if artifact.get("object_ref") is None else str(artifact["object_ref"])
                ),
                metadata=dict(artifact.get("metadata", {})),
            )
            for artifact in value["artifacts"]
        ),
        usage=UsageMetrics(
            executor_wall_ms=int(usage.get("executor_wall_ms", 0)),
            gpu_active_ms=(
                None if usage.get("gpu_active_ms") is None else int(usage["gpu_active_ms"])
            ),
            gpu_count=int(usage.get("gpu_count", 1)),
            input_bytes=int(usage.get("input_bytes", 0)),
            output_bytes=int(usage.get("output_bytes", 0)),
            frames=None if usage.get("frames") is None else int(usage["frames"]),
            duration_ms=(None if usage.get("duration_ms") is None else int(usage["duration_ms"])),
            denoise_steps=(
                None if usage.get("denoise_steps") is None else int(usage["denoise_steps"])
            ),
            native=dict(usage.get("native", {})),
        ),
        executor_type=str(value["executor_type"]),
        executor_version=str(value["executor_version"]),
        executor_run_id=(
            None if value.get("executor_run_id") is None else str(value["executor_run_id"])
        ),
        metadata=dict(value.get("metadata", {})),
    )
