"""Durable encrypted-output spool for upload-only recovery.

Only ciphertext, public artifact metadata, lease fencing identifiers, and
canonical aggregate usage measurements are persisted. Transfer tickets, task
keys, payloads, executor-native metrics, run handles, and plaintext never enter
the journal.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vgen.executors import UsageMetrics
from vgen.protocol.media import canonical_media_probes

from .models import (
    LeaseReference,
    WorkerResult,
    WorkerResultArtifact,
)

_VERSION = 1
_MANIFEST = "upload-manifest.json"
logger = logging.getLogger("vgen.worker.spool")


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
            if path.is_symlink():
                raise UploadJournalError("Spool artifact must be a regular file.")
            resolved = path.resolve()
            if resolved.parent != directory or not resolved.is_file():
                raise UploadJournalError("Spool artifact is outside its attempt directory.")
            if os.name != "nt":
                resolved.chmod(0o600)
            # Publish the manifest only after every ciphertext has reached the
            # filesystem. This prevents a durable manifest from pointing at a
            # zero-length or missing file after power loss.
            try:
                # Windows implements fsync with _commit(), which rejects a
                # read-only descriptor even though POSIX platforms commonly
                # accept it. Open the already-written ciphertext for update so
                # the durability barrier has identical semantics everywhere.
                with resolved.open("rb+") as stream:
                    os.fsync(stream.fileno())
            except OSError as exc:
                raise UploadJournalError("Spool ciphertext could not be synchronized.") from exc
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
            if directory.is_symlink() or not directory.is_dir():
                raise UploadJournalError("Invalid upload spool directory.")
            manifest = directory / _MANIFEST
            if manifest.is_symlink() or not manifest.is_file():
                raise UploadJournalError("Invalid upload spool manifest.")
            raw = json.loads(manifest.read_text(encoding="utf-8"))
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
                candidate = directory / name
                if candidate.is_symlink():
                    raise UploadJournalError("Upload spool ciphertext is not a regular file.")
                path = candidate.resolve()
                if path.parent != directory or not path.is_file():
                    raise UploadJournalError("Upload spool ciphertext is missing.")
                if not _matches_artifact_size(path, artifact):
                    raise UploadJournalError("Upload spool ciphertext failed integrity checks.")
                files[artifact.artifact_id] = path
            if set(file_names) != set(files):
                raise UploadJournalError("Invalid upload spool file table.")
            expected_names = {_MANIFEST, *(path.name for path in files.values())}
            try:
                entries = list(os.scandir(directory))
            except OSError as exc:
                raise UploadJournalError("Upload spool directory cannot be inspected.") from exc
            if {entry.name for entry in entries} != expected_names or any(
                entry.is_symlink() or not entry.is_file(follow_symlinks=False) for entry in entries
            ):
                raise UploadJournalError("Upload spool contains unexpected entries.")
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
            directories = sorted(
                (path for path in self.root.iterdir() if not path.is_symlink() and path.is_dir()),
                key=lambda path: path.lstat().st_mtime,
            )
        except OSError as exc:
            raise UploadJournalError("Upload spool cannot be listed.") from exc
        for directory in directories:
            manifest = directory / _MANIFEST
            try:
                if manifest.is_symlink() or not manifest.is_file():
                    raise UploadJournalError("Invalid upload spool manifest.")
                raw = json.loads(manifest.read_text(encoding="utf-8"))
                attempt_id = str(raw["reference"]["attempt_id"])
                values.append(self.load(attempt_id))
            except (
                UploadJournalError,
                KeyError,
                TypeError,
                ValueError,
                OSError,
                json.JSONDecodeError,
            ):
                try:
                    self._quarantine_directory(manifest.parent)
                except UploadJournalError:
                    # One locked or permission-denied corrupt entry must not
                    # restart the supervisor or starve later recoverable work.
                    logger.exception("Could not quarantine one invalid upload spool attempt.")
        return tuple(values)

    def oldest_pending(self) -> PendingUpload | None:
        """Return the oldest valid attempt while isolating corrupt predecessors."""

        values = self.list_pending()
        return values[0] if values else None

    def quarantine(self, attempt_id: str) -> None:
        """Atomically remove a permanently corrupt attempt from the retry queue."""

        self._quarantine_directory(self._directory(attempt_id))

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
        return self.root / name

    def _quarantine_directory(self, directory: Path) -> None:
        try:
            if directory.parent != self.root or directory == self.root or not directory.exists():
                raise UploadJournalError("Invalid upload spool quarantine target.")
            quarantine_root = self.root.with_name(f"{self.root.name}-quarantine")
            quarantine_root.mkdir(parents=True, exist_ok=True, mode=0o700)
            if quarantine_root.is_symlink() or not quarantine_root.is_dir():
                raise UploadJournalError("Upload spool quarantine is unsafe.")
            if os.name != "nt":
                quarantine_root.chmod(0o700)
            target = quarantine_root / f"{directory.name}-{time.time_ns()}-{os.getpid()}"
            # os.replace moves the directory entry itself and does not traverse
            # any attacker-created symlink or Windows junction below it.
            os.replace(directory, target)
            logger.error("Quarantined one invalid upload spool attempt.")
        except UploadJournalError:
            raise
        except OSError as exc:
            raise UploadJournalError("Invalid upload spool could not be quarantined.") from exc

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
            _fsync_directory(directory)
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
        },
        "executor_type": result.executor_type,
        "executor_version": result.executor_version,
        "metadata": dict(result.metadata),
    }


def _matches_artifact_size(path: Path, artifact: WorkerResultArtifact) -> bool:
    """Cheap startup check; upload receipts verify SHA-256 while streaming."""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise UploadJournalError("Upload spool ciphertext is unreadable.") from exc
    return size == artifact.size_bytes


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
                metadata=canonical_media_probes(
                    artifact.get("metadata", {})
                    if isinstance(artifact.get("metadata", {}), Mapping)
                    else {}
                ),
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
            # Legacy manifests may contain arbitrary executor-native values.
            # Upload recovery needs only canonical aggregate measurements.
            native={},
        ),
        executor_type=str(value["executor_type"]),
        executor_version=str(value["executor_version"]),
        executor_run_id=None,
        metadata=canonical_media_probes(
            value.get("metadata", {}) if isinstance(value.get("metadata", {}), Mapping) else {}
        ),
    )
