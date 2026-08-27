"""Immutable workflow releases activated by owner-authorized maintenance.

The uploaded artifact is the ordinary VGen workflow release ZIP.  The Gateway
does not interpret it.  A Worker verifies the ZIP, publisher pin, package
digest and exact workflow reference again before atomically adding it to the
local active index.  Workflow files are inert data; executable custom-node
installation remains a separate machine-administrator boundary.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vgen.crypto import canonical_json, verify_maintenance_intent
from vgen.market.capabilities import (
    WorkflowCapabilityError,
    comfyui_capability_facts,
    workflow_model_digests,
)
from vgen.market.registry import InstallResult, RegistryError, WorkflowRegistry, validate_package

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF = re.compile(
    r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*@"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_INDEX_NAME = "active.json"
_INDEX_LOCK_NAME = ".active.lock"
_INDEX_VERSION = 2
_LEGACY_INDEX_VERSION = 1
_CAPABILITY_SPEC_FIELDS_V1 = frozenset(
    {
        "kind",
        "workflow_ref",
        "workflow_digest",
        "artifact_sha256",
        "artifact_size",
        "node_classes_digest",
        "publisher_key",
        "allow_unsigned_workflow",
        "apply",
    }
)
_CAPABILITY_SPEC_FIELDS_V2 = _CAPABILITY_SPEC_FIELDS_V1 | frozenset(
    {"model_digests", "node_classes"}
)

logger = logging.getLogger("vgen.worker.capabilities")


class CapabilityInstallError(RuntimeError):
    """Bounded error safe to map onto the Worker maintenance contract."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class CapabilityActivation:
    workflow_ref: str
    workflow_digest: str
    status: str
    path: Path


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attributes & reparse_flag)


def _has_reparse_ancestor(path: Path) -> bool:
    absolute = path.absolute()
    for candidate in (absolute, *absolute.parents):
        if _is_reparse_point(candidate):
            return True
    return False


def _posix_writable_by_others(metadata: os.stat_result) -> bool:
    return os.name != "nt" and bool(stat.S_IMODE(metadata.st_mode) & 0o022)


def _safe_root(path: Path) -> Path:
    expanded = path.expanduser().absolute()
    if _has_reparse_ancestor(expanded):
        raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
    try:
        expanded.mkdir(parents=True, exist_ok=True)
        if _has_reparse_ancestor(expanded):
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
        resolved = expanded.resolve(strict=True)
        metadata = resolved.lstat()
    except CapabilityInstallError:
        raise
    except OSError as exc:
        raise CapabilityInstallError("CAPABILITY_ROOT_UNAVAILABLE") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
    if _posix_writable_by_others(metadata):
        raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class WorkerCapabilityStore:
    """Content-addressed workflow releases with an atomic active generation."""

    def __init__(
        self,
        root: Path,
        *,
        owner_root_signing_public_key: str | None = None,
        worker_id: str | None = None,
    ) -> None:
        self.root = _safe_root(root)
        self.releases = self.root / "releases"
        if _is_reparse_point(self.releases):
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
        self.releases.mkdir(exist_ok=True)
        releases_metadata = self.releases.lstat()
        if (
            _is_reparse_point(self.releases)
            or not stat.S_ISDIR(releases_metadata.st_mode)
            or _posix_writable_by_others(releases_metadata)
        ):
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
        self.index_path = self.root / _INDEX_NAME
        self.index_lock_path = self.root / _INDEX_LOCK_NAME
        self.active_errors = 0
        self._owner_root_signing_public_key: str | None = None
        self._worker_id: str | None = None
        if owner_root_signing_public_key is not None or worker_id is not None:
            self.configure_trust(owner_root_signing_public_key, worker_id)

    def configure_trust(
        self,
        owner_root_signing_public_key: str | None,
        worker_id: str | None,
    ) -> None:
        """Pin the owner root and Worker identity used by activation receipts."""

        if (
            not isinstance(owner_root_signing_public_key, str)
            or not owner_root_signing_public_key
            or not isinstance(worker_id, str)
            or not worker_id
        ):
            raise CapabilityInstallError("CAPABILITY_TRUST_UNAVAILABLE")
        self._owner_root_signing_public_key = owner_root_signing_public_key
        self._worker_id = worker_id

    @contextmanager
    def _index_lock(self) -> Iterator[None]:
        """Serialize the complete active-index read/modify/write transaction."""

        if _is_reparse_point(self.root) or _is_reparse_point(self.index_lock_path):
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(self.index_lock_path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or _posix_writable_by_others(metadata)
                or _is_reparse_point(self.index_lock_path)
            ):
                raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                if metadata.st_size == 0:
                    os.write(descriptor, b"\0")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
            else:
                import fcntl  # noqa: PLC0415

                fcntl.flock(descriptor, fcntl.LOCK_EX)
        except CapabilityInstallError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise CapabilityInstallError("CAPABILITY_INDEX_UNAVAILABLE") from exc
        if descriptor is None:
            raise CapabilityInstallError("CAPABILITY_INDEX_UNAVAILABLE")
        try:
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt  # noqa: PLC0415

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl  # noqa: PLC0415

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def activate(
        self,
        archive: Path,
        *,
        workflow_ref: str,
        workflow_digest: str,
        publisher_key: str | None,
        allow_unsigned: bool,
        node_classes_digest: str,
        model_digests: tuple[str, ...] | None = None,
        node_classes: tuple[str, ...] | None = None,
        authorization: Mapping[str, Any] | None = None,
        validator: Callable[[InstallResult], None] | None = None,
    ) -> CapabilityActivation:
        if (
            not _REF.fullmatch(workflow_ref)
            or not _DIGEST.fullmatch(workflow_digest)
            or not re.fullmatch(r"[0-9a-f]{64}", node_classes_digest)
        ):
            raise CapabilityInstallError("CAPABILITY_SPEC_INVALID")
        if allow_unsigned != (publisher_key is None):
            raise CapabilityInstallError("CAPABILITY_SPEC_INVALID")
        if _is_reparse_point(archive) or not archive.is_file():
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID")

        try:
            archive_size = archive.stat().st_size
            artifact_sha256 = _sha256_file(archive)
        except OSError as exc:
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID") from exc
        spec = {
            "kind": "capability_install",
            "workflow_ref": workflow_ref,
            "workflow_digest": workflow_digest,
            "artifact_sha256": artifact_sha256,
            "artifact_size": archive_size,
            "node_classes_digest": node_classes_digest,
            "publisher_key": publisher_key,
            "allow_unsigned_workflow": allow_unsigned,
            "apply": "on_idle",
        }
        if (model_digests is None) != (node_classes is None):
            raise CapabilityInstallError("CAPABILITY_SPEC_INVALID")
        if model_digests is not None and node_classes is not None:
            spec["model_digests"] = list(model_digests)
            spec["node_classes"] = list(node_classes)
        receipt = dict(authorization) if isinstance(authorization, Mapping) else None
        if receipt is None or not self._receipt_valid(spec, receipt, historical=False):
            raise CapabilityInstallError("CAPABILITY_AUTHORIZATION_INVALID")

        expected_digest = workflow_digest.removeprefix("sha256:")
        try:
            with tempfile.TemporaryDirectory(prefix="vgen-capability-verify-") as temporary:
                # A Worker capability is not a user-facing registry install.
                # Validate the uploaded archive directly in one bounded staging
                # directory instead of copying it through a temporary registry
                # and adding workflow.lock.  Besides avoiding unnecessary I/O,
                # this keeps activation identical on Windows and POSIX.
                unpacked = WorkflowRegistry._materialize(  # noqa: SLF001
                    archive,
                    Path(temporary),
                )
                manifest, digest, signed = validate_package(
                    unpacked,
                    allow_unsigned=allow_unsigned,
                )
                if publisher_key is not None and (
                    not signed or manifest.publisher.public_key != publisher_key
                ):
                    raise CapabilityInstallError("CAPABILITY_PUBLISHER_PIN_MISMATCH")
                installed = InstallResult(manifest, unpacked, digest, signed)
                actual_ref = f"{installed.manifest.id}@{installed.manifest.version}"
                if actual_ref != workflow_ref or installed.digest != expected_digest:
                    raise CapabilityInstallError("CAPABILITY_BINDING_MISMATCH")
                self._validate_inert_workflow(installed)
                facts = comfyui_capability_facts(installed.manifest, installed.path)
                if facts.node_classes_digest != node_classes_digest:
                    raise CapabilityInstallError("CAPABILITY_NODE_APPROVAL_MISMATCH")
                if model_digests is not None and node_classes is not None:
                    actual_models = list(workflow_model_digests(facts.variant))
                    if actual_models != list(model_digests):
                        raise CapabilityInstallError("CAPABILITY_MODEL_APPROVAL_MISMATCH")
                    if sorted(facts.node_classes) != list(node_classes):
                        raise CapabilityInstallError("CAPABILITY_NODE_APPROVAL_MISMATCH")
                if validator is not None:
                    try:
                        validator(installed)
                    except CapabilityInstallError:
                        raise
                    except Exception as exc:
                        raise CapabilityInstallError("CAPABILITY_COMPILE_INVALID") from exc
                return self._publish(
                    installed,
                    workflow_ref,
                    workflow_digest,
                    spec=spec,
                    authorization=receipt,
                )
        except CapabilityInstallError:
            raise
        except (RegistryError, WorkflowCapabilityError, ValueError, OSError) as exc:
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID") from exc

    def active(self) -> tuple[InstallResult, ...]:
        index = self._read_index()
        results: list[InstallResult] = []
        self.active_errors = 0
        for workflow_ref, entry in sorted(index["workflows"].items()):
            try:
                trusted = self._trusted_entry(workflow_ref, entry)
                if trusted is None:
                    raise CapabilityInstallError("CAPABILITY_TRUST_MIGRATION_REQUIRED")
                spec, authorization = trusted
                if not self._receipt_valid(spec, authorization, historical=True):
                    raise CapabilityInstallError("CAPABILITY_AUTHORIZATION_INVALID")
                digest = str(spec["workflow_digest"])
                directory = self._release_path(digest)
                allow_unsigned = bool(spec["allow_unsigned_workflow"])
                manifest, actual, signed = validate_package(
                    directory,
                    allow_unsigned=allow_unsigned,
                )
                if f"{manifest.id}@{manifest.version}" != workflow_ref or actual != digest[7:]:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_INVALID")
                publisher_key = spec["publisher_key"]
                if publisher_key is not None and (
                    not signed or manifest.publisher.public_key != publisher_key
                ):
                    raise CapabilityInstallError("CAPABILITY_PUBLISHER_PIN_MISMATCH")
                result = InstallResult(manifest, directory, actual, signed)
                self._validate_inert_workflow(result)
                facts = comfyui_capability_facts(result.manifest, result.path)
                if facts.node_classes_digest != spec["node_classes_digest"]:
                    raise CapabilityInstallError("CAPABILITY_NODE_APPROVAL_MISMATCH")
                if set(spec) == _CAPABILITY_SPEC_FIELDS_V2:
                    actual_models = list(workflow_model_digests(facts.variant))
                    if actual_models != spec["model_digests"]:
                        raise CapabilityInstallError("CAPABILITY_MODEL_APPROVAL_MISMATCH")
                    if sorted(facts.node_classes) != spec["node_classes"]:
                        raise CapabilityInstallError("CAPABILITY_NODE_APPROVAL_MISMATCH")
            except (
                CapabilityInstallError,
                RegistryError,
                WorkflowCapabilityError,
                ValueError,
                OSError,
            ) as exc:
                self.active_errors += 1
                logger.error(
                    "Ignoring invalid active workflow release %s: %s",
                    workflow_ref,
                    type(exc).__name__,
                )
                continue
            results.append(result)
        return tuple(results)

    def deactivate(self, workflow_ref: str, workflow_digest: str) -> bool:
        """Atomically remove one exact release from the active index.

        The content-addressed release directory is deliberately retained so a
        later authorized workflow can reuse the verified bytes.
        """

        if not _REF.fullmatch(workflow_ref) or not _DIGEST.fullmatch(workflow_digest):
            raise CapabilityInstallError("CAPABILITY_SPEC_INVALID")
        with self._index_lock():
            current = self._read_index()
            workflows = self._migrated_workflows(current)
            entry = workflows.get(workflow_ref)
            if entry is None or self._entry_digest(entry) != workflow_digest:
                return False
            workflows.pop(workflow_ref)
            self._write_index({"schema_version": _INDEX_VERSION, "workflows": workflows})
            return True

    def reconcile_authorizations(
        self, authorizations: Any
    ) -> tuple[tuple[str, str], ...]:
        """Deactivate active releases absent from one validated Gateway snapshot."""

        # The active index is capped at 256 dynamic releases, while a Gateway
        # snapshot can additionally include release-owned bootstrap grants.
        if not isinstance(authorizations, (list, tuple)) or len(authorizations) > 512:
            raise CapabilityInstallError("CAPABILITY_AUTHORIZATION_SNAPSHOT_INVALID")
        allowed: set[tuple[str, str]] = set()
        for item in authorizations:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"workflow_ref", "workflow_digest"}
                or not isinstance(item.get("workflow_ref"), str)
                or not _REF.fullmatch(item["workflow_ref"])
                or not isinstance(item.get("workflow_digest"), str)
                or not _DIGEST.fullmatch(item["workflow_digest"])
            ):
                raise CapabilityInstallError("CAPABILITY_AUTHORIZATION_SNAPSHOT_INVALID")
            identity = (item["workflow_ref"], item["workflow_digest"])
            if identity in allowed:
                raise CapabilityInstallError("CAPABILITY_AUTHORIZATION_SNAPSHOT_INVALID")
            allowed.add(identity)

        with self._index_lock():
            current = self._read_index()
            workflows = self._migrated_workflows(current)
            removed: list[tuple[str, str]] = []
            for workflow_ref, entry in tuple(workflows.items()):
                digest = self._entry_digest(entry)
                if digest is None:
                    raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
                if (workflow_ref, digest) not in allowed:
                    workflows.pop(workflow_ref)
                    removed.append((workflow_ref, digest))
            if removed or current["schema_version"] != _INDEX_VERSION:
                self._write_index({"schema_version": _INDEX_VERSION, "workflows": workflows})
            return tuple(sorted(removed))

    def _trusted_entry(
        self,
        workflow_ref: object,
        entry: object,
    ) -> tuple[dict[str, Any], dict[str, Any]] | None:
        if not isinstance(workflow_ref, str) or not _REF.fullmatch(workflow_ref):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        if isinstance(entry, str):
            # Schema v1 contains no owner authorization and can never safely
            # bootstrap its own trust from a self-signed release.
            if not _DIGEST.fullmatch(entry):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
            return None
        if not isinstance(entry, dict):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        if set(entry) == {"legacy_digest"}:
            if not isinstance(entry["legacy_digest"], str) or not _DIGEST.fullmatch(
                entry["legacy_digest"]
            ):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
            return None
        if set(entry) != {"spec", "authorization"}:
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        spec = entry["spec"]
        authorization = entry["authorization"]
        if (
            not isinstance(spec, dict)
            or not isinstance(authorization, dict)
            or not self._valid_spec(spec)
            or spec["workflow_ref"] != workflow_ref
        ):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        return dict(spec), dict(authorization)

    @staticmethod
    def _valid_spec(spec: Mapping[str, Any]) -> bool:
        publisher_key = spec.get("publisher_key")
        allow_unsigned = spec.get("allow_unsigned_workflow")
        artifact_size = spec.get("artifact_size")
        fields = set(spec)
        v2_identifiers_valid = fields == _CAPABILITY_SPEC_FIELDS_V1 or (
            fields == _CAPABILITY_SPEC_FIELDS_V2
            and isinstance(spec.get("model_digests"), list)
            and len(spec["model_digests"]) <= 128
            and all(
                isinstance(item, str) and bool(_DIGEST.fullmatch(item))
                for item in spec["model_digests"]
            )
            and spec["model_digests"] == sorted(set(spec["model_digests"]))
            and isinstance(spec.get("node_classes"), list)
            and len(spec["node_classes"]) <= 512
            and all(
                isinstance(item, str)
                and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", item))
                for item in spec["node_classes"]
            )
            and spec["node_classes"] == sorted(set(spec["node_classes"]))
            and hashlib.sha256(canonical_json(spec["node_classes"])).hexdigest()
            == spec.get("node_classes_digest")
        )
        return (
            v2_identifiers_valid
            and spec.get("kind") == "capability_install"
            and isinstance(spec.get("workflow_ref"), str)
            and bool(_REF.fullmatch(str(spec["workflow_ref"])))
            and isinstance(spec.get("workflow_digest"), str)
            and bool(_DIGEST.fullmatch(str(spec["workflow_digest"])))
            and isinstance(spec.get("artifact_sha256"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(spec["artifact_sha256"])))
            and type(artifact_size) is int
            and artifact_size > 0
            and isinstance(spec.get("node_classes_digest"), str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", str(spec["node_classes_digest"])))
            and (publisher_key is None or isinstance(publisher_key, str))
            and type(allow_unsigned) is bool
            and allow_unsigned == (publisher_key is None)
            and spec.get("apply") == "on_idle"
        )

    def _receipt_valid(
        self,
        spec: Mapping[str, Any],
        authorization: Mapping[str, Any],
        *,
        historical: bool,
    ) -> bool:
        if (
            self._owner_root_signing_public_key is None
            or self._worker_id is None
            or not self._valid_spec(spec)
        ):
            return False
        payload = authorization.get("payload")
        if not isinstance(payload, Mapping):
            return False
        broker_id = payload.get("broker_id")
        issued_at = payload.get("issued_at")
        if not isinstance(broker_id, str) or not broker_id:
            return False
        if type(issued_at) is not int:
            return False
        return verify_maintenance_intent(
            authorization,
            self._owner_root_signing_public_key,
            expected_worker_id=self._worker_id,
            expected_broker_id=broker_id,
            expected_kind="capability_install",
            expected_spec=spec,
            now=issued_at if historical else None,
        )

    def generation(self) -> object:
        try:
            metadata = self.index_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CapabilityInstallError("CAPABILITY_INDEX_UNAVAILABLE") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or _posix_writable_by_others(metadata)
            or _is_reparse_point(self.index_path)
        ):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        index = self._read_index()
        release_fingerprints: list[tuple[str, tuple[tuple[object, ...], ...]]] = []
        digests = {
            digest
            for entry in index["workflows"].values()
            if (digest := self._entry_digest(entry)) is not None
        }
        for digest in sorted(digests):
            directory = self._release_path(digest)
            entries: list[tuple[object, ...]] = []
            try:
                paths = sorted(directory.rglob("*"), key=lambda item: item.as_posix())
                if len(paths) > 4096:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_INVALID")
                for path in paths:
                    item = path.lstat()
                    entries.append(
                        (
                            path.relative_to(directory).as_posix(),
                            stat.S_IFMT(item.st_mode),
                            item.st_size,
                            item.st_mtime_ns,
                            item.st_ctime_ns,
                        )
                    )
            except (OSError, ValueError):
                entries.append(("<unavailable>",))
            release_fingerprints.append((digest, tuple(entries)))
        return (
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            tuple(release_fingerprints),
        )

    @staticmethod
    def _entry_digest(entry: object) -> str | None:
        if isinstance(entry, str):
            return entry if _DIGEST.fullmatch(entry) else None
        if not isinstance(entry, dict):
            return None
        if set(entry) == {"legacy_digest"}:
            digest = entry.get("legacy_digest")
        elif set(entry) == {"spec", "authorization"} and isinstance(entry.get("spec"), dict):
            digest = entry["spec"].get("workflow_digest")
        else:
            return None
        return digest if isinstance(digest, str) and _DIGEST.fullmatch(digest) else None

    def _publish(
        self,
        installed: InstallResult,
        workflow_ref: str,
        workflow_digest: str,
        *,
        spec: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> CapabilityActivation:
        with self._index_lock():
            return self._publish_locked(
                installed,
                workflow_ref,
                workflow_digest,
                spec=spec,
                authorization=authorization,
            )

    def _publish_locked(
        self,
        installed: InstallResult,
        workflow_ref: str,
        workflow_digest: str,
        *,
        spec: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> CapabilityActivation:
        current = self._read_index()
        workflows = self._migrated_workflows(current)
        active_entry = workflows.get(workflow_ref)
        active_digest = self._entry_digest(active_entry)
        if active_entry is not None and active_digest is None:
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        if active_digest is not None and active_digest != workflow_digest:
            raise CapabilityInstallError("CAPABILITY_VERSION_CONFLICT")

        target = self._release_path(workflow_digest)
        trusted_active = isinstance(active_entry, dict) and set(active_entry) == {
            "spec",
            "authorization",
        }
        status = (
            "already_active" if active_digest == workflow_digest and trusted_active else "activated"
        )
        target_present = target.exists() or _is_reparse_point(target)
        repair = False
        if target_present:
            if _is_reparse_point(target) or not target.is_dir():
                raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT")
            try:
                manifest, digest, _signed = validate_package(target, allow_unsigned=True)
                existing = InstallResult(manifest, target, digest, _signed)
                self._validate_inert_workflow(existing)
                if (
                    digest != installed.digest
                    or f"{manifest.id}@{manifest.version}" != workflow_ref
                ):
                    raise RegistryError("release binding mismatch")
                if not self._trust_satisfies(existing, installed):
                    raise RegistryError("release trust mismatch")
            except (CapabilityInstallError, RegistryError, ValueError):
                # Only an already-active digest may be repaired in place.  An
                # orphan or differently bound directory is evidence of local
                # tampering and must not be overwritten automatically.
                if active_digest != workflow_digest:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from None
                repair = True

        if not target_present or repair:
            staging = Path(tempfile.mkdtemp(prefix=f".{installed.digest[:16]}-", dir=self.releases))
            candidate = staging / "release"
            quarantine_root: Path | None = None
            old_release: Path | None = None
            replacement_installed = False
            old_release_restored = False
            try:
                shutil.copytree(installed.path, candidate)
                staged_manifest, staged_digest, staged_signed = validate_package(
                    candidate, allow_unsigned=True
                )
                staged = InstallResult(
                    staged_manifest,
                    candidate,
                    staged_digest,
                    staged_signed,
                )
                self._validate_inert_workflow(staged)
                if (
                    staged_digest != installed.digest
                    or f"{staged_manifest.id}@{staged_manifest.version}" != workflow_ref
                    or not self._trust_satisfies(staged, installed)
                ):
                    raise CapabilityInstallError("CAPABILITY_INSTALL_FAILED")

                if repair:
                    quarantine_root = Path(
                        tempfile.mkdtemp(
                            prefix=f".{installed.digest[:16]}-corrupt-",
                            dir=self.releases,
                        )
                    )
                    old_release = quarantine_root / "release"
                    os.replace(target, old_release)
                try:
                    os.replace(candidate, target)
                    replacement_installed = True
                except OSError:
                    if old_release is not None and not (
                        target.exists() or _is_reparse_point(target)
                    ):
                        try:
                            os.replace(old_release, target)
                            old_release_restored = True
                        except OSError:
                            logger.exception(
                                "Unable to restore quarantined workflow release %s from %s",
                                workflow_ref,
                                old_release,
                            )
                    raise
                if repair:
                    status = "repaired"
            except FileExistsError as exc:
                if not target.is_dir() or _is_reparse_point(target):
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from exc
                try:
                    manifest, digest, existing_signed = validate_package(
                        target, allow_unsigned=True
                    )
                    existing = InstallResult(
                        manifest,
                        target,
                        digest,
                        existing_signed,
                    )
                    self._validate_inert_workflow(existing)
                except (CapabilityInstallError, RegistryError, ValueError) as validation_exc:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from (
                        validation_exc
                    )
                if (
                    digest != installed.digest
                    or f"{manifest.id}@{manifest.version}" != workflow_ref
                    or not self._trust_satisfies(existing, installed)
                ):
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from exc
            except CapabilityInstallError:
                raise
            except OSError as exc:
                raise CapabilityInstallError("CAPABILITY_INSTALL_FAILED") from exc
            finally:
                shutil.rmtree(staging, ignore_errors=True)
                if quarantine_root is not None and (replacement_installed or old_release_restored):
                    shutil.rmtree(quarantine_root, ignore_errors=True)

        if repair and not replacement_installed:
            # A concurrent valid install is acceptable, but a failed repair
            # must never be reported as successful.
            try:
                manifest, digest, existing_signed = validate_package(target, allow_unsigned=True)
                existing = InstallResult(
                    manifest,
                    target,
                    digest,
                    existing_signed,
                )
                self._validate_inert_workflow(existing)
            except (CapabilityInstallError, RegistryError, ValueError) as validation_exc:
                raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from (validation_exc)
            if (
                digest != installed.digest
                or f"{manifest.id}@{manifest.version}" != workflow_ref
                or not self._trust_satisfies(existing, installed)
            ):
                raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from None

        trusted_entry = {
            "spec": dict(spec),
            "authorization": dict(authorization),
        }
        if active_entry != trusted_entry or current["schema_version"] != _INDEX_VERSION:
            workflows[workflow_ref] = trusted_entry
            updated = {"schema_version": _INDEX_VERSION, "workflows": workflows}
            self._write_index(updated)
        return CapabilityActivation(workflow_ref, workflow_digest, status, target)

    @staticmethod
    def _migrated_workflows(index: Mapping[str, Any]) -> dict[str, Any]:
        workflows = index["workflows"]
        if index["schema_version"] == _INDEX_VERSION:
            return dict(workflows)
        return {
            workflow_ref: {"legacy_digest": digest} for workflow_ref, digest in workflows.items()
        }

    @staticmethod
    def _trust_satisfies(existing: InstallResult, requested: InstallResult) -> bool:
        """Do not reuse weaker bytes for a newly authenticated activation."""

        if not requested.signed:
            return True
        return (
            existing.signed
            and existing.manifest.publisher.public_key == requested.manifest.publisher.public_key
        )

    def _read_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            if _is_reparse_point(self.index_path):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
            return {"schema_version": _INDEX_VERSION, "workflows": {}}
        if _is_reparse_point(self.index_path):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        try:
            metadata = self.index_path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or _posix_writable_by_others(metadata):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except CapabilityInstallError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID") from exc
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "workflows"}
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] not in {_LEGACY_INDEX_VERSION, _INDEX_VERSION}
            or not isinstance(raw["workflows"], dict)
            or len(raw["workflows"]) > 256
        ):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        workflows = raw["workflows"]
        if any(not isinstance(key, str) or not _REF.fullmatch(key) for key in workflows):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        if raw["schema_version"] == _LEGACY_INDEX_VERSION:
            if any(
                not isinstance(value, str) or not _DIGEST.fullmatch(value)
                for value in workflows.values()
            ):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        elif any(
            not isinstance(value, dict)
            or set(value) not in ({"legacy_digest"}, {"spec", "authorization"})
            for value in workflows.values()
        ):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        return raw

    def _write_index(self, value: dict[str, Any]) -> None:
        if _is_reparse_point(self.root) or _is_reparse_point(self.index_path):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        temporary = self.root / f".{_INDEX_NAME}.{os.getpid()}.tmp"
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(payload + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.index_path)
        except OSError as exc:
            raise CapabilityInstallError("CAPABILITY_INDEX_UNAVAILABLE") from exc
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _release_path(self, digest: str) -> Path:
        try:
            metadata = self.releases.lstat()
        except OSError as exc:
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE") from exc
        if (
            _is_reparse_point(self.releases)
            or not stat.S_ISDIR(metadata.st_mode)
            or _posix_writable_by_others(metadata)
        ):
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
        return self.releases / digest.removeprefix("sha256:")

    @staticmethod
    def _validate_inert_workflow(installed: InstallResult) -> None:
        try:
            facts = comfyui_capability_facts(installed.manifest, installed.path)
        except WorkflowCapabilityError as exc:
            raise CapabilityInstallError("CAPABILITY_GRAPH_INVALID") from exc
        if any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item) for item in facts.node_classes):
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID")
        # Custom-node requirements remain review metadata.  A capability ZIP
        # must never carry source trees, wheel files, native libraries or setup
        # scripts which could turn data activation into code installation.
        allowed = {
            "manifest.yaml",
            "checksums.sha256",
            "artifact.sig",
            "workflow.lock",
            facts.variant.payload,
        }
        if facts.variant.mapping:
            allowed.add(facts.variant.mapping)
        for path in installed.path.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(installed.path).as_posix()
            if relative in allowed or relative.lower() in {
                "readme",
                "readme.md",
                "readme.txt",
            }:
                continue
            raise CapabilityInstallError("CAPABILITY_CONTAINS_EXECUTABLE_CONTENT")


__all__ = [
    "CapabilityActivation",
    "CapabilityInstallError",
    "WorkerCapabilityStore",
]
