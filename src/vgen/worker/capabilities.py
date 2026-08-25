"""Immutable workflow releases activated by owner-authorized maintenance.

The uploaded artifact is the ordinary VGen workflow release ZIP.  The Gateway
does not interpret it.  A Worker verifies the ZIP, publisher pin, package
digest and exact workflow reference again before atomically adding it to the
local active index.  Workflow files are inert data; executable custom-node
installation remains a separate machine-administrator boundary.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vgen.market.capabilities import WorkflowCapabilityError, comfyui_capability_facts
from vgen.market.registry import InstallResult, RegistryError, WorkflowRegistry, validate_package

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF = re.compile(
    r"^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*@"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_INDEX_NAME = "active.json"
_INDEX_VERSION = 1

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


def _safe_root(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
    try:
        expanded.mkdir(parents=True, exist_ok=True)
        resolved = expanded.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise CapabilityInstallError("CAPABILITY_ROOT_UNAVAILABLE") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
    return resolved


class WorkerCapabilityStore:
    """Content-addressed workflow releases with an atomic active generation."""

    def __init__(self, root: Path) -> None:
        self.root = _safe_root(root)
        self.releases = self.root / "releases"
        self.releases.mkdir(exist_ok=True)
        if self.releases.is_symlink():
            raise CapabilityInstallError("CAPABILITY_ROOT_UNSAFE")
        self.index_path = self.root / _INDEX_NAME
        self.active_errors = 0

    def activate(
        self,
        archive: Path,
        *,
        workflow_ref: str,
        workflow_digest: str,
        publisher_key: str | None,
        allow_unsigned: bool,
        node_classes_digest: str,
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
        if archive.is_symlink() or not archive.is_file():
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID")

        expected_digest = workflow_digest.removeprefix("sha256:")
        try:
            with tempfile.TemporaryDirectory(prefix="vgen-capability-verify-") as temporary:
                registry = WorkflowRegistry(Path(temporary) / "registry")
                installed = registry.install(
                    archive,
                    allow_unsigned=allow_unsigned,
                    expected_digest=workflow_digest,
                    expected_publisher_key=publisher_key,
                )
                actual_ref = f"{installed.manifest.id}@{installed.manifest.version}"
                if actual_ref != workflow_ref or installed.digest != expected_digest:
                    raise CapabilityInstallError("CAPABILITY_BINDING_MISMATCH")
                self._validate_inert_workflow(installed)
                facts = comfyui_capability_facts(installed.manifest, installed.path)
                if facts.node_classes_digest != node_classes_digest:
                    raise CapabilityInstallError("CAPABILITY_NODE_APPROVAL_MISMATCH")
                if validator is not None:
                    validator(installed)
                return self._publish(installed, workflow_ref, workflow_digest)
        except CapabilityInstallError:
            raise
        except (RegistryError, WorkflowCapabilityError, ValueError, OSError) as exc:
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID") from exc

    def active(self) -> tuple[InstallResult, ...]:
        index = self._read_index()
        results: list[InstallResult] = []
        self.active_errors = 0
        for workflow_ref, digest in sorted(index["workflows"].items()):
            if not isinstance(workflow_ref, str) or not _REF.fullmatch(workflow_ref):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
                raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
            directory = self._release_path(digest)
            try:
                manifest, actual, signed = validate_package(directory, allow_unsigned=True)
                if f"{manifest.id}@{manifest.version}" != workflow_ref or actual != digest[7:]:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_INVALID")
                result = InstallResult(manifest, directory, actual, signed)
                self._validate_inert_workflow(result)
            except (CapabilityInstallError, RegistryError, ValueError) as exc:
                self.active_errors += 1
                logger.error(
                    "Ignoring invalid active workflow release %s: %s",
                    workflow_ref,
                    type(exc).__name__,
                )
                continue
            results.append(result)
        return tuple(results)

    def generation(self) -> object:
        try:
            metadata = self.index_path.stat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CapabilityInstallError("CAPABILITY_INDEX_UNAVAILABLE") from exc
        if not stat.S_ISREG(metadata.st_mode) or self.index_path.is_symlink():
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        index = self._read_index()
        release_fingerprints: list[tuple[str, tuple[tuple[object, ...], ...]]] = []
        for digest in sorted(set(index["workflows"].values())):
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

    def _publish(
        self,
        installed: InstallResult,
        workflow_ref: str,
        workflow_digest: str,
    ) -> CapabilityActivation:
        current = self._read_index()
        active_digest = current["workflows"].get(workflow_ref)
        if active_digest is not None and active_digest != workflow_digest:
            raise CapabilityInstallError("CAPABILITY_VERSION_CONFLICT")

        target = self._release_path(workflow_digest)
        status = "already_active" if active_digest == workflow_digest else "activated"
        target_present = target.exists() or target.is_symlink()
        repair = False
        if target_present:
            if target.is_symlink() or not target.is_dir():
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
            except (CapabilityInstallError, RegistryError, ValueError):
                # Only an already-active digest may be repaired in place.  An
                # orphan or differently bound directory is evidence of local
                # tampering and must not be overwritten automatically.
                if active_digest != workflow_digest:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from None
                repair = True

        if not target_present or repair:
            staging = Path(
                tempfile.mkdtemp(prefix=f".{installed.digest[:16]}-", dir=self.releases)
            )
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
                        target.exists() or target.is_symlink()
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
                if not target.is_dir() or target.is_symlink():
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from exc
                try:
                    manifest, digest, _signed = validate_package(
                        target, allow_unsigned=True
                    )
                except (RegistryError, ValueError) as validation_exc:
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from (
                        validation_exc
                    )
                if (
                    digest != installed.digest
                    or f"{manifest.id}@{manifest.version}" != workflow_ref
                ):
                    raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from exc
            except CapabilityInstallError:
                raise
            except OSError as exc:
                raise CapabilityInstallError("CAPABILITY_INSTALL_FAILED") from exc
            finally:
                shutil.rmtree(staging, ignore_errors=True)
                if quarantine_root is not None and (
                    replacement_installed or old_release_restored
                ):
                    shutil.rmtree(quarantine_root, ignore_errors=True)

        if repair and not replacement_installed:
            # A concurrent valid install is acceptable, but a failed repair
            # must never be reported as successful.
            try:
                manifest, digest, _signed = validate_package(target, allow_unsigned=True)
            except (RegistryError, ValueError) as validation_exc:
                raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from (
                    validation_exc
                )
            if digest != installed.digest or f"{manifest.id}@{manifest.version}" != workflow_ref:
                raise CapabilityInstallError("CAPABILITY_RELEASE_CONFLICT") from None

        if active_digest != workflow_digest:
            updated = {
                "schema_version": _INDEX_VERSION,
                "workflows": {**current["workflows"], workflow_ref: workflow_digest},
            }
            self._write_index(updated)
        return CapabilityActivation(workflow_ref, workflow_digest, status, target)

    def _read_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"schema_version": _INDEX_VERSION, "workflows": {}}
        if self.index_path.is_symlink():
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        try:
            raw = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID") from exc
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "workflows"}
            or raw["schema_version"] != _INDEX_VERSION
            or not isinstance(raw["workflows"], dict)
            or len(raw["workflows"]) > 256
        ):
            raise CapabilityInstallError("CAPABILITY_INDEX_INVALID")
        return raw

    def _write_index(self, value: dict[str, Any]) -> None:
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
        return self.releases / digest.removeprefix("sha256:")

    @staticmethod
    def _validate_inert_workflow(installed: InstallResult) -> None:
        try:
            facts = comfyui_capability_facts(installed.manifest, installed.path)
        except WorkflowCapabilityError as exc:
            raise CapabilityInstallError("CAPABILITY_ARCHIVE_INVALID") from exc
        if any(
            not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item) for item in facts.node_classes
        ):
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
