"""Transactional installation of reviewed ComfyUI Node Packs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from vgen.crypto import canonical_json
from vgen.market.node_packs import NodePackError, NodePackManifest, materialize_node_pack

from .host_control import ComfyUIHostControl, ComfyUIHostControlError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MARKER = ".vgen-node-pack.json"
_BOOTSTRAP = b"""# VGen managed dependency path; generated from a verified Node Pack.
import sys as _vgen_sys
from pathlib import Path as _VGenPath
_vgen_deps = str(_VGenPath(__file__).resolve().parent / ".vgen-deps")
if _vgen_deps not in _vgen_sys.path:
    _vgen_sys.path.insert(0, _vgen_deps)
del _vgen_deps, _VGenPath, _vgen_sys
"""


class NodePackInstallError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class NodePackInstallResult:
    node_pack_id: str
    version: str
    artifact_sha256: str
    directory: Path
    status: str
    node_classes: tuple[str, ...]


WheelInstaller = Callable[[Path, tuple[Path, ...], Path], None]
NodeProbe = Callable[[], set[str] | None]
StageReporter = Callable[[str], None]


def _safe_directory(path: Path, *, create: bool) -> Path:
    absolute = path.expanduser().absolute()
    try:
        if create:
            absolute.mkdir(parents=True, exist_ok=True)
        metadata = absolute.lstat()
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise NodePackInstallError("NODE_PACK_ROOT_UNAVAILABLE") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or absolute.is_symlink()
        or resolved != absolute
        or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022)
    ):
        raise NodePackInstallError("NODE_PACK_ROOT_UNSAFE")
    return resolved


def _default_wheel_installer(
    python_executable: Path,
    wheels: tuple[Path, ...],
    destination: Path,
) -> None:
    if not wheels:
        return
    destination.mkdir(parents=True, exist_ok=True)
    command = [
        str(python_executable),
        "-I",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-input",
        "--no-index",
        "--no-deps",
        "--target",
        str(destination),
        *(str(path) for path in wheels),
    ]
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NodePackInstallError("NODE_PACK_DEPENDENCY_INSTALL_FAILED") from exc
    if completed.returncode != 0 or len(completed.stdout) > 2 * 1024 * 1024:
        raise NodePackInstallError("NODE_PACK_DEPENDENCY_INSTALL_FAILED")


class NodePackInstaller:
    def __init__(
        self,
        work_root: Path,
        custom_nodes_root: Path,
        python_executable: Path,
        host_control: ComfyUIHostControl,
        node_probe: NodeProbe,
        *,
        pure_python_only: bool = False,
        wheel_installer: WheelInstaller = _default_wheel_installer,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.work_root = _safe_directory(work_root, create=True)
        self.custom_nodes_root = _safe_directory(custom_nodes_root, create=True)
        raw_python = python_executable.expanduser().absolute()
        try:
            python_metadata = raw_python.lstat()
            resolved_python = raw_python.resolve(strict=True)
        except OSError as exc:
            raise NodePackInstallError("NODE_PACK_RUNTIME_UNAVAILABLE") from exc
        if (
            not stat.S_ISREG(python_metadata.st_mode)
            or raw_python.is_symlink()
            or resolved_python != raw_python
        ):
            raise NodePackInstallError("NODE_PACK_RUNTIME_UNSAFE")
        self.python_executable = resolved_python
        self.host_control = host_control
        self.node_probe = node_probe
        self.pure_python_only = pure_python_only
        self.wheel_installer = wheel_installer
        self.sleeper = sleeper
        self.monotonic = monotonic

    def install(
        self,
        archive: Path,
        *,
        expected_sha256: str,
        expected_node_pack_ref: str,
        expected_node_classes: tuple[str, ...],
        probe_timeout: float = 120,
        stage: StageReporter | None = None,
    ) -> NodePackInstallResult:
        expected = expected_sha256.removeprefix("sha256:").lower()
        if not _DIGEST.fullmatch(expected) or probe_timeout <= 0:
            raise NodePackInstallError("NODE_PACK_INSTALL_SPEC_INVALID")
        transaction = self.work_root / "node-packs" / "transactions" / secrets.token_hex(16)
        unpacked = transaction / "unpacked"
        candidate = transaction / "candidate"
        backup = transaction / "backup"
        failed = transaction / "failed"
        transaction.mkdir(parents=True)
        try:
            if stage is not None:
                stage("validating")
            try:
                manifest, source_root, wheel_root, artifact_digest = materialize_node_pack(
                    archive, unpacked
                )
            except NodePackError as exc:
                raise NodePackInstallError(str(exc)) from exc
            if artifact_digest != expected:
                raise NodePackInstallError("NODE_PACK_ARTIFACT_DIGEST_MISMATCH")
            if (
                f"{manifest.id}@{manifest.version}" != expected_node_pack_ref
                or tuple(sorted(manifest.node_classes)) != expected_node_classes
            ):
                raise NodePackInstallError("NODE_PACK_MANIFEST_BINDING_MISMATCH")
            target = self.custom_nodes_root / manifest.directory
            existing = self._existing_result(target, manifest, artifact_digest)
            if existing is not None:
                return existing

            os.replace(source_root, candidate)
            wheels = tuple(
                wheel_root / item.filename for item in manifest.wheels
            )
            if self.pure_python_only and any(
                not wheel.name.endswith("-py3-none-any.whl") for wheel in wheels
            ):
                raise NodePackInstallError("NODE_PACK_RUNTIME_INCOMPATIBLE")
            if stage is not None:
                stage("installing_dependencies")
            self.wheel_installer(
                self.python_executable,
                wheels,
                candidate / ".vgen-deps",
            )
            self._prepare_candidate(candidate, manifest, artifact_digest)

            activated = False
            try:
                if stage is not None:
                    stage("pausing_comfyui")
                with self.host_control.paused(timeout=90, ttl_seconds=600):
                    if target.exists():
                        self._validate_activation_path(target)
                        os.replace(target, backup)
                    os.replace(candidate, target)
                    activated = True
                if stage is not None:
                    stage("probing_nodes")
                self._wait_for_nodes(set(manifest.node_classes), timeout=probe_timeout)
            except BaseException as exc:
                if activated:
                    try:
                        if stage is not None:
                            stage("rolling_back")
                        self._rollback(target, backup, failed)
                    except BaseException as rollback_exc:
                        raise NodePackInstallError("NODE_PACK_ROLLBACK_FAILED") from rollback_exc
                if isinstance(exc, NodePackInstallError):
                    raise
                if isinstance(exc, ComfyUIHostControlError):
                    raise NodePackInstallError(str(exc)) from exc
                raise NodePackInstallError("NODE_PACK_ACTIVATION_FAILED") from exc

            if backup.exists():
                shutil.rmtree(backup)
            return NodePackInstallResult(
                node_pack_id=manifest.id,
                version=manifest.version,
                artifact_sha256=artifact_digest,
                directory=target,
                status="installed",
                node_classes=tuple(manifest.node_classes),
            )
        finally:
            shutil.rmtree(transaction, ignore_errors=True)

    def _existing_result(
        self,
        target: Path,
        manifest: NodePackManifest,
        artifact_digest: str,
    ) -> NodePackInstallResult | None:
        if not target.exists():
            return None
        self._validate_activation_path(target)
        marker = target / _MARKER
        try:
            value = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            return None
        if not self._active_receipt_matches(target, value, manifest, artifact_digest):
            return None
        loaded = self.node_probe()
        if loaded is None or not set(manifest.node_classes).issubset(loaded):
            return None
        return NodePackInstallResult(
            node_pack_id=manifest.id,
            version=manifest.version,
            artifact_sha256=artifact_digest,
            directory=target,
            status="already_installed",
            node_classes=tuple(manifest.node_classes),
        )

    @staticmethod
    def _active_receipt_matches(
        target: Path,
        value: object,
        manifest: NodePackManifest,
        artifact_digest: str,
    ) -> bool:
        if not isinstance(value, dict) or set(value) != {
            "format",
            "version",
            "node_pack_id",
            "node_pack_version",
            "artifact_sha256",
            "source",
            "revision",
            "node_classes",
            "files",
        }:
            return False
        if (
            value.get("format") != "vgen-node-pack-activation"
            or value.get("version") != 1
            or value.get("node_pack_id") != manifest.id
            or value.get("node_pack_version") != manifest.version
            or value.get("artifact_sha256") != artifact_digest
            or value.get("source") != manifest.source
            or value.get("revision") != manifest.revision
            or value.get("node_classes") != manifest.node_classes
        ):
            return False
        raw_files = value.get("files")
        if not isinstance(raw_files, list) or not 1 <= len(raw_files) <= 8192:
            return False
        declared: dict[str, tuple[int, str]] = {}
        for item in raw_files:
            if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
                return False
            path = item.get("path")
            digest = item.get("sha256")
            size = item.get("size")
            if (
                not isinstance(path, str)
                or not path
                or path.startswith(("/", "\\"))
                or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or not isinstance(digest, str)
                or not _DIGEST.fullmatch(digest)
                or type(size) is not int
                or size < 0
                or path.casefold() in declared
            ):
                return False
            declared[path.casefold()] = (size, digest)
        observed: set[str] = set()
        try:
            for path in target.rglob("*"):
                relative = path.relative_to(target).as_posix()
                if relative == _MARKER:
                    continue
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode) and not path.is_symlink():
                    continue
                if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                    return False
                expected = declared.get(relative.casefold())
                if expected is None or metadata.st_size != expected[0]:
                    return False
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() != expected[1]:
                    return False
                observed.add(relative.casefold())
        except OSError:
            return False
        return observed == set(declared)

    @staticmethod
    def _prepare_candidate(
        candidate: Path,
        manifest: NodePackManifest,
        artifact_digest: str,
    ) -> None:
        initializer = candidate / "__init__.py"
        try:
            metadata = initializer.lstat()
            if not stat.S_ISREG(metadata.st_mode) or initializer.is_symlink():
                raise OSError
            original = initializer.read_bytes()
            initializer.write_bytes(_BOOTSTRAP + original)
            files: list[dict[str, object]] = []
            for path in sorted(
                (item for item in candidate.rglob("*") if item != candidate / _MARKER),
                key=lambda item: item.relative_to(candidate).as_posix().encode("utf-8"),
            ):
                path_metadata = path.lstat()
                if stat.S_ISDIR(path_metadata.st_mode) and not path.is_symlink():
                    continue
                if not stat.S_ISREG(path_metadata.st_mode) or path.is_symlink():
                    raise OSError
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                files.append(
                    {
                        "path": path.relative_to(candidate).as_posix(),
                        "sha256": digest.hexdigest(),
                        "size": path_metadata.st_size,
                    }
                )
                if len(files) > 8192:
                    raise OSError
            marker = {
                "format": "vgen-node-pack-activation",
                "version": 1,
                "node_pack_id": manifest.id,
                "node_pack_version": manifest.version,
                "artifact_sha256": artifact_digest,
                "source": manifest.source,
                "revision": manifest.revision,
                "node_classes": manifest.node_classes,
                "files": files,
            }
            (candidate / _MARKER).write_bytes(canonical_json(marker) + b"\n")
        except OSError as exc:
            raise NodePackInstallError("NODE_PACK_CANDIDATE_INVALID") from exc

    @staticmethod
    def _validate_activation_path(path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise NodePackInstallError("NODE_PACK_TARGET_UNSAFE") from exc
        if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
            raise NodePackInstallError("NODE_PACK_TARGET_UNSAFE")

    def _wait_for_nodes(self, required: set[str], *, timeout: float) -> None:
        deadline = self.monotonic() + timeout
        while self.monotonic() < deadline:
            loaded = self.node_probe()
            if loaded is not None and required.issubset(loaded):
                return
            self.sleeper(1)
        raise NodePackInstallError("NODE_PACK_NODE_VALIDATION_FAILED")

    def _rollback(self, target: Path, backup: Path, failed: Path) -> None:
        with self.host_control.paused(timeout=90, ttl_seconds=600):
            if target.exists():
                self._validate_activation_path(target)
                os.replace(target, failed)
            if backup.exists():
                self._validate_activation_path(backup)
                os.replace(backup, target)
__all__ = ["NodePackInstallError", "NodePackInstallResult", "NodePackInstaller"]
