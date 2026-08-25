"""Broker-authorized Worker maintenance execution.

The Gateway is only a queue and artifact relay.  Every claimed instruction is
verified again against the Worker's locally stored owner root key and the local
ComfyUI machine policy before it can change files.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import shutil
import socket
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import requests

from vgen.artifacts import (
    ArtifactTransferError,
    HttpArtifactAdapter,
    OssStsArtifactAdapter,
    TransferTicket,
)
from vgen.crypto import verify_maintenance_intent
from vgen.protocol import ErrorCode, VGenError

from .capabilities import CapabilityInstallError, WorkerCapabilityStore
from .credentials import WorkerCredentials
from .model_installer import ModelInstaller, ModelInstallError
from .updater import RuntimeUpdater, WorkerUpdateError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WORKFLOW_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ROLLBACK_ENV = "VGEN_WORKER_UPDATE_ROLLBACK"
_LEASE_RENEW_INTERVAL_SECONDS = 20.0

TicketResolver = Callable[[str, int], Iterable[str]]


def _default_ticket_resolver(host: str, port: int) -> tuple[str, ...]:
    try:
        values = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WorkerUpdateError("WORKER_UPDATE_TICKET_UNAVAILABLE", retryable=True) from exc
    return tuple(dict.fromkeys(str(item[4][0]) for item in values))


class MaintenanceGateway(Protocol):
    def claim_maintenance(self, *, ttl_seconds: int = 60) -> Mapping[str, Any] | None: ...

    def heartbeat_maintenance(
        self,
        job_id: str,
        *,
        fencing_token: int,
        ttl_seconds: int = 60,
        state: str = "running",
        progress: Mapping[str, Any] | None = None,
        adopt_restart_session: bool = False,
    ) -> Mapping[str, Any]: ...

    def complete_maintenance(
        self,
        job_id: str,
        *,
        fencing_token: int,
        succeeded: bool,
        result: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def maintenance_artifact_ticket(self, job: Mapping[str, Any]) -> TransferTicket: ...


class MaintenanceExecutor(Protocol):
    @property
    def maintenance_model_pins(self) -> tuple[Any, ...]: ...

    @property
    def maintenance_workflows(self) -> tuple[tuple[str, str], ...]: ...

    def invalidate_model_digest_cache(self) -> None: ...

    def workflow_model_pins(self, workflow_ref: str, workflow_digest: str) -> tuple[Any, ...]: ...

    def reload_capabilities(self) -> None: ...


@dataclass(frozen=True, slots=True)
class MaintenanceOutcome:
    mode: str
    succeeded: bool
    restart_required: bool = False
    rollback_required: bool = False
    job_id: str | None = None
    error_code: int | None = None


class _LeaseKeeper:
    """Renew one lease while a blocking maintenance phase is in progress."""

    def __init__(
        self,
        gateway: MaintenanceGateway,
        job_id: str,
        fencing_token: int,
        *,
        stage: str,
        gateway_lock: threading.Lock,
        state: str = "running",
    ) -> None:
        self._gateway = gateway
        self._job_id = job_id
        self._fencing_token = fencing_token
        self._stage = stage
        self._gateway_lock = gateway_lock
        self._state = state
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._run, name="vgen-maintenance-lease", daemon=True
        )

    def __enter__(self) -> _LeaseKeeper:
        self._thread.start()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self._stop.set()
        # GatewayV1Client uses a (10s connect, 30s read) timeout. Do not let a
        # still-finishing heartbeat overlap the foreground completion request.
        self._thread.join(timeout=45)
        if _type is None:
            if self._thread.is_alive():
                raise VGenError(ErrorCode.GATEWAY_UNREACHABLE)
            self.check()

    def check(self) -> None:
        if self._error is not None:
            raise self._error

    def _run(self) -> None:
        # The caller sends the first heartbeat before entering.  Renew every
        # twenty seconds and request a five-minute lease for slow Windows disk
        # work without widening the server's hard upper bound. Preserve the
        # caller-selected state so target activation remains `restarting`.
        while not self._stop.wait(_LEASE_RENEW_INTERVAL_SECONDS):
            try:
                with self._gateway_lock:
                    response = self._gateway.heartbeat_maintenance(
                        self._job_id,
                        fencing_token=self._fencing_token,
                        ttl_seconds=300,
                        state=self._state,
                        progress={
                            "stage": self._stage,
                            "completed_bytes": 0,
                            "total_bytes": None,
                        },
                    )
                    if response.get("cancelled") is True:
                        raise _MaintenanceCancelled()
            except BaseException as exc:  # surfaced in the foreground thread
                self._error = exc
                self._stop.set()
                return


class WorkerMaintenanceController:
    def __init__(
        self,
        credentials: WorkerCredentials,
        gateway: MaintenanceGateway,
        executor: MaintenanceExecutor,
        *,
        work_root: Path,
        model_root: Path | None,
        session: requests.Session | None = None,
        updater: RuntimeUpdater | None = None,
        model_installer: ModelInstaller | None = None,
        capability_store: WorkerCapabilityStore | None = None,
        ticket_resolver: TicketResolver = _default_ticket_resolver,
        clock: Any = time.time,
    ) -> None:
        self._credentials = credentials
        self._gateway = gateway
        self._executor = executor
        self._work_root = work_root.expanduser().resolve()
        self._work_root.mkdir(parents=True, exist_ok=True)
        self._session = session or requests.Session()
        self._updater = updater or RuntimeUpdater(self._work_root)
        self._model_root = model_root
        self._model_installer = model_installer
        self._capability_store = capability_store
        self._ticket_resolver = ticket_resolver
        self._clock = clock
        self._last_progress_at = 0.0
        self._gateway_lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        # Old 0.1.x credentials remain valid for inference, but do not contain
        # the pinned owner trust anchor and therefore cannot execute maintenance.
        return self._credentials.owner_root_signing_public_key is not None

    def recover_pending_update(
        self,
        *,
        activation_probe: Callable[[], Any] | None = None,
    ) -> MaintenanceOutcome | None:
        """Finish or roll back a pointer left by the previous process."""

        pointer = self._updater.pending_activation()
        if pointer is None:
            return None
        job_id, fencing_token, target_version, artifact_sha256 = _pending_fields(pointer)

        if os.environ.get(_ROLLBACK_ENV) == "1":
            result = {
                "kind": "worker_update",
                "status": "rolled_back",
                "target_version": target_version,
                "artifact_sha256": artifact_sha256,
                "error_code": int(ErrorCode.EXECUTOR_UNAVAILABLE),
            }
            try:
                self._gateway.complete_maintenance(
                    job_id,
                    fencing_token=fencing_token,
                    succeeded=False,
                    result=result,
                )
            finally:
                # Local availability takes precedence if the old lease expired.
                self._updater.mark_activation_rolled_back(pointer)
            return MaintenanceOutcome(
                "maintenance_update_rolled_back",
                False,
                job_id=job_id,
                error_code=int(ErrorCode.EXECUTOR_UNAVAILABLE),
            )

        if not self._updater.is_target_process(pointer):
            return MaintenanceOutcome(
                "maintenance_update_restart", True, restart_required=True, job_id=job_id
            )

        try:
            activation = self._gateway.heartbeat_maintenance(
                job_id,
                fencing_token=fencing_token,
                ttl_seconds=300,
                state="restarting",
                adopt_restart_session=True,
                progress={
                    "stage": "activating",
                    "completed_bytes": 0,
                    "total_bytes": None,
                },
            )
            if activation.get("cancelled") is True:
                raise _MaintenanceCancelled()
            # A new interpreter importing VGen is not sufficient proof that it
            # can serve as a Worker.  Confirm one authenticated control-plane
            # announce before committing the update and clearing the rollback
            # pointer.
            if activation_probe is not None:
                with _LeaseKeeper(
                    self._gateway,
                    job_id,
                    fencing_token,
                    stage="activating",
                    gateway_lock=self._gateway_lock,
                    state="restarting",
                ) as keeper:
                    activation_probe()
                    keeper.check()
            self._gateway.complete_maintenance(
                job_id,
                fencing_token=fencing_token,
                succeeded=True,
                result={
                    "kind": "worker_update",
                    "status": "activated",
                    "target_version": target_version,
                    "artifact_sha256": artifact_sha256,
                },
            )
        except BaseException:
            # Keep the pending pointer until the previous runtime starts with
            # the rollback marker. It must report the signed failure before
            # clearing local activation state; otherwise the Gateway would
            # leave the maintenance job in a restart loop.
            return MaintenanceOutcome(
                "maintenance_update_activation_failed",
                False,
                rollback_required=True,
                job_id=job_id,
                error_code=int(ErrorCode.UPDATE_ACTIVATION_FAILED),
            )
        self._updater.mark_activation_succeeded(pointer)
        return MaintenanceOutcome("maintenance_update_activated", True, job_id=job_id)

    def run_one(self) -> MaintenanceOutcome | None:
        if not self.enabled or not hasattr(self._gateway, "claim_maintenance"):
            return None
        job = self._gateway.claim_maintenance(ttl_seconds=60)
        if job is None:
            return None
        try:
            job_id = _required_string(job, "id")
            worker_id = _required_string(job, "worker_id")
            broker_id = _required_string(job, "broker_id")
            kind = _required_string(job, "kind")
            spec = _required_mapping(job, "spec")
            authorization = _required_mapping(job, "authorization")
            fencing_token = _required_positive_int(job, "fencing_token")
            if worker_id != self._credentials.worker_id or kind not in {
                "worker_update",
                "model_install",
                "capability_install",
            }:
                raise _MaintenanceRejected("MAINTENANCE_JOB_INVALID")
            if spec.get("kind") != kind:
                raise _MaintenanceRejected("MAINTENANCE_SPEC_INVALID")
            if not verify_maintenance_intent(
                authorization,
                self._credentials.owner_root_signing_public_key or "",
                expected_worker_id=worker_id,
                expected_broker_id=broker_id,
                expected_kind=kind,
                expected_spec=spec,
            ):
                raise _MaintenanceRejected("MAINTENANCE_INTENT_INVALID")
            self._heartbeat(job_id, fencing_token, "validating", 0, None)
            if kind == "model_install":
                return self._install_models(job_id, fencing_token, spec)
            if kind == "capability_install":
                return self._install_capability(job, job_id, fencing_token, spec)
            return self._stage_update(job, job_id, fencing_token, spec)
        except VGenError:
            # Gateway availability errors are not finalized: the same leased
            # job and model partial can continue after connectivity returns.
            raise
        except ArtifactTransferError:
            if job.get("kind") == "capability_install":
                return self._complete_capability_failure(job, "CAPABILITY_DOWNLOAD_FAILED")
            return self._complete_update_failure(job, "WORKER_UPDATE_DOWNLOAD_FAILED")
        except _MaintenanceCancelled:
            return MaintenanceOutcome(
                "maintenance_cancelled",
                False,
                job_id=(str(job.get("id")) if job.get("id") else None),
            )
        except _MaintenanceRejected as exc:
            return self._complete_rejected(job, exc.code)
        except _ModelInstallJobError as exc:
            return self._complete_model_failure(
                job,
                exc.code,
                installed=exc.installed,
                failed_digest=exc.failed_digest,
            )
        except ModelInstallError as exc:
            return self._complete_model_failure(job, exc.code)
        except CapabilityInstallError as exc:
            return self._complete_capability_failure(job, exc.code)
        except WorkerUpdateError as exc:
            if job.get("kind") == "capability_install":
                return self._complete_capability_failure(job, exc.code)
            return self._complete_update_failure(job, exc.code)
        except (OSError, ValueError, TypeError, KeyError):
            kind = job.get("kind")
            if kind == "model_install":
                return self._complete_model_failure(job, "MAINTENANCE_INTERNAL_ERROR")
            if kind == "capability_install":
                return self._complete_capability_failure(job, "MAINTENANCE_INTERNAL_ERROR")
            return self._complete_update_failure(job, "MAINTENANCE_INTERNAL_ERROR")

    def _install_models(
        self,
        job_id: str,
        fencing_token: int,
        spec: Mapping[str, Any],
    ) -> MaintenanceOutcome:
        workflow_ref = _required_string(spec, "workflow_ref")
        workflow_digest = _required_string(spec, "workflow_digest")
        if not _WORKFLOW_DIGEST.fullmatch(workflow_digest):
            raise _MaintenanceRejected("MAINTENANCE_WORKFLOW_INVALID")
        workflow_bindings = dict(self._executor.maintenance_workflows)
        if workflow_bindings.get(workflow_ref) != workflow_digest:
            raise _MaintenanceRejected("MAINTENANCE_WORKFLOW_NOT_ALLOWED")

        digests = spec.get("model_digests")
        acceptances = spec.get("license_acceptances")
        if (
            not isinstance(digests, list)
            or not digests
            or len(digests) != len(set(digests))
            or not isinstance(acceptances, list)
        ):
            raise _MaintenanceRejected("MAINTENANCE_SPEC_INVALID")
        resolver = getattr(self._executor, "workflow_model_pins", None)
        workflow_pins = (
            tuple(resolver(workflow_ref, workflow_digest))
            if callable(resolver)
            else tuple(self._executor.maintenance_model_pins)
        )
        pins: dict[str, list[Any]] = {}
        for pin in workflow_pins:
            digest = "sha256:" + str(pin.sha256).removeprefix("sha256:").lower()
            pins.setdefault(digest, []).append(pin)
        accepted: dict[str, Mapping[str, Any]] = {}
        for item in acceptances:
            if not isinstance(item, Mapping):
                raise _MaintenanceRejected("MAINTENANCE_LICENSE_INVALID")
            digest = item.get("model_digest")
            if not isinstance(digest, str) or digest in accepted:
                raise _MaintenanceRejected("MAINTENANCE_LICENSE_INVALID")
            accepted[digest] = item
        if set(accepted) != set(digests):
            raise _MaintenanceRejected("MAINTENANCE_LICENSE_INVALID")

        if self._model_installer is None:
            if self._model_root is None:
                raise ModelInstallError("MODEL_ROOT_UNAVAILABLE")
            self._model_installer = ModelInstaller(self._model_root, session=self._session)

        requested: list[tuple[str, tuple[Any, ...]]] = []
        for raw_digest in digests:
            if not isinstance(raw_digest, str) or not _WORKFLOW_DIGEST.fullmatch(raw_digest):
                raise _MaintenanceRejected("MAINTENANCE_MODEL_DIGEST_INVALID")
            digest_pins = pins.get(raw_digest)
            if not digest_pins:
                raise _MaintenanceRejected("MAINTENANCE_MODEL_NOT_ALLOWED")
            acceptance = accepted[raw_digest]
            accepted_at = acceptance.get("accepted_at")
            license_pairs = {(pin.license, pin.revision) for pin in digest_pins}
            if (
                len(license_pairs) != 1
                or (acceptance.get("license_id"), acceptance.get("revision"))
                != next(iter(license_pairs))
                or not isinstance(accepted_at, int)
                or isinstance(accepted_at, bool)
                or accepted_at < 1
                or accepted_at > int(self._clock()) + 300
            ):
                raise _MaintenanceRejected("MAINTENANCE_LICENSE_INVALID")
            requested.append((raw_digest, tuple(digest_pins)))

        installed: list[str] = []
        all_preexisting = True
        for raw_digest, placement_pins in requested:
            placement_preexisting = True
            for pin in placement_pins:
                self._last_progress_at = 0.0
                self._heartbeat(
                    job_id, fencing_token, "downloading", 0, pin.size, ttl_seconds=300
                )

                def progress(completed: int, total: int, *, _job: str = job_id) -> None:
                    now = time.monotonic()
                    if completed == total or now - self._last_progress_at >= 10:
                        self._heartbeat(
                            _job,
                            fencing_token,
                            "downloading",
                            completed,
                            total,
                            ttl_seconds=300,
                        )
                        self._last_progress_at = now

                try:
                    with _LeaseKeeper(
                        self._gateway,
                        job_id,
                        fencing_token,
                        stage="downloading",
                        gateway_lock=self._gateway_lock,
                    ) as keeper:
                        result = self._model_installer.install(pin, progress=progress)
                        keeper.check()
                except ModelInstallError as exc:
                    self._executor.invalidate_model_digest_cache()
                    raise _ModelInstallJobError(
                        exc.code,
                        installed=tuple(installed),
                        failed_digest=raw_digest,
                    ) from exc
                except BaseException:
                    self._executor.invalidate_model_digest_cache()
                    raise
                placement_preexisting = (
                    placement_preexisting and result.status == "already_installed"
                )
                self._heartbeat(job_id, fencing_token, "verifying", result.size, result.size)
            installed.append(result.digest)
            all_preexisting = all_preexisting and placement_preexisting

        self._executor.invalidate_model_digest_cache()
        status = "already_installed" if all_preexisting else "installed"
        self._gateway.complete_maintenance(
            job_id,
            fencing_token=fencing_token,
            succeeded=True,
            result={
                "kind": "model_install",
                "status": status,
                "installed_model_digests": installed,
            },
        )
        return MaintenanceOutcome("maintenance_models_installed", True, job_id=job_id)

    def _install_capability(
        self,
        job: Mapping[str, Any],
        job_id: str,
        fencing_token: int,
        spec: Mapping[str, Any],
    ) -> MaintenanceOutcome:
        workflow_ref = _required_string(spec, "workflow_ref")
        workflow_digest = _required_string(spec, "workflow_digest")
        artifact_sha256 = _required_string(spec, "artifact_sha256").lower()
        artifact_size = _required_positive_int(spec, "artifact_size")
        node_classes_digest = _required_string(spec, "node_classes_digest").lower()
        publisher_key = spec.get("publisher_key")
        allow_unsigned = spec.get("allow_unsigned_workflow")
        if (
            spec.get("kind") != "capability_install"
            or spec.get("apply") != "on_idle"
            or not _WORKFLOW_DIGEST.fullmatch(workflow_digest)
            or not _DIGEST.fullmatch(artifact_sha256)
            or not _DIGEST.fullmatch(node_classes_digest)
            or not isinstance(allow_unsigned, bool)
            or (publisher_key is not None and not isinstance(publisher_key, str))
            or allow_unsigned != (publisher_key is None)
        ):
            raise _MaintenanceRejected("MAINTENANCE_SPEC_INVALID")

        ticket = self._gateway.maintenance_artifact_ticket(job)
        self._validate_update_ticket(ticket, artifact_size, artifact_sha256)
        download_root = self._work_root / "capability-downloads"
        download_root.mkdir(parents=True, exist_ok=True)
        archive = download_root / f"{artifact_sha256}.zip"
        if not _matches_file(archive, artifact_size, artifact_sha256):
            try:
                free = shutil.disk_usage(download_root).free
            except OSError as exc:
                raise CapabilityInstallError("CAPABILITY_DISK_UNAVAILABLE") from exc
            if free < artifact_size + 32 * 1024 * 1024:
                raise CapabilityInstallError("CAPABILITY_DISK_FULL")
            adapter = (
                OssStsArtifactAdapter()
                if ticket.url.startswith("oss://")
                else HttpArtifactAdapter(self._session)
            )

            def progress(completed: int, total: int | None) -> None:
                now = time.monotonic()
                if completed == total or now - self._last_progress_at >= 10:
                    self._heartbeat(
                        job_id,
                        fencing_token,
                        "downloading",
                        completed,
                        total,
                        ttl_seconds=300,
                    )
                    self._last_progress_at = now

            self._last_progress_at = 0.0
            self._heartbeat(
                job_id, fencing_token, "downloading", 0, artifact_size, ttl_seconds=300
            )
            with _LeaseKeeper(
                self._gateway,
                job_id,
                fencing_token,
                stage="downloading",
                gateway_lock=self._gateway_lock,
            ) as keeper:
                adapter.download(ticket, archive, progress)
                keeper.check()
        if not _matches_file(archive, artifact_size, artifact_sha256):
            raise CapabilityInstallError("CAPABILITY_INTEGRITY_FAILED")

        self._heartbeat(
            job_id, fencing_token, "activating", artifact_size, artifact_size, ttl_seconds=300
        )
        if self._capability_store is None:
            self._capability_store = WorkerCapabilityStore(
                self._work_root / "capabilities"
            )
        validator = getattr(self._executor, "validate_capability_release", None)
        activation = self._capability_store.activate(
            archive,
            workflow_ref=workflow_ref,
            workflow_digest=workflow_digest,
            publisher_key=publisher_key,
            allow_unsigned=allow_unsigned,
            node_classes_digest=node_classes_digest,
            validator=validator if callable(validator) else None,
        )
        reload_capabilities = getattr(self._executor, "reload_capabilities", None)
        if callable(reload_capabilities):
            reload_capabilities()
        ready = False
        capability_probe = getattr(self._executor, "capabilities", None)
        if callable(capability_probe):
            try:
                report = capability_probe()
                readiness = report.get("workflow_readiness", [])
                ready = any(
                    isinstance(item, Mapping)
                    and item.get("workflow_ref") == workflow_ref
                    and item.get("workflow_digest") == workflow_digest
                    and item.get("state") == "ready"
                    for item in readiness
                )
            except Exception:
                ready = False
        self._gateway.complete_maintenance(
            job_id,
            fencing_token=fencing_token,
            succeeded=True,
            result={
                "kind": "capability_install",
                "status": activation.status,
                "workflow_ref": workflow_ref,
                "workflow_digest": workflow_digest,
                "artifact_sha256": artifact_sha256,
                "ready": ready,
            },
        )
        return MaintenanceOutcome("maintenance_capability_activated", True, job_id=job_id)

    def _stage_update(
        self,
        job: Mapping[str, Any],
        job_id: str,
        fencing_token: int,
        spec: Mapping[str, Any],
    ) -> MaintenanceOutcome:
        target_version = _required_string(spec, "target_version")
        artifact_sha256 = _required_string(spec, "artifact_sha256").lower()
        artifact_size = _required_positive_int(spec, "artifact_size")
        if (
            spec.get("apply") != "on_idle"
            or not _DIGEST.fullmatch(artifact_sha256)
            or spec.get("kind") != "worker_update"
        ):
            raise _MaintenanceRejected("MAINTENANCE_SPEC_INVALID")
        ticket = self._gateway.maintenance_artifact_ticket(job)
        self._validate_update_ticket(ticket, artifact_size, artifact_sha256)
        download_root = self._updater.download_root
        download_root.mkdir(parents=True, exist_ok=True)
        wheel = download_root / f"vgen-{target_version}-{artifact_sha256[:16]}.whl"
        if not _matches_file(wheel, artifact_size, artifact_sha256):
            try:
                free = shutil.disk_usage(download_root).free
            except OSError as exc:
                raise WorkerUpdateError("WORKER_UPDATE_DISK_UNAVAILABLE", retryable=True) from exc
            if free < artifact_size + 32 * 1024 * 1024:
                raise WorkerUpdateError("WORKER_UPDATE_DISK_FULL")
            adapter = (
                OssStsArtifactAdapter()
                if ticket.url.startswith("oss://")
                else HttpArtifactAdapter(self._session)
            )

            def progress(completed: int, total: int | None) -> None:
                now = time.monotonic()
                if completed == total or now - self._last_progress_at >= 10:
                    self._heartbeat(
                        job_id,
                        fencing_token,
                        "downloading",
                        completed,
                        total,
                        ttl_seconds=300,
                    )
                    self._last_progress_at = now

            self._heartbeat(job_id, fencing_token, "downloading", 0, artifact_size, ttl_seconds=300)
            with _LeaseKeeper(
                self._gateway,
                job_id,
                fencing_token,
                stage="downloading",
                gateway_lock=self._gateway_lock,
            ) as keeper:
                adapter.download(ticket, wheel, progress)
                keeper.check()
        self._heartbeat(job_id, fencing_token, "verifying", artifact_size, artifact_size)
        self._updater.validate_wheel(
            wheel,
            target_version=target_version,
            expected_size=artifact_size,
            expected_sha256=artifact_sha256,
        )
        self._heartbeat(job_id, fencing_token, "staging", 0, None, ttl_seconds=300)
        pointer: dict[str, Any] | None = None
        try:
            with _LeaseKeeper(
                self._gateway,
                job_id,
                fencing_token,
                stage="installing",
                gateway_lock=self._gateway_lock,
            ) as keeper:
                pointer = self._updater.stage(
                    wheel,
                    job_id=job_id,
                    fencing_token=fencing_token,
                    target_version=target_version,
                    expected_size=artifact_size,
                    expected_sha256=artifact_sha256,
                )
                keeper.check()
        except BaseException:
            if pointer is not None:
                self._updater.mark_activation_rolled_back(pointer)
            raise
        try:
            activation = self._gateway.heartbeat_maintenance(
                job_id,
                fencing_token=fencing_token,
                ttl_seconds=300,
                state="restarting",
                progress={
                    "stage": "activating",
                    "completed_bytes": artifact_size,
                    "total_bytes": artifact_size,
                },
            )
        except BaseException:
            if pointer is not None:
                self._updater.mark_activation_rolled_back(pointer)
            raise
        if activation.get("cancelled") is True:
            if pointer is not None:
                self._updater.mark_activation_rolled_back(pointer)
            return MaintenanceOutcome("maintenance_cancelled", False, job_id=job_id)
        # Completion is intentionally deferred until the target interpreter has
        # imported VGen and reached recover_pending_update on its first start.
        return MaintenanceOutcome(
            "maintenance_update_restart", True, restart_required=True, job_id=job_id
        )

    def _heartbeat(
        self,
        job_id: str,
        fencing_token: int,
        stage: str,
        completed: int,
        total: int | None,
        *,
        ttl_seconds: int = 60,
    ) -> None:
        with self._gateway_lock:
            response = self._gateway.heartbeat_maintenance(
                job_id,
                fencing_token=fencing_token,
                ttl_seconds=ttl_seconds,
                state="running",
                progress={
                    "stage": stage,
                    "completed_bytes": int(completed),
                    "total_bytes": None if total is None else int(total),
                },
            )
            if response.get("cancelled") is True:
                raise _MaintenanceCancelled()

    def _complete_rejected(self, job: Mapping[str, Any], _safe_reason: str) -> MaintenanceOutcome:
        if job.get("kind") == "model_install":
            return self._complete_model_failure(job, "MAINTENANCE_REJECTED")
        if job.get("kind") == "capability_install":
            return self._complete_capability_failure(job, "MAINTENANCE_REJECTED")
        return self._complete_update_failure(job, "MAINTENANCE_REJECTED")

    def _complete_model_failure(
        self,
        job: Mapping[str, Any],
        reason: str,
        *,
        installed: tuple[str, ...] = (),
        failed_digest: str | None = None,
    ) -> MaintenanceOutcome:
        job_id = _required_string(job, "id")
        fencing_token = _required_positive_int(job, "fencing_token")
        spec = _required_mapping(job, "spec")
        raw_digests = spec.get("model_digests")
        digests = raw_digests if isinstance(raw_digests, list) else []
        failed = failed_digest or next(
            (
                item
                for item in digests
                if isinstance(item, str) and _WORKFLOW_DIGEST.fullmatch(item)
            ),
            None,
        )
        code = _model_error_code(reason)
        result: dict[str, Any] = {
            "kind": "model_install",
            "status": "failed",
            "installed_model_digests": list(installed),
            "error_code": code,
        }
        if failed is not None:
            result["failed_model_digest"] = failed
        self._gateway.complete_maintenance(
            job_id,
            fencing_token=fencing_token,
            succeeded=False,
            result=result,
        )
        return MaintenanceOutcome("maintenance_model_failed", False, job_id=job_id, error_code=code)

    def _complete_capability_failure(
        self, job: Mapping[str, Any], reason: str
    ) -> MaintenanceOutcome:
        job_id = _required_string(job, "id")
        fencing_token = _required_positive_int(job, "fencing_token")
        spec = _required_mapping(job, "spec")
        workflow_ref = _required_string(spec, "workflow_ref")
        workflow_digest = _required_string(spec, "workflow_digest")
        artifact_sha256 = _required_string(spec, "artifact_sha256")
        code = _capability_error_code(reason)
        self._gateway.complete_maintenance(
            job_id,
            fencing_token=fencing_token,
            succeeded=False,
            result={
                "kind": "capability_install",
                "status": "failed",
                "workflow_ref": workflow_ref,
                "workflow_digest": workflow_digest,
                "artifact_sha256": artifact_sha256,
                "error_code": code,
            },
        )
        return MaintenanceOutcome(
            "maintenance_capability_failed", False, job_id=job_id, error_code=code
        )

    def _complete_update_failure(self, job: Mapping[str, Any], reason: str) -> MaintenanceOutcome:
        job_id = _required_string(job, "id")
        fencing_token = _required_positive_int(job, "fencing_token")
        spec = _required_mapping(job, "spec")
        target_version = spec.get("target_version")
        digest = spec.get("artifact_sha256")
        if not isinstance(target_version, str) or not isinstance(digest, str):
            # The Gateway schema normally makes this unreachable.  Still avoid
            # fabricating a result that can accidentally match another job.
            raise VGenError(ErrorCode.VALIDATION_FAILED)
        code = _update_error_code(reason)
        self._gateway.complete_maintenance(
            job_id,
            fencing_token=fencing_token,
            succeeded=False,
            result={
                "kind": "worker_update",
                "status": "failed",
                "target_version": target_version,
                "artifact_sha256": digest,
                "error_code": code,
            },
        )
        return MaintenanceOutcome(
            "maintenance_update_failed", False, job_id=job_id, error_code=code
        )

    def _validate_update_ticket(
        self, ticket: TransferTicket, expected_size: int, expected_sha256: str
    ) -> None:
        parsed = urlparse(ticket.url)
        oss_ticket = parsed.scheme == "oss"
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "127.0.0.1",
            "::1",
            "localhost",
        }
        if (
            ticket.method != "GET"
            or (parsed.scheme != "https" and not local_http and not oss_ticket)
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or ticket.expected_size != expected_size
            or ticket.expected_sha256 != expected_sha256
        ):
            raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID")
        if oss_ticket:
            endpoint = urlparse(ticket.endpoint or "")
            if (
                endpoint.scheme != "https"
                or not endpoint.hostname
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.path not in {"", "/"}
                or endpoint.query
                or endpoint.fragment
                or not ticket.credentials
            ):
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID")
            addresses = tuple(self._ticket_resolver(str(endpoint.hostname), endpoint.port or 443))
            if not addresses:
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_UNAVAILABLE", retryable=True)
            try:
                if any(not ipaddress.ip_address(address).is_global for address in addresses):
                    raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID")
            except ValueError as exc:
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID") from exc
            return
        if not local_http:
            try:
                port = parsed.port or 443
            except ValueError as exc:
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID") from exc
            if port != 443:
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID")
            addresses = tuple(self._ticket_resolver(str(parsed.hostname), port))
            if not addresses:
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_UNAVAILABLE", retryable=True)
            try:
                if any(not ipaddress.ip_address(address).is_global for address in addresses):
                    raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID")
            except ValueError as exc:
                raise WorkerUpdateError("WORKER_UPDATE_TICKET_INVALID") from exc


class _MaintenanceRejected(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _MaintenanceCancelled(RuntimeError):
    pass


class _ModelInstallJobError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        installed: tuple[str, ...],
        failed_digest: str,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.installed = installed
        self.failed_digest = failed_digest


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise _MaintenanceRejected("MAINTENANCE_JOB_INVALID")
    return item


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    item = value.get(key)
    if not isinstance(item, Mapping):
        raise _MaintenanceRejected("MAINTENANCE_JOB_INVALID")
    return item


def _required_positive_int(value: Mapping[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool) or item < 1:
        raise _MaintenanceRejected("MAINTENANCE_JOB_INVALID")
    return item


def _pending_fields(pointer: Mapping[str, Any]) -> tuple[str, int, str, str]:
    try:
        job_id = str(pointer["pending_job_id"])
        fencing_token = int(pointer["pending_fencing_token"])
        target_version = str(pointer["active_version"])
        artifact_sha256 = str(pointer["artifact_sha256"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID") from exc
    if (
        not job_id
        or fencing_token < 1
        or not target_version
        or not _DIGEST.fullmatch(artifact_sha256)
    ):
        raise WorkerUpdateError("WORKER_UPDATE_POINTER_INVALID")
    return job_id, fencing_token, target_version, artifact_sha256


def _matches_file(path: Path, expected_size: int, expected_sha256: str) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > expected_size:
                    return False
                digest.update(chunk)
    except OSError:
        return False
    return size == expected_size and digest.hexdigest() == expected_sha256


def _model_error_code(reason: str) -> int:
    if "LICENSE" in reason:
        return int(ErrorCode.LICENSE_APPROVAL_REQUIRED)
    if any(item in reason for item in ("SOURCE_INVALID", "SOURCE_NOT_PUBLIC", "REDIRECT")):
        return int(ErrorCode.SOURCE_NOT_ALLOWED)
    if "DISK" in reason:
        return int(ErrorCode.DISK_SPACE_INSUFFICIENT)
    if any(
        item in reason
        for item in (
            "PATH",
            "TARGET_CONFLICT",
            "PARTIAL_UNSAFE",
            "ROOT_UNSAFE",
            "ROOT_UNAVAILABLE",
            "CACHE_UNAVAILABLE",
        )
    ):
        return int(ErrorCode.PATH_CONFLICT)
    if any(item in reason for item in ("INTEGRITY", "SIZE_MISMATCH", "CACHE_CONFLICT")):
        return int(ErrorCode.DIGEST_MISMATCH)
    if any(item in reason for item in ("SOURCE_UNAVAILABLE", "DOWNLOAD", "RANGE")):
        return int(ErrorCode.DOWNLOAD_INTERRUPTED)
    if any(item in reason for item in ("MANUAL", "GATED_CREDENTIAL")):
        return int(ErrorCode.GATED_CREDENTIAL_UNAVAILABLE)
    if any(item in reason for item in ("NOT_ALLOWED", "POLICY", "REJECTED")):
        return int(ErrorCode.MAINTENANCE_POLICY_DENIED)
    if any(item in reason for item in ("INVALID", "AMBIGUOUS", "PIN")):
        return int(ErrorCode.MANIFEST_UNTRUSTED)
    return int(ErrorCode.INTERNAL_ERROR)


def _capability_error_code(reason: str) -> int:
    if "INTEGRITY" in reason or "DIGEST" in reason or "BINDING_MISMATCH" in reason:
        return int(ErrorCode.DIGEST_MISMATCH)
    if "DISK" in reason:
        return int(ErrorCode.DISK_SPACE_INSUFFICIENT)
    if "DOWNLOAD" in reason or "ARTIFACT_UNREADABLE" in reason:
        return int(ErrorCode.DOWNLOAD_INTERRUPTED)
    if any(item in reason for item in ("ROOT", "INDEX", "RELEASE_CONFLICT", "PATH")):
        return int(ErrorCode.PATH_CONFLICT)
    if any(item in reason for item in ("NODE_APPROVAL", "REJECTED", "INTENT", "TICKET")):
        return int(ErrorCode.MAINTENANCE_POLICY_DENIED)
    if any(
        item in reason
        for item in (
            "ARCHIVE",
            "MANIFEST",
            "SPEC",
            "EXECUTOR",
            "EXECUTABLE",
            "VERSION",
            "RELEASE_INVALID",
        )
    ):
        return int(ErrorCode.MANIFEST_UNTRUSTED)
    return int(ErrorCode.INTERNAL_ERROR)


def _update_error_code(reason: str) -> int:
    if "INTEGRITY" in reason or "SIZE_MISMATCH" in reason:
        return int(ErrorCode.DIGEST_MISMATCH)
    if "DISK" in reason:
        return int(ErrorCode.DISK_SPACE_INSUFFICIENT)
    if any(item in reason for item in ("DOWNLOAD", "ARTIFACT_UNREADABLE")):
        return int(ErrorCode.DOWNLOAD_INTERRUPTED)
    if "DOWNGRADE" in reason:
        return int(ErrorCode.UPDATE_DOWNGRADE_DENIED)
    if any(item in reason for item in ("WHEEL_INCOMPATIBLE", "VERSION_MISMATCH")):
        return int(ErrorCode.UPDATE_INCOMPATIBLE)
    if any(item in reason for item in ("INSTALL_FAILED", "RUNTIME", "ROLLBACK", "POINTER")):
        return int(ErrorCode.UPDATE_ACTIVATION_FAILED)
    if any(item in reason for item in ("WHEEL_INVALID", "SPEC_INVALID", "VERSION_INVALID")):
        return int(ErrorCode.MANIFEST_UNTRUSTED)
    if any(item in reason for item in ("TICKET_INVALID", "REJECTED", "INTENT_INVALID")):
        return int(ErrorCode.MAINTENANCE_POLICY_DENIED)
    return int(ErrorCode.INTERNAL_ERROR)


__all__ = ["MaintenanceOutcome", "WorkerMaintenanceController"]
