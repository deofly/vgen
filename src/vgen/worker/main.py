"""``vgen-worker`` identity, diagnostics, and encrypted lease runtime."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import stat
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from packaging.version import InvalidVersion, Version
from platformdirs import user_data_path

from vgen import __version__
from vgen.artifacts import (
    ArtifactAdapterRegistry,
    HttpArtifactAdapter,
    LocalArtifactAdapter,
    OssStsArtifactAdapter,
)
from vgen.executors import Executor, ExecutorRegistry
from vgen.protocol import ErrorCode, VGenError

from .core import (
    GatewayUnavailableError,
    LeaseLostError,
    UploadPendingError,
    WorkerCore,
)
from .credentials import (
    WorkerCredentialError,
    WorkerCredentials,
    WorkerIdentityStore,
    load_worker_credentials_file,
    load_worker_credentials_keyring,
    normalize_worker_gateway_origin,
)
from .gateway import GatewayV1Client
from .host_control import ComfyUIHostControl
from .maintenance import MaintenanceOutcome, WorkerMaintenanceController
from .models import WorkerOutcome
from .node_packs import NodePackInstaller
from .supervisor import (
    EXIT_UPDATE_RESTART,
    EXIT_UPDATE_ROLLBACK,
    is_supervised_child,
    supervise_worker,
)
from .updater import WorkerUpdateError
from .windows_supervisor import prepare_windows_supervisor

logger = logging.getLogger("vgen.worker")

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_UNAVAILABLE = 5
EXIT_EXECUTION_FAILED = 6
EXIT_CRYPTO = 7
_SUPERVISOR_BASE_VERSION_ENV = "VGEN_WORKER_SUPERVISOR_BASE_VERSION"
_STARTUP_ANNOUNCE_INTERVAL_SECONDS = 30.0

ExecutorFactory = Callable[[argparse.Namespace], Executor]
GatewayFactory = Callable[
    [argparse.Namespace, WorkerCredentials, requests.Session], GatewayV1Client
]
CoreFactory = Callable[[argparse.Namespace, Executor, requests.Session], WorkerCore]
MaintenanceFactory = Callable[
    [
        argparse.Namespace,
        WorkerCredentials,
        GatewayV1Client,
        Executor,
        requests.Session,
    ],
    WorkerMaintenanceController,
]


def _newer_supervisor_base_is_waiting() -> bool:
    raw = os.environ.get(_SUPERVISOR_BASE_VERSION_ENV)
    if not raw or len(raw) > 64:
        return False
    try:
        return Version(raw) > Version(__version__)
    except InvalidVersion:
        return False


class WorkerConfigurationError(ValueError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vgen-worker",
        description="VGen provider-neutral encrypted GPU Worker runtime",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    identity = subcommands.add_parser(
        "identity-init",
        help="generate a stable random Worker identity in keyring or a 0600 file",
    )
    identity.add_argument(
        "--account",
        default=os.environ.get("VGEN_WORKER_IDENTITY_ACCOUNT", "default"),
        help="OS keyring account (ignored with --identity-file)",
    )
    identity.add_argument("--identity-file", type=Path)
    identity.add_argument("--force", action="store_true")
    identity.add_argument("--json", action="store_true")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--executor",
        default=os.environ.get("VGEN_WORKER_EXECUTOR", "comfyui"),
        choices=("comfyui",),
    )
    common.add_argument(
        "--comfy-url",
        default=os.environ.get("VGEN_COMFYUI_URL", "http://127.0.0.1:8188"),
    )
    common.add_argument(
        "--comfy-output-dir",
        type=Path,
        default=Path(
            os.environ.get(
                "VGEN_COMFYUI_OUTPUT_DIR",
                str(Path.home() / "ComfyUI" / "output"),
            )
        ),
    )
    common.add_argument(
        "--comfy-model-root",
        type=Path,
        default=(
            Path(os.environ["VGEN_COMFYUI_MODEL_ROOT"])
            if os.environ.get("VGEN_COMFYUI_MODEL_ROOT")
            else None
        ),
        help="ComfyUI models root used to verify policy-pinned model files",
    )
    common.add_argument(
        "--comfy-custom-nodes-root",
        type=Path,
        default=(
            Path(os.environ["VGEN_COMFYUI_CUSTOM_NODES_ROOT"])
            if os.environ.get("VGEN_COMFYUI_CUSTOM_NODES_ROOT")
            else None
        ),
        help="isolated ComfyUI custom_nodes root used to verify pinned Git revisions",
    )
    common.add_argument(
        "--comfy-python-executable",
        type=Path,
        default=(
            Path(os.environ["VGEN_COMFYUI_PYTHON_EXECUTABLE"])
            if os.environ.get("VGEN_COMFYUI_PYTHON_EXECUTABLE")
            else None
        ),
        help="verified ComfyUI Python used for offline Node Pack dependencies",
    )
    common.add_argument(
        "--comfy-policy-file",
        type=Path,
        default=(
            Path(os.environ["VGEN_COMFYUI_POLICY_FILE"])
            if os.environ.get("VGEN_COMFYUI_POLICY_FILE")
            else None
        ),
        help=(
            "local machine-admin graph allowlist (required before authenticated ComfyUI execution)"
        ),
    )
    common.add_argument("--json", action="store_true", help="write one JSON status per line")

    doctor = subcommands.add_parser(
        "doctor",
        parents=(common,),
        help="check the configured executor and print its capabilities",
    )
    doctor.add_argument(
        "--progress",
        action="store_true",
        help="write model verification progress to stderr",
    )

    serve = subcommands.add_parser(
        "serve",
        parents=(common,),
        help="announce, lease, decrypt, execute, and report Gateway work",
    )
    serve.add_argument(
        "--gateway-url",
        default=os.environ.get("VGEN_GATEWAY_URL"),
        help="Gateway endpoint (or VGEN_GATEWAY_URL)",
    )
    serve.add_argument(
        "--worker-id",
        default=os.environ.get("VGEN_WORKER_ID"),
        help="registered Worker ID",
    )
    serve.add_argument(
        "--identity-file",
        type=Path,
        default=(
            Path(os.environ["VGEN_WORKER_IDENTITY_FILE"])
            if os.environ.get("VGEN_WORKER_IDENTITY_FILE")
            else None
        ),
        help="explicit 0600 stable Worker identity file",
    )
    serve.add_argument(
        "--identity-account",
        default=os.environ.get("VGEN_WORKER_IDENTITY_ACCOUNT"),
        help="OS keyring identity account (defaults to Worker ID)",
    )
    serve.add_argument(
        "--credentials-file",
        type=Path,
        default=(
            Path(os.environ["VGEN_WORKER_CREDENTIALS_FILE"])
            if os.environ.get("VGEN_WORKER_CREDENTIALS_FILE")
            else None
        ),
        help="0600 compatibility bundle containing identity and a short session",
    )
    serve.add_argument(
        "--credentials-keyring",
        action="store_true",
        help="load the Worker credential bundle from the OS keyring by Worker ID",
    )
    serve.add_argument(
        "--session-token-file",
        type=Path,
        default=(
            Path(os.environ["VGEN_WORKER_SESSION_FILE"])
            if os.environ.get("VGEN_WORKER_SESSION_FILE")
            else None
        ),
        help="0600 file containing a short-lived Worker session token",
    )
    serve.add_argument(
        "--announce",
        action="store_true",
        help="require authenticated execution mode (normally inferred from credentials)",
    )
    serve.add_argument(
        "--allow-http",
        action="store_true",
        help="allow non-TLS Gateway access (localhost is always allowed)",
    )
    serve.add_argument(
        "--local-artifact-root",
        type=Path,
        action="append",
        default=[],
        help="enable file:// tickets only below this root (repeatable)",
    )
    serve.add_argument("--work-root", type=Path)
    serve.add_argument(
        "--lease-ttl",
        type=int,
        default=int(os.environ.get("VGEN_WORKER_LEASE_TTL", "60")),
    )
    serve.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("VGEN_WORKER_HEALTH_INTERVAL", "5")),
    )
    serve.add_argument("--once", action="store_true", help="poll at most one lease and exit")
    return parser


def _build_executor(arguments: argparse.Namespace) -> Executor:
    if arguments.executor == "comfyui":
        from vgen.executors.comfyui import (
            ComfyUIExecutionPolicy,
            ComfyUIExecutor,
            ComfyUIPolicyError,
            ModelVerificationProgress,
        )

        def show_model_progress(progress: ModelVerificationProgress) -> None:
            file_percent = int(progress.file_bytes_read * 100 / progress.file_size)
            total_percent = (
                100
                if progress.total_size == 0
                else int(progress.total_bytes_read * 100 / progress.total_size)
            )
            file_gib = progress.file_bytes_read / (1024**3)
            file_size_gib = progress.file_size / (1024**3)
            total_gib = progress.total_bytes_read / (1024**3)
            total_size_gib = progress.total_size / (1024**3)
            print(
                f"[vgen] Verifying model {progress.model_index}/{progress.model_count}: "
                f"{progress.path} | file {file_percent}% "
                f"({file_gib:.1f}/{file_size_gib:.1f} GiB) | total {total_percent}% "
                f"({total_gib:.1f}/{total_size_gib:.1f} GiB)",
                file=sys.stderr,
                flush=True,
            )

        try:
            policy = (
                ComfyUIExecutionPolicy.load(arguments.comfy_policy_file)
                if arguments.comfy_policy_file is not None
                else None
            )
        except ComfyUIPolicyError as exc:
            raise WorkerConfigurationError(str(exc)) from exc
        capability_source = None
        if arguments.command == "serve":
            from .capabilities import CapabilityInstallError, WorkerCapabilityStore

            try:
                capability_source = WorkerCapabilityStore(
                    _worker_work_root(arguments) / "capabilities"
                )
            except CapabilityInstallError as exc:
                raise WorkerConfigurationError(exc.code) from exc
        return ComfyUIExecutor(
            arguments.comfy_url,
            arguments.comfy_output_dir,
            policy=policy,
            capability_source=capability_source,
            model_root=arguments.comfy_model_root,
            custom_nodes_root=arguments.comfy_custom_nodes_root,
            model_verification_progress=(
                show_model_progress if getattr(arguments, "progress", False) else None
            ),
        )
    raise WorkerConfigurationError(f"Unsupported executor: {arguments.executor}")


def _build_gateway(
    arguments: argparse.Namespace,
    credentials: WorkerCredentials,
    session: requests.Session,
) -> GatewayV1Client:
    return GatewayV1Client(
        arguments.gateway_url,
        credentials,
        session=session,
        lease_ttl_seconds=arguments.lease_ttl,
        allow_http=arguments.allow_http,
        report_progress=True,
        session_token_provider=(
            (lambda: _session_token(arguments) or "")
            if arguments.session_token_file is not None
            else None
        ),
    )


def _build_core(
    arguments: argparse.Namespace,
    executor: Executor,
    session: requests.Session,
) -> WorkerCore:
    adapters = [HttpArtifactAdapter(session), OssStsArtifactAdapter()]
    if arguments.local_artifact_root:
        adapters.append(LocalArtifactAdapter(tuple(arguments.local_artifact_root)))
    work_root = _worker_work_root(arguments)
    return WorkerCore(
        ExecutorRegistry(executor),
        ArtifactAdapterRegistry(*adapters),
        work_root=work_root,
        heartbeat_interval_seconds=max(0.25, min(15.0, arguments.lease_ttl / 3)),
    )


def _worker_work_root(arguments: argparse.Namespace) -> Path:
    return (
        getattr(arguments, "work_root", None) or (Path(user_data_path("vgen")) / "worker")
    ).expanduser()


def _safe_configured_python(path: Path | None) -> Path | None:
    if path is None:
        return None
    raw = path.expanduser().absolute()
    try:
        metadata = raw.lstat()
        resolved = raw.resolve(strict=True)
    except OSError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or raw.is_symlink() or resolved != raw:
        return None
    return resolved


def _build_maintenance(
    arguments: argparse.Namespace,
    credentials: WorkerCredentials,
    gateway: GatewayV1Client,
    executor: Executor,
    _session: requests.Session,
) -> WorkerMaintenanceController:
    work_root = _worker_work_root(arguments)
    custom_nodes_root = arguments.comfy_custom_nodes_root or getattr(
        executor, "maintenance_custom_nodes_root", None
    )
    node_probe = getattr(executor, "maintenance_node_classes", None)
    node_pack_installer = None
    host_control_ready = prepare_windows_supervisor(work_root)
    if custom_nodes_root is not None and callable(node_probe) and host_control_ready:
        configured_python = _safe_configured_python(arguments.comfy_python_executable)
        installer_python = configured_python or Path(sys.executable).resolve(strict=True)
        node_pack_installer = NodePackInstaller(
            work_root,
            custom_nodes_root,
            installer_python,
            ComfyUIHostControl(work_root),
            node_probe,
            pure_python_only=configured_python is None,
        )
    return WorkerMaintenanceController(
        credentials,
        gateway,
        executor,  # type: ignore[arg-type]
        work_root=work_root,
        model_root=(
            arguments.comfy_model_root or getattr(executor, "maintenance_model_root", None)
        ),
        # Downloads can run while the lease-keeper thread heartbeats through
        # the Gateway client. requests.Session is not a concurrency contract,
        # so maintenance artifacts use a separate connection pool.
        session=requests.Session(),
        node_pack_installer=node_pack_installer,
    )


def _executor_status(executor: Executor) -> dict[str, Any]:
    descriptor = executor.descriptor()
    health = executor.health()
    capabilities: Mapping[str, Any]
    if health.healthy:
        try:
            probed = executor.capabilities()
            if not isinstance(probed, Mapping):
                raise TypeError("executor capabilities must be an object")
            if descriptor.executor_type == "comfyui" and (
                probed.get("capability_schema_version") != 2
                or not isinstance(probed.get("workflow_readiness"), list)
            ):
                raise ValueError("ComfyUI capability schema is unavailable")
            capabilities = probed
        except Exception as exc:
            health = type(health)(
                False,
                "capability_probe_failed",
                details={"error_type": type(exc).__name__},
            )
            capabilities = _fail_closed_executor_capabilities(descriptor.executor_type)
    else:
        capabilities = _fail_closed_executor_capabilities(descriptor.executor_type)
    return {
        "ok": health.healthy,
        "executor": {
            "type": descriptor.executor_type,
            "version": descriptor.version,
            "payload_formats": list(descriptor.payload_formats),
            "operations": list(descriptor.operations),
            "max_concurrency": descriptor.max_concurrency,
            "health": health.status,
            "health_details": dict(health.details),
            "capabilities": dict(capabilities),
        },
    }


def _starting_executor_status(executor: Executor) -> dict[str, Any]:
    """Build a fast, fail-closed descriptor before any large model hashing."""

    descriptor = executor.descriptor()
    return {
        "ok": False,
        "executor": {
            "type": descriptor.executor_type,
            "version": descriptor.version,
            "payload_formats": list(descriptor.payload_formats),
            "operations": list(descriptor.operations),
            "max_concurrency": descriptor.max_concurrency,
            "health": "starting",
            "health_details": {},
            "capabilities": _fail_closed_executor_capabilities(descriptor.executor_type),
        },
    }


def _executor_status_with_startup_liveness(
    executor: Executor,
    gateway: GatewayV1Client,
    keepalive_capabilities: Mapping[str, Any],
) -> dict[str, Any]:
    """Keep a cold-starting ComfyUI Worker online during its full model probe."""

    stop = threading.Event()

    def keep_alive() -> None:
        while not stop.wait(_STARTUP_ANNOUNCE_INTERVAL_SECONDS):
            try:
                gateway.announce(keepalive_capabilities)
            except Exception:
                # A transient transport failure must not permanently disable
                # cold-start liveness. The foreground full announce remains the
                # authoritative error/reporting path after the probe completes.
                logger.debug("Worker startup liveness announce will retry")

    thread = threading.Thread(
        target=keep_alive,
        name="vgen-worker-startup-liveness",
        daemon=True,
    )
    thread.start()
    try:
        status = _executor_status(executor)
    finally:
        stop.set()
        thread.join()
    return status


def _fail_closed_executor_capabilities(executor_type: str) -> dict[str, Any]:
    """Keep modern workflow scheduling fail-closed when probing is unavailable."""

    if executor_type != "comfyui":
        return {}
    return {
        "capability_schema_version": 2,
        "model_digests": [],
        "ready_workflow_digests": [],
        "workflow_readiness": [],
    }


def _gateway_url(value: str, *, allow_http: bool) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WorkerConfigurationError("Gateway URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise WorkerConfigurationError(
            "Gateway URL must not contain credentials, query, or fragment."
        )
    localhost = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if parsed.scheme != "https" and not allow_http and not localhost:
        raise WorkerConfigurationError(
            "Remote Gateway URLs must use HTTPS (or explicitly pass --allow-http)."
        )
    return value.rstrip("/")


def _session_token(arguments: argparse.Namespace) -> str | None:
    environment_token = os.environ.get("VGEN_WORKER_SESSION_TOKEN")
    if arguments.session_token_file is None:
        return environment_token
    expanded = arguments.session_token_file.expanduser()
    if expanded.is_symlink():
        raise WorkerConfigurationError("Worker session token file must not be a symbolic link.")
    path = expanded.resolve()
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if os.name != "nt" and mode & 0o077:
            raise WorkerConfigurationError("Worker session token file must have mode 0600.")
        token = path.read_text(encoding="utf-8").strip()
    except WorkerConfigurationError:
        raise
    except OSError as exc:
        raise WorkerConfigurationError("Worker session token file cannot be read.") from exc
    if not token:
        raise WorkerConfigurationError("Worker session token file is empty.")
    return token


def _runtime_credentials(arguments: argparse.Namespace) -> WorkerCredentials | None:
    if arguments.credentials_file is not None and arguments.credentials_keyring:
        raise WorkerConfigurationError("Choose either --credentials-file or --credentials-keyring.")
    if arguments.credentials_keyring:
        if not arguments.worker_id:
            raise WorkerConfigurationError("--credentials-keyring requires --worker-id.")
        try:
            return load_worker_credentials_keyring(arguments.worker_id)
        except WorkerCredentialError as exc:
            raise WorkerConfigurationError(str(exc)) from exc
    if arguments.credentials_file is not None:
        try:
            credentials = load_worker_credentials_file(arguments.credentials_file)
        except WorkerCredentialError as exc:
            raise WorkerConfigurationError(str(exc)) from exc
        if arguments.worker_id and arguments.worker_id != credentials.worker_id:
            raise WorkerConfigurationError(
                "Credential bundle Worker ID does not match --worker-id."
            )
        return credentials
    token = _session_token(arguments)
    if not token:
        return None
    if not arguments.worker_id:
        raise WorkerConfigurationError("A session token requires --worker-id.")
    account = arguments.identity_account or arguments.worker_id
    try:
        identity = WorkerIdentityStore().load(account, file_path=arguments.identity_file)
    except WorkerCredentialError as exc:
        raise WorkerConfigurationError(str(exc)) from exc
    return WorkerCredentials(arguments.worker_id, identity.device_keys, token)


def _gateway_probe(base_url: str, *, session: requests.Session) -> dict[str, Any]:
    try:
        response = session.get(f"{base_url}/healthz", timeout=(10, 20))
        if response.status_code >= 400:
            return {
                "ok": False,
                "status": "gateway_rejected_health",
                "http_status": response.status_code,
            }
        return {"ok": True, "status": "ready"}
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status": "gateway_unreachable",
            "code": 700001,
            "error_type": type(exc).__name__,
        }


def _write_status(status: Mapping[str, Any], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps(status, ensure_ascii=False, sort_keys=True))
        return
    executor = status["executor"]
    line = f"executor={executor['type']} version={executor['version']} health={executor['health']}"
    gateway = status.get("gateway")
    if isinstance(gateway, Mapping):
        line += f" gateway={gateway.get('status')}"
    line += f" mode={status.get('mode', 'unknown')}"
    print(line, flush=True)


def _announced_capabilities(
    status: Mapping[str, Any],
    *,
    maintenance_actions: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the single-executor descriptor from one coherent health probe.

    This keeps the Worker online for signed model/update maintenance without
    advertising missing models or unavailable GPUs as executable capacity, and
    avoids a second capability probe producing a different scheduling view.
    """

    executor = status["executor"]
    if not isinstance(executor, Mapping):
        raise WorkerConfigurationError("Executor status must be an object.")
    capabilities = executor.get("capabilities")
    nested = dict(capabilities) if isinstance(capabilities, Mapping) else {}
    if executor.get("type") == "comfyui" and nested.get("capability_schema_version") != 2:
        nested = _fail_closed_executor_capabilities("comfyui")
    return {
        "worker_runtime_version": __version__,
        # Negotiate the signed capability-spec shape explicitly. Published
        # 0.13.10 builds predate bound dependency receipts, so semver alone is
        # not evidence that this protocol is implemented.
        "capability_install_spec_version": 2,
        "node_pack_install_spec_version": 1,
        "maintenance_actions": list(maintenance_actions),
        "executors": [
            {
                "type": executor["type"],
                "version": executor["version"],
                "payload_formats": list(executor["payload_formats"]),
                "operations": list(executor["operations"]),
                "max_concurrency": executor["max_concurrency"],
                "capabilities": nested,
            }
        ],
    }


def _reconcile_gateway_workflow_authorizations(
    executor: Executor, response: object
) -> None:
    """Apply an optional new-Gateway authorization snapshot fail closed.

    Older Gateways omit the field and remain compatible. A malformed snapshot
    is never interpreted as an empty set, avoiding accidental mass
    deactivation on protocol corruption.
    """

    # Test doubles and pre-contract Gateway adapters historically returned no
    # response body. Treat that exactly like an older Gateway omitting the new
    # optional field.
    if response is None:
        return
    if not isinstance(response, Mapping):
        raise WorkerConfigurationError("Gateway workflow authorizations are invalid.")
    if "workflow_authorizations" not in response:
        return
    values = response.get("workflow_authorizations")
    if not isinstance(values, list):
        raise WorkerConfigurationError("Gateway workflow authorizations are invalid.")
    reconcile = getattr(executor, "reconcile_workflow_authorizations", None)
    if not callable(reconcile):
        return
    try:
        reconcile(values)
    except (TypeError, ValueError, RuntimeError, OSError) as exc:
        raise WorkerConfigurationError("Gateway workflow authorizations are invalid.") from exc


def _enabled_maintenance_actions(
    controller: WorkerMaintenanceController | None,
) -> tuple[str, ...]:
    if controller is None or not bool(getattr(controller, "enabled", False)):
        return ()
    actions = getattr(
        controller,
        "supported_actions",
        ("worker_update", "model_install", "capability_install", "node_pack_install"),
    )
    return tuple(str(action) for action in actions)


def _can_poll_inference(executor: Executor, status: Mapping[str, Any]) -> bool:
    if not bool(status.get("ok")):
        return False
    if not getattr(executor, "requires_execution_policy", False):
        return True
    try:
        return bool(getattr(executor, "execution_policy_configured", False))
    except Exception:
        return False


def _apply_maintenance_outcome(status: dict[str, Any], outcome: MaintenanceOutcome) -> None:
    status["mode"] = outcome.mode
    status["maintenance_job_id"] = outcome.job_id
    status["maintenance_succeeded"] = outcome.succeeded
    if outcome.error_code is not None:
        status["ok"] = False
        status["failure"] = {
            "code": outcome.error_code,
            "name": "WORKER_MAINTENANCE_FAILED",
        }


def _identity_init(arguments: argparse.Namespace) -> int:
    try:
        identity = WorkerIdentityStore().generate(
            arguments.account,
            file_path=arguments.identity_file,
            overwrite=arguments.force,
        )
    except WorkerCredentialError as exc:
        raise WorkerConfigurationError(str(exc)) from exc
    value = {
        "ok": True,
        "storage": "file" if arguments.identity_file else "keyring",
        "account": arguments.account,
        **identity.public_info(),
    }
    if arguments.json:
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    else:
        print(f"worker_identity={value['key_id']} storage={value['storage']}")
    return EXIT_OK


def run(
    argv: Sequence[str] | None = None,
    *,
    executor_factory: ExecutorFactory = _build_executor,
    gateway_factory: GatewayFactory = _build_gateway,
    core_factory: CoreFactory = _build_core,
    maintenance_factory: MaintenanceFactory = _build_maintenance,
    http_session: requests.Session | None = None,
) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "identity-init":
            return _identity_init(arguments)
        executor = executor_factory(arguments)
        if arguments.command == "doctor":
            status = _executor_status(executor)
            status["mode"] = "diagnostic"
            _write_status(status, json_output=arguments.json)
            return EXIT_OK if status["ok"] else EXIT_UNAVAILABLE

        if arguments.interval <= 0:
            raise WorkerConfigurationError("Worker health interval must be positive.")
        if not 15 <= arguments.lease_ttl <= 300:
            raise WorkerConfigurationError("Worker lease TTL must be between 15 and 300 seconds.")
        gateway_url = (
            _gateway_url(arguments.gateway_url, allow_http=arguments.allow_http)
            if arguments.gateway_url
            else None
        )
        if arguments.announce and gateway_url is None:
            raise WorkerConfigurationError("--announce requires --gateway-url.")
        credentials = _runtime_credentials(arguments)
        if credentials is not None and credentials.owner_root_signing_public_key is not None:
            configure_capability_trust = getattr(
                executor,
                "configure_capability_trust",
                None,
            )
            if callable(configure_capability_trust):
                configure_capability_trust(
                    credentials.owner_root_signing_public_key,
                    credentials.worker_id,
                )
        if gateway_url is not None and credentials is not None and credentials.gateway_url:
            try:
                selected_gateway = normalize_worker_gateway_origin(gateway_url)
            except WorkerCredentialError as exc:
                raise WorkerConfigurationError(str(exc)) from exc
            if selected_gateway != credentials.gateway_url:
                raise WorkerConfigurationError(
                    "Worker credentials are bound to a different Gateway; refusing to start. "
                    "Use the reviewed Worker re-enrollment flow instead."
                )
        if arguments.announce and credentials is None:
            raise WorkerConfigurationError(
                "--announce requires a Worker identity and short-lived session."
            )
        session = http_session or requests.Session()
        gateway = (
            gateway_factory(arguments, credentials, session)
            if gateway_url is not None and credentials is not None
            else None
        )
        core = core_factory(arguments, executor, session) if gateway is not None else None
        maintenance = (
            maintenance_factory(arguments, credentials, gateway, executor, session)
            if gateway is not None and credentials is not None
            else None
        )
        stopping = False
        last_announced_capabilities: dict[str, Any] | None = None

        def stop(_signum: int, _frame: object) -> None:
            nonlocal stopping
            stopping = True

        if not arguments.once:
            signal.signal(signal.SIGINT, stop)
            signal.signal(signal.SIGTERM, stop)

        while not stopping:
            recovered: MaintenanceOutcome | None = None
            recovery_error: Exception | None = None
            activation_status: dict[str, Any] | None = None
            announced_this_iteration = False

            def probe_activated_runtime() -> dict[str, Any]:
                nonlocal activation_status
                # Importing the new runtime plus an authenticated fail-closed
                # announce proves that the Worker control path is usable. A
                # multi-minute model hash is neither necessary for update
                # activation nor safe ahead of durable output recovery.
                activation_status = _starting_executor_status(executor)
                return _announced_capabilities(
                    activation_status,
                    maintenance_actions=_enabled_maintenance_actions(maintenance),
                )

            def announce_activated_runtime(capabilities: Any) -> None:
                nonlocal announced_this_iteration, last_announced_capabilities
                if gateway is None:
                    raise WorkerConfigurationError(
                        "Worker update activation requires a Gateway connection."
                    )
                if not isinstance(capabilities, Mapping):
                    raise WorkerConfigurationError(
                        "Worker update activation produced invalid capabilities."
                    )
                response = gateway.announce(capabilities)
                _reconcile_gateway_workflow_authorizations(executor, response)
                announced_this_iteration = True
                last_announced_capabilities = dict(capabilities)

            if gateway is not None and core is not None and maintenance is not None:
                try:
                    # Do this before probing ComfyUI or hashing large model
                    # files. A newly selected runtime must confirm/rollback its
                    # pending activation before any other Worker operation.
                    recovered = maintenance.recover_pending_update(
                        activation_probe=probe_activated_runtime,
                        activation_announce=announce_activated_runtime,
                    )
                except (
                    GatewayUnavailableError,
                    LeaseLostError,
                    VGenError,
                    WorkerUpdateError,
                ) as exc:
                    recovery_error = exc

            startup_status = activation_status or _starting_executor_status(executor)
            startup_capabilities = _announced_capabilities(
                startup_status,
                maintenance_actions=_enabled_maintenance_actions(maintenance),
            )
            startup_resume_checked = False
            startup_resumed: WorkerOutcome | None = None
            startup_resume_error: Exception | None = None
            update_requires_exit = bool(
                recovered and (recovered.restart_required or recovered.rollback_required)
            )
            update_requires_exit = update_requires_exit or bool(
                recovered
                and recovered.mode == "maintenance_update_activated"
                and _newer_supervisor_base_is_waiting()
            )
            if (
                gateway is not None
                and core is not None
                and recovery_error is None
                and not update_requires_exit
            ):
                try:
                    # Restore the control-plane channel and renew any fenced
                    # upload attempt before ComfyUI hashes large model files.
                    safe_liveness_capabilities = last_announced_capabilities or startup_capabilities
                    if not announced_this_iteration:
                        response = gateway.announce(safe_liveness_capabilities)
                        _reconcile_gateway_workflow_authorizations(executor, response)
                        announced_this_iteration = True
                        last_announced_capabilities = dict(safe_liveness_capabilities)
                except Exception:
                    # Ticket renewal below performs its own authenticated
                    # request. A transient idle-heartbeat failure must not move
                    # a model scan ahead of a recoverable output attempt.
                    logger.debug("Initial Worker startup announce will retry")
                try:
                    startup_resumed = core.resume_pending(gateway)
                    startup_resume_checked = True
                except (
                    GatewayUnavailableError,
                    LeaseLostError,
                    UploadPendingError,
                    VGenError,
                ) as exc:
                    startup_resume_checked = True
                    startup_resume_error = exc

            status: dict[str, Any]
            if update_requires_exit:
                # A non-target or rolled-back runtime must yield to the stable
                # supervisor immediately; probing ComfyUI here only delays the
                # required process transition and can hash tens of GiB.
                status = startup_status
            elif startup_resumed is not None or startup_resume_error is not None:
                status = startup_status
            elif (
                gateway is not None
                and core is not None
                and maintenance is not None
                and recovery_error is None
                and not bool(
                    recovered and (recovered.restart_required or recovered.rollback_required)
                )
            ):
                if startup_status["executor"]["type"] == "comfyui":
                    keepalive_capabilities = last_announced_capabilities or startup_capabilities
                    status = _executor_status_with_startup_liveness(
                        executor,
                        gateway,
                        keepalive_capabilities,
                    )
                else:
                    status = _executor_status(executor)
            else:
                status = _executor_status(executor)
            if gateway is not None and core is not None:
                try:
                    if recovery_error is not None:
                        raise recovery_error
                    if startup_resume_error is not None:
                        raise startup_resume_error
                    if recovered is not None:
                        _apply_maintenance_outcome(status, recovered)
                        status["gateway"] = {"ok": True, "status": "connected"}
                        if recovered.rollback_required:
                            _write_status(status, json_output=arguments.json)
                            return EXIT_UPDATE_ROLLBACK
                        if recovered.restart_required:
                            _write_status(status, json_output=arguments.json)
                            return EXIT_UPDATE_RESTART
                        if (
                            recovered.mode == "maintenance_update_activated"
                            and _newer_supervisor_base_is_waiting()
                        ):
                            # The pending target completed its signed Gateway
                            # transaction. Yield immediately so the stable
                            # supervisor can select its newer reviewed base.
                            status["mode"] = "maintenance_update_superseded"
                            _write_status(status, json_output=arguments.json)
                            return EXIT_UPDATE_RESTART

                    # Announce a generic descriptor even if ComfyUI is down or
                    # models are missing, so the Gateway can deliver maintenance.
                    announced = _announced_capabilities(
                        status,
                        maintenance_actions=_enabled_maintenance_actions(maintenance),
                    )
                    if announced != last_announced_capabilities:
                        response = gateway.announce(announced)
                        _reconcile_gateway_workflow_authorizations(executor, response)
                        announced_this_iteration = True
                        last_announced_capabilities = dict(announced)
                    resumed = (
                        startup_resumed if startup_resume_checked else core.resume_pending(gateway)
                    )
                    if resumed is not None:
                        status["mode"] = "upload_resumed"
                        status["succeeded"] = resumed.succeeded
                        status["ok"] = resumed.succeeded
                        status["gateway"] = {"ok": True, "status": "connected"}
                        if resumed.failure is not None:
                            status["ok"] = False
                            status["failure"] = {
                                "code": int(resumed.failure.code),
                                "name": resumed.failure.name,
                            }
                    else:
                        maintenance_outcome = (
                            maintenance.run_one() if maintenance is not None else None
                        )
                        if maintenance_outcome is not None:
                            _apply_maintenance_outcome(status, maintenance_outcome)
                            status["gateway"] = {"ok": True, "status": "connected"}
                            if maintenance_outcome.rollback_required:
                                _write_status(status, json_output=arguments.json)
                                return EXIT_UPDATE_ROLLBACK
                            if maintenance_outcome.restart_required:
                                _write_status(status, json_output=arguments.json)
                                return EXIT_UPDATE_RESTART
                        elif not _can_poll_inference(executor, status):
                            status["mode"] = "maintenance_only"
                            status["gateway"] = {"ok": True, "status": "connected"}
                        else:
                            lease = gateway.poll_lease()
                            if lease is None:
                                status["mode"] = "idle"
                                status["gateway"] = {"ok": True, "status": "connected"}
                            else:
                                outcome = core.process(lease, gateway)
                                status["mode"] = "executed"
                                status["attempt_id"] = lease.reference.attempt_id
                                status["succeeded"] = outcome.succeeded
                                status["gateway"] = {"ok": True, "status": "connected"}
                                if outcome.failure is not None:
                                    status["failure"] = {
                                        "code": int(outcome.failure.code),
                                        "name": outcome.failure.name,
                                    }
                                    status["ok"] = False
                except UploadPendingError as exc:
                    status["ok"] = False
                    status["mode"] = "upload_pending"
                    status["attempt_id"] = exc.attempt_id
                    status["gateway"] = {"ok": True, "status": "connected"}
                    status["failure"] = {
                        "code": int(exc.code),
                        "name": exc.name,
                    }
                except GatewayUnavailableError:
                    status["ok"] = False
                    status["mode"] = "unavailable"
                    status["gateway"] = {
                        "ok": False,
                        "status": "gateway_unreachable",
                        "code": 700001,
                    }
                except LeaseLostError:
                    status["ok"] = False
                    status["mode"] = "lease_lost"
                    status["gateway"] = {
                        "ok": False,
                        "status": "lease_lost",
                        "code": 310001,
                    }
                except VGenError as exc:
                    status["ok"] = False
                    status["mode"] = "gateway_error"
                    status["gateway"] = {
                        "ok": False,
                        "status": "gateway_rejected_request",
                        "code": int(exc.code),
                    }
                except WorkerUpdateError:
                    status["ok"] = False
                    status["mode"] = "maintenance_update_error"
                    status["gateway"] = {"ok": True, "status": "connected"}
                    status["failure"] = {
                        "code": int(ErrorCode.EXECUTOR_UNAVAILABLE),
                        "name": "WORKER_UPDATE_RUNTIME_INVALID",
                    }
            elif gateway_url:
                status["gateway"] = _gateway_probe(gateway_url, session=session)
                status["ok"] = status["ok"] and status["gateway"]["ok"]
                status["mode"] = "readiness"
            else:
                status["mode"] = "readiness"
            _write_status(status, json_output=arguments.json)
            if arguments.once:
                if status["ok"]:
                    return EXIT_OK
                failure = status.get("failure")
                if isinstance(failure, Mapping) and 400000 <= int(failure["code"]) < 500000:
                    return EXIT_CRYPTO
                gateway_status = status.get("gateway")
                if (
                    isinstance(gateway_status, Mapping)
                    and 400000 <= int(gateway_status.get("code", 0)) < 500000
                ):
                    return EXIT_CRYPTO
                if status.get("mode") == "executed":
                    return EXIT_EXECUTION_FAILED
                return EXIT_UNAVAILABLE
            deadline = time.monotonic() + arguments.interval
            while not stopping and time.monotonic() < deadline:
                time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
        return EXIT_OK
    except WorkerConfigurationError as exc:
        print(f"vgen-worker: {exc}", file=sys.stderr)
        return EXIT_CONFIG


def run_entrypoint(argv: Sequence[str] | None = None) -> int:
    selected_argv = list(sys.argv[1:] if argv is None else argv)
    arguments = build_parser().parse_args(selected_argv)
    if arguments.command == "serve" and not arguments.once and not is_supervised_child():
        try:
            return supervise_worker(selected_argv, work_root=_worker_work_root(arguments))
        except WorkerUpdateError as exc:
            print(f"vgen-worker: {exc.code}", file=sys.stderr)
            return EXIT_CONFIG
    return run(selected_argv)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("VGEN_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    raise SystemExit(run_entrypoint())


if __name__ == "__main__":
    main()
