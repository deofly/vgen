"""Provision a Windows Worker and emit a private, one-click installation bundle."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import tempfile
import time
import zipfile
from dataclasses import dataclass
from importlib import metadata, resources
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlparse

from vgen import __version__
from vgen.crypto import (
    build_allocation_proof_payload,
    sign_allocation_proof,
    sign_key_manifest,
)
from vgen.worker.credentials import WorkerCredentials, WorkerIdentity

from .auth import login_worker_session

if TYPE_CHECKING:
    from .client import GatewayClient
    from .identity_store import DeviceIdentity


_BUNDLE_FORMAT = "vgen-windows-worker-bundle"
_BUNDLE_VERSION = 1
_EXECUTOR_VERSION = "1.1.0"
_POLICY_NAME = "comfyui-minimax-h3-policy.yaml"
_SCRIPT_NAME = "setup-worker.ps1"
_LAUNCHER_NAME = "start-worker.cmd"
_ENROLLMENT_SCRIPT_NAME = "enroll-worker.ps1"
_WORKER_UPDATE_VERSION = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")


class WorkerBundleError(ValueError):
    """A safe, user-actionable bundle provisioning error."""


@dataclass(frozen=True, slots=True)
class WorkerBundleResult:
    path: Path
    worker_name: str
    pool_name: str

    def public_dict(self) -> dict[str, str]:
        return {
            "bundle": str(self.path),
            "worker_name": self.worker_name,
            "pool_name": self.pool_name,
            "next": "Extract the ZIP on Windows, then double-click start-worker.cmd.",
        }


@dataclass(frozen=True, slots=True)
class WorkerInstallerBundleResult:
    """A credential-free bundle safe for public release distribution."""

    path: Path
    gateway_url: str

    def public_dict(self) -> dict[str, str]:
        return {
            "bundle": str(self.path),
            "gateway": self.gateway_url,
            "credentials": "generated-locally-after-one-time-invite",
            "next": "Extract the ZIP on Windows, then run enroll-worker.ps1.",
        }


@dataclass(frozen=True, slots=True)
class WorkerUpdateArtifact:
    path: Path
    version: str
    size_bytes: int
    sha256: str


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _asset_bytes(name: str) -> bytes:
    packaged = resources.files("vgen").joinpath("assets", "worker", name)
    if packaged.is_file():
        return packaged.read_bytes()
    repository = Path(__file__).resolve().parents[3]
    if name in {_SCRIPT_NAME, _LAUNCHER_NAME, _ENROLLMENT_SCRIPT_NAME}:
        source = repository / "examples" / "windows-worker" / name
    else:
        source = repository / "examples" / name
    try:
        return source.read_bytes()
    except OSError as exc:
        raise WorkerBundleError(f"Bundled Windows Worker asset is unavailable: {name}") from exc


def _validate_wheel(name: str, value: bytes, *, expected_version: str = __version__) -> None:
    expected_name = f"vgen-{expected_version}-py3-none-any.whl"
    if name != expected_name:
        raise WorkerBundleError(f"The Worker wheel must be named {expected_name}.")
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            names = archive.namelist()
            if any(
                item.startswith(("/", "\\")) or ".." in Path(item.replace("\\", "/")).parts
                for item in names
            ):
                raise WorkerBundleError("The Worker wheel contains an unsafe path.")
            metadata_names = [item for item in names if item.endswith(".dist-info/METADATA")]
            wheel_names = [item for item in names if item.endswith(".dist-info/WHEEL")]
            if len(metadata_names) != 1 or len(wheel_names) != 1:
                raise WorkerBundleError("The Worker wheel metadata is incomplete.")
            package_metadata = archive.read(metadata_names[0]).decode("utf-8")
            wheel_metadata = archive.read(wheel_names[0]).decode("utf-8")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile, KeyError) as exc:
        raise WorkerBundleError("The Worker wheel is not a readable Python wheel.") from exc
    if not re.search(r"(?m)^Name:\s*vgen\s*$", package_metadata):
        raise WorkerBundleError("The Worker wheel is not the VGen distribution.")
    if not re.search(rf"(?m)^Version:\s*{re.escape(expected_version)}\s*$", package_metadata):
        raise WorkerBundleError(f"The Worker wheel must be VGen {expected_version}.")
    if not re.search(r"(?m)^Tag:\s*py3-none-any\s*$", wheel_metadata):
        raise WorkerBundleError("The Worker wheel must be the reviewed py3-none-any build.")


def _validate_public_installer_wheel(value: bytes) -> None:
    """Reject a stale wheel which cannot perform local Invite enrollment."""

    required = {
        "vgen/cli/main.py",
        "vgen/cli/worker_enrollment.py",
        "vgen/assets/worker/enroll-worker.ps1",
    }
    try:
        with zipfile.ZipFile(io.BytesIO(value)) as archive:
            missing = sorted(required - set(archive.namelist()))
    except zipfile.BadZipFile as exc:
        raise WorkerBundleError("The Worker wheel is not a readable Python wheel.") from exc
    if missing:
        raise WorkerBundleError(
            "The Worker wheel predates credential-free enrollment; build the current release first."
        )


def inspect_worker_update_wheel(path: Path) -> WorkerUpdateArtifact:
    """Validate a local, pure-Python VGen wheel without importing its code."""

    expanded = path.expanduser()
    try:
        if expanded.is_symlink():
            raise WorkerBundleError("The Worker update wheel must not be a symbolic link.")
        resolved = expanded.resolve(strict=True)
        metadata = resolved.stat()
    except WorkerBundleError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WorkerBundleError("The Worker update wheel must be a regular local file.") from exc
    if not resolved.is_file() or resolved.is_symlink():
        raise WorkerBundleError("The Worker update wheel must be a regular local file.")
    match = re.fullmatch(r"vgen-(.+)-py3-none-any\.whl", resolved.name)
    if match is None or not match.group(1):
        raise WorkerBundleError(
            "The Worker update wheel must be named vgen-<version>-py3-none-any.whl."
        )
    version = match.group(1)
    if _WORKER_UPDATE_VERSION.fullmatch(version) is None:
        raise WorkerBundleError("The Worker update wheel version must be MAJOR.MINOR.PATCH.")
    if not 1 <= metadata.st_size <= 512 * 1024 * 1024:
        raise WorkerBundleError("The Worker update wheel size is outside the supported limit.")
    try:
        value = resolved.read_bytes()
    except OSError as exc:
        raise WorkerBundleError("The Worker update wheel cannot be read.") from exc
    if len(value) != metadata.st_size:
        raise WorkerBundleError("The Worker update wheel changed while it was being reviewed.")
    _validate_wheel(resolved.name, value, expected_version=version)
    return WorkerUpdateArtifact(
        path=resolved,
        version=version,
        size_bytes=len(value),
        sha256=_sha256(value),
    )


def _direct_url_wheel() -> Path | None:
    try:
        raw = metadata.distribution("vgen").read_text("direct_url.json")
        value = json.loads(raw) if raw else {}
        parsed = urlparse(str(value.get("url", "")))
        if parsed.scheme != "file":
            return None
        path = Path(unquote(parsed.path))
        return path if path.suffix == ".whl" and path.is_file() else None
    except (metadata.PackageNotFoundError, OSError, ValueError, json.JSONDecodeError):
        return None


def _installed_wheel_bytes() -> tuple[str, bytes]:
    """Rebuild the installed pure-Python distribution without network access."""

    try:
        distribution = metadata.distribution("vgen")
        files = distribution.files or []
    except metadata.PackageNotFoundError as exc:
        raise WorkerBundleError(
            "No VGen Worker wheel is available. Reinstall the downloadable VGen CLI package."
        ) from exc

    selected: list[tuple[str, bytes]] = []
    dist_info_prefix: str | None = None
    for entry in files:
        relative = str(entry).replace("\\", "/")
        first = relative.split("/", 1)[0]
        if first == "vgen":
            pass
        elif first.endswith(".dist-info") and first.lower().startswith("vgen-"):
            dist_info_prefix = first
        else:
            continue
        if relative.endswith(".dist-info/RECORD"):
            continue
        resolved = Path(distribution.locate_file(entry))
        if not resolved.is_file() or resolved.is_symlink():
            continue
        selected.append((relative, resolved.read_bytes()))

    if not selected or dist_info_prefix is None:
        raise WorkerBundleError(
            "The installed VGen CLI cannot materialize its Worker wheel; reinstall the CLI."
        )

    record_name = f"{dist_info_prefix}/RECORD"
    buffer = io.BytesIO()
    records: list[list[str]] = []
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in sorted(selected):
            info = zipfile.ZipInfo(name, (2020, 2, 2, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, value)
            digest = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
            records.append([name, f"sha256={digest}", str(len(value))])
        record_buffer = io.StringIO(newline="")
        writer = csv.writer(record_buffer, lineterminator="\n")
        writer.writerows(records)
        writer.writerow([record_name, "", ""])
        info = zipfile.ZipInfo(record_name, (2020, 2, 2, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, record_buffer.getvalue().encode("utf-8"))
    return f"vgen-{__version__}-py3-none-any.whl", buffer.getvalue()


def load_worker_wheel(explicit: Path | None = None) -> tuple[str, bytes]:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit.expanduser())
    else:
        repository = Path(__file__).resolve().parents[3]
        candidates.extend(
            sorted((repository / "dist").glob(f"vgen-{__version__}-py3-none-any.whl"))
        )
        direct = _direct_url_wheel()
        if direct is not None and direct not in candidates:
            candidates.append(direct)

    if candidates:
        selected = candidates[0].resolve()
        try:
            value = selected.read_bytes()
        except OSError as exc:
            raise WorkerBundleError("The selected Worker wheel cannot be read.") from exc
        _validate_wheel(selected.name, value)
        return selected.name, value

    name, value = _installed_wheel_bytes()
    _validate_wheel(name, value)
    return name, value


def select_pool(
    pools: list[dict[str, Any]],
    *,
    requested: str | None,
    default: str | None = None,
) -> dict[str, Any]:
    selector = requested or default
    if selector:
        matches = [
            pool for pool in pools if selector in {str(pool.get("id")), str(pool.get("name"))}
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise WorkerBundleError(f"No active Pool named '{selector}' exists in this Workspace.")
        raise WorkerBundleError(
            f"More than one active Pool is named '{selector}'. Rename one first."
        )
    if len(pools) == 1:
        return pools[0]
    if not pools:
        raise WorkerBundleError(
            "This Workspace has no Pool. Create one, then run this command again."
        )
    names = ", ".join(sorted(str(pool.get("name") or "unnamed") for pool in pools))
    raise WorkerBundleError(f"Choose a Pool by name with --pool. Available Pools: {names}")


def _safe_output_path(output: Path | None, worker_name: str) -> Path:
    if output is None:
        target_root = Path.home() / "Downloads"
        if not target_root.is_dir():
            target_root = Path.cwd()
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", worker_name.strip()).strip("-.") or "worker"
        output = target_root / f"vgen-worker-{slug}.zip"
    target = output.expanduser().resolve()
    if target.suffix.lower() != ".zip":
        raise WorkerBundleError("Worker bundle output must use the .zip extension.")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _safe_installer_output_path(output: Path | None) -> Path:
    if output is None:
        target_root = Path.home() / "Downloads"
        if not target_root.is_dir():
            target_root = Path.cwd()
        output = target_root / f"vgen-windows-worker-installer-{__version__}.zip"
    target = output.expanduser().resolve()
    if target.suffix.lower() != ".zip":
        raise WorkerBundleError("Worker installer bundle output must use the .zip extension.")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _validated_gateway_origin(value: str) -> str:
    endpoint = value.strip().rstrip("/")
    try:
        parsed = urlparse(endpoint)
        _ = parsed.port
    except ValueError as exc:
        raise WorkerBundleError("Gateway URL is invalid.") from exc
    localhost = (parsed.hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or (parsed.scheme != "https" and not localhost)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise WorkerBundleError(
            "Gateway URL must be an HTTPS origin without credentials, path, query, or fragment."
        )
    return endpoint


def _write_public_installer_bundle(
    target: Path,
    *,
    overwrite: bool,
    entries: list[tuple[str, bytes, int]],
) -> None:
    if target.exists() and not overwrite:
        raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        checksums = b"".join(
            f"{_sha256(value)}  {name}\n".encode("ascii") for name, value, _ in entries
        )
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value, mode in [*entries, ("SHA256SUMS", checksums, 0o644)]:
                info = zipfile.ZipInfo(name, (2020, 2, 2, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = mode << 16
                archive.writestr(info, value)
        if target.exists() and not overwrite:
            raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
        os.replace(temporary, target)
        os.chmod(target, 0o644)
    finally:
        temporary.unlink(missing_ok=True)


def create_public_windows_worker_installer_bundle(
    *,
    gateway_url: str,
    output: Path | None = None,
    wheel_path: Path | None = None,
    overwrite: bool = False,
) -> WorkerInstallerBundleResult:
    """Create a reusable Windows ZIP with no principal credentials.

    The ZIP is byte-for-byte independent of a Worker or Invite.  Windows
    generates its private key only after extraction and the Invite is entered
    into a hidden prompt.  Authenticating this public ZIP is the responsibility
    of the signed release manifest/notarized installer layer.
    """

    endpoint = _validated_gateway_origin(gateway_url)
    target = _safe_installer_output_path(output)
    if target.exists() and not overwrite:
        raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
    script = _asset_bytes(_SCRIPT_NAME)
    launcher = _asset_bytes(_LAUNCHER_NAME)
    enrollment_script = _asset_bytes(_ENROLLMENT_SCRIPT_NAME)
    policy = _asset_bytes(_POLICY_NAME)
    wheel_name, wheel = load_worker_wheel(wheel_path)
    _validate_public_installer_wheel(wheel)
    config = {
        "format": _BUNDLE_FORMAT,
        "version": _BUNDLE_VERSION,
        "gateway_url": endpoint,
        "worker_credentials": "worker-credentials.json",
        "comfyui_root": None,
        "wheel": {
            "name": wheel_name,
            "version": __version__,
            "sha256": _sha256(wheel),
        },
        "policy": {"name": _POLICY_NAME, "sha256": _sha256(policy)},
        "enrollment": {
            "kind": "worker",
            "secret_input": "hidden_prompt_or_stdin",
            "identity": "generated_on_worker",
        },
    }
    config_bytes = json.dumps(config, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    install_text = (
        b"VGen Windows Worker\r\n"
        b"===================\r\n\r\n"
        b"1. Extract every file in this ZIP to a normal local folder.\r\n"
        b"2. Right-click enroll-worker.ps1 and choose Run with PowerShell.\r\n"
        b"3. Paste the one-time Invite only into the hidden VGen prompt.\r\n"
        b"4. Send the displayed verification code to the Workspace owner through "
        b"a trusted channel.\r\n"
        b"5. The owner approves with: vgen worker approve-enrollment <id> --code "
        b"<displayed-code>\r\n\r\n"
        b"This public installer contains no Worker identity or credentials.\r\n"
    )
    _write_public_installer_bundle(
        target,
        overwrite=overwrite,
        entries=[
            ("INSTALL.txt", install_text, 0o644),
            (_ENROLLMENT_SCRIPT_NAME, enrollment_script, 0o644),
            (_LAUNCHER_NAME, launcher, 0o755),
            (_SCRIPT_NAME, script, 0o644),
            ("vgen-worker-bundle.json", config_bytes, 0o644),
            (_POLICY_NAME, policy, 0o644),
            (wheel_name, wheel, 0o644),
        ],
    )
    return WorkerInstallerBundleResult(target, endpoint)


def _write_private_bundle(
    target: Path,
    *,
    overwrite: bool,
    config: dict[str, Any],
    script: bytes,
    launcher: bytes,
    policy: bytes,
    wheel_name: str,
    wheel: bytes,
    credentials: bytes,
) -> None:
    if target.exists() and not overwrite:
        raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            entries = (
                (_LAUNCHER_NAME, launcher, 0o755),
                (_SCRIPT_NAME, script, 0o644),
                (
                    "vgen-worker-bundle.json",
                    json.dumps(config, indent=2, sort_keys=True).encode() + b"\n",
                    0o644,
                ),
                (_POLICY_NAME, policy, 0o644),
                (wheel_name, wheel, 0o644),
                ("worker-credentials.json", credentials, 0o600),
            )
            for name, value, mode in entries:
                info = zipfile.ZipInfo(name, time.localtime()[:6])
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = mode << 16
                archive.writestr(info, value)
        if target.exists() and not overwrite:
            raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def create_windows_worker_bundle(
    client: GatewayClient,
    owner_identity: DeviceIdentity,
    *,
    worker_name: str,
    workspace_id: str,
    pool: str | None,
    default_pool: str | None,
    output: Path | None,
    comfyui_root: str | None,
    compute_rate: int,
    traffic_rate: int,
    manager_broker_id: str | None = None,
    wheel_path: Path | None = None,
    overwrite: bool = False,
) -> WorkerBundleResult:
    if not worker_name.strip():
        raise WorkerBundleError("Worker name is required.")
    if compute_rate < 0 or traffic_rate < 0:
        raise WorkerBundleError("Worker rates cannot be negative.")

    target = _safe_output_path(output, worker_name)
    script = _asset_bytes(_SCRIPT_NAME)
    launcher = _asset_bytes(_LAUNCHER_NAME)
    policy = _asset_bytes(_POLICY_NAME)
    wheel_name, wheel = load_worker_wheel(wheel_path)
    if target.exists() and not overwrite:
        raise WorkerBundleError(f"Refusing to overwrite existing bundle: {target}")

    pools = client.request("GET", f"/api/v1/workspaces/{workspace_id}/pools")
    if not isinstance(pools, list):
        raise WorkerBundleError("Gateway returned an invalid Pool list.")
    selected_pool = select_pool(pools, requested=pool, default=default_pool)
    pool_id = str(selected_pool["id"])
    pool_name = str(selected_pool["name"])

    identity = WorkerIdentity.generate()
    owner_certificate = sign_key_manifest(
        owner_identity.root_keys,
        {
            "version": 1,
            "kind": "vgen-worker-owner-certificate",
            "owner_root_key_id": owner_identity.root_key_id,
            "worker_key_id": identity.key_id,
            "worker_signing_public_key": identity.public_info()["signing_public_key"],
            "worker_encryption_public_key": identity.public_info()["encryption_public_key"],
            "issued_at": int(time.time()),
        },
    )
    worker_id: str | None = None
    try:
        worker = client.request(
            "POST",
            "/api/v1/workers",
            json_body=identity.public_registration(
                name=worker_name.strip(),
                executor_type="comfyui",
                executor_version=_EXECUTOR_VERSION,
                capacity=1,
                manager_broker_id=manager_broker_id,
                certificate=json.dumps(owner_certificate, separators=(",", ":")),
            ),
            idempotency_key=f"worker-bundle:{identity.key_id}",
        )
        worker_id = str(worker["id"])
        session = login_worker_session(client.profile, worker_id, identity.device_keys)
        allocation = client.request(
            "POST",
            f"/api/v1/workers/{worker_id}/offer",
            json_body={"pool_id": pool_id},
            idempotency_key=f"worker-offer:{worker_id}:{pool_id}",
        )
        allocation = client.request("GET", f"/api/v1/worker-allocations/{allocation['id']}")
        worker_manifest = allocation.get("worker")
        if not isinstance(worker_manifest, dict):
            raise WorkerBundleError("Gateway allocation response has no Worker key manifest.")
        proof_payload = build_allocation_proof_payload(
            allocation_id=str(allocation["id"]),
            workspace_id=str(allocation["workspace_id"]),
            pool_id=str(allocation["pool_id"]),
            worker_id=str(allocation["worker_id"]),
            worker_signing_public_key=str(worker_manifest["signing_public_key"]),
            worker_encryption_public_key=str(worker_manifest["encryption_public_key"]),
            worker_certificate=worker_manifest["certificate"],
            owner_consent_at=float(allocation["owner_consent_at"]),
            approver_root_key_id=owner_identity.root_key_id,
        )
        client.request(
            "POST",
            f"/api/v1/worker-allocations/{allocation['id']}/approve",
            json_body={"proof": sign_allocation_proof(owner_identity.root_keys, proof_payload)},
            idempotency_key=(
                f"allocation-approve:{allocation['id']}:{proof_payload['owner_consent_at_ms']}"
            ),
        )
        rate = client.request(
            "POST",
            f"/api/v1/workers/{worker_id}/rates",
            json_body={
                "workspace_id": workspace_id,
                "rate_microtokens_per_gpu_second": compute_rate,
                "traffic_microtokens_per_gib": traffic_rate,
            },
            idempotency_key=(
                f"worker-rate:{worker_id}:{workspace_id}:{compute_rate}:{traffic_rate}"
            ),
        )
        client.request(
            "POST",
            f"/api/v1/rates/{rate['id']}/approve",
            json_body={},
            idempotency_key=f"rate-approve:{rate['id']}",
        )
        credentials = WorkerCredentials(
            worker_id=worker_id,
            device_keys=identity.device_keys,
            session_token=str(session["token"]),
            owner_root_signing_public_key=owner_identity.root_signing_public_key,
        )
        config = {
            "format": _BUNDLE_FORMAT,
            "version": _BUNDLE_VERSION,
            "gateway_url": client.profile.endpoint,
            "worker_credentials": "worker-credentials.json",
            "comfyui_root": comfyui_root,
            "wheel": {
                "name": wheel_name,
                "version": __version__,
                "sha256": _sha256(wheel),
            },
            "policy": {"name": _POLICY_NAME, "sha256": _sha256(policy)},
        }
        _write_private_bundle(
            target,
            overwrite=overwrite,
            config=config,
            script=script,
            launcher=launcher,
            policy=policy,
            wheel_name=wheel_name,
            wheel=wheel,
            credentials=credentials.to_bytes(),
        )
    except Exception:
        if worker_id is not None:
            try:
                client.request(
                    "POST",
                    f"/api/v1/workers/{worker_id}/revoke",
                    json_body={},
                    idempotency_key=f"worker-revoke:{worker_id}",
                )
            except Exception as cleanup_exc:
                raise WorkerBundleError(
                    "Bundle creation failed and automatic Worker cleanup could not be confirmed; "
                    "inspect `vgen worker list` before retrying."
                ) from cleanup_exc
        raise

    return WorkerBundleResult(target, worker_name.strip(), pool_name)
