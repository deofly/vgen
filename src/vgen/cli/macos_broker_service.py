from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_log_path

LABEL = "com.vgen.home-broker"
MANAGED_MARKER = "VGEN_MANAGED_HOME_BROKER_V1"
_RELOAD_TIMEOUT_SECONDS = 5.0
_RELOAD_POLL_SECONDS = 0.05


@dataclass(frozen=True, slots=True)
class BrokerServiceResult:
    label: str
    plist_path: Path
    loaded: bool
    error: str | None = None


def launch_agent_payload(
    *,
    python_executable: Path,
    profile_name: str,
    broker_id: str,
    broker_device_id: str,
    log_directory: Path,
) -> dict[str, object]:
    """Build the user LaunchAgent without putting a session or secret in it."""

    return {
        "Label": LABEL,
        "ProgramArguments": [
            str(python_executable),
            "-m",
            "vgen.broker.main",
            "serve",
            "--broker-id",
            broker_id,
            "--broker-device-id",
            broker_device_id,
            "--profile",
            profile_name,
        ],
        "EnvironmentVariables": {
            "PYTHONUNBUFFERED": "1",
            "VGEN_LAUNCH_AGENT_MARKER": MANAGED_MARKER,
        },
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "ThrottleInterval": 10,
        "StandardOutPath": str(log_directory / "home-broker.log"),
        "StandardErrorPath": str(log_directory / "home-broker-error.log"),
    }


def _is_managed_payload(value: object) -> bool:
    if not isinstance(value, dict) or value.get("Label") != LABEL:
        return False
    environment = value.get("EnvironmentVariables")
    return (
        isinstance(environment, dict)
        and environment.get("VGEN_LAUNCH_AGENT_MARKER") == MANAGED_MARKER
    )


def _run_launchctl(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )


def _launchctl_message(result: subprocess.CompletedProcess[str]) -> str | None:
    output = (result.stderr or result.stdout or "").strip()
    if not output:
        return None
    # launchctl can emit a multi-line diagnostic. Keep the setup error readable and
    # bounded while still exposing the actual reason that was previously discarded.
    compact = " ".join(output.split())
    return compact if len(compact) <= 300 else f"{compact[:297]}..."


def _operation_already_in_progress(result: subprocess.CompletedProcess[str]) -> bool:
    message = _launchctl_message(result)
    return result.returncode == 37 or (
        message is not None and "operation already in progress" in message.casefold()
    )


def _wait_until_unloaded(
    *,
    launchctl: str,
    service: str,
    deadline: float,
) -> bool:
    while True:
        if _run_launchctl([launchctl, "print", service]).returncode != 0:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(_RELOAD_POLL_SECONDS, remaining))


def _bootstrap_with_retry(
    *,
    launchctl: str,
    domain: str,
    service: str,
    plist_path: Path,
    deadline: float,
) -> subprocess.CompletedProcess[str]:
    command = [launchctl, "bootstrap", domain, str(plist_path)]
    while True:
        result = _run_launchctl(command)
        if result.returncode == 0:
            return result
        # A failed bootstrap can still have loaded the service. Avoid submitting the
        # same job again when launchd has already accepted it.
        if _run_launchctl([launchctl, "print", service]).returncode == 0:
            return subprocess.CompletedProcess(command, 0, result.stdout, result.stderr)
        if not _operation_already_in_progress(result):
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return result
        time.sleep(min(_RELOAD_POLL_SECONDS, remaining))


def install_macos_broker_service(
    *,
    profile_name: str,
    broker_id: str,
    broker_device_id: str,
    python_executable: Path | None = None,
    launch_agents_directory: Path | None = None,
    log_directory: Path | None = None,
    launchctl: str = "/bin/launchctl",
) -> BrokerServiceResult:
    """Install and load the current user's Home Broker LaunchAgent.

    Existing files are replaced only when they carry VGen's explicit marker.
    This keeps one-click setup idempotent without overwriting an unrelated
    LaunchAgent that happens to use the same filename.
    """

    if sys.platform != "darwin":
        raise ValueError("automatic Home Broker service installation currently requires macOS")
    agents = launch_agents_directory or Path.home() / "Library" / "LaunchAgents"
    logs = log_directory or user_log_path("vgen")
    plist_path = agents / f"{LABEL}.plist"
    if plist_path.is_symlink():
        raise ValueError(f"refusing to replace symbolic link: {plist_path}")
    if plist_path.exists():
        try:
            existing = plistlib.loads(plist_path.read_bytes())
        except (OSError, plistlib.InvalidFileException) as exc:
            raise ValueError(
                f"existing LaunchAgent is not a valid VGen file: {plist_path}"
            ) from exc
        if not _is_managed_payload(existing):
            raise ValueError(f"refusing to overwrite an unmanaged LaunchAgent: {plist_path}")

    agents.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    # A virtualenv's interpreter is commonly a symlink to the base Python.  Launch the
    # symlink itself so Python discovers the virtualenv and its installed vgen package.
    # Path.absolute() makes relative overrides safe for launchd without resolving links.
    interpreter = (python_executable or Path(sys.executable)).expanduser().absolute()
    payload = launch_agent_payload(
        python_executable=interpreter,
        profile_name=profile_name,
        broker_id=broker_id,
        broker_device_id=broker_device_id,
        log_directory=logs,
    )
    temporary = plist_path.with_suffix(".plist.tmp")
    temporary.write_bytes(plistlib.dumps(payload, sort_keys=False))
    temporary.chmod(0o600)
    temporary.replace(plist_path)

    domain = f"gui/{os.getuid()}"
    service = f"{domain}/{LABEL}"
    deadline = time.monotonic() + _RELOAD_TIMEOUT_SECONDS
    bootout = _run_launchctl([launchctl, "bootout", service])
    if not _wait_until_unloaded(launchctl=launchctl, service=service, deadline=deadline):
        detail = _launchctl_message(bootout)
        error = "launchd did not finish stopping the previous Home Broker within 5 seconds"
        if detail:
            error = f"{error}: {detail}"
        return BrokerServiceResult(
            label=LABEL,
            plist_path=plist_path,
            loaded=False,
            error=error,
        )

    bootstrap = _bootstrap_with_retry(
        launchctl=launchctl,
        domain=domain,
        service=service,
        plist_path=plist_path,
        deadline=deadline,
    )
    loaded = bootstrap.returncode == 0
    if loaded:
        _run_launchctl([launchctl, "enable", service])
    detail = _launchctl_message(bootstrap) if not loaded else None
    error = f"launchctl bootstrap failed: {detail}" if detail else None
    return BrokerServiceResult(
        label=LABEL,
        plist_path=plist_path,
        loaded=loaded,
        error=error,
    )
