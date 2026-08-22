from __future__ import annotations

import hashlib
import importlib.util
import os
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILDER_PATH = ROOT / "tools" / "build_gateway_bundle.py"
BUILDER_SPEC = importlib.util.spec_from_file_location("vgen_build_gateway_bundle", BUILDER_PATH)
assert BUILDER_SPEC is not None and BUILDER_SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(BUILDER_SPEC)
BUILDER_SPEC.loader.exec_module(BUILDER)
BUNDLE_NAME = BUILDER.BUNDLE_NAME
VERSION = BUILDER.VERSION
WHEEL_NAME = BUILDER.WHEEL_NAME
build_bundle = BUILDER.build_bundle
INSTALLER = ROOT / "examples" / "ecs" / "setup-gateway.sh"


def _write_test_wheel(
    path: Path,
    *,
    version: str = VERSION,
    distribution: str = "vgen",
    tag: str = "py3-none-any",
) -> Path:
    dist_info = f"vgen-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            f"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: {tag}\n",
        )
    return path


def _run_installer(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(INSTALLER), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )


def _runtime_with_distribution(tmp_path: Path, version: str) -> tuple[Path, Path]:
    runtime = tmp_path / f"runtime-{version}"
    binary = runtime / "bin" / "python"
    binary.parent.mkdir(parents=True)
    binary.symlink_to(sys.executable)
    packages = tmp_path / f"packages-{version}"
    metadata = packages / f"vgen-{version}.dist-info" / "METADATA"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(
        f"Metadata-Version: 2.4\nName: vgen\nVersion: {version}\n",
        encoding="utf-8",
    )
    return runtime, packages


def test_gateway_installer_has_valid_bash_syntax_and_concise_help() -> None:
    syntax = subprocess.run(
        ["bash", "-n", str(INSTALLER)], check=False, capture_output=True, text=True
    )
    assert syntax.returncode == 0, syntax.stderr

    result = _run_installer("--help")
    assert result.returncode == 0
    assert "sudo ./setup-gateway.sh install \\" in result.stdout
    assert "--artifact-store oss" in result.stdout
    assert "Task media must use oss" in result.stdout
    assert "Release files remain local" in result.stdout
    assert "sudo ./setup-gateway.sh resume --domain vgen.example.com" in result.stdout
    assert "sudo ./setup-gateway.sh activate --domain vgen.example.com" in result.stdout
    assert "sudo ./setup-gateway.sh upgrade --domain vgen.example.com" in result.stdout
    assert "sudo ./setup-gateway.sh reset-test --domain vgen.example.com" in result.stdout
    assert "Non-interactive upgrade additionally requires --confirm-upgrade" in result.stdout
    assert "OSS mode uses only an ECS RAM Role" in result.stdout


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("install", "--domain", "https://vgen.example.com"), "valid lowercase DNS hostname"),
        (
            (
                "install",
                "--domain",
                "vgen.example.com",
                "--confirm-domain",
                "other.example.com",
            ),
            "must exactly match",
        ),
        (
            (
                "install",
                "--domain",
                "vgen.example.com",
                "--confirm-domain",
                "vgen.example.com",
            ),
            "requires --confirm-no-active-tasks",
        ),
        (
            (
                "activate",
                "--domain",
                "vgen.example.com",
                "--confirm-domain",
                "vgen.example.com",
            ),
            "requires --confirm-activate",
        ),
        (
            (
                "upgrade",
                "--domain",
                "vgen.example.com",
                "--confirm-domain",
                "vgen.example.com",
            ),
            "requires --confirm-upgrade",
        ),
        (
            (
                "reset-test",
                "--domain",
                "vgen.example.com",
                "--confirm-domain",
                "vgen.example.com",
                "--confirm-no-active-tasks",
            ),
            "requires --confirm-reset-test",
        ),
    ],
)
def test_gateway_installer_fails_closed_before_mutation(
    arguments: tuple[str, ...], message: str
) -> None:
    result = _run_installer(*arguments)
    assert result.returncode != 0
    assert message in result.stderr


def test_gateway_release_version_comes_from_pyproject_and_installer_bundle() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    unit = (ROOT / "examples" / "ecs" / "vgen-gateway.service").read_text(
        encoding="utf-8"
    )
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project_version = tomllib.load(handle)["project"]["version"]

    assert VERSION == project_version
    assert WHEEL_NAME == f"vgen-{project_version}-py3-none-any.whl"
    assert BUNDLE_NAME == f"vgen-gateway-{project_version}"
    assert "readonly VGEN_VERSION=" not in source
    assert "EXPECTED_WHEEL_SHA256" not in source
    assert "EXPECTED_SERVICE_SHA256" not in source
    assert 'wheel_candidates+=("${candidate}")' in source
    assert "exactly one VGen py3-none-any wheel" in source
    assert 'metadata.get("Version", "")' in source
    assert 'path.name != f"vgen-{version}-py3-none-any.whl"' in source
    assert "release manifest validation failed" in source
    assert '"VGEN_ARTIFACT_STORE=oss"' in source
    assert '"${WHEEL_PATH}[gateway,oss]"' in source
    assert 'VGEN_SETUP_OSS_ECS_ROLE="${OSS_ECS_ROLE}"' in source
    assert "01-ecs-role-assume-policy.json" in source
    assert "02-transfer-role-trust-policy.json" in source
    assert "03-transfer-role-oss-policy.json" in source
    assert "--confirm-oss-configured" in source
    assert "VGEN_ARTIFACT_ROOT" not in source
    assert "source.backup(target)" in source
    assert '--resolve "${DOMAIN}:443:127.0.0.1"' in source
    assert "Next steps:" in source
    assert "sudo cat %s" in source
    assert "Paste it only into the hidden VGen prompt" in source
    assert "vgen setup --gateway https://%s" in source
    assert "LEGACY_GATEWAY_BRIDGE_VERSION" not in source
    assert "LEGACY_V1_" not in source
    assert 'readonly INSTALL_ROOT="/opt/vgen"' in source
    assert 'readonly DATA_ROOT="/var/lib/vgen"' in source
    assert 'readonly CONFIG_ROOT="/etc/vgen"' in source
    assert 'readonly BACKUP_ROOT="/var/backups/vgen"' in source
    assert "WorkingDirectory=/opt/vgen" in unit
    assert "EnvironmentFile=/etc/vgen/gateway.env" in unit
    assert "--database /var/lib/vgen/vgen-gateway.db" in unit
    assert "ReadWritePaths=/var/lib/vgen" in unit
    assert 'usermod --home "${DATA_ROOT}" --shell /usr/sbin/nologin vgen' in source
    assert 'verify_service_user_configuration' in source
    assert 'Gateway service user home must be ${DATA_ROOT}' in source


def test_gateway_installer_validates_oss_configuration_before_mutation() -> None:
    missing_role = _run_installer(
        "install",
        "--domain",
        "vgen.example.com",
        "--confirm-domain",
        "vgen.example.com",
        "--confirm-no-active-tasks",
        "--artifact-store",
        "oss",
        "--oss-endpoint",
        "https://oss-cn-hangzhou.aliyuncs.com",
        "--oss-bucket",
        "vgen-private",
    )
    assert missing_role.returncode != 0
    assert "--oss-ecs-role is required" in missing_role.stderr

    prohibited_local = _run_installer(
        "install",
        "--domain",
        "vgen.example.com",
        "--confirm-domain",
        "vgen.example.com",
        "--confirm-no-active-tasks",
        "--artifact-store",
        "local",
    )
    assert prohibited_local.returncode != 0
    assert "local artifact storage is prohibited" in prohibited_local.stderr

    source = INSTALLER.read_text(encoding="utf-8")
    install = source.split("install_gateway() {", 1)[1].split("\n}", 1)[0]
    assert install.index("write_gateway_environment") < install.index(
        'verify_artifact_store_access_at "${INSTALL_ROOT}/venv"'
    )
    assert install.index('verify_artifact_store_access_at "${INSTALL_ROOT}/venv"') < (
        install.index("initialize_gateway")
    )


def test_gateway_upgrade_preserves_oss_sdk_and_probes_role_access() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    stage = source.split("stage_upgrade_runtime() {", 1)[1].split("\n}", 1)[0]
    assert '"${WHEEL_PATH}[gateway,oss]"' in stage
    assert "verify_artifact_store_access_at" in stage
    environment = source.split("verify_existing_gateway_environment() {", 1)[1].split(
        "write_gateway_environment() {", 1
    )[0]
    assert 'values.get("VGEN_ARTIFACT_STORE") != "oss"' in environment
    assert "local ArtifactStore" not in environment


def test_gateway_sts_preflight_can_read_root_only_environment_and_resume_new_runtime() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    verifier = source.split("verify_artifact_store_access_at() {", 1)[1].split("\n}", 1)[0]
    assert 'env VGEN_GATEWAY_ENVIRONMENT_PATH="${ENVIRONMENT_PATH}"' in verifier
    assert "runuser -u vgen" not in verifier
    resume = source.split("prepare_resume_runtime() {", 1)[1].split("\n}", 1)[0]
    assert 'mv -- "${INSTALL_ROOT}/venv" "${backup_runtime}"' in resume
    assert "install_python_runtime" in resume
    resume_action = source.split("resume_gateway() {", 1)[1].split("\n}", 1)[0]
    assert "prepare_resume_runtime" in resume_action


def test_gateway_test_reset_is_recoverable_and_does_not_touch_cloud_resources() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    body = source.split("reset_test_gateway() {", 1)[1].split("\n}", 1)[0]
    assert '[[ "${CONFIRM_RESET_TEST}" -eq 1 ]]' in body
    assert '[[ "${CONFIRM_NO_ACTIVE_TASKS}" -eq 1 ]]' in body
    assert 'systemctl disable --now "${SERVICE_NAME}"' in body
    assert 'mv -- "${INSTALL_ROOT}"' in body
    assert 'mv -- "${DATA_ROOT}"' in body
    assert 'mv -- "${CONFIG_ROOT}"' in body
    assert 'mv -- "${UNIT_PATH}"' in body
    assert "rm -rf" not in body
    assert "NGINX_CONFIG_PATH" not in body
    assert "RELEASE_ROOT" not in body
    assert "OSS objects were not changed" in body


def test_fresh_gateway_install_can_start_without_a_legacy_nginx_virtual_host() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    preconditions = source.split("verify_install_nginx_and_tls() {", 1)[1].split(
        "\n}", 1
    )[0]
    switch = source.split("switch_nginx() {", 1)[1].split("\n}", 1)[0]
    fallback = source.split("render_uninitialized_nginx_config() {", 1)[1].split(
        "render_previous_gateway_nginx_config() {", 1
    )[0]
    assert 'if [[ ! -e "${NGINX_CONFIG_PATH}" ]]' in preconditions
    assert "verify_gateway_tls_certificate" in preconditions
    assert 'if [[ -e "${NGINX_CONFIG_PATH}" ]]' in switch
    assert "render_uninitialized_nginx_config" in switch
    assert "return 503" in fallback
    assert "proxy_pass" not in fallback


def test_gateway_runtime_version_accepts_release(tmp_path: Path) -> None:
    installed = VERSION
    runtime, packages = _runtime_with_distribution(tmp_path, installed)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; read_runtime_version "$2"',
            "bash",
            str(INSTALLER),
            str(runtime),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ
        | {
            "PYTHONPATH": str(packages),
            "VGEN_SETUP_LIBRARY_ONLY": "1",
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == installed


@pytest.mark.parametrize("installed", ["2.0.0a1", "2.0.0a2", "0.2.1rc1"])
def test_gateway_runtime_version_rejects_prerelease_versions(
    tmp_path: Path, installed: str
) -> None:
    runtime, packages = _runtime_with_distribution(tmp_path, installed)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; read_runtime_version "$2"',
            "bash",
            str(INSTALLER),
            str(runtime),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ
        | {
            "PYTHONPATH": str(packages),
            "VGEN_SETUP_LIBRARY_ONLY": "1",
        },
    )
    assert result.returncode != 0
    assert "installed VGen version is not a supported release version" in result.stderr


@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        ("0.2.0", "-1"),
        (VERSION, "0"),
        ("2.0.0", "1"),
    ],
)
def test_gateway_upgrade_orders_release_versions(
    tmp_path: Path, installed: str, expected: str
) -> None:
    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "python3.11").symlink_to(sys.executable)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; compare_release_versions "$2" "$3"',
            "bash",
            str(INSTALLER),
            installed,
            VERSION,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ
        | {
            "PATH": f"{commands}:{os.environ['PATH']}",
            "VGEN_SETUP_LIBRARY_ONLY": "1",
        },
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


def test_gateway_runtime_permissions_are_readable_and_executable(tmp_path: Path) -> None:
    runtime = tmp_path / "venv"
    binary = runtime / "bin" / "python"
    module = runtime / "lib" / "vgen.py"
    binary.parent.mkdir(parents=True, mode=0o700)
    module.parent.mkdir(parents=True, mode=0o700)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    module.write_text("VERSION = 1\n", encoding="utf-8")
    runtime.chmod(0o700)
    binary.parent.chmod(0o700)
    module.parent.chmod(0o700)
    binary.chmod(0o700)
    module.chmod(0o600)

    environment = os.environ | {"VGEN_SETUP_LIBRARY_ONLY": "1"}
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; make_runtime_tree_readable "$2"',
            "bash",
            str(INSTALLER),
            str(runtime),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(runtime.stat().st_mode) == 0o755
    assert stat.S_IMODE(binary.parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(module.parent.stat().st_mode) == 0o755
    assert stat.S_IMODE(binary.stat().st_mode) == 0o755
    assert stat.S_IMODE(module.stat().st_mode) == 0o644


def test_resume_accepts_only_the_exact_pre_database_partial_state() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    assert '[[ -d "${INSTALL_ROOT}/venv" && ! -L "${INSTALL_ROOT}/venv" ]]' in source
    assert '[[ -f "${ENVIRONMENT_PATH}" && ! -L "${ENVIRONMENT_PATH}" ]]' in source
    assert '[[ ! -e "${DATABASE_PATH}" ]]' in source
    assert '[[ ! -e "${BOOTSTRAP_PATH}" ]]' in source
    assert '[[ ! -e "${UNIT_PATH}" ]]' in source
    assert '[[ ! -e "${INSTALL_STATE_PATH}" ]]' in source
    resume_body = source.split("resume_gateway() {", 1)[1].split("\n}", 1)[0]
    assert resume_body.index("prepare_resume_runtime") < resume_body.index(
        "initialize_gateway"
    )
    assert resume_body.index("initialize_gateway") < resume_body.index("install_and_start_service")
    assert resume_body.index("install_and_start_service") < resume_body.index("switch_nginx")


def test_https_health_retries_without_leaking_failed_response(tmp_path: Path) -> None:
    probe = tmp_path / "probe.sh"
    probe.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
export VGEN_SETUP_LIBRARY_ONLY=1
source {str(INSTALLER)!r}
DOMAIN=vgen.example.com
attempts=0
curl() {{
  attempts=$((attempts + 1))
  local output=''
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == '--output' ]]; then output="$2"; shift 2; else shift; fi
  done
  if ((attempts < 3)); then
    printf 'PRIVATE_UPSTREAM_FAILURE' >"${{output}}"
    return 22
  fi
  printf '{{"ok":true}}' >"${{output}}"
}}
health_payload_is_ok() {{ grep -q '"ok":true'; }}
sleep() {{ :; }}
gateway_https_health_with_retry
printf 'attempts=%s\n' "${{attempts}}"
""",
        encoding="utf-8",
    )
    result = subprocess.run(["bash", str(probe)], check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "attempts=4" in result.stdout
    assert "PRIVATE_UPSTREAM_FAILURE" not in result.stdout
    assert "PRIVATE_UPSTREAM_FAILURE" not in result.stderr


def test_activate_reuses_only_the_exact_healthy_rolled_back_state() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    activate_body = source.split("activate_gateway() {", 1)[1].split("\n}", 1)[0]
    preconditions = source.split("verify_activation_preconditions() {", 1)[1].split("\n}", 1)[0]

    for required in (
        "${INSTALL_ROOT}/venv",
        "${ENVIRONMENT_PATH}",
        "${DATABASE_PATH}",
        "${BOOTSTRAP_PATH}",
        "${UNIT_PATH}",
        "${INSTALL_STATE_PATH}",
        "systemctl is-active --quiet",
        "systemctl is-enabled --quiet",
        "gateway_local_health_is_ok",
        "cmp --silent",
    ):
        assert required in preconditions
    assert 'switch_nginx "${ACTIVATION_BACKUP_PATH}" 1' in activate_body
    assert "initialize_gateway" not in activate_body
    assert "write_gateway_environment" not in activate_body
    assert "write_install_state" not in activate_body
    assert "backup_legacy_database" not in activate_body
    assert "deadline=$((SECONDS + 30))" in source
    assert "consecutive >= 2" in source
    assert 'payload.get("schema_version") == 1' in source
    assert 'payload.get("journal_mode") == "wal"' in source
    assert '--output "${response_file}"' in source
    assert "2>/dev/null" in source
    assert "--http1.1" in source
    assert "--header 'Connection: close'" in source
    assert "--connect-timeout 1" in source


def test_nginx_activation_state_and_replacement_are_hardened() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    switch_body = source.split("switch_nginx() {", 1)[1].split("\n}", 1)[0]
    activate_body = source.split("activate_gateway() {", 1)[1].split("\n}", 1)[0]

    assert source.count("object_pairs_hook=unique_object") >= 2
    assert "backup.parent != root" in source
    assert "nginx-vgen-[0-9]{8}T[0-9]{6}Z" in source
    assert 'verify_root_owned_not_writable "${NGINX_CONFIG_PATH}"' in source
    assert 'generated_path="$(mktemp "${NGINX_CONFIG_PATH}.v1-candidate.XXXXXX")"' in source
    atomic_move = 'mv -f -- "${generated_path}" "${NGINX_CONFIG_PATH}"'
    assert atomic_move in switch_body
    assert switch_body.index("trap 'handle_nginx_switch_error $?' ERR") < switch_body.index(
        atomic_move
    )
    for signal in ("INT", "TERM", "HUP"):
        assert signal in switch_body
    assert "clear_nginx_switch_traps" in switch_body
    assert 'atomic_replace_nginx_config "${backup_path}"' in source
    assert 'if [[ "${ACTIVATION_ALREADY_ACTIVE}" -eq 1 ]]' in activate_body
    assert "already active with the deterministic Nginx config and strict health" in activate_body


def test_gateway_upgrade_is_staged_backed_up_health_gated_and_reversible() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    upgrade_body = source.split("upgrade_gateway() {", 1)[1].split("\n}", 1)[0]
    rollback_body = source.split("handle_upgrade_error() {", 1)[1].split("\n}", 1)[0]
    preconditions = source.split("verify_upgrade_preconditions() {", 1)[1].split(
        "\n}", 1
    )[0]

    assert "verify_release_bundle" in upgrade_body
    assert upgrade_body.index("verify_release_bundle") < upgrade_body.index(
        "verify_upgrade_preconditions"
    )
    assert upgrade_body.index("stage_upgrade_runtime") < upgrade_body.index(
        "systemctl stop"
    )
    assert upgrade_body.index("backup_upgrade_config_and_preflight_database") < upgrade_body.index(
        "systemctl stop"
    )
    assert upgrade_body.index("systemctl stop") < upgrade_body.index(
        "create_stopped_upgrade_database_backup"
    )
    assert upgrade_body.index("create_stopped_upgrade_database_backup") < upgrade_body.index(
        "swap_upgrade_runtime"
    )
    assert upgrade_body.index("swap_upgrade_runtime") < upgrade_body.index(
        '--database "${DATABASE_PATH}" doctor'
    )
    assert upgrade_body.index('--database "${DATABASE_PATH}" doctor') < upgrade_body.index(
        'systemctl start "${SERVICE_NAME}"'
    )
    assert upgrade_body.index("gateway_local_health_with_retry") < upgrade_body.index(
        "gateway_https_health_with_retry"
    )
    assert "trap 'handle_upgrade_error $?' ERR" in upgrade_body
    for signal in ("INT", "TERM", "HUP"):
        assert signal in upgrade_body

    assert '[[ "${CONFIRM_UPGRADE}" -eq 1 ]]' in preconditions
    assert "verify_existing_gateway_environment" in preconditions
    assert "verify_upgrade_runtime_security" in preconditions
    assert "verify_upgrade_install_state" in preconditions
    assert "systemctl is-active --quiet" in preconditions
    assert "systemctl is-enabled --quiet" in preconditions
    assert "gateway_local_health_with_retry" in preconditions
    assert "gateway_https_health_with_retry" in preconditions

    assert 'mv -- "${INSTALL_ROOT}/venv" "${UPGRADE_PREVIOUS_RUNTIME}"' in source
    assert 'mv -- "${candidate_runtime}" "${INSTALL_ROOT}/venv"' in source
    assert "restore_sqlite_backup" in rollback_body
    assert 'mv -- "${UPGRADE_PREVIOUS_RUNTIME}" "${INSTALL_ROOT}/venv"' in rollback_body
    assert rollback_body.count("atomic_restore_upgrade_config") == 4
    assert '"${UPGRADE_BACKUP_DIR}/nginx-vgen.conf"' in rollback_body
    assert "systemctl reload nginx" in rollback_body
    assert 'systemctl start "${SERVICE_NAME}"' in rollback_body
    assert "gateway_local_health_with_retry" in rollback_body
    assert "gateway_https_health_with_retry" in rollback_body
    assert "rm -rf" not in source


def test_gateway_upgrade_relocates_staged_virtualenv_entrypoints_atomically(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "venv.candidate.0.2.2.ABC123"
    runtime = tmp_path / "venv"
    binary_directory = runtime / "bin"
    binary_directory.mkdir(parents=True)
    for name in ("vgen-gateway", "pip"):
        script = binary_directory / name
        script.write_text(
            f"#!{candidate}/bin/python\nprint('fixture')\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
    activation = binary_directory / "activate"
    activation.write_text(f'VIRTUAL_ENV="{candidate}"\n', encoding="utf-8")
    (runtime / "pyvenv.cfg").write_text(
        f"command = python3.11 -m venv {candidate}\n",
        encoding="utf-8",
    )

    commands = tmp_path / "commands"
    commands.mkdir()
    (commands / "python3.11").symlink_to(sys.executable)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; relocate_python_runtime_scripts "$2" "$3"',
            "bash",
            str(INSTALLER),
            str(candidate),
            str(runtime),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ
        | {
            "PATH": f"{commands}:{os.environ['PATH']}",
            "VGEN_SETUP_LIBRARY_ONLY": "1",
        },
    )
    assert result.returncode == 0, result.stderr
    for path in (
        binary_directory / "vgen-gateway",
        binary_directory / "pip",
        activation,
        runtime / "pyvenv.cfg",
    ):
        payload = path.read_text(encoding="utf-8")
        assert str(candidate) not in payload
        assert str(runtime) in payload
    assert (binary_directory / "vgen-gateway").stat().st_mode & 0o111
    assert not list(binary_directory.glob(".*.relocate.*"))

    source = INSTALLER.read_text(encoding="utf-8")
    swap = source.split("swap_upgrade_runtime() {", 1)[1].split("\n}", 1)[0]
    assert swap.index('mv -- "${candidate_runtime}" "${INSTALL_ROOT}/venv"') < swap.index(
        "relocate_python_runtime_scripts"
    )
    assert swap.index("relocate_python_runtime_scripts") < swap.index(
        "normalize_and_verify_runtime_at"
    )


def test_gateway_upgrade_same_version_is_an_idempotent_health_status() -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    body = source.split("upgrade_gateway() {", 1)[1].split("\n}", 1)[0]
    branch = body.split('if [[ "${UPGRADE_ALREADY_TARGET}" -eq 1 ]]', 1)[1].split(
        "\n  fi", 1
    )[0]

    assert "already installed and healthy locally and publicly" in branch
    assert "no files, database rows or services were changed" in branch
    assert "return" in branch
    assert body.index('if [[ "${UPGRADE_ALREADY_TARGET}" -eq 1 ]]') < body.index(
        "stage_upgrade_runtime"
    )


def test_upgrade_sqlite_backup_includes_committed_wal_rows(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    backup = tmp_path / "backup.db"
    connection = sqlite3.connect(source)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE events(value TEXT NOT NULL)")
    connection.execute("INSERT INTO events(value) VALUES ('from-wal')")
    connection.commit()
    assert source.with_name(f"{source.name}-wal").exists()

    command_root = tmp_path / "commands"
    command_root.mkdir()
    (command_root / "python3.11").symlink_to(sys.executable)
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; sqlite_online_backup "$2" "$3"',
            "bash",
            str(INSTALLER),
            str(source),
            str(backup),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ
        | {
            "PATH": f"{command_root}:{os.environ['PATH']}",
            "VGEN_SETUP_LIBRARY_ONLY": "1",
        },
    )
    connection.close()

    assert result.returncode == 0, result.stderr
    with sqlite3.connect(backup) as copied:
        assert copied.execute("SELECT value FROM events").fetchall() == [("from-wal",)]
        assert copied.execute("PRAGMA quick_check").fetchone() == ("ok",)


def test_upgrade_sqlite_restore_replaces_post_backup_changes(tmp_path: Path) -> None:
    live = tmp_path / "live.db"
    backup = tmp_path / "backup.db"
    with sqlite3.connect(live) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE events(value TEXT NOT NULL)")
        connection.execute("INSERT INTO events(value) VALUES ('before-upgrade')")

    command_root = tmp_path / "commands"
    command_root.mkdir()
    (command_root / "python3.11").symlink_to(sys.executable)
    environment = os.environ | {
        "PATH": f"{command_root}:{os.environ['PATH']}",
        "VGEN_SETUP_LIBRARY_ONLY": "1",
    }
    copied = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; sqlite_online_backup "$2" "$3"',
            "bash",
            str(INSTALLER),
            str(live),
            str(backup),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert copied.returncode == 0, copied.stderr

    with sqlite3.connect(live) as connection:
        connection.execute("INSERT INTO events(value) VALUES ('during-upgrade')")

    restored = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; chown() { :; }; restore_sqlite_backup "$2" "$3"',
            "bash",
            str(INSTALLER),
            str(backup),
            str(live),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert restored.returncode == 0, restored.stderr
    with sqlite3.connect(live) as connection:
        assert connection.execute("SELECT value FROM events").fetchall() == [
            ("before-upgrade",)
        ]
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)


def test_gateway_bundle_is_source_free_and_self_verifying(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path / WHEEL_NAME)
    output = tmp_path / "gateway.tar.gz"
    build_bundle(repository=ROOT, wheel=wheel, output=output)

    with tarfile.open(output, "r:gz") as archive:
        names = sorted(archive.getnames())
        expected = sorted(
            f"{BUNDLE_NAME}/{name}"
            for name in (
                "INSTALL.txt",
                "SHA256SUMS",
                "setup-gateway.sh",
                "setup-release-site.sh",
                "vgen-gateway.service",
                WHEEL_NAME,
            )
        )
        assert names == expected
        manifest_file = archive.extractfile(f"{BUNDLE_NAME}/SHA256SUMS")
        assert manifest_file is not None
        manifest = manifest_file.read().decode("utf-8")
        assert f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {WHEEL_NAME}" in manifest
        assert "src/" not in manifest
        install_file = archive.extractfile(f"{BUNDLE_NAME}/INSTALL.txt")
        assert install_file is not None
        install_text = install_file.read().decode("utf-8")
        guide = (ROOT / "docs" / "user-guide.md").read_text(encoding="utf-8")
        section = guide.split("<!-- VGEN_GATEWAY_INSTALL_BEGIN -->", 1)[1].split(
            "<!-- VGEN_GATEWAY_INSTALL_END -->", 1
        )[0].strip()
        assert install_text == (
            "VGen Gateway offline install card\n"
            "Generated from docs/user-guide.md; do not edit this file separately.\n\n"
            f"{section}\n"
        )
        assert "./setup-gateway.sh upgrade --domain <Gateway域名>" in install_text

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(output, "r:gz") as archive:
        archive.extractall(extracted, filter="data")
    bundle_root = extracted / BUNDLE_NAME
    command_root = tmp_path / "commands"
    command_root.mkdir()
    (command_root / "python3.11").symlink_to(sys.executable)
    stat_command = command_root / "stat"
    stat_command.write_text(
        """#!/usr/bin/env python3
import os
import stat
import sys

if sys.argv[1:3] == ["-c", "%a"] and len(sys.argv) == 4:
    print(f"{stat.S_IMODE(os.stat(sys.argv[3]).st_mode):o}")
else:
    raise SystemExit("unsupported test stat invocation")
""",
        encoding="utf-8",
    )
    stat_command.chmod(0o755)
    result = subprocess.run(
        [
            "bash",
            "-c",
            (
                'export VGEN_SETUP_LIBRARY_ONLY=1; source "$1"; '
                'verify_release_bundle; printf "version=%s\\n" "${VGEN_VERSION}"'
            ),
            "bash",
            str(bundle_root / "setup-gateway.sh"),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"PATH": f"{command_root}:{os.environ['PATH']}"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"version={VERSION}\n"


@pytest.mark.parametrize(
    ("wheel_name", "version", "distribution", "tag", "message"),
    [
        ("vgen-wrong-py3-none-any.whl", VERSION, "vgen", "py3-none-any", "must be named"),
        (WHEEL_NAME, "9.9.9", "vgen", "py3-none-any", "metadata version"),
        (WHEEL_NAME, VERSION, "other", "py3-none-any", "distribution name"),
        (WHEEL_NAME, VERSION, "vgen", "cp311-cp311-manylinux", "py3-none-any tag"),
    ],
)
def test_gateway_bundle_builder_rejects_mismatched_wheel_identity(
    tmp_path: Path,
    wheel_name: str,
    version: str,
    distribution: str,
    tag: str,
    message: str,
) -> None:
    wheel = _write_test_wheel(
        tmp_path / wheel_name,
        version=version,
        distribution=distribution,
        tag=tag,
    )
    with pytest.raises(ValueError, match=message):
        build_bundle(repository=ROOT, wheel=wheel, output=tmp_path / "gateway.tar.gz")


def test_gateway_bundle_builder_rejects_an_unreadable_wheel(tmp_path: Path) -> None:
    wheel = tmp_path / WHEEL_NAME
    wheel.write_bytes(b"not the reviewed release")
    with pytest.raises(ValueError, match="readable Python wheel"):
        build_bundle(repository=ROOT, wheel=wheel, output=tmp_path / "gateway.tar.gz")
