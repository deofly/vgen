from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import zipfile
from argparse import Namespace
from pathlib import Path

import pytest

import vgen.broker.main as broker_main
import vgen.cli.macos_broker_service as broker_service
import vgen.cli.setup as cli_setup
from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.macos_broker_service import MANAGED_MARKER, launch_agent_payload
from vgen.cli.profile import ProfileStore
from vgen.cli.session_store import StoredSession


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):  # type: ignore[no-untyped-def]
        return self.values.get((service, username))

    def set_password(self, service, username, password):  # type: ignore[no-untyped-def]
        self.values[(service, username)] = password

    def delete_password(self, service, username):  # type: ignore[no-untyped-def]
        self.values.pop((service, username), None)


def test_setup_does_not_keep_an_unconfirmed_new_identity(monkeypatch) -> None:
    store = DeviceIdentityStore(MemorySecrets())
    answers = iter(("y", "not-the-final-word"))
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    with pytest.raises(ValueError, match="恢复词确认失败"):
        cli_setup._prepare_identity(
            Namespace(
                identity="default",
                non_interactive=False,
                recovery_file=None,
                json=False,
            ),
            store,
        )
    assert not store.exists("default")


def test_setup_does_not_save_a_new_profile_before_gateway_health_passes(
    tmp_path, monkeypatch
) -> None:
    profiles = ProfileStore(tmp_path / "profiles.yaml")

    class UnhealthyClient:
        def __init__(self, _profile):  # type: ignore[no-untyped-def]
            pass

        def health(self):  # type: ignore[no-untyped-def]
            return {"ok": False}

        def close(self):
            pass

    monkeypatch.setattr(cli_setup, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_setup, "GatewayClient", UnhealthyClient)
    with pytest.raises(ValueError, match="健康检查未通过"):
        cli_setup.setup_command(
            Namespace(
                profile="home",
                identity="default",
                endpoint="https://wrong-gateway.example",
                non_interactive=True,
            )
        )
    current, stored = profiles.load()
    assert current is None
    assert stored == {}


def test_setup_resumes_partial_bootstrap_with_chinese_defaults_and_ascii_keys(
    tmp_path, monkeypatch, capsys
) -> None:
    from vgen.cli.main import build_parser

    profiles = ProfileStore(tmp_path / "profiles.yaml")
    identity_store = DeviceIdentityStore(MemorySecrets())
    saved_session: StoredSession | None = None
    requests: list[tuple[str, str, dict | None, str | None]] = []
    workspace_key_calls: list[str] = []
    workspace_attempts = 0
    registered_device_id: str | None = None

    class FakeSessionStore:
        def save(self, profile_name, session):  # type: ignore[no-untyped-def]
            nonlocal saved_session
            assert profile_name == "home"
            saved_session = session

        def load(self, profile_name):  # type: ignore[no-untyped-def]
            assert profile_name == "home"
            return saved_session

    class FakeAuthorityStore:
        def pin(self, **values):  # type: ignore[no-untyped-def]
            assert values["workspace_id"] == "wsp_private_internal"

        def pin_owner(self, **values):  # type: ignore[no-untyped-def]
            assert values["workspace_id"] == "wsp_private_internal"

    class FakeClient:
        def __init__(self, profile, **kwargs):  # type: ignore[no-untyped-def]
            self.profile = profile
            self.kwargs = kwargs

        def health(self):  # type: ignore[no-untyped-def]
            return {"ok": True, "schema_version": 1}

        def request(
            self,
            method,
            path,
            *,
            json_body=None,
            auth=True,
            idempotency_key=None,
        ):  # type: ignore[no-untyped-def]
            nonlocal registered_device_id, workspace_attempts
            requests.append((method, path, json_body, idempotency_key))
            if path == "/api/v1/auth/bootstrap":
                assert json_body["bootstrap_code"] == "bootstrap-must-stay-secret"
                registered_device_id = json_body["device_id"]
                return {
                    "user": {"id": "usr_private_internal"},
                    "device": {"id": json_body["device_id"]},
                    "session": {
                        "token": "session-must-stay-secret",
                        "expires_at": 4_000_000_000,
                    },
                }
            if path == "/api/v1/brokers" and method == "POST":
                assert json_body == {
                    "name": "我的 Home Broker",
                    "device_id": registered_device_id,
                }
                return {
                    "id": "brk_private_internal",
                    "broker_device": {"id": "bdev_private_internal"},
                }
            if path == "/api/v1/workspaces" and method == "POST":
                workspace_attempts += 1
                assert json_body == {
                    "name": "我的工作空间",
                    "founder_broker_id": "brk_private_internal",
                }
                if workspace_attempts == 1:
                    raise cli_setup.VgenClientError(
                        700001,
                        "GATEWAY_UNREACHABLE",
                        "simulated lost workspace response",
                        retry_action="later",
                    )
                return {
                    "id": "wsp_private_internal",
                    "owner_user_id": "usr_private_internal",
                    "key_version": 1,
                }
            if path == "/api/v1/workspaces" and method == "GET":
                return [
                    {
                        "id": "wsp_private_internal",
                        "owner_user_id": "usr_private_internal",
                        "key_version": 1,
                    }
                ]
            if path.endswith("/pools") and method == "POST":
                assert json_body == {"name": "默认 GPU 池", "policy": {}}
                return {"id": "pol_private_internal", "name": json_body["name"]}
            if path.endswith("/pools") and method == "GET":
                return [{"id": "pol_private_internal", "name": "默认 GPU 池"}]
            raise AssertionError((method, path, json_body, auth, idempotency_key))

        def close(self):
            pass

    monkeypatch.setattr(cli_setup, "ProfileStore", lambda: profiles)
    monkeypatch.setattr(cli_setup, "DeviceIdentityStore", lambda: identity_store)
    monkeypatch.setattr(cli_setup, "SessionStore", FakeSessionStore)
    monkeypatch.setattr(cli_setup, "GatewayClient", FakeClient)
    monkeypatch.setattr(cli_setup, "WorkspaceAuthorityStore", FakeAuthorityStore)
    monkeypatch.setattr(
        cli_setup,
        "initialize_workspace_keys",
        lambda _client, _identity, workspace: workspace_key_calls.append(workspace["id"]),
    )
    monkeypatch.setattr(
        cli_setup,
        "sync_workspace_key",
        lambda *_args, **_kwargs: workspace_key_calls.append("resumed"),
    )
    monkeypatch.setattr(cli_setup, "_install_official_workflow", lambda _args: None)
    monkeypatch.setattr(
        cli_setup,
        "login_session",
        lambda _profile, _identity: saved_session,
    )

    bootstrap = tmp_path / "bootstrap-code"
    bootstrap.write_text("bootstrap-must-stay-secret\n", encoding="utf-8")
    bootstrap.chmod(0o600)
    recovery = tmp_path / "identity-recovery.vgen"
    common = [
        "setup",
        "--gateway",
        "https://gateway.example",
        "--display-name",
        "Alice",
        "--device-name",
        "Alice Mac",
        "--non-interactive",
        "--no-broker-service",
    ]
    first = build_parser().parse_args(
        [
            *common,
            "--bootstrap-code-file",
            str(bootstrap),
            "--recovery-file",
            str(recovery),
        ]
    )
    with pytest.raises(cli_setup.VgenClientError, match="simulated lost workspace response"):
        cli_setup.setup_command(first)

    partial = profiles.get("home")
    assert registered_device_id is not None
    assert partial.user_id == "usr_private_internal"
    assert partial.device_id == registered_device_id
    assert partial.home_broker_id == "brk_private_internal"
    assert partial.home_broker_device_id == "bdev_private_internal"
    assert partial.default_workspace is None
    assert partial.default_pool is None

    cli_setup.setup_command(build_parser().parse_args(common))

    profile = profiles.get("home")
    assert profile.default_workspace == "wsp_private_internal"
    assert profile.default_pool == "pol_private_internal"
    assert profile.home_broker_id == "brk_private_internal"
    assert profile.home_broker_device_id == "bdev_private_internal"
    assert stat.S_IMODE(recovery.stat().st_mode) == 0o600
    assert workspace_key_calls == ["wsp_private_internal"]
    setup_writes = [
        (path, body, key)
        for method, path, body, key in requests
        if method == "POST" and path != "/api/v1/auth/bootstrap"
    ]
    assert setup_writes
    assert all(key is not None and key.isascii() for _, _, key in setup_writes)

    identity = identity_store.load("default")
    broker_write = next(item for item in setup_writes if item[0] == "/api/v1/brokers")
    assert broker_write[2] == cli_setup._setup_idempotency_key(
        "broker",
        root_key_id=identity.root_key_id,
        profile_name="home",
        broker_name="我的 Home Broker",
        device_id=registered_device_id,
    )
    workspace_writes = [item for item in setup_writes if item[0] == "/api/v1/workspaces"]
    assert len(workspace_writes) == 2
    assert workspace_writes[0][2] == workspace_writes[1][2]
    assert workspace_writes[0][2] == cli_setup._setup_idempotency_key(
        "workspace",
        root_key_id=identity.root_key_id,
        profile_name="home",
        workspace_name="我的工作空间",
        founder_broker_id="brk_private_internal",
    )
    pool_write = next(item for item in setup_writes if item[0].endswith("/pools"))
    assert pool_write[2] == cli_setup._setup_idempotency_key(
        "pool",
        workspace_id="wsp_private_internal",
        profile_name="home",
        pool_name="默认 GPU 池",
    )

    output = capsys.readouterr().out
    assert "初始化完成" in output
    assert "vgen worker bundle" in output
    for secret in (
        "bootstrap-must-stay-secret",
        "session-must-stay-secret",
        "wsp_private_internal",
        "pol_private_internal",
        "brk_private_internal",
    ):
        assert secret not in output

    post_count = sum(method == "POST" for method, _, _, _ in requests)
    cli_setup.setup_command(build_parser().parse_args(common))
    assert sum(method == "POST" for method, _, _, _ in requests) == post_count
    assert workspace_key_calls[-1] == "resumed"


def test_macos_launch_agent_contains_no_session_or_private_key(tmp_path) -> None:
    payload = launch_agent_payload(
        python_executable=Path("/opt/vgen/bin/python"),
        profile_name="home",
        broker_id="brk_example",
        broker_device_id="bdev_example",
        log_directory=tmp_path,
    )
    encoded = plistlib.dumps(payload)
    text = encoded.decode("utf-8")
    assert MANAGED_MARKER in text
    assert "session-token" not in text.casefold()
    assert "private-key" not in text.casefold()
    assert "recovery" not in text.casefold()
    assert payload["ProgramArguments"][-2:] == ["--profile", "home"]


def test_macos_launch_agent_refuses_to_overwrite_an_unmanaged_file(tmp_path, monkeypatch) -> None:
    agents = tmp_path / "LaunchAgents"
    agents.mkdir()
    target = agents / f"{broker_service.LABEL}.plist"
    original = plistlib.dumps({"Label": broker_service.LABEL, "ProgramArguments": ["other"]})
    target.write_bytes(original)
    monkeypatch.setattr(broker_service.sys, "platform", "darwin")
    with pytest.raises(ValueError, match="不会覆盖|refusing to overwrite"):
        broker_service.install_macos_broker_service(
            profile_name="home",
            broker_id="brk_example",
            broker_device_id="bdev_example",
            launch_agents_directory=agents,
            log_directory=tmp_path / "logs",
        )
    assert target.read_bytes() == original


def test_macos_launch_agent_preserves_venv_symlink_and_safely_reloads_managed_plist(
    tmp_path, monkeypatch
) -> None:
    base_python = tmp_path / "base" / "python3.14"
    base_python.parent.mkdir()
    base_python.touch()
    venv_python = tmp_path / "bundle" / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.symlink_to(base_python)

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        commands.append(command)
        return subprocess.CompletedProcess(command, 1 if command[1] == "print" else 0)

    monkeypatch.setattr(broker_service.sys, "platform", "darwin")
    monkeypatch.setattr(broker_service.sys, "executable", str(venv_python))
    monkeypatch.setattr(broker_service.subprocess, "run", fake_run)

    agents = tmp_path / "LaunchAgents"
    logs = tmp_path / "logs"
    first = broker_service.install_macos_broker_service(
        profile_name="home",
        broker_id="brk_first",
        broker_device_id="bdev_first",
        launch_agents_directory=agents,
        log_directory=logs,
    )
    first_payload = plistlib.loads(first.plist_path.read_bytes())
    assert first.loaded is True
    assert first_payload["ProgramArguments"][0] == str(venv_python)
    assert first_payload["ProgramArguments"][0] != str(venv_python.resolve())
    assert first_payload["EnvironmentVariables"]["VGEN_LAUNCH_AGENT_MARKER"] == MANAGED_MARKER

    second = broker_service.install_macos_broker_service(
        profile_name="home",
        broker_id="brk_second",
        broker_device_id="bdev_second",
        launch_agents_directory=agents,
        log_directory=logs,
    )
    second_payload = plistlib.loads(second.plist_path.read_bytes())
    arguments = second_payload["ProgramArguments"]
    assert second.loaded is True
    assert arguments[0] == str(venv_python)
    assert arguments[arguments.index("--broker-id") + 1] == "brk_second"
    assert arguments[arguments.index("--broker-device-id") + 1] == "bdev_second"
    assert stat.S_IMODE(second.plist_path.stat().st_mode) == 0o600

    domain = f"gui/{broker_service.os.getuid()}"
    service = f"{domain}/{broker_service.LABEL}"
    reload_commands = [
        ["/bin/launchctl", "bootout", service],
        ["/bin/launchctl", "print", service],
        ["/bin/launchctl", "bootstrap", domain, str(second.plist_path)],
        ["/bin/launchctl", "enable", service],
    ]
    assert commands == reload_commands * 2


def test_macos_launch_agent_waits_for_bootout_before_bootstrap(tmp_path, monkeypatch) -> None:
    commands: list[list[str]] = []
    sleeps: list[float] = []
    print_attempts = 0

    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        nonlocal print_attempts
        commands.append(command)
        if command[1] == "print":
            print_attempts += 1
            return subprocess.CompletedProcess(command, 0 if print_attempts < 3 else 1)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(broker_service.sys, "platform", "darwin")
    monkeypatch.setattr(broker_service.subprocess, "run", fake_run)
    monkeypatch.setattr(broker_service.time, "sleep", sleeps.append)

    result = broker_service.install_macos_broker_service(
        profile_name="home",
        broker_id="brk_example",
        broker_device_id="bdev_example",
        launch_agents_directory=tmp_path / "LaunchAgents",
        log_directory=tmp_path / "logs",
    )

    assert result.loaded is True
    assert print_attempts == 3
    assert sleeps == [broker_service._RELOAD_POLL_SECONDS] * 2
    actions = [command[1] for command in commands]
    assert actions == ["bootout", "print", "print", "print", "bootstrap", "enable"]


def test_macos_launch_agent_retries_operation_in_progress(tmp_path, monkeypatch) -> None:
    commands: list[list[str]] = []
    sleeps: list[float] = []
    bootstrap_attempts = 0

    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        nonlocal bootstrap_attempts
        commands.append(command)
        if command[1] == "print":
            return subprocess.CompletedProcess(command, 1)
        if command[1] == "bootstrap":
            bootstrap_attempts += 1
            if bootstrap_attempts == 1:
                return subprocess.CompletedProcess(
                    command,
                    37,
                    "",
                    "Bootstrap failed: 37: Operation already in progress",
                )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(broker_service.sys, "platform", "darwin")
    monkeypatch.setattr(broker_service.subprocess, "run", fake_run)
    monkeypatch.setattr(broker_service.time, "sleep", sleeps.append)

    result = broker_service.install_macos_broker_service(
        profile_name="home",
        broker_id="brk_example",
        broker_device_id="bdev_example",
        launch_agents_directory=tmp_path / "LaunchAgents",
        log_directory=tmp_path / "logs",
    )

    assert result.loaded is True
    assert result.error is None
    assert bootstrap_attempts == 2
    assert sleeps == [broker_service._RELOAD_POLL_SECONDS]
    assert [command[1] for command in commands] == [
        "bootout",
        "print",
        "bootstrap",
        "print",
        "bootstrap",
        "enable",
    ]


def test_macos_launch_agent_reports_bootstrap_failure(tmp_path, monkeypatch) -> None:
    def fake_run(command, **_kwargs):  # type: ignore[no-untyped-def]
        if command[1] == "print":
            return subprocess.CompletedProcess(command, 1)
        if command[1] == "bootstrap":
            return subprocess.CompletedProcess(
                command,
                5,
                "",
                "Bootstrap failed: 5: Input/output error",
            )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(broker_service.sys, "platform", "darwin")
    monkeypatch.setattr(broker_service.subprocess, "run", fake_run)

    result = broker_service.install_macos_broker_service(
        profile_name="home",
        broker_id="brk_example",
        broker_device_id="bdev_example",
        launch_agents_directory=tmp_path / "LaunchAgents",
        log_directory=tmp_path / "logs",
    )

    assert result.loaded is False
    assert result.error == (
        "launchctl bootstrap failed: Bootstrap failed: 5: Input/output error"
    )


def test_broker_renews_missing_session_without_user_input(monkeypatch) -> None:
    identity = object()
    refreshed = StoredSession("fresh", 4_000_000_000, "usr_test", "dev_test")
    captured: dict[str, object] = {}

    class Profiles:
        def get(self, _name):  # type: ignore[no-untyped-def]
            return type(
                "Profile",
                (),
                {"name": "home", "key_ref": "default", "device_id": "dev_test"},
            )()

    class Sessions:
        def load(self, _name):  # type: ignore[no-untyped-def]
            return None

    class Identities:
        def load(self, _name):  # type: ignore[no-untyped-def]
            return identity

    class Client:
        def __init__(self, profile, **kwargs):  # type: ignore[no-untyped-def]
            captured["profile"] = profile
            captured.update(kwargs)

    monkeypatch.setattr(broker_main, "ProfileStore", Profiles)
    monkeypatch.setattr(broker_main, "SessionStore", Sessions)
    monkeypatch.setattr(broker_main, "DeviceIdentityStore", Identities)
    monkeypatch.setattr(
        broker_main,
        "login_session",
        lambda profile, selected: (
            refreshed
            if selected is identity and profile.name == "home"
            else (_ for _ in ()).throw(AssertionError())
        ),
    )
    monkeypatch.setattr(broker_main, "GatewayClient", Client)

    broker_main._client("home")
    assert captured["session_token"] == "fresh"
    assert callable(captured["token_refresher"])


def test_macos_installer_is_shell_valid_and_does_not_mutate_system() -> None:
    root = Path(__file__).resolve().parents[2]
    installer = root / "examples" / "macos" / "install.command"
    builder = root / "examples" / "macos" / "build-bundle.sh"
    subprocess.run(["/bin/bash", "-n", str(installer)], check=True)
    subprocess.run(["/bin/bash", "-n", str(builder)], check=True)
    text = installer.read_text(encoding="utf-8")
    assert "shasum -a 256" in text
    assert "vgen.zcbiz.com" not in text
    assert " sudo " not in f" {text} "
    assert "curl " not in text
    assert ".zshrc" not in text
    assert '"${RELEASE_DIR}/bin/python" -I -B "${VGEN_BIN}" "${SETUP_ARGS[@]}" "$@"' in text
    assert '"${RELEASE_DIR}/bin/python" -I -B "${VGEN_BIN}" profile show' in text
    assert re.search(r'(?m)^VERSION="[0-9]', text) is None
    assert re.search(r'(?m)^WHEEL_SHA256="[0-9a-f]{64}"', text) is None
    assert 'WHEEL_CANDIDATES+=("${candidate}")' in text
    assert 'VGEN_MANIFEST_PATH="${MANIFEST_PATH}"' in text
    assert '"${candidate}" -I -B -c' in text
    assert '"${PYTHON_BIN}" -I -B <<\'PY\'' in text
    assert '"${PYTHON_BIN}" -I -B -m venv' in text
    assert '"${RELEASE_DIR}/bin/python" -I -B -m pip' in text
    assert 'metadata.get("Version", "")' in text
    assert 'wheel.name != f"vgen-{version}-py3-none-any.whl"' in text
    builder_text = builder.read_text(encoding="utf-8")
    assert "VGen-macOS-${VERSION}.zip" in builder_text
    assert "zip sha256" in builder_text
    assert re.search(r'(?m)^VERSION="[0-9]', builder_text) is None
    assert "tools/project_version.py" in builder_text
    assert 'python3 -I -B "${ROOT_DIR}/tools/project_version.py"' in builder_text
    assert 'VGEN_WHEEL_PATH="${WHEEL}" python3 -I -B' in builder_text
    assert 'metadata.get("Version") != version' in builder_text
    assert '"VGen-macOS-${VERSION}/SHA256SUMS"' in builder_text
    assert '"${ROOT_DIR}/docs/user-guide.md" "${OUTPUT_DIR}/README.md"' in builder_text
    assert "examples/macos/README.md" not in builder_text


def test_macos_installer_derives_version_from_the_verified_wheel(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    installer = bundle / "install.command"
    installer.write_bytes((root / "examples" / "macos" / "install.command").read_bytes())
    installer.chmod(0o755)
    readme = bundle / "README.md"
    readme.write_text("temporary installer fixture\n", encoding="utf-8")

    version = "7.8.9"
    wheel = bundle / f"vgen-{version}-py3-none-any.whl"
    dist_info = f"vgen-{version}.dist-info"
    files = {
        "vgen/__init__.py": f'__version__ = "{version}"\n',
        "vgen/cli.py": 'def main():\n    print("fixture")\n',
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: vgen\nVersion: {version}\n"
            "Requires-Python: >=3.11\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: tests\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
        f"{dist_info}/entry_points.txt": "[console_scripts]\nvgen = vgen.cli:main\n",
    }
    record_name = f"{dist_info}/RECORD"
    record = "".join(f"{name},,\n" for name in files) + f"{record_name},,\n"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
        archive.writestr(record_name, record)

    manifest = bundle / "SHA256SUMS"
    manifest.write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in (readme, installer, wheel)
        ),
        encoding="utf-8",
    )
    home = tmp_path / "home"
    home.mkdir()
    attacker = tmp_path / "attacker-cwd"
    attacker.mkdir()
    attack_marker = tmp_path / "sitecustomize-loaded"
    (attacker / "sitecustomize.py").write_text(
        f"open({str(attack_marker)!r}, 'w').write('loaded')\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        ["/bin/bash", str(installer), "--install-only"],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"HOME": str(home)},
        cwd=attacker,
    )
    assert result.returncode == 0, result.stderr
    assert not attack_marker.exists()
    wheel_sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
    release = home / "Library" / "Application Support" / "VGen" / "cli" / "releases"
    assert (release / f"{version}-{wheel_sha[:12]}" / "bin" / "vgen").is_file()
    assert f"VGen CLI {version}" in result.stdout

    upgrade = subprocess.run(
        ["/bin/bash", str(installer)],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ | {"HOME": str(home)},
        cwd=attacker,
    )
    assert upgrade.returncode == 0, upgrade.stderr
    assert not attack_marker.exists()
    assert "已保留现有 VGen 身份" in upgrade.stdout
    assert "Bootstrap code" in upgrade.stdout


def test_setup_json_does_not_contain_bootstrap_or_session_fields() -> None:
    # Guard the public machine-readable shape independently of a live Gateway.
    allowed = {
        "ready",
        "profile",
        "workflow",
        "home_broker_service",
        "next_command",
    }
    sample = json.loads(
        json.dumps(
            {
                "ready": True,
                "profile": {},
                "workflow": "vgen/minimax-h3-8step@1.0.0",
                "home_broker_service": "已启动",
                "next_command": "vgen worker bundle",
            }
        )
    )
    assert set(sample) == allowed
