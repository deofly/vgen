from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "release.py"
WRAPPER_PATH = ROOT / "tools" / "release.sh"
PUBLISHER_PATH = ROOT / "examples" / "ecs" / "publish-release.sh"
SPEC = importlib.util.spec_from_file_location("vgen_release_tool", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
TOOL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TOOL
SPEC.loader.exec_module(TOOL)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path, *, version: str = "0.3.1") -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "VGen Test")
    _git(repository, "config", "user.email", "vgen@example.invalid")
    (repository / "pyproject.toml").write_text(
        f'[project]\nname = "vgen"\nversion = "{version}"\n', encoding="utf-8"
    )
    _git(repository, "add", "pyproject.toml")
    _git(repository, "commit", "-q", "-m", "release source")
    return repository


def _public_release(tmp_path: Path, *, version: str = "0.3.1") -> Path:
    root = tmp_path / "public-releases"
    version_root = root / version
    channels = root / "channels"
    version_root.mkdir(parents=True)
    channels.mkdir()
    artifacts = {
        f"VGen-macOS-{version}.zip": b"macos-installer",
        f"vgen-windows-worker-installer-{version}.zip": b"windows-installer",
    }
    metadata = []
    for index, (filename, value) in enumerate(artifacts.items()):
        (version_root / filename).write_bytes(value)
        metadata.append(
            {
                "name": "macos-cli" if index == 0 else "windows-worker-installer",
                "kind": "cli-installer" if index == 0 else "worker-installer",
                "platform": "macos" if index == 0 else "windows",
                "filename": filename,
                "size": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
                "content_type": "application/zip",
            }
        )
    manifest = {
        "schema_version": 1,
        "audience": "public",
        "version": version,
        "published_at": "2026-08-22T12:34:56Z",
        "artifacts": metadata,
    }
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    (version_root / "manifest.json").write_bytes(manifest_bytes)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    stable = {
        "schema_version": 1,
        "channel": "stable",
        "version": version,
        "manifest_sha256": digest,
    }
    (channels / "stable.json").write_text(
        json.dumps(stable, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    bootstrap = (
        "#!/bin/sh\n"
        f"EXPECTED_VERSION={version}\n"
        f"EXPECTED_MANIFEST_SHA256={digest}\n"
        "exit 0\n"
    )
    (root / "install-macos.sh").write_text(bootstrap, encoding="utf-8")
    (root / "install-macos.sh").chmod(0o755)
    return root


def test_release_preflight_requires_clean_tagged_source(tmp_path) -> None:
    repository = _repository(tmp_path)
    with pytest.raises(TOOL.ReleaseError, match="required release tag"):
        TOOL._git_preflight("0.3.1", require_tag=True, repository=repository)

    _git(repository, "tag", "v0.3.1")
    commit, published_at = TOOL._git_preflight(
        "0.3.1", require_tag=True, repository=repository
    )
    assert commit == _git(repository, "rev-parse", "HEAD")
    assert published_at.endswith("Z")

    (repository / "untracked.txt").write_text("dirty", encoding="utf-8")
    with pytest.raises(TOOL.ReleaseError, match="worktree is not clean"):
        TOOL._git_preflight("0.3.1", require_tag=True, repository=repository)


def test_release_deployment_archive_is_closed_and_reproducible(tmp_path) -> None:
    public_root = _public_release(tmp_path)
    first = TOOL.build_deployment_archive(
        version="0.3.1",
        public_root=public_root,
        output=tmp_path / "first.tar.gz",
    )
    second = TOOL.build_deployment_archive(
        version="0.3.1",
        public_root=public_root,
        output=tmp_path / "second.tar.gz",
    )
    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, "r:gz") as archive:
        assert set(archive.getnames()) == {
            "install-macos.sh",
            "channels/stable.json",
            "0.3.1/manifest.json",
            "0.3.1/VGen-macOS-0.3.1.zip",
            "0.3.1/vgen-windows-worker-installer-0.3.1.zip",
        }
        assert all(member.isfile() for member in archive.getmembers())


def test_release_cleanup_replaces_only_current_local_staging(
    tmp_path, monkeypatch
) -> None:
    repository = tmp_path / "repository"
    current = repository / "dist" / "public-releases" / "0.3.1"
    previous = repository / "dist" / "public-releases" / "0.3.0"
    current.mkdir(parents=True)
    previous.mkdir(parents=True)
    (current / "manifest.json").write_text("stale", encoding="utf-8")
    (previous / "manifest.json").write_text("published", encoding="utf-8")
    monkeypatch.setattr(TOOL, "REPOSITORY", repository)

    TOOL._clean_transient_outputs("0.3.1")

    assert not current.exists()
    assert (previous / "manifest.json").read_text(encoding="utf-8") == "published"


def test_release_scripts_have_valid_syntax_and_help() -> None:
    for script in (WRAPPER_PATH, PUBLISHER_PATH):
        syntax = subprocess.run(
            ["bash", "-n", str(script)], check=False, capture_output=True, text=True
        )
        assert syntax.returncode == 0, syntax.stderr
        assert stat.S_IMODE(script.stat().st_mode) == 0o755

    help_result = subprocess.run(
        [str(WRAPPER_PATH), "--help"], check=False, capture_output=True, text=True
    )
    assert help_result.returncode == 0
    assert "build" in help_result.stdout
    assert "publish" in help_result.stdout

    publisher_help = subprocess.run(
        [str(PUBLISHER_PATH), "--help"], check=False, capture_output=True, text=True
    )
    assert publisher_help.returncode == 0
    assert "switches stable.json last" in publisher_help.stdout


def test_publish_parser_separates_gateway_install_and_upgrade_modes() -> None:
    parser = TOOL._parser()
    common = [
        "publish",
        "--version",
        "0.7.0",
        "--gateway",
        "https://vgen-gw.example.com",
        "--releases",
        "https://vgen.example.com",
        "--ssh",
        "root@ecs.example.com",
    ]
    installed = parser.parse_args([*common, "--install-gateway", "--artifact-store", "oss"])
    assert installed.install_gateway is True
    assert installed.resume_gateway is False
    assert installed.upgrade_gateway is False
    assert installed.artifact_store == "oss"
    with pytest.raises(SystemExit):
        parser.parse_args([*common, "--install-gateway", "--upgrade-gateway"])
    resumed = parser.parse_args([*common, "--resume-gateway"])
    assert resumed.resume_gateway is True
    with pytest.raises(SystemExit):
        parser.parse_args([*common, "--resume-gateway", "--upgrade-gateway"])
    with pytest.raises(SystemExit):
        parser.parse_args([*common, "--install-gateway", "--artifact-store", "local"])


def test_publish_can_reset_and_initialize_gateway_with_oss_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = TOOL.BuildResult(
        version="0.7.0",
        commit="a" * 40,
        published_at="2026-08-22T12:34:56Z",
        gateway_bundle=tmp_path / "vgen-gateway-0.7.0.tar.gz",
        macos_bundle=tmp_path / "VGen-macOS-0.7.0.zip",
        windows_bundle=tmp_path / "vgen-windows-worker-installer-0.7.0.zip",
        deployment_archive=tmp_path / "vgen-public-release-0.7.0.tar.gz",
        deployment_sha256="b" * 64,
    )
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        TOOL,
        "_capture",
        lambda *args, **kwargs: "/tmp/vgen-release.0.7.0.ABCDEFGH",
    )
    monkeypatch.setattr(TOOL, "_run", fake_run)
    monkeypatch.setattr(TOOL, "_verify_public_release", lambda *args: None)

    TOOL.publish_release(
        result,
        gateway_origin="https://vgen-gw.example.com",
        release_origin="https://vgen.example.com",
        ssh_target="root@ecs.example.com",
        ssh_port=22,
        confirmed=True,
        gateway_action="install",
        reset_test_gateway=True,
        artifact_store="oss",
        oss_endpoint="https://oss-cn-hangzhou.aliyuncs.com",
        oss_bucket="vgen-private",
        oss_prefix="vgen/v1",
        oss_ecs_role="VGenGatewayOssRole",
        aliyun_account_id="1234567890123456",
        oss_transfer_role="VGenArtifactTransferRole",
        confirm_oss_configured=True,
    )

    ssh_commands = [" ".join(command) for command in commands if command[0] == "ssh"]
    gateway = next(command for command in ssh_commands if "setup-gateway.sh" in command)
    assert "setup-gateway.sh reset-test" in gateway
    assert "--confirm-reset-test" in gateway
    assert "setup-gateway.sh install" in gateway
    assert "--artifact-store oss" in gateway
    assert "--oss-bucket vgen-private" in gateway
    assert "--oss-ecs-role VGenGatewayOssRole" in gateway
    assert "--aliyun-account-id 1234567890123456" in gateway
    assert "--oss-transfer-role VGenArtifactTransferRole" in gateway
    assert "--confirm-oss-configured" in gateway
    assert "setup-gateway.sh upgrade" not in gateway


def test_publish_rejects_incomplete_oss_install_before_ssh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = TOOL.BuildResult(
        version="0.7.0",
        commit="a" * 40,
        published_at="2026-08-22T12:34:56Z",
        gateway_bundle=tmp_path / "gateway.tar.gz",
        macos_bundle=tmp_path / "mac.zip",
        windows_bundle=tmp_path / "worker.zip",
        deployment_archive=tmp_path / "public.tar.gz",
        deployment_sha256="b" * 64,
    )
    contacted = False

    def unexpected_capture(*args: object, **kwargs: object) -> str:
        nonlocal contacted
        contacted = True
        return ""

    monkeypatch.setattr(TOOL, "_capture", unexpected_capture)
    with pytest.raises(TOOL.ReleaseError, match="requires endpoint, bucket, account ID"):
        TOOL.publish_release(
            result,
            gateway_origin="https://vgen-gw.example.com",
            release_origin="https://vgen.example.com",
            ssh_target="root@ecs.example.com",
            ssh_port=22,
            confirmed=True,
            gateway_action="install",
            artifact_store="oss",
            oss_endpoint="https://oss-cn-hangzhou.aliyuncs.com",
            oss_bucket="vgen-private",
        )
    assert contacted is False


def test_publish_can_resume_partial_gateway_without_repeating_cloud_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = TOOL.BuildResult(
        version="0.7.1",
        commit="a" * 40,
        published_at="2026-08-23T00:40:00Z",
        gateway_bundle=tmp_path / "vgen-gateway-0.7.1.tar.gz",
        macos_bundle=tmp_path / "VGen-macOS-0.7.1.zip",
        windows_bundle=tmp_path / "vgen-windows-worker-installer-0.7.1.zip",
        deployment_archive=tmp_path / "vgen-public-release-0.7.1.tar.gz",
        deployment_sha256="b" * 64,
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(
        TOOL, "_capture", lambda *args, **kwargs: "/tmp/vgen-release.0.7.1.ABCDEFGH"
    )
    monkeypatch.setattr(TOOL, "_run", lambda command, **kwargs: commands.append(command))
    monkeypatch.setattr(TOOL, "_verify_public_release", lambda *args: None)
    TOOL.publish_release(
        result,
        gateway_origin="https://vgen-gw.example.com",
        release_origin="https://vgen.example.com",
        ssh_target="root@ecs.example.com",
        ssh_port=22,
        confirmed=True,
        gateway_action="resume",
    )
    gateway = next(
        " ".join(command) for command in commands if "setup-gateway.sh" in " ".join(command)
    )
    assert "setup-gateway.sh resume" in gateway
    assert "--confirm-no-active-tasks" in gateway
    assert "--artifact-store" not in gateway


def test_publish_generates_cloud_kit_before_resetting_test_gateway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = TOOL.BuildResult(
        version="0.7.0",
        commit="a" * 40,
        published_at="2026-08-22T12:34:56Z",
        gateway_bundle=tmp_path / "gateway.tar.gz",
        macos_bundle=tmp_path / "mac.zip",
        windows_bundle=tmp_path / "worker.zip",
        deployment_archive=tmp_path / "public.tar.gz",
        deployment_sha256="b" * 64,
    )
    commands: list[list[str]] = []
    monkeypatch.setattr(
        TOOL, "_capture", lambda *args, **kwargs: "/tmp/vgen-release.0.7.0.ABCDEFGH"
    )
    monkeypatch.setattr(
        TOOL,
        "_run",
        lambda command, **kwargs: commands.append(command),
    )
    monkeypatch.setattr(TOOL, "_verify_public_release", lambda *args: None)
    TOOL.publish_release(
        result,
        gateway_origin="https://vgen-gw.example.com",
        release_origin="https://vgen.example.com",
        ssh_target="root@ecs.example.com",
        ssh_port=22,
        confirmed=True,
        gateway_action="install",
        reset_test_gateway=True,
        artifact_store="oss",
        oss_endpoint="https://oss-cn-hangzhou.aliyuncs.com",
        oss_bucket="vgen-private",
        oss_ecs_role="VGenGatewayRole",
        aliyun_account_id="1234567890123456",
        oss_transfer_role="VGenArtifactTransferRole",
    )
    gateway = next(" ".join(command) for command in commands if "setup-gateway.sh" in " ".join(command))
    assert "setup-gateway.sh reset-test" not in gateway
    assert "setup-gateway.sh install" in gateway
    assert "--confirm-oss-configured" not in gateway


def test_ecs_publisher_inline_python_supports_python_36() -> None:
    source = PUBLISHER_PATH.read_text(encoding="utf-8")
    inline_blocks = re.findall(
        r"python3 -I -B <<'PY'\n(.*?)\nPY(?:\n|$)", source, flags=re.DOTALL
    )
    assert len(inline_blocks) == 3
    for inline_python in inline_blocks:
        ast.parse(inline_python, filename=str(PUBLISHER_PATH), feature_version=(3, 6))


def test_release_baseline_and_one_command_flow_are_documented() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    guide = (ROOT / "docs" / "developer-guide.md").read_text(encoding="utf-8")
    assert "/:memory:" in gitignore.splitlines()
    assert "git status --short --ignored" in guide
    assert "git diff --cached --check" in guide
    assert "git tag -a v0.3.1" in guide
    assert 'rm -rf -- "$PWD/dist/public-releases/0.3.1"' in guide
    assert "不得删除整个 `dist/public-releases/`" in guide
    assert "./tools/release.sh publish" in guide
    assert "--upgrade-gateway" in guide
    assert "stable.json" in guide


def test_ecs_publisher_is_idempotent_and_rejects_immutable_changes(tmp_path) -> None:
    version = "0.3.1"
    public_root = _public_release(tmp_path, version=version)
    archive = TOOL.build_deployment_archive(
        version=version,
        public_root=public_root,
        output=tmp_path / f"vgen-public-release-{version}.tar.gz",
    )
    release_root = tmp_path / "served"
    backup_root = tmp_path / "backups"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    flock = fake_bin / "flock"
    flock.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    flock.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VGEN_PUBLISH_TESTING": "1",
        "VGEN_RELEASE_ROOT_OVERRIDE": str(release_root),
        "VGEN_BACKUP_ROOT_OVERRIDE": str(backup_root),
        "VGEN_LOCK_PATH_OVERRIDE": str(tmp_path / "publisher.lock"),
        "VGEN_SKIP_PUBLIC_CHECK": "1",
    }

    def publish() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "bash",
                str(PUBLISHER_PATH),
                "--archive",
                str(archive),
                "--version",
                version,
                "--domain",
                "vgen.example.com",
                "--confirm-stable",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )

    first = publish()
    assert first.returncode == 0, first.stderr
    assert json.loads((release_root / "channels" / "stable.json").read_text())["version"] == version
    assert stat.S_IMODE((release_root / version).stat().st_mode) == 0o755
    assert stat.S_IMODE((release_root / "install-macos.sh").stat().st_mode) == 0o755

    second = publish()
    assert second.returncode == 0, second.stderr
    assert "already exists with identical bytes" in second.stdout

    (release_root / version / f"VGen-macOS-{version}.zip").write_bytes(b"changed")
    rejected = publish()
    assert rejected.returncode != 0
    assert "already exists with different bytes" in rejected.stderr


def test_ecs_publisher_restores_channel_when_public_check_fails(tmp_path) -> None:
    version = "0.3.1"
    public_root = _public_release(tmp_path, version=version)
    archive = TOOL.build_deployment_archive(
        version=version,
        public_root=public_root,
        output=tmp_path / f"vgen-public-release-{version}.tar.gz",
    )
    release_root = tmp_path / "served"
    channels = release_root / "channels"
    channels.mkdir(parents=True)
    old_bootstrap = b"#!/bin/sh\necho old\n"
    old_stable = b'{"channel":"stable","version":"0.3.0"}\n'
    (release_root / "install-macos.sh").write_bytes(old_bootstrap)
    (channels / "stable.json").write_bytes(old_stable)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name, body in (
        ("flock", "#!/bin/sh\nexit 0\n"),
        ("curl", "#!/bin/sh\nexit 22\n"),
    ):
        executable = fake_bin / name
        executable.write_text(body, encoding="utf-8")
        executable.chmod(0o755)
    environment = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "VGEN_PUBLISH_TESTING": "1",
        "VGEN_RELEASE_ROOT_OVERRIDE": str(release_root),
        "VGEN_BACKUP_ROOT_OVERRIDE": str(tmp_path / "backups"),
        "VGEN_LOCK_PATH_OVERRIDE": str(tmp_path / "publisher.lock"),
    }
    result = subprocess.run(
        [
            "bash",
            str(PUBLISHER_PATH),
            "--archive",
            str(archive),
            "--version",
            version,
            "--domain",
            "vgen.example.com",
            "--confirm-stable",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode != 0
    assert (release_root / "install-macos.sh").read_bytes() == old_bootstrap
    assert (channels / "stable.json").read_bytes() == old_stable
    assert (release_root / version).is_dir()
    assert "restored the previous public release channel" in result.stdout
