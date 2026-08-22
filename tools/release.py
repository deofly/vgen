#!/usr/bin/env python3
"""Build and optionally publish one reviewed VGen release."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tomllib
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
SSH_TARGET_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9._-]+@)?(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)$"
)
REMOTE_DIRECTORY_PATTERN = re.compile(r"^/tmp/vgen-release\.[A-Za-z0-9.-]+$")


class ReleaseError(RuntimeError):
    """A release precondition, build, upload, or verification failed safely."""


@dataclass(frozen=True, slots=True)
class BuildResult:
    version: str
    commit: str
    published_at: str
    gateway_bundle: Path
    macos_bundle: Path
    windows_bundle: Path
    deployment_archive: Path
    deployment_sha256: str


def _run(
    command: list[str],
    *,
    cwd: Path = REPOSITORY,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    print("+", shlex.join(command), flush=True)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        suffix = f": {' '.join(detail.split())[:500]}" if detail else ""
        raise ReleaseError(f"command failed ({result.returncode}){suffix}")
    return result


def _capture(command: list[str], *, cwd: Path = REPOSITORY) -> str:
    return (_run(command, cwd=cwd, capture=True).stdout or "").strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _project_version(repository: Path = REPOSITORY) -> str:
    try:
        with (repository / "pyproject.toml").open("rb") as handle:
            value = tomllib.load(handle)["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError("cannot read project.version from pyproject.toml") from exc
    if not isinstance(value, str) or VERSION_PATTERN.fullmatch(value) is None:
        raise ReleaseError("project.version must be a complete MAJOR.MINOR.PATCH version")
    return value


def _validated_origin(value: str) -> tuple[str, str]:
    origin = value.strip().rstrip("/")
    try:
        parsed = urllib.parse.urlsplit(origin)
        _ = parsed.port
    except ValueError as exc:
        raise ReleaseError("origin is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ReleaseError("origin must be a credential-free HTTPS origin")
    return origin, parsed.hostname.lower()


def _git_preflight(
    version: str,
    *,
    require_tag: bool,
    repository: Path = REPOSITORY,
) -> tuple[str, str]:
    try:
        commit = _capture(["git", "rev-parse", "--verify", "HEAD"], cwd=repository)
    except ReleaseError as exc:
        raise ReleaseError(
            "Git has no source baseline; create and review the initial commit before releasing"
        ) from exc
    dirty = _capture(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
    )
    if dirty:
        preview = ", ".join(line[:160] for line in dirty.splitlines()[:8])
        raise ReleaseError(f"Git worktree is not clean: {preview}")
    project_version = _project_version(repository)
    if project_version != version:
        raise ReleaseError(
            f"pyproject.toml is {project_version}, but the requested release is {version}"
        )
    if require_tag:
        tag = f"v{version}"
        try:
            tagged_commit = _capture(
                ["git", "rev-list", "-n", "1", tag], cwd=repository
            )
        except ReleaseError as exc:
            raise ReleaseError(f"required release tag does not exist: {tag}") from exc
        if tagged_commit != commit:
            raise ReleaseError(f"{tag} does not point to the current source commit")
    timestamp = _capture(
        ["git", "show", "-s", "--format=%ct", commit], cwd=repository
    )
    try:
        published_at = datetime.fromtimestamp(int(timestamp), UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, OSError, OverflowError) as exc:
        raise ReleaseError("current Git commit has an invalid timestamp") from exc
    return commit, published_at


def _remove_generated_candidate(path: Path) -> None:
    try:
        path.relative_to(REPOSITORY / "dist")
    except ValueError as exc:
        raise ReleaseError(f"refusing to clean a generated path outside dist: {path}") from exc
    if path.is_symlink():
        raise ReleaseError(f"refusing to replace a symbolic-link build output: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def _clean_transient_outputs(version: str) -> None:
    dist = REPOSITORY / "dist"
    for path in (
        dist / f"vgen-{version}-py3-none-any.whl",
        dist / f"vgen-{version}.tar.gz",
        dist / f"vgen-gateway-{version}.tar.gz",
        dist / f"VGen-macOS-{version}",
        dist / f"VGen-macOS-{version}.zip",
        dist / f"vgen-windows-worker-installer-{version}.zip",
        dist / f"vgen-public-release-{version}.tar.gz",
        dist / "public-releases" / version,
    ):
        _remove_generated_candidate(path)


def build_deployment_archive(*, version: str, public_root: Path, output: Path) -> Path:
    expected = (
        Path("install-macos.sh"),
        Path("channels") / "stable.json",
        Path(version) / "manifest.json",
        Path(version) / f"VGen-macOS-{version}.zip",
        Path(version) / f"vgen-windows-worker-installer-{version}.zip",
    )
    sources: list[tuple[Path, Path]] = []
    for relative in expected:
        source = public_root / relative
        if source.is_symlink() or not source.is_file():
            raise ReleaseError(f"public release staging is missing a regular file: {relative}")
        sources.append((source, relative))

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ReleaseError(f"deployment archive must not be a symbolic link: {output}")
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0) as gzip_stream:
        with tarfile.open(fileobj=gzip_stream, mode="w") as archive:
            for source, relative in sources:
                info = archive.gettarinfo(source, arcname=relative.as_posix())
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.mtime = 0
                info.mode = 0o755 if relative == Path("install-macos.sh") else 0o644
                with source.open("rb") as handle:
                    archive.addfile(info, handle)
    output.write_bytes(buffer.getvalue())
    output.chmod(0o644)
    return output


def build_release(
    *,
    version: str,
    gateway_origin: str,
    release_origin: str,
    require_tag: bool,
) -> BuildResult:
    gateway, _ = _validated_origin(gateway_origin)
    release, _ = _validated_origin(release_origin)
    commit, published_at = _git_preflight(version, require_tag=require_tag)
    _clean_transient_outputs(version)
    python = sys.executable
    dist = REPOSITORY / "dist"

    _run([python, "-m", "ruff", "check", "src", "tests", "tools"])
    _run([python, "-m", "pytest"])
    _run([python, "tools/export_openapi_v1.py", "--check"])
    _run([python, "-m", "build"])
    _run([python, "tools/check_distribution.py", "dist"])
    _run([python, "tools/build_gateway_bundle.py"])
    _run(
        [
            "bash",
            "examples/macos/build-bundle.sh",
            "--gateway",
            gateway,
            "--release-origin",
            release,
        ]
    )

    wheel = dist / f"vgen-{version}-py3-none-any.whl"
    windows = dist / f"vgen-windows-worker-installer-{version}.zip"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPOSITORY / "src")
    _run(
        [
            python,
            "-m",
            "vgen",
            "worker",
            "installer-bundle",
            "--gateway-url",
            gateway,
            "--worker-wheel",
            str(wheel),
            "--output",
            str(windows),
        ],
        env=environment,
    )
    macos = dist / f"VGen-macOS-{version}.zip"
    _run(
        [
            python,
            "tools/build_public_release.py",
            "--version",
            version,
            "--published-at",
            published_at,
            "--gateway-origin",
            gateway,
            "--release-origin",
            release,
            "--mac-bundle",
            str(macos),
            "--windows-worker-bundle",
            str(windows),
        ]
    )
    deployment = build_deployment_archive(
        version=version,
        public_root=dist / "public-releases",
        output=dist / f"vgen-public-release-{version}.tar.gz",
    )
    return BuildResult(
        version=version,
        commit=commit,
        published_at=published_at,
        gateway_bundle=dist / f"vgen-gateway-{version}.tar.gz",
        macos_bundle=macos,
        windows_bundle=windows,
        deployment_archive=deployment,
        deployment_sha256=_sha256(deployment),
    )


def _ssh_commands(target: str, port: int) -> tuple[list[str], list[str]]:
    if SSH_TARGET_PATTERN.fullmatch(target) is None:
        raise ReleaseError("SSH target must use the form user@hostname or hostname")
    if not 1 <= port <= 65535:
        raise ReleaseError("SSH port must be between 1 and 65535")
    return ["ssh", "-p", str(port), target], ["scp", "-P", str(port)]


def _verify_public_release(release_origin: str, version: str) -> None:
    def read(url: str, limit: int) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "vgen-release/1"})
        with urllib.request.urlopen(request, timeout=20) as response:
            value = response.read(limit + 1)
        if len(value) > limit:
            raise ReleaseError(f"public verification response exceeded its limit: {url}")
        return value

    stable = json.loads(
        read(f"{release_origin}/releases/channels/stable.json", 1024 * 1024)
    )
    if (
        not isinstance(stable, dict)
        or set(stable) != {"schema_version", "channel", "version", "manifest_sha256"}
        or stable.get("version") != version
    ):
        raise ReleaseError("public stable pointer did not switch to the requested version")
    read(f"{release_origin}/releases/install-macos.sh", 2 * 1024 * 1024)
    manifest = json.loads(
        read(f"{release_origin}/releases/{version}/manifest.json", 1024 * 1024)
    )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise ReleaseError("public manifest does not contain the two expected installers")
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("filename"), str):
            raise ReleaseError("public manifest contains invalid artifact metadata")
        url = f"{release_origin}/releases/{version}/{artifact['filename']}"
        request = urllib.request.Request(
            url,
            headers={"Range": "bytes=0-0", "User-Agent": "vgen-release/1"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(1)


def _validate_gateway_publish_options(
    *,
    gateway_action: str,
    reset_test_gateway: bool,
    artifact_store: str | None,
    oss_endpoint: str | None,
    oss_bucket: str | None,
    oss_prefix: str,
    oss_ecs_role: str | None,
    aliyun_account_id: str | None,
    oss_transfer_role: str | None,
    confirm_oss_configured: bool,
) -> None:
    if gateway_action not in {"none", "install", "resume", "upgrade"}:
        raise ReleaseError("Gateway action must be none, install, resume, or upgrade")
    if reset_test_gateway and gateway_action != "install":
        raise ReleaseError("test reset is only valid with Gateway install")
    install_only_options = (
        artifact_store is not None
        or oss_endpoint is not None
        or oss_bucket is not None
        or oss_prefix != "vgen/v1"
        or oss_ecs_role is not None
        or aliyun_account_id is not None
        or oss_transfer_role is not None
        or confirm_oss_configured
    )
    if gateway_action != "install" and install_only_options:
        raise ReleaseError("artifact storage options require --install-gateway")
    if gateway_action == "install":
        if artifact_store not in {None, "oss"}:
            raise ReleaseError("artifact store must be oss; local storage is prohibited")
        if not all((oss_endpoint, oss_bucket, oss_ecs_role, aliyun_account_id, oss_transfer_role)):
            raise ReleaseError(
                "OSS Gateway install requires endpoint, bucket, account ID, and both RAM roles"
            )
        _validated_origin(oss_endpoint or "")
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}[a-z0-9]", oss_bucket or "") is None:
            raise ReleaseError("OSS bucket name is invalid")
        if re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", oss_prefix) is None:
            raise ReleaseError("OSS prefix is invalid")
        if re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", oss_ecs_role or "") is None:
            raise ReleaseError("ECS RAM Role name is invalid")
        if re.fullmatch(r"[0-9]{8,24}", aliyun_account_id or "") is None:
            raise ReleaseError("Alibaba Cloud account ID is invalid")
        if re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", oss_transfer_role or "") is None:
            raise ReleaseError("OSS transfer RAM Role name is invalid")


def publish_release(
    result: BuildResult,
    *,
    gateway_origin: str,
    release_origin: str,
    ssh_target: str,
    ssh_port: int,
    confirmed: bool,
    gateway_action: str,
    reset_test_gateway: bool = False,
    artifact_store: str | None = None,
    oss_endpoint: str | None = None,
    oss_bucket: str | None = None,
    oss_prefix: str = "vgen/v1",
    oss_ecs_role: str | None = None,
    aliyun_account_id: str | None = None,
    oss_transfer_role: str | None = None,
    confirm_oss_configured: bool = False,
) -> None:
    _, gateway_domain = _validated_origin(gateway_origin)
    release, release_domain = _validated_origin(release_origin)
    ssh, scp = _ssh_commands(ssh_target, ssh_port)
    _validate_gateway_publish_options(
        gateway_action=gateway_action,
        reset_test_gateway=reset_test_gateway,
        artifact_store=artifact_store,
        oss_endpoint=oss_endpoint,
        oss_bucket=oss_bucket,
        oss_prefix=oss_prefix,
        oss_ecs_role=oss_ecs_role,
        aliyun_account_id=aliyun_account_id,
        oss_transfer_role=oss_transfer_role,
        confirm_oss_configured=confirm_oss_configured,
    )
    if not confirmed:
        answer = input(
            f"Type {release_domain} to publish VGen {result.version} and switch stable: "
        ).strip()
        if answer != release_domain:
            raise ReleaseError("stable publication was not confirmed")

    remote_dir = _capture(
        [
            *ssh,
            f"umask 077; mktemp -d /tmp/vgen-release.{result.version}.XXXXXXXX",
        ],
        cwd=REPOSITORY,
    )
    if REMOTE_DIRECTORY_PATTERN.fullmatch(remote_dir) is None:
        raise ReleaseError("SSH returned an unsafe remote staging directory")
    publisher = REPOSITORY / "examples" / "ecs" / "publish-release.sh"
    upload_sources = [str(result.deployment_archive), str(publisher)]
    if gateway_action != "none":
        upload_sources.append(str(result.gateway_bundle))
    _run([*scp, *upload_sources, f"{ssh_target}:{remote_dir}/"])
    remote_archive = f"{remote_dir}/{result.deployment_archive.name}"
    remote_publisher = f"{remote_dir}/{publisher.name}"
    prefix = "" if ssh_target.startswith("root@") else "sudo "
    if gateway_action != "none":
        remote_gateway = f"{remote_dir}/{result.gateway_bundle.name}"
        remote_gateway_root = f"{remote_dir}/gateway"
        setup_commands: list[str] = []
        if reset_test_gateway and confirm_oss_configured:
            setup_commands.append(
                f"{prefix}bash ./setup-gateway.sh reset-test "
                f"--domain {shlex.quote(gateway_domain)} "
                f"--confirm-domain {shlex.quote(gateway_domain)} "
                "--confirm-no-active-tasks --confirm-reset-test"
            )
        action_options = ""
        if gateway_action == "install":
            action_options = (
                " --confirm-no-active-tasks"
                " --artifact-store oss"
            )
            action_options += (
                f" --oss-endpoint {shlex.quote(oss_endpoint or '')}"
                f" --oss-bucket {shlex.quote(oss_bucket or '')}"
                f" --oss-prefix {shlex.quote(oss_prefix)}"
                f" --oss-ecs-role {shlex.quote(oss_ecs_role or '')}"
                f" --aliyun-account-id {shlex.quote(aliyun_account_id or '')}"
                f" --oss-transfer-role {shlex.quote(oss_transfer_role or '')}"
            )
            if confirm_oss_configured:
                action_options += " --confirm-oss-configured"
        elif gateway_action == "resume":
            action_options = " --confirm-no-active-tasks"
        confirmation = "--confirm-upgrade" if gateway_action == "upgrade" else ""
        setup_commands.append(
            f"{prefix}bash ./setup-gateway.sh {gateway_action} "
            f"--domain {shlex.quote(gateway_domain)} "
            f"--confirm-domain {shlex.quote(gateway_domain)} "
            f"{confirmation}{action_options}".strip()
        )
        gateway_command = (
            f"mkdir -p {shlex.quote(remote_gateway_root)} && "
            f"tar -xzf {shlex.quote(remote_gateway)} "
            f"-C {shlex.quote(remote_gateway_root)} --strip-components=1 && "
            f"cd {shlex.quote(remote_gateway_root)} && "
            + " && ".join(setup_commands)
        )
        _run([*ssh, gateway_command])
    remote_command = (
        f"{prefix}bash {shlex.quote(remote_publisher)} "
        f"--archive {shlex.quote(remote_archive)} "
        f"--version {shlex.quote(result.version)} "
        f"--domain {shlex.quote(release_domain)} --confirm-stable"
    )
    _run([*ssh, remote_command])
    _verify_public_release(release, result.version)
    cleanup = f"rm -rf -- {shlex.quote(remote_dir)}"
    _run([*ssh, cleanup])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="./tools/release.sh",
        description="Build all VGen artifacts and optionally publish stable through ECS."
    )
    subcommands = parser.add_subparsers(dest="action", required=True)
    build = subcommands.add_parser("build", help="build a reviewed local release candidate")
    build.add_argument("--version", required=True)
    build.add_argument("--gateway", required=True, dest="gateway_origin")
    build.add_argument("--releases", required=True, dest="release_origin")
    build.add_argument(
        "--allow-untagged-candidate",
        action="store_true",
        help="allow a local candidate build without vX.Y.Z; never accepted by publish",
    )
    publish = subcommands.add_parser(
        "publish", help="build, upload, atomically switch stable, and verify"
    )
    publish.add_argument("--version", required=True)
    publish.add_argument("--gateway", required=True, dest="gateway_origin")
    publish.add_argument("--releases", required=True, dest="release_origin")
    publish.add_argument("--ssh", required=True, dest="ssh_target")
    publish.add_argument("--ssh-port", type=int, default=22)
    publish.add_argument("--confirm-stable", action="store_true")
    gateway_actions = publish.add_mutually_exclusive_group()
    gateway_actions.add_argument(
        "--upgrade-gateway",
        action="store_true",
        help="upgrade the ECS Gateway runtime before publishing the download channel",
    )
    gateway_actions.add_argument(
        "--install-gateway",
        action="store_true",
        help="initialize a new ECS Gateway before publishing the download channel",
    )
    gateway_actions.add_argument(
        "--resume-gateway",
        action="store_true",
        help="resume a safe partial Gateway initialization before publishing",
    )
    publish.add_argument(
        "--reset-test-gateway",
        action="store_true",
        help="archive an existing test Gateway before --install-gateway (destructive to live state)",
    )
    publish.add_argument(
        "--artifact-store",
        choices=("oss",),
        default=None,
        help="ciphertext artifact backend for a new Gateway; only oss is allowed",
    )
    publish.add_argument("--oss-endpoint", help="HTTPS OSS endpoint for Gateway signing")
    publish.add_argument("--oss-bucket", help="private OSS bucket for encrypted artifacts")
    publish.add_argument("--oss-prefix", default="vgen/v1", help="OSS object key prefix")
    publish.add_argument("--oss-ecs-role", help="ECS RAM Role used by Gateway; no AccessKey")
    publish.add_argument("--aliyun-account-id", help="Alibaba Cloud account ID owning the roles")
    publish.add_argument(
        "--oss-transfer-role", help="RAM Role assumed for object-scoped STS credentials"
    )
    publish.add_argument(
        "--confirm-oss-configured",
        action="store_true",
        help="confirm the generated OSS/RAM setup checklist is complete",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if VERSION_PATTERN.fullmatch(arguments.version) is None:
        raise ReleaseError("--version must use MAJOR.MINOR.PATCH")
    gateway_action = "none"
    if arguments.action == "publish":
        gateway_action = (
            "install"
            if arguments.install_gateway
            else "resume"
            if arguments.resume_gateway
            else "upgrade"
            if arguments.upgrade_gateway
            else "none"
        )
        _validate_gateway_publish_options(
            gateway_action=gateway_action,
            reset_test_gateway=arguments.reset_test_gateway,
            artifact_store=arguments.artifact_store,
            oss_endpoint=arguments.oss_endpoint,
            oss_bucket=arguments.oss_bucket,
            oss_prefix=arguments.oss_prefix,
            oss_ecs_role=arguments.oss_ecs_role,
            aliyun_account_id=arguments.aliyun_account_id,
            oss_transfer_role=arguments.oss_transfer_role,
            confirm_oss_configured=arguments.confirm_oss_configured,
        )
    require_tag = arguments.action == "publish" or not arguments.allow_untagged_candidate
    result = build_release(
        version=arguments.version,
        gateway_origin=arguments.gateway_origin,
        release_origin=arguments.release_origin,
        require_tag=require_tag,
    )
    print(f"release_version={result.version}")
    print(f"source_commit={result.commit}")
    print(f"published_at={result.published_at}")
    print(f"deployment_archive={result.deployment_archive}")
    print(f"deployment_sha256={result.deployment_sha256}")
    if arguments.action == "publish":
        publish_release(
            result,
            gateway_origin=arguments.gateway_origin,
            release_origin=arguments.release_origin,
            ssh_target=arguments.ssh_target,
            ssh_port=arguments.ssh_port,
            confirmed=arguments.confirm_stable,
            gateway_action=gateway_action,
            reset_test_gateway=arguments.reset_test_gateway,
            artifact_store=arguments.artifact_store,
            oss_endpoint=arguments.oss_endpoint,
            oss_bucket=arguments.oss_bucket,
            oss_prefix=arguments.oss_prefix,
            oss_ecs_role=arguments.oss_ecs_role,
            aliyun_account_id=arguments.aliyun_account_id,
            oss_transfer_role=arguments.oss_transfer_role,
            confirm_oss_configured=arguments.confirm_oss_configured,
        )
        print(f"stable={result.version}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, json.JSONDecodeError) as exc:
        print(f"[vgen-release] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
