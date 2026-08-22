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
        raise ReleaseError("Gateway origin is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ReleaseError("Gateway origin must be a credential-free HTTPS origin")
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
    require_tag: bool,
) -> BuildResult:
    origin, _ = _validated_origin(gateway_origin)
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
    _run(["bash", "examples/macos/build-bundle.sh", "--gateway", origin])

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
            origin,
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
            origin,
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


def _verify_public_release(origin: str, version: str) -> None:
    def read(url: str, limit: int) -> bytes:
        request = urllib.request.Request(url, headers={"User-Agent": "vgen-release/1"})
        with urllib.request.urlopen(request, timeout=20) as response:
            value = response.read(limit + 1)
        if len(value) > limit:
            raise ReleaseError(f"public verification response exceeded its limit: {url}")
        return value

    stable = json.loads(read(f"{origin}/api/v1/releases/channels/stable", 1024 * 1024))
    if not isinstance(stable, dict) or stable.get("version") != version:
        raise ReleaseError("public stable API did not switch to the requested version")
    read(f"{origin}/releases/install-macos.sh", 2 * 1024 * 1024)
    read(f"{origin}/releases/{version}/manifest.json", 1024 * 1024)
    artifacts = stable.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise ReleaseError("public stable API does not contain the two expected installers")
    origin_key = urllib.parse.urlsplit(origin)[:2]
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("url"), str):
            raise ReleaseError("public stable API contains invalid artifact metadata")
        url = urllib.parse.urljoin(f"{origin}/", artifact["url"])
        if urllib.parse.urlsplit(url)[:2] != origin_key:
            raise ReleaseError("public artifact URL escaped the Gateway origin")
        request = urllib.request.Request(
            url,
            headers={"Range": "bytes=0-0", "User-Agent": "vgen-release/1"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(1)


def publish_release(
    result: BuildResult,
    *,
    gateway_origin: str,
    ssh_target: str,
    ssh_port: int,
    confirmed: bool,
    upgrade_gateway: bool,
) -> None:
    origin, domain = _validated_origin(gateway_origin)
    ssh, scp = _ssh_commands(ssh_target, ssh_port)
    if not confirmed:
        answer = input(
            f"Type {domain} to publish VGen {result.version} and switch stable: "
        ).strip()
        if answer != domain:
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
    if upgrade_gateway:
        upload_sources.append(str(result.gateway_bundle))
    _run([*scp, *upload_sources, f"{ssh_target}:{remote_dir}/"])
    remote_archive = f"{remote_dir}/{result.deployment_archive.name}"
    remote_publisher = f"{remote_dir}/{publisher.name}"
    prefix = "" if ssh_target.startswith("root@") else "sudo "
    if upgrade_gateway:
        remote_gateway = f"{remote_dir}/{result.gateway_bundle.name}"
        remote_gateway_root = f"{remote_dir}/gateway"
        gateway_command = (
            f"mkdir -p {shlex.quote(remote_gateway_root)} && "
            f"tar -xzf {shlex.quote(remote_gateway)} "
            f"-C {shlex.quote(remote_gateway_root)} --strip-components=1 && "
            f"cd {shlex.quote(remote_gateway_root)} && "
            f"{prefix}bash ./setup-gateway.sh upgrade "
            f"--domain {shlex.quote(domain)} "
            f"--confirm-domain {shlex.quote(domain)} --confirm-upgrade"
        )
        _run([*ssh, gateway_command])
    remote_command = (
        f"{prefix}bash {shlex.quote(remote_publisher)} "
        f"--archive {shlex.quote(remote_archive)} "
        f"--version {shlex.quote(result.version)} "
        f"--domain {shlex.quote(domain)} --confirm-stable"
    )
    _run([*ssh, remote_command])
    _verify_public_release(origin, result.version)
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
    publish.add_argument("--ssh", required=True, dest="ssh_target")
    publish.add_argument("--ssh-port", type=int, default=22)
    publish.add_argument("--confirm-stable", action="store_true")
    publish.add_argument(
        "--upgrade-gateway",
        action="store_true",
        help="upgrade the ECS Gateway runtime before publishing the download channel",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    if VERSION_PATTERN.fullmatch(arguments.version) is None:
        raise ReleaseError("--version must use MAJOR.MINOR.PATCH")
    require_tag = arguments.action == "publish" or not arguments.allow_untagged_candidate
    result = build_release(
        version=arguments.version,
        gateway_origin=arguments.gateway_origin,
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
            ssh_target=arguments.ssh_target,
            ssh_port=arguments.ssh_port,
            confirmed=arguments.confirm_stable,
            upgrade_gateway=arguments.upgrade_gateway,
        )
        print(f"stable={result.version}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, OSError, json.JSONDecodeError) as exc:
        print(f"[vgen-release] ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
