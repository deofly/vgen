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
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tomllib
import urllib.error
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


@dataclass(frozen=True, slots=True)
class ReleaseConfig:
    gateway_origin: str
    release_origin: str
    ssh_target: str
    ssh_port: int = 22


def _release_config_path() -> Path:
    override = os.environ.get("VGEN_RELEASE_CONFIG")
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise ReleaseError("VGEN_RELEASE_CONFIG must be an absolute path")
        return path
    config_home = os.environ.get("XDG_CONFIG_HOME")
    root = Path(config_home).expanduser() if config_home else Path.home() / ".config"
    return root / "vgen" / "release.toml"


def _validated_ssh_target(value: str) -> str:
    target = value.strip()
    if SSH_TARGET_PATTERN.fullmatch(target) is None:
        raise ReleaseError("SSH target must use the form user@hostname or hostname")
    return target


def _validated_ssh_port(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ReleaseError("SSH port must be between 1 and 65535")
    return value


def _validated_release_config(
    *, gateway: object, releases: object, ssh: object, ssh_port: object
) -> ReleaseConfig:
    if not all(isinstance(value, str) for value in (gateway, releases, ssh)):
        raise ReleaseError("release config origins and SSH target must be strings")
    gateway_origin, _ = _validated_origin(str(gateway))
    release_origin, _ = _validated_origin(str(releases))
    return ReleaseConfig(
        gateway_origin=gateway_origin,
        release_origin=release_origin,
        ssh_target=_validated_ssh_target(str(ssh)),
        ssh_port=_validated_ssh_port(ssh_port),
    )


def _read_release_config() -> ReleaseConfig | None:
    path = _release_config_path()
    if not path.exists():
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReleaseError(f"cannot inspect release config: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise ReleaseError(f"release config must be a regular file, not a symlink: {path}")
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise ReleaseError(f"release config permissions must be 0600: {path}")
    if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
        raise ReleaseError(f"release config must be owned by the current user: {path}")
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"cannot read release config: {path}") from exc
    if set(value) != {"schema_version", "gateway", "releases", "ssh", "ssh_port"}:
        raise ReleaseError(f"release config has unknown or missing fields: {path}")
    if value.get("schema_version") != 1:
        raise ReleaseError(f"release config schema_version must be 1: {path}")
    return _validated_release_config(
        gateway=value.get("gateway"),
        releases=value.get("releases"),
        ssh=value.get("ssh"),
        ssh_port=value.get("ssh_port"),
    )


def _write_release_config(config: ReleaseConfig) -> Path:
    path = _release_config_path()
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ReleaseError(f"refusing to replace non-regular release config: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    content = (
        "schema_version = 1\n"
        f"gateway = {json.dumps(config.gateway_origin)}\n"
        f"releases = {json.dumps(config.release_origin)}\n"
        f"ssh = {json.dumps(config.ssh_target)}\n"
        f"ssh_port = {config.ssh_port}\n"
    ).encode()
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return path


def _resolved_release_config(arguments: argparse.Namespace, *, require_ssh: bool) -> ReleaseConfig:
    saved = _read_release_config()
    gateway = arguments.gateway_origin or (saved.gateway_origin if saved else None)
    releases = arguments.release_origin or (saved.release_origin if saved else None)
    ssh = getattr(arguments, "ssh_target", None) or (saved.ssh_target if saved else None)
    explicit_port = getattr(arguments, "ssh_port", None)
    ssh_port = explicit_port if explicit_port is not None else (saved.ssh_port if saved else 22)
    missing = []
    if gateway is None:
        missing.append("--gateway")
    if releases is None:
        missing.append("--releases")
    if require_ssh and ssh is None:
        missing.append("--ssh")
    if missing:
        raise ReleaseError(
            "missing release target "
            + ", ".join(missing)
            + "; run ./tools/release.sh configure once or pass it explicitly"
        )
    return _validated_release_config(
        gateway=gateway,
        releases=releases,
        ssh=ssh or "localhost",
        ssh_port=ssh_port,
    )


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


def _version_tuple(value: str) -> tuple[int, int, int]:
    if VERSION_PATTERN.fullmatch(value) is None:
        raise ReleaseError("version must use MAJOR.MINOR.PATCH")
    major, minor, patch = value.split(".")
    return int(major), int(minor), int(patch)


def _public_version_exists(release_origin: str, version: str) -> bool:
    release, _ = _validated_origin(release_origin)
    url = f"{release}/releases/{version}/manifest.json"
    request = urllib.request.Request(url, headers={"User-Agent": "vgen-release/1"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response.read(1)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise ReleaseError(
            f"cannot verify whether VGen {version} is already public: HTTP {exc.code}"
        ) from None
    except OSError as exc:
        raise ReleaseError(
            f"cannot verify whether VGen {version} is already public: {type(exc).__name__}"
        ) from None
    return True


def _remote_tag_locations(tag: str, *, repository: Path) -> list[str]:
    remotes = _capture(["git", "remote"], cwd=repository).splitlines()
    locations = []
    for remote in remotes:
        value = _capture(
            [
                "git",
                "ls-remote",
                "--tags",
                remote,
                f"refs/tags/{tag}",
                f"refs/tags/{tag}^{{}}",
            ],
            cwd=repository,
        )
        if value:
            locations.append(remote)
    return locations


def _replace_project_version(
    current: str, requested: str, *, repository: Path
) -> None:
    path = repository / "pyproject.toml"
    if path.is_symlink() or not path.is_file():
        raise ReleaseError("pyproject.toml must be a regular file, not a symlink")
    original = path.read_text(encoding="utf-8")
    project_start = original.find("[project]")
    if project_start < 0:
        raise ReleaseError("pyproject.toml has no [project] table")
    next_table = original.find("\n[", project_start + len("[project]"))
    project_end = len(original) if next_table < 0 else next_table + 1
    section = original[project_start:project_end]
    pattern = re.compile(rf'(?m)^version = "{re.escape(current)}"$')
    replaced, count = pattern.subn(f'version = "{requested}"', section)
    if count != 1:
        raise ReleaseError("pyproject.toml [project] must contain exactly one current version")
    updated = original[:project_start] + replaced + original[project_end:]
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(updated, encoding="utf-8")
        temporary.chmod(stat.S_IMODE(path.stat().st_mode))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _prepare_release_source(
    version: str,
    *,
    release_origin: str,
    confirmed: bool,
    repository: Path = REPOSITORY,
) -> None:
    requested = _version_tuple(version)
    dirty = _capture(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=repository,
    )
    if dirty:
        preview = ", ".join(line[:160] for line in dirty.splitlines()[:8])
        raise ReleaseError(
            "Git worktree must be clean before automatic release preparation: " + preview
        )
    current = _project_version(repository)
    if _version_tuple(current) > requested:
        raise ReleaseError(f"refusing to downgrade project.version from {current} to {version}")
    head = _capture(["git", "rev-parse", "--verify", "HEAD"], cwd=repository)
    tag = f"v{version}"
    tag_target = ""
    tag_exists = True
    try:
        tag_target = _capture(["git", "rev-list", "-n", "1", tag], cwd=repository)
    except ReleaseError:
        tag_exists = False
    version_change = current != version
    if not version_change and tag_exists and tag_target == head:
        return
    if _public_version_exists(release_origin, version):
        raise ReleaseError(
            f"VGen {version} already exists on the public release site; use a new version"
        )
    if tag_exists and (tag_target != head or version_change):
        locations = _remote_tag_locations(tag, repository=repository)
        if locations:
            raise ReleaseError(
                f"{tag} already exists on remote(s) {', '.join(locations)}; use a new version"
            )
    if not confirmed:
        changes = []
        if version_change:
            changes.append(f"update project.version {current} -> {version} and commit it")
        if tag_exists:
            changes.append(f"move unpublished local tag {tag} to the release commit")
        else:
            changes.append(f"create annotated tag {tag}")
        answer = input(
            "Release preparation will " + "; ".join(changes) + f". Type {version} to continue: "
        ).strip()
        if answer != version:
            raise ReleaseError("release source preparation was not confirmed")
    if version_change:
        _replace_project_version(current, version, repository=repository)
        _run(["git", "add", "--", "pyproject.toml"], cwd=repository)
        _run(
            ["git", "commit", "-m", f"release: prepare vgen {version}"],
            cwd=repository,
        )
        head = _capture(["git", "rev-parse", "--verify", "HEAD"], cwd=repository)
    if tag_exists:
        current_target = _capture(["git", "rev-list", "-n", "1", tag], cwd=repository)
        if current_target != head:
            _run(["git", "tag", "-d", tag], cwd=repository)
            tag_exists = False
    if not tag_exists:
        _run(["git", "tag", "-a", tag, "-m", f"VGen {version}"], cwd=repository)


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
    target = _validated_ssh_target(target)
    port = _validated_ssh_port(port)
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
    configure = subcommands.add_parser(
        "configure", help="save the default Gateway, release site, and SSH target"
    )
    configure.add_argument("--gateway", required=True, dest="gateway_origin")
    configure.add_argument("--releases", required=True, dest="release_origin")
    configure.add_argument("--ssh", required=True, dest="ssh_target")
    configure.add_argument("--ssh-port", type=int, default=22)
    build = subcommands.add_parser("build", help="build a reviewed local release candidate")
    build.add_argument("--version", required=True)
    build.add_argument("--gateway", dest="gateway_origin")
    build.add_argument("--releases", dest="release_origin")
    build.add_argument(
        "--allow-untagged-candidate",
        action="store_true",
        help="allow a local candidate build without vX.Y.Z; never accepted by publish",
    )
    publish = subcommands.add_parser(
        "publish", help="build, upload, atomically switch stable, and verify"
    )
    publish.add_argument("--version", required=True)
    publish.add_argument("--gateway", dest="gateway_origin")
    publish.add_argument("--releases", dest="release_origin")
    publish.add_argument("--ssh", dest="ssh_target")
    publish.add_argument("--ssh-port", type=int)
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
    if arguments.action == "configure":
        config = _validated_release_config(
            gateway=arguments.gateway_origin,
            releases=arguments.release_origin,
            ssh=arguments.ssh_target,
            ssh_port=arguments.ssh_port,
        )
        path = _write_release_config(config)
        print(f"release_config={path}")
        print(f"gateway={config.gateway_origin}")
        print(f"releases={config.release_origin}")
        print(f"ssh={config.ssh_target}")
        print(f"ssh_port={config.ssh_port}")
        return 0
    if VERSION_PATTERN.fullmatch(arguments.version) is None:
        raise ReleaseError("--version must use MAJOR.MINOR.PATCH")
    targets = _resolved_release_config(
        arguments, require_ssh=arguments.action == "publish"
    )
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
        _prepare_release_source(
            arguments.version,
            release_origin=targets.release_origin,
            confirmed=arguments.confirm_stable,
        )
    require_tag = arguments.action == "publish" or not arguments.allow_untagged_candidate
    result = build_release(
        version=arguments.version,
        gateway_origin=targets.gateway_origin,
        release_origin=targets.release_origin,
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
            gateway_origin=targets.gateway_origin,
            release_origin=targets.release_origin,
            ssh_target=targets.ssh_target,
            ssh_port=targets.ssh_port,
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
