from __future__ import annotations

import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

import vgen.cli.upgrade as upgrade
from vgen.cli.profile import GatewayProfile


class Response:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.headers: dict[str, str] = {}

    def __enter__(self):  # type: ignore[no-untyped-def]
        return self

    def __exit__(self, *_args):  # type: ignore[no-untyped-def]
        return False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            value, self.value = self.value, b""
            return value
        value, self.value = self.value[:size], self.value[size:]
        return value


class Opener:
    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values

    def open(self, request, timeout: int):  # type: ignore[no-untyped-def]
        assert timeout > 0
        return Response(self.values[request.full_url])


def _release_metadata(endpoint: str, version: str = "0.5.0") -> tuple[Opener, bytes]:
    filename = f"VGen-macOS-{version}.zip"
    artifact = b"reviewed-archive"
    metadata = {
        "name": "macos-cli",
        "kind": "cli-installer",
        "platform": "macos",
        "filename": filename,
        "size": len(artifact),
        "sha256": hashlib.sha256(artifact).hexdigest(),
        "content_type": "application/zip",
    }
    manifest = {
        "schema_version": 1,
        "audience": "public",
        "version": version,
        "published_at": "2026-08-22T12:34:56Z",
        "artifacts": [metadata],
    }
    manifest_bytes = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    stable = {
        "schema_version": 1,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "channel": "stable",
        "version": version,
    }
    stable_bytes = (json.dumps(stable, separators=(",", ":")) + "\n").encode()
    return (
        Opener(
            {
                f"{endpoint}/releases/channels/stable.json": stable_bytes,
                f"{endpoint}/releases/{version}/manifest.json": manifest_bytes,
                f"{endpoint}/releases/{version}/{filename}": artifact,
            }
        ),
        artifact,
    )


def _zip(path: Path, *, version: str = "0.5.0", unsafe: bool = False) -> None:
    prefix = f"VGen-macOS-{version}/"
    files = {
        "README.md": b"guide\n",
        "install.command": b"#!/bin/bash\nexit 0\n",
        f"vgen-{version}-py3-none-any.whl": b"wheel",
    }
    checksums = b"".join(
        f"{hashlib.sha256(value).hexdigest()}  {name}\n".encode()
        for name, value in files.items()
    )
    with zipfile.ZipFile(path, "w") as archive:
        for name, value in {**files, "SHA256SUMS": checksums}.items():
            info = zipfile.ZipInfo(prefix + name)
            info.external_attr = (0o755 if name == "install.command" else 0o644) << 16
            archive.writestr(info, value)
        if unsafe:
            archive.writestr(prefix + "../escape", b"bad")


def test_upgrade_candidate_is_bound_to_stable_manifest() -> None:
    endpoint = "https://gateway.example"
    opener, artifact = _release_metadata(endpoint)

    candidate = upgrade._candidate(endpoint, opener)

    assert candidate.version == "0.5.0"
    assert candidate.size == len(artifact)
    assert candidate.artifact_url == (
        "https://gateway.example/releases/0.5.0/VGen-macOS-0.5.0.zip"
    )


def test_upgrade_uses_pinned_release_origin_independent_of_gateway(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "release-source.json"
    source.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release_origin": "https://downloads.example",
            }
        ),
        encoding="utf-8",
    )
    source.chmod(0o600)
    monkeypatch.setattr(upgrade, "_release_source_path", lambda: source)

    assert (
        upgrade._configured_release_origin("https://gateway.example")
        == "https://downloads.example"
    )


def test_upgrade_legacy_bridge_falls_back_to_gateway_when_source_is_absent(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(
        upgrade,
        "_release_source_path",
        lambda: tmp_path / "not-installed-yet.json",
    )
    assert (
        upgrade._configured_release_origin("https://gateway.example")
        == "https://gateway.example"
    )


def test_upgrade_check_never_downgrades(monkeypatch) -> None:
    profile = GatewayProfile("home", "https://gateway.example")
    candidate = upgrade.UpgradeCandidate(
        "0.4.0", "https://gateway.example/release.zip", "release.zip", 1, "0" * 64
    )
    monkeypatch.setattr(upgrade.sys, "platform", "darwin")
    monkeypatch.setattr(upgrade, "__version__", "0.5.0")
    monkeypatch.setattr(upgrade, "_candidate", lambda *_args: candidate)

    assert upgrade.upgrade_cli(profile, check_only=True) == {
        "status": "ahead_of_stable",
        "current_version": "0.5.0",
        "available_version": "0.4.0",
    }


def test_upgrade_extracts_closed_bundle_and_rejects_traversal(tmp_path) -> None:
    archive = tmp_path / "valid.zip"
    _zip(archive)
    bundle = upgrade._extract_bundle(archive, tmp_path / "valid", "0.5.0")
    assert (bundle / "install.command").is_file()

    unsafe = tmp_path / "unsafe.zip"
    _zip(unsafe, unsafe=True)
    with pytest.raises(upgrade.UpgradeError, match="unsafe path"):
        upgrade._extract_bundle(unsafe, tmp_path / "unsafe", "0.5.0")


def test_stable_worker_wheel_comes_from_verified_release_bundle(
    tmp_path, monkeypatch
) -> None:
    profile = GatewayProfile("home", "https://gateway.example")
    candidate = upgrade.UpgradeCandidate(
        "0.5.0",
        "https://downloads.example/releases/0.5.0/VGen-macOS-0.5.0.zip",
        "VGen-macOS-0.5.0.zip",
        1,
        "0" * 64,
    )
    monkeypatch.setattr(
        upgrade, "_configured_release_origin", lambda _endpoint: "https://downloads.example"
    )
    monkeypatch.setattr(upgrade, "_candidate", lambda *_args: candidate)

    def download(_opener, _candidate, destination, _origin):  # type: ignore[no-untyped-def]
        _zip(destination)

    monkeypatch.setattr(upgrade, "_download", download)

    with upgrade.stable_worker_wheel(profile) as (version, wheel):
        assert version == "0.5.0"
        assert wheel.name == "vgen-0.5.0-py3-none-any.whl"
        assert wheel.read_bytes() == b"wheel"
        temporary_wheel = wheel

    assert not temporary_wheel.exists()


def test_upgrade_requires_managed_launcher(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    release = (
        home
        / "Library"
        / "Application Support"
        / "VGen"
        / "cli"
        / "releases"
        / "0.4.0-reviewed"
    )
    executable = release / "bin" / "vgen"
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    (release / ".vgen-managed-install").write_text("digest", encoding="utf-8")
    launcher = home / ".local" / "bin" / "vgen"
    launcher.parent.mkdir(parents=True)
    launcher.symlink_to(executable)
    monkeypatch.setenv("HOME", str(home))

    assert upgrade._managed_launcher() == (launcher, str(executable), executable)

    launcher.unlink()
    outside = tmp_path / "outside-vgen"
    outside.write_text("#!/bin/sh\n", encoding="utf-8")
    launcher.symlink_to(outside)
    with pytest.raises(upgrade.UpgradeError, match="outside"):
        upgrade._managed_launcher()


def test_upgrade_installs_switches_and_refreshes_broker(tmp_path, monkeypatch) -> None:
    profile = GatewayProfile("home", "https://gateway.example")
    candidate = upgrade.UpgradeCandidate(
        "0.5.0", "https://gateway.example/release.zip", "release.zip", 1, "0" * 64
    )
    launcher = tmp_path / "vgen"
    old = tmp_path / "old-vgen"
    new = tmp_path / "new-vgen"
    managed = iter(((launcher, str(old), old), (launcher, str(new), new)))
    commands: list[list[str]] = []
    monkeypatch.setattr(upgrade.sys, "platform", "darwin")
    monkeypatch.setattr(upgrade, "__version__", "0.4.0")
    monkeypatch.setattr(upgrade, "_candidate", lambda *_args: candidate)
    monkeypatch.setattr(upgrade, "_managed_launcher", lambda: next(managed))
    monkeypatch.setattr(upgrade, "_download", lambda *_args: None)

    def extract(_archive, output, _version):  # type: ignore[no-untyped-def]
        bundle = output / "bundle"
        bundle.mkdir()
        (bundle / "install.command").write_text("#!/bin/bash\n", encoding="utf-8")
        return bundle

    def run(command, *, label):  # type: ignore[no-untyped-def]
        commands.append(command)
        stdout = (
            "vgen 0.5.0\n"
            if command[-1] == "--version"
            else '{"loaded":true,"runtime_version":"0.5.0"}\n'
            if label == "Home Broker refresh"
            else ""
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(upgrade, "_extract_bundle", extract)
    monkeypatch.setattr(upgrade, "_run_checked", run)

    result = upgrade.upgrade_cli(profile, assume_yes=True)

    assert result == {
        "status": "upgraded",
        "previous_version": "0.4.0",
        "current_version": "0.5.0",
        "home_broker_refreshed": True,
    }
    assert commands[-1] == [str(new), "broker", "service-refresh"]


def test_upgrade_rolls_back_launcher_when_broker_refresh_fails(tmp_path, monkeypatch) -> None:
    profile = GatewayProfile("home", "https://gateway.example")
    candidate = upgrade.UpgradeCandidate(
        "0.5.0", "https://gateway.example/release.zip", "release.zip", 1, "0" * 64
    )
    launcher = tmp_path / "vgen"
    old = tmp_path / "old-vgen"
    new = tmp_path / "new-vgen"
    managed = iter(((launcher, str(old), old), (launcher, str(new), new)))
    restored: list[tuple[Path, str]] = []
    monkeypatch.setattr(upgrade.sys, "platform", "darwin")
    monkeypatch.setattr(upgrade, "__version__", "0.4.0")
    monkeypatch.setattr(upgrade, "_candidate", lambda *_args: candidate)
    monkeypatch.setattr(upgrade, "_managed_launcher", lambda: next(managed))
    monkeypatch.setattr(upgrade, "_download", lambda *_args: None)
    monkeypatch.setattr(
        upgrade,
        "_extract_bundle",
        lambda _archive, output, _version: output,
    )

    def run(command, *, label):  # type: ignore[no-untyped-def]
        if label == "Home Broker refresh":
            raise upgrade.UpgradeError("refresh failed")
        stdout = "vgen 0.5.0\n" if command[-1] == "--version" else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(upgrade, "_run_checked", run)
    monkeypatch.setattr(
        upgrade, "_restore_launcher", lambda path, target: restored.append((path, target))
    )
    monkeypatch.setattr(
        upgrade.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", ""),
    )

    with pytest.raises(upgrade.UpgradeError, match="refresh failed"):
        upgrade.upgrade_cli(profile, assume_yes=True)

    assert restored == [(launcher, str(old))]
