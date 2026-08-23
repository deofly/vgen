#!/usr/bin/env python3
"""Check that release archives contain v1 contracts and no legacy runtime."""

from __future__ import annotations

import argparse
import tarfile
import tomllib
import zipfile
from pathlib import Path

LEGACY_ROOTS = ("cli/", "server/", "worker/", "deploy/")
REQUIRED_SDIST = {
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "docs/developer-guide.md",
    "docs/user-guide.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "schemas/openapi-v1.json",
    "examples/ecs/setup-gateway.sh",
    "examples/ecs/publish-release.sh",
    "examples/ecs/vgen-gateway.service",
    "examples/macos/build-bundle.sh",
    "examples/macos/install.command",
    "examples/windows-worker/enroll-worker.ps1",
    "examples/windows-worker/setup-worker.ps1",
    "examples/windows-worker/start-worker.cmd",
    "src/vgen/gateway/openapi.py",
    "src/vgen/cli/upgrade.py",
    "tools/build_public_release.py",
    "tools/build_windows_worker_bundle.py",
    "tools/check_distribution.py",
    "tools/check_public_repository.py",
    "tools/export_openapi_v1.py",
    "tools/project_version.py",
    "tools/release.py",
    "tools/release.sh",
    "workflows/vgen/minimax-h3-8step/1.0.0/manifest.yaml",
}
REQUIRED_WHEEL = {
    "vgen/assets/worker/comfyui-minimax-h3-policy.yaml",
    "vgen/assets/worker/enroll-worker.ps1",
    "vgen/assets/worker/setup-worker.ps1",
    "vgen/assets/worker/start-worker.cmd",
    "vgen/assets/workflows/vgen/minimax-h3-8step/1.0.0/manifest.yaml",
    "vgen/assets/workflows/vgen/minimax-h3-8step/1.0.0/mapping.json",
    "vgen/assets/workflows/vgen/minimax-h3-8step/1.0.0/workflow.json",
    "vgen/cli/setup.py",
    "vgen/cli/upgrade.py",
    "vgen/cli/worker_bundle.py",
    "vgen/cli/worker_enrollment.py",
    "vgen/crypto/maintenance.py",
    "vgen/gateway/openapi.py",
    "vgen/worker/maintenance.py",
    "vgen/worker/model_installer.py",
    "vgen/worker/updater.py",
}
CONSOLE_SCRIPTS = {
    "vgen = vgen.cli.main:main",
    "vgen-broker = vgen.broker.main:main",
    "vgen-gateway = vgen.gateway.main:main",
    "vgen-worker = vgen.worker.main:main",
}


def _version() -> str:
    with Path("pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def _one(paths: list[Path], kind: str) -> Path:
    if len(paths) != 1:
        raise RuntimeError(f"expected exactly one {kind}, found {len(paths)}")
    return paths[0]


def _check_sdist(path: Path, version: str) -> None:
    root = f"vgen-{version}/"
    with tarfile.open(path, "r:gz") as archive:
        names = set(archive.getnames())
    relative = {name.removeprefix(root) for name in names if name.startswith(root)}
    leaked = sorted(name for name in relative if name.startswith(LEGACY_ROOTS))
    if leaked:
        raise RuntimeError(f"sdist contains legacy v0 paths: {leaked[:10]}")
    missing = sorted(REQUIRED_SDIST - relative)
    if missing:
        raise RuntimeError(f"sdist is missing public v1 contracts: {missing}")


def _check_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        missing = sorted(REQUIRED_WHEEL - names)
        if missing:
            raise RuntimeError(f"wheel is missing runtime modules: {missing}")
        entrypoint_names = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        entrypoint_path = _one([Path(name) for name in entrypoint_names], "entry point file")
        entrypoints = archive.read(str(entrypoint_path)).decode("utf-8")
        for legal_file in ("LICENSE", "NOTICE"):
            matches = [name for name in names if name.endswith(f".dist-info/licenses/{legal_file}")]
            _one([Path(name) for name in matches], f"wheel {legal_file}")
    missing_scripts = sorted(script for script in CONSOLE_SCRIPTS if script not in entrypoints)
    if missing_scripts:
        raise RuntimeError(f"wheel is missing console scripts: {missing_scripts}")


def run(directory: Path) -> None:
    version = _version()
    sdist = _one(sorted(directory.glob(f"vgen-{version}.tar.gz")), "sdist")
    wheel = _one(sorted(directory.glob(f"vgen-{version}-*.whl")), "wheel")
    _check_sdist(sdist, version)
    _check_wheel(wheel)
    print(f"Distribution contract is valid: {sdist.name}, {wheel.name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=Path("dist"))
    arguments = parser.parse_args()
    run(arguments.directory)


if __name__ == "__main__":
    main()
