from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

from vgen import __version__

ROOT = Path(__file__).resolve().parents[2]


def _project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def test_checkout_and_release_tool_use_canonical_project_version() -> None:
    expected = _project_version()
    assert re.fullmatch(r"0\.[0-9]+\.[0-9]+", expected)
    assert __version__ == expected
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "project_version.py")],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == expected


def test_pre_v1_runtime_tools_do_not_copy_product_version() -> None:
    version = _project_version()
    release_files = (
        ROOT / "tools" / "build_gateway_bundle.py",
        ROOT / "tools" / "build_public_release.py",
        ROOT / "examples" / "ecs" / "setup-gateway.sh",
        ROOT / "examples" / "macos" / "build-bundle.sh",
        ROOT / "examples" / "macos" / "install.command",
        ROOT / "examples" / "windows-worker" / "setup-worker.ps1",
    )
    for path in release_files:
        assert version not in path.read_text(encoding="utf-8"), path


def test_pre_v1_legacy_runtime_is_not_hidden_or_packaged() -> None:
    for relative in ("cli", "server", "worker", "deploy"):
        assert not (ROOT / relative).exists()

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for ignored in ("/cli/", "/server/", "/worker/", "/deploy/"):
        assert ignored not in gitignore

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"/cli/**"' not in pyproject
    assert '"/server/**"' not in pyproject
    assert '"/worker/**"' not in pyproject
    assert '"/deploy/**"' not in pyproject
