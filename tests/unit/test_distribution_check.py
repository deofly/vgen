from __future__ import annotations

import importlib.util
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "vgen_distribution_check", ROOT / "tools" / "check_distribution.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def test_distribution_contract_requires_new_runtime_modules() -> None:
    modules = {
        "gateway/bootstrap_capabilities.py",
        "market/paths.py",
        "protocol/diagnostics.py",
        "protocol/media.py",
    }

    assert {f"vgen/{module}" for module in modules} <= CHECKER.REQUIRED_WHEEL
    assert {f"src/vgen/{module}" for module in modules} <= CHECKER.REQUIRED_SDIST


@pytest.mark.parametrize(
    "generated_path",
    [
        "sdks/java/target/vgen-sdk.jar",
        "sdks/java/build/Leaked.class",
        "src/vgen/__pycache__/module.pyc",
        "sdks/python/.pytest_cache/README.md",
    ],
)
def test_sdist_rejects_generated_build_artifacts(
    tmp_path: Path, generated_path: str
) -> None:
    version = "1.2.3"
    archive_path = tmp_path / f"vgen-{version}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.addfile(tarfile.TarInfo(f"vgen-{version}/{generated_path}"))

    with pytest.raises(RuntimeError, match="generated build artifacts"):
        CHECKER._check_sdist(archive_path, version)
