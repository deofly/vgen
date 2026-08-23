from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_public_repository", ROOT / "tools" / "check_public_repository.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_public_repository_check_rejects_local_state_and_private_key_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment = tmp_path / ".env"
    environment.write_text("VGEN_SECRET=not-a-live-value\n", encoding="utf-8")
    production_environment = tmp_path / ".env.production"
    production_environment.write_text("VGEN_SECRET=also-not-live\n", encoding="utf-8")
    database = tmp_path / "gateway.db"
    database.write_bytes(b"SQLite format 3\0synthetic")
    source = tmp_path / "accidental.txt"
    source.write_text(
        "-----BEGIN OPENSSH " + "PRIVATE KEY-----\nsynthetic-test-only\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(
        MODULE,
        "tracked_files",
        lambda: [environment, production_environment, database, source],
    )

    failures = MODULE.violations()

    assert "forbidden tracked file: .env" in failures
    assert "forbidden tracked file: .env.production" in failures
    assert "forbidden tracked file: gateway.db" in failures
    assert "private key material found in: accidental.txt" in failures


def test_public_repository_check_accepts_normal_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "module.py"
    source.write_text("VALUE = 'public'\n", encoding="utf-8")
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    monkeypatch.setattr(MODULE, "tracked_files", lambda: [source])

    assert MODULE.violations() == []
