from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _allow_explicit_test_artifact_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production defaults fail closed; tests opt into isolated temporary storage."""

    monkeypatch.setenv("VGEN_ARTIFACT_STORE", "local")
    monkeypatch.setenv("VGEN_ALLOW_LOCAL_ARTIFACT_STORE_FOR_TESTS", "1")
