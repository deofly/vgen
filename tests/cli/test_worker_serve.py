from __future__ import annotations

from pathlib import Path
from typing import Any

from vgen.cli.main import main
from vgen.worker import main as worker_main


def test_worker_serve_forwards_comfy_policy_file(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    policy = tmp_path / "comfy-policy.yaml"
    received: list[str] = []

    def fake_run(arguments: list[str]) -> int:
        received.extend(arguments)
        return 0

    monkeypatch.setattr(worker_main, "run", fake_run)

    assert main(["worker", "serve", "--once", "--comfy-policy-file", str(policy)]) == 0
    position = received.index("--comfy-policy-file")
    assert received[position + 1] == str(policy)


def test_worker_serve_preserves_comfy_policy_environment(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    policy = tmp_path / "environment-policy.yaml"
    received: list[str] = []
    monkeypatch.setenv("VGEN_COMFYUI_POLICY_FILE", str(policy))
    monkeypatch.setattr(
        worker_main,
        "run",
        lambda arguments: received.extend(arguments) or 0,
    )

    assert main(["worker", "serve", "--once"]) == 0
    position = received.index("--comfy-policy-file")
    assert received[position + 1] == str(policy)
