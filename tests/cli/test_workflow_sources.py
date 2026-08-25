from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from vgen.cli import main as cli_main
from vgen.cli.main import build_parser, dispatch
from vgen.market.registry import WorkflowRegistry, build_archive, write_checksums


def _make_package(path: Path, *, workflow_id: str) -> Path:
    path.mkdir(parents=True)
    manifest = {
        "schema_version": 1,
        "id": workflow_id,
        "version": "1.0.0",
        "title": "Workflow source test",
        "summary": "Exercise CLI workflow source resolution",
        "license": "Apache-2.0",
        "provenance": "market",
        "publisher": {"id": "tests", "public_key": None},
        "parameters": {"type": "object"},
        "variants": [
            {
                "name": "comfyui",
                "executor_type": "comfyui",
                "payload_format": "comfyui-api-graph/v1",
                "payload": "workflow.json",
                "mapping": "mapping.json",
                "operations": ["t2v"],
                "models": [],
            }
        ],
    }
    (path / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    (path / "workflow.json").write_text("{}\n", encoding="utf-8")
    (path / "mapping.json").write_text("{}\n", encoding="utf-8")
    write_checksums(path)
    return path


@pytest.mark.parametrize("action", ("show", "verify"))
def test_workflow_inspection_resolves_bundled_reference(
    action: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(
        build_parser().parse_args(
            ["workflow", action, "vgen/ltx-2.5-distilled-t2v@1.0.0"]
        )
    )

    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["id"] == "vgen/ltx-2.5-distilled-t2v"
    assert result["digest"] == (
        "sha256:d782e1a99b360198f288f745932a23ac86a01b0357ec4728de8852b7754547fb"
    )
    assert result["signed"] is False
    assert len(registry.installed()) == 1


def test_workflow_inspection_resolves_installed_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    package = _make_package(tmp_path / "package", workflow_id="example/installed")
    installed = registry.install(package, allow_unsigned=True)
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(
        build_parser().parse_args(
            ["workflow", "show", "example/installed@1.0.0"]
        )
    )

    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["id"] == "example/installed"
    assert result["digest"] == f"sha256:{installed.digest}"


def test_workflow_inspection_prefers_existing_directory_over_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    _make_package(
        tmp_path / "example" / "reference@1.0.0",
        workflow_id="local/directory",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(
        build_parser().parse_args(
            ["workflow", "verify", "example/reference@1.0.0"]
        )
    )

    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["id"] == "local/directory"
    assert registry.installed() == []


def test_workflow_inspection_supports_zip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    package = _make_package(tmp_path / "package", workflow_id="example/archive")
    archive = build_archive(package, tmp_path / "workflow.zip", allow_unsigned=True)
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(build_parser().parse_args(["workflow", "show", str(archive)]))

    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["id"] == "example/archive"
    assert result["signed"] is False
    assert registry.installed() == []


def test_workflow_package_builds_reviewed_unsigned_local_release(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    package = _make_package(tmp_path / "package", workflow_id="example/package")
    output = tmp_path / "dist" / "workflow.zip"

    dispatch(
        build_parser().parse_args(
            ["workflow", "package", str(package), str(output)]
        )
    )

    result = json.loads(capsys.readouterr().out)
    assert result == {"archive": str(output.resolve())}
    assert output.is_file()
    manifest, _digest, signed = WorkflowRegistry(tmp_path / "registry").inspect_source(
        output,
        allow_unsigned=True,
    )
    assert manifest.id == "example/package"
    assert signed is False


def test_workflow_inspection_supports_https_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    package = _make_package(tmp_path / "package", workflow_id="example/remote")
    archive = build_archive(package, tmp_path / "workflow.zip", allow_unsigned=True)
    archive_bytes = archive.read_bytes()

    def download(url: str, *, max_bytes: int, timeout: float) -> bytes:
        assert url == "https://market.example/workflow.zip"
        assert max_bytes == 64 * 1024**2
        assert timeout == 60
        return archive_bytes

    monkeypatch.setattr(WorkflowRegistry, "_download", staticmethod(download))
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(
        build_parser().parse_args(
            ["workflow", "verify", "https://market.example/workflow.zip"]
        )
    )

    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["id"] == "example/remote"
    assert result["signed"] is False
    assert registry.installed() == []
