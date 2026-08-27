from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vgen.cli import main as cli_main
from vgen.cli.main import build_parser, dispatch
from vgen.market.registry import (
    RegistryError,
    WorkflowRegistry,
    build_archive,
    package_digest,
    sign_package,
    write_checksums,
)


def _make_package(
    path: Path,
    *,
    workflow_id: str,
    version: str = "1.0.0",
) -> Path:
    path.mkdir(parents=True)
    manifest = {
        "schema_version": 1,
        "id": workflow_id,
        "version": version,
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


def _make_signed_package(
    path: Path,
    *,
    workflow_id: str,
    version: str,
    key: Ed25519PrivateKey,
) -> Path:
    package = _make_package(path, workflow_id=workflow_id, version=version)
    sign_package(package, key)
    return package


@pytest.mark.parametrize("action", ("show", "verify"))
def test_workflow_inspection_resolves_bundled_reference(
    action: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(build_parser().parse_args(["workflow", action, "vgen/ltx-2.5-distilled-t2v@1.0.0"]))

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

    dispatch(build_parser().parse_args(["workflow", "show", "example/installed@1.0.0"]))

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

    dispatch(build_parser().parse_args(["workflow", "verify", "example/reference@1.0.0"]))

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

    dispatch(build_parser().parse_args(["workflow", "package", str(package), str(output)]))

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
        build_parser().parse_args(["workflow", "verify", "https://market.example/workflow.zip"])
    )

    result = json.loads(capsys.readouterr().out)
    assert result["manifest"]["id"] == "example/remote"
    assert result["signed"] is False
    assert registry.installed() == []


def test_workflow_update_rejects_unsigned_installed_release_as_trust_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    package = _make_package(
        tmp_path / "unsigned",
        workflow_id="example/update",
    )
    key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    raw = yaml.safe_load((package / "manifest.yaml").read_text(encoding="utf-8"))
    raw["publisher"]["public_key"] = public_key
    (package / "manifest.yaml").write_text(
        yaml.safe_dump(raw, sort_keys=False),
        encoding="utf-8",
    )
    write_checksums(package)
    registry.install(package, allow_unsigned=True)
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    with pytest.raises(RegistryError, match="cannot establish update trust"):
        dispatch(
            build_parser().parse_args(
                [
                    "workflow",
                    "update",
                    "example/update",
                    "--index",
                    "https://market.example/index.json",
                ]
            )
        )


def test_workflow_update_binds_same_key_package_to_requested_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    key = Ed25519PrivateKey.generate()
    installed = _make_signed_package(
        tmp_path / "installed",
        workflow_id="example/requested",
        version="1.0.0",
        key=key,
    )
    confused_deputy = _make_signed_package(
        tmp_path / "confused-deputy",
        workflow_id="example/other",
        version="2.0.0",
        key=key,
    )
    registry.install(installed)
    source = "https://market.example/requested-2.0.0.zip"
    monkeypatch.setattr(
        registry,
        "search_index",
        lambda _index, _query: [
            {
                "id": "example/requested",
                "version": "2.0.0",
                "source": source,
                "digest": "sha256:" + package_digest(confused_deputy),
            }
        ],
    )
    monkeypatch.setattr(
        WorkflowRegistry,
        "_materialize",
        staticmethod(lambda remote, _temporary: confused_deputy if remote == source else installed),
    )
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    with pytest.raises(RegistryError, match="id does not match"):
        dispatch(
            build_parser().parse_args(
                [
                    "workflow",
                    "update",
                    "example/requested",
                    "--index",
                    "https://market.example/index.json",
                ]
            )
        )

    assert {(item.manifest.id, item.manifest.version) for item in registry.installed()} == {
        ("example/requested", "1.0.0")
    }


def test_workflow_update_installs_exact_signed_index_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    key = Ed25519PrivateKey.generate()
    installed = _make_signed_package(
        tmp_path / "installed",
        workflow_id="example/upgrade",
        version="1.0.0",
        key=key,
    )
    update = _make_signed_package(
        tmp_path / "update",
        workflow_id="example/upgrade",
        version="2.0.0",
        key=key,
    )
    registry.install(installed)
    source = "https://market.example/upgrade-2.0.0.zip"
    digest = "sha256:" + package_digest(update)
    monkeypatch.setattr(
        registry,
        "search_index",
        lambda _index, _query: [
            {
                "id": "example/upgrade",
                "version": "2.0.0",
                "source": source,
                "digest": digest,
            }
        ],
    )
    monkeypatch.setattr(
        WorkflowRegistry,
        "_materialize",
        staticmethod(lambda remote, _temporary: update if remote == source else installed),
    )
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    dispatch(
        build_parser().parse_args(
            [
                "workflow",
                "update",
                "example/upgrade",
                "--index",
                "https://market.example/index.json",
            ]
        )
    )

    assert json.loads(capsys.readouterr().out) == {
        "id": "example/upgrade",
        "updated": True,
        "version": "2.0.0",
        "digest": digest,
    }
    assert {(item.manifest.id, item.manifest.version) for item in registry.installed()} == {
        ("example/upgrade", "1.0.0"),
        ("example/upgrade", "2.0.0"),
    }


@pytest.mark.parametrize(
    "target",
    [
        {
            "id": "example/strict",
            "version": "2",
            "source": "https://market.example/strict.zip",
            "digest": "sha256:" + "0" * 64,
        },
        {
            "id": "example/strict",
            "version": "2.0.0",
            "source": "http://market.example/strict.zip",
            "digest": "sha256:" + "0" * 64,
        },
        {
            "id": "example/strict",
            "version": "2.0.0",
            "source": "https://market.example/strict.zip",
        },
        {
            "id": "example/strict",
            "version": "2.0.0",
            "source": "https://market.example/strict.zip",
            "digest": "0" * 64,
        },
        {
            "id": "example/strict",
            "version": "2.0.0",
            "source": "https://169.254.169.254/latest/meta-data",
            "digest": "sha256:" + "0" * 64,
        },
        {
            "id": "example/strict",
            "version": "2.0.0",
            "source": "https://[::1]/private",
            "digest": "sha256:" + "0" * 64,
        },
    ],
)
def test_workflow_update_rejects_incomplete_or_unpinned_index_target(
    target: dict[str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    installed = _make_signed_package(
        tmp_path / "installed",
        workflow_id="example/strict",
        version="1.0.0",
        key=Ed25519PrivateKey.generate(),
    )
    registry.install(installed)
    monkeypatch.setattr(
        registry,
        "search_index",
        lambda _index, _query: [target],
    )
    monkeypatch.setattr(cli_main, "WorkflowRegistry", lambda: registry)

    with pytest.raises(RegistryError, match="market index workflow"):
        dispatch(
            build_parser().parse_args(
                [
                    "workflow",
                    "update",
                    "example/strict",
                    "--index",
                    "https://market.example/index.json",
                ]
            )
        )
