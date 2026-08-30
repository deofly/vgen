from __future__ import annotations

import json

import pytest

from tests.cli.test_workflow_sources import _make_package
from vgen.cli import completion
from vgen.cli import main as cli
from vgen.cli.workflow_catalog import read_catalog_cache, write_catalog_cache
from vgen.market.registry import RegistryError, WorkflowRegistry, build_archive, package_digest


@pytest.fixture
def market(tmp_path, monkeypatch):
    registry = WorkflowRegistry(tmp_path / "registry")
    index = "https://market.example/index.json"
    packages = {}
    entries = []
    for version in ("1.0.0", "1.10.0", "1.2.0"):
        package = _make_package(
            tmp_path / version, workflow_id="example/face-reference", version=version
        )
        source = f"https://market.example/{version}.zip"
        packages[source] = build_archive(
            package, tmp_path / f"{version}.zip", allow_unsigned=True
        ).read_bytes()
        entries.append(
            {
                "id": "example/face-reference",
                "version": version,
                "code": "face",
                "source": source,
                "digest": "sha256:" + package_digest(package),
                "title": "人脸参考视频",
                "summary": "参考照片生成视频，保留原音轨。",
            }
        )
    calls = []

    def download(url, **kwargs):
        calls.append(url)
        if url == index:
            return json.dumps({"workflows": entries}).encode()
        return packages[url]

    monkeypatch.setenv("VGEN_WORKFLOW_MARKET_INDEX", index)
    monkeypatch.setattr(cli, "WorkflowRegistry", lambda: registry)
    monkeypatch.setattr(WorkflowRegistry, "_download", staticmethod(download))
    return registry, index, entries, calls, packages


def run(*args):
    cli.dispatch(cli.build_parser().parse_args(list(args)))


def test_market_list_shows_codes_and_descriptions_without_installing(market, capsys):
    registry, index, entries, calls, _ = market
    run("workflow", "list", "--market")
    output = capsys.readouterr().out
    assert "face@1.10.0" in output
    assert "人脸参考视频" in output and "保留原音轨" in output
    assert registry.installed() == []
    assert len(read_catalog_cache(registry.root, index)) == 3
    assert calls == [index]
    run("workflow", "search", "原音轨", "--format", "json")
    assert len(json.loads(capsys.readouterr().out)) == 3


def test_install_code_keeps_unsigned_approval_and_pins_latest_semver(market, capsys):
    registry, _, _, _, _ = market
    with pytest.raises(RegistryError, match="unsigned"):
        run("workflow", "install", "face")
    assert registry.installed() == []
    run("workflow", "install", "face", "--allow-unsigned")
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["id"] == "example/face-reference"
    assert receipt["version"] == "1.10.0"
    assert cli._resolve_workflow("face")[0].version == "1.10.0"


def test_remote_code_resolution_binds_exact_version(market):
    _, _, _, _, _ = market
    manifest, _, _ = cli._resolve_workflow("face@1.2.0")
    assert manifest.id == "example/face-reference"
    assert manifest.version == "1.2.0"


@pytest.mark.parametrize("action", ["show", "help"])
def test_show_code_reads_market_manifest_without_installing(market, capsys, action):
    registry, _, _, _, _ = market
    run("workflow", action, "face@1.2.0")
    output = capsys.readouterr().out
    assert "代号：face@1.2.0" in output
    assert "说明：Exercise CLI workflow source resolution" in output
    assert registry.installed() == []


def test_cached_code_and_local_details_work_offline(market, monkeypatch, capsys):
    registry, _, _, calls, _ = market
    run("workflow", "install", "face@1.0.0", "--allow-unsigned")
    capsys.readouterr()
    calls.clear()

    def no_network(*args, **kwargs):
        pytest.fail("installed code resolution must be offline")

    monkeypatch.setattr(WorkflowRegistry, "_download", staticmethod(no_network))
    assert cli._resolve_workflow("face")[0].version == "1.0.0"
    run("workflow", "list", "--format", "json")
    row = json.loads(capsys.readouterr().out)[0]
    assert row["code"] == "face"
    assert row["title"] and row["summary"]
    run("workflow", "show", "face", "--format", "json")
    assert json.loads(capsys.readouterr().out)["manifest"]["id"] == "example/face-reference"


def test_bare_names_fail_closed_across_namespaces(tmp_path, monkeypatch, capsys):
    registry = WorkflowRegistry(tmp_path / "registry")
    for namespace in ("alice", "bob"):
        registry.install(
            _make_package(tmp_path / namespace, workflow_id=f"{namespace}/demo"),
            allow_unsigned=True,
        )
    with pytest.raises(RegistryError, match="ambiguous.*alice/demo.*bob/demo"):
        cli._resolve_workflow("demo", registry=registry)
    assert cli._resolve_workflow("alice/demo", registry=registry)[0].id == "alice/demo"
    monkeypatch.setattr(cli, "WorkflowRegistry", lambda: registry)
    run("workflow", "list")
    output = capsys.readouterr().out
    assert "alice/demo@1.0.0" in output and "bob/demo@1.0.0" in output


def test_catalog_alias_cannot_shadow_a_local_bare_name(market, tmp_path):
    registry, index, entries, _, _ = market
    registry.install(
        _make_package(tmp_path / "other", workflow_id="other/face"), allow_unsigned=True
    )
    write_catalog_cache(registry.root, index, entries)
    with pytest.raises(RegistryError, match="ambiguous"):
        cli._resolve_workflow("face", registry=registry)


def test_filtered_market_search_does_not_show_an_ambiguous_code(market, tmp_path, capsys):
    registry, _, _, _, _ = market
    registry.install(
        _make_package(tmp_path / "other", workflow_id="other/face"), allow_unsigned=True
    )
    run("workflow", "search", "原音轨", "--format", "json")
    assert {row["code"] for row in json.loads(capsys.readouterr().out)} == {"face-reference"}


def test_index_code_reassignment_does_not_replace_cached_identity(market):
    registry, index, entries, _, _ = market
    write_catalog_cache(registry.root, index, entries)
    changed = [{**entries[0], "id": "malicious/different"}]
    with pytest.raises(RegistryError, match="changed identity"):
        write_catalog_cache(registry.root, index, changed)
    assert read_catalog_cache(registry.root, index)[0]["id"] == "example/face-reference"
    assert read_catalog_cache(registry.root, "https://another.example/index.json") == []


def test_index_digest_mismatch_is_rejected_before_install(market):
    registry, _, entries, _, _ = market
    entries[0]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(RegistryError, match="digest does not match"):
        run("workflow", "install", "face@1.0.0", "--allow-unsigned")
    assert registry.installed() == []


def test_description_control_characters_do_not_reach_terminal(market, capsys):
    _, _, entries, _, _ = market
    entries[0]["summary"] = "safe\x1b[31m\nnew line"
    run("workflow", "list", "--market")
    output = capsys.readouterr().out
    assert "\x1b" not in output and "safe [31m new line" in output


def test_market_codes_complete_without_network(market, monkeypatch):
    registry, index, entries, _, _ = market
    write_catalog_cache(registry.root, index, entries)
    monkeypatch.setattr(completion, "WorkflowRegistry", lambda: registry)

    def no_network(*args, **kwargs):
        pytest.fail("completion must never access the network")

    monkeypatch.setattr(WorkflowRegistry, "_download", staticmethod(no_network))
    assert {"face", "face@1.10.0"} <= set(completion._workflow_completer())


def test_incomplete_cached_entry_is_ignored(market):
    registry, index, entries, _, _ = market
    incomplete = [{key: value for key, value in entries[0].items() if key != "version"}]
    write_catalog_cache(registry.root, index, incomplete)
    assert read_catalog_cache(registry.root, index) == []
