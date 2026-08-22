from __future__ import annotations

import base64
import json
import stat
import zipfile
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vgen.market.builder import WorkflowBuildError, build_comfy_graph
from vgen.market.models import (
    CustomNodeRequirement,
    ModelRequirement,
    WorkflowManifest,
    WorkflowVariant,
)
from vgen.market.registry import (
    RegistryError,
    WorkflowRegistry,
    build_archive,
    package_digest,
    sign_package,
    validate_package,
    write_checksums,
)


def make_package(path: Path, *, signed: bool) -> Path:
    path.mkdir()
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    manifest = {
        "schema_version": 1,
        "id": "vgen/example",
        "version": "1.0.0",
        "title": "Example",
        "summary": "Executor-neutral package test",
        "license": "Apache-2.0",
        "provenance": "market",
        "publisher": {"id": "vgen", "public_key": public if signed else None},
        "parameters": {"type": "object"},
        "variants": [
            {
                "name": "comfyui",
                "executor_type": "comfyui",
                "payload_format": "comfyui-api-graph/v1",
                "payload": "workflow.json",
                "mapping": "mapping.json",
                "operations": ["t2v", "i2v", "flf"],
                "models": [],
            }
        ],
    }
    (path / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
    (path / "workflow.json").write_text(
        json.dumps(
            {
                "1": {
                    "inputs": {"prompt": "old", "first_frame": ["2", 0], "last_frame": ["3", 0]},
                    "_meta": {"title": "LATENT"},
                },
                "2": {"inputs": {"image": "default.png"}, "_meta": {"title": "INPUT_IMAGE"}},
                "3": {"inputs": {"image": "default-last.png"}, "_meta": {"title": "LAST_IMAGE"}},
            }
        ),
        encoding="utf-8",
    )
    (path / "mapping.json").write_text("{}", encoding="utf-8")
    write_checksums(path)
    if signed:
        signature = key.sign(bytes.fromhex(package_digest(path)))
        (path / "artifact.sig").write_text(base64.b64encode(signature).decode("ascii"))
    return path


def test_signed_package_installs_immutably(tmp_path: Path) -> None:
    package = make_package(tmp_path / "package", signed=True)
    registry = WorkflowRegistry(tmp_path / "installed")
    result = registry.install(package)
    assert result.signed is True
    assert result.manifest.id == "vgen/example"
    assert result.path.name == "1.0.0"
    assert result.path.parts[-4] == "market"
    assert registry.install(package).digest == result.digest


def test_remote_market_install_requires_independent_publisher_key_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = make_package(tmp_path / "package", signed=True)
    publisher_key = yaml.safe_load((package / "manifest.yaml").read_text(encoding="utf-8"))[
        "publisher"
    ]["public_key"]
    monkeypatch.setattr(
        WorkflowRegistry,
        "_materialize",
        staticmethod(lambda _source, _temp: package),
    )
    source = "https://market.example/vgen-example-1.0.0.zip"

    with pytest.raises(RegistryError, match="publisher-key pin"):
        WorkflowRegistry(tmp_path / "missing-pin").install(source)
    with pytest.raises(RegistryError, match="does not match"):
        WorkflowRegistry(tmp_path / "wrong-pin").install(
            source,
            expected_publisher_key=base64.b64encode(b"x" * 32).decode("ascii"),
        )

    installed = WorkflowRegistry(tmp_path / "installed").install(
        source,
        expected_publisher_key=publisher_key,
    )
    lock = yaml.safe_load((installed.path / "workflow.lock").read_text(encoding="utf-8"))
    assert lock["publisher_key"] == publisher_key


def test_market_and_custom_provenance_are_isolated(tmp_path: Path) -> None:
    market = make_package(tmp_path / "market-package", signed=True)
    custom = make_package(tmp_path / "custom-package", signed=False)
    raw = yaml.safe_load((custom / "manifest.yaml").read_text(encoding="utf-8"))
    raw["provenance"] = "custom"
    (custom / "manifest.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    write_checksums(custom)

    registry = WorkflowRegistry(tmp_path / "installed")
    market_result = registry.install(market)
    custom_result = registry.install(custom, allow_unsigned=True)
    assert market_result.path != custom_result.path
    assert {item.manifest.provenance for item in registry.installed()} == {"market", "custom"}

    registry.remove("vgen/example", "1.0.0", provenance="market")
    assert [item.manifest.provenance for item in registry.installed()] == ["custom"]


def test_remove_rejects_path_traversal(tmp_path: Path) -> None:
    registry_root = tmp_path / "registry"
    outside = tmp_path / "outside" / "1.0.0"
    outside.mkdir(parents=True)
    marker = outside / "keep.txt"
    marker.write_text("keep", encoding="utf-8")

    registry = WorkflowRegistry(registry_root)
    with pytest.raises(RegistryError):
        registry.remove("../outside", "1.0.0", provenance="market")
    with pytest.raises(RegistryError):
        registry.remove("vgen/demo", "../../outside", provenance="market")

    assert marker.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    "value",
    ["../escape.safetensors", r"..\\escape.safetensors", r"C:\\models\\escape.ckpt", "/etc/passwd"],
)
def test_manifest_rejects_cross_platform_model_path_escape(value: str) -> None:
    with pytest.raises(ValueError):
        ModelRequirement(
            filename=value,
            folder="checkpoints",
            sha256="0" * 64,
            size=1,
            license="Apache-2.0",
        )

    with pytest.raises(ValueError):
        WorkflowVariant(
            name="unsafe",
            executor_type="comfyui",
            payload_format="comfyui-api-graph/v1",
            payload=value,
            operations=["t2v"],
        )


def test_market_dependencies_require_pinned_secure_metadata() -> None:
    with pytest.raises(ValueError):
        ModelRequirement(
            filename="model.safetensors",
            folder="diffusion_models",
            source="http://models.invalid/model.safetensors",
            revision="main",
            sha256="not-a-digest",
            size=1,
            license="NOASSERTION",
        )
    with pytest.raises(ValueError):
        CustomNodeRequirement(
            name="unsafe",
            source="https://github.com/example/plugin",
            revision="main",
            license="Apache-2.0",
            node_types=["Example"],
        )


def test_minimax_reference_declares_all_weight_and_code_dependencies() -> None:
    root = Path(__file__).parents[2]
    manifest = WorkflowManifest.load(root / "workflows/vgen/minimax-h3-8step/1.0.0/manifest.yaml")
    variant = manifest.variants[0]
    assert variant.executor_min_version == "1.1.0"
    assert variant.runtime_min_version == "0.30.0"
    assert len(variant.models) == 5
    assert all(
        model.source and model.revision and len(model.sha256) == 64 for model in variant.models
    )
    assert {item for dependency in variant.custom_nodes for item in dependency.node_types} == {
        "MiniMaxH3AudioConditioningT8",
        "MiniMaxH3DualClockSamplerT8",
        "MiniMaxH3AVDecodeT8",
        "VHS_VideoCombine",
    }
    assert all(dependency.manual_install for dependency in variant.custom_nodes)


def test_archive_rejects_symbolic_links_and_windows_paths(tmp_path: Path) -> None:
    for name, member_name, mode in (
        ("symlink.zip", "workflow-link", stat.S_IFLNK | 0o777),
        ("windows.zip", r"C:\\outside\\manifest.yaml", stat.S_IFREG | 0o644),
    ):
        archive_path = tmp_path / name
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo(member_name)
            info.external_attr = mode << 16
            archive.writestr(info, "target")
        with pytest.raises(RegistryError):
            WorkflowRegistry(tmp_path / "installed").install(archive_path, allow_unsigned=True)


def test_unsigned_package_requires_explicit_opt_in(tmp_path: Path) -> None:
    package = make_package(tmp_path / "package", signed=False)
    try:
        validate_package(package)
    except Exception as exc:
        assert "unsigned" in str(exc)
    else:
        raise AssertionError("unsigned package was accepted")
    manifest, _, signed = validate_package(package, allow_unsigned=True)
    assert isinstance(manifest, WorkflowManifest)
    assert signed is False


def test_package_can_be_signed_and_archived(tmp_path: Path) -> None:
    package = make_package(tmp_path / "package", signed=False)
    key = Ed25519PrivateKey.generate()
    sign_package(package, key)
    manifest, _, signed = validate_package(package)
    assert manifest.publisher.public_key
    assert signed is True
    archive = build_archive(package, tmp_path / "dist" / "workflow.zip")
    installed = WorkflowRegistry(tmp_path / "installed").install(archive)
    assert installed.digest == package_digest(package)


def test_builder_distinguishes_zero_one_and_two_images() -> None:
    graph = {
        "1": {
            "inputs": {"prompt": "old", "first_frame": ["2", 0], "last_frame": ["3", 0]},
            "_meta": {"title": "LATENT"},
        },
        "2": {"inputs": {"image": "default.png"}, "_meta": {"title": "INPUT_IMAGE"}},
        "3": {"inputs": {"image": "default-last.png"}, "_meta": {"title": "LAST_IMAGE"}},
    }
    mapping = {
        "prompt": {"title": "LATENT", "input": "prompt"},
        "image": {
            "title": "INPUT_IMAGE",
            "input": "image",
            "optional_connection": {"target_title": "LATENT", "input": "first_frame"},
        },
        "last_image": {
            "title": "LAST_IMAGE",
            "input": "image",
            "optional_connection": {"target_title": "LATENT", "input": "last_frame"},
        },
    }
    t2v, _, operation = build_comfy_graph(graph, mapping, {"prompt": "cat"})
    assert operation == "t2v"
    assert "2" not in t2v and "3" not in t2v
    i2v, _, operation = build_comfy_graph(graph, mapping, {"prompt": "cat", "image": "first.png"})
    assert operation == "i2v" and "2" in i2v and "3" not in i2v
    flf, _, operation = build_comfy_graph(
        graph,
        mapping,
        {"prompt": "cat", "image": "first.png", "last_image": "last.png"},
    )
    assert operation == "flf" and "2" in flf and "3" in flf
    try:
        build_comfy_graph(graph, mapping, {"prompt": "cat", "last_image": "last.png"})
    except WorkflowBuildError:
        pass
    else:
        raise AssertionError("last-only workflow was accepted")
