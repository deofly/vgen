from __future__ import annotations

import base64
import json
import shutil
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vgen.crypto import canonical_json
from vgen.executors.comfyui import ComfyUIExecutionPolicy
from vgen.market.builder import WorkflowBuildError, build_comfy_graph
from vgen.market.capabilities import workflow_model_digests
from vgen.market.models import (
    CustomNodeRequirement,
    ModelRequirement,
    WorkflowManifest,
    WorkflowVariant,
)
from vgen.market.paths import canonical_package_path
from vgen.market.registry import (
    RegistryError,
    WorkflowRegistry,
    build_archive,
    package_digest,
    package_files,
    sign_package,
    validate_package,
    write_checksums,
)


def test_workflow_model_digests_reuse_one_blob_across_multiple_placements() -> None:
    digest = "a" * 64
    variant = WorkflowVariant(
        name="comfyui",
        executor_type="comfyui",
        payload_format="comfyui-api-graph/v1",
        payload="workflow.json",
        operations=["t2v"],
        models=[
            ModelRequirement(
                filename="shared-a.safetensors",
                folder="text_encoders",
                sha256=digest,
                size=123,
            ),
            ModelRequirement(
                filename="shared-b.safetensors",
                folder="vae",
                sha256=digest,
                size=123,
            ),
        ],
    )

    assert workflow_model_digests(variant) == (f"sha256:{digest}",)


def test_package_file_order_is_cross_platform_digest_order(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    for name in ("workflow.json", "README.md", "mapping.json", "manifest.yaml"):
        (package / name).write_text(name, encoding="utf-8")

    assert [path.name for path in package_files(package)] == [
        "README.md",
        "manifest.yaml",
        "mapping.json",
        "workflow.json",
    ]


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "./payload.json",
        "graphs//payload.json",
        "payload<draft>.json",
        "payload>draft.json",
        'payload"draft.json',
        "payload:draft.json",
        "payload|draft.json",
        "payload?draft.json",
        "payload*draft.json",
        "CONIN$",
        "conout$.json",
        "CLOCK$",
        "COM¹",
        "lpt².bin",
        "CON .txt",
    ],
)
def test_canonical_package_path_rejects_empty_dot_and_windows_aliases(value: str) -> None:
    with pytest.raises(ValueError):
        canonical_package_path(value, label="workflow package path")


def test_windows_device_archive_path_is_rejected_before_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "device-path.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("CONIN$", b"must never reach the filesystem")
    extracted = False

    def unexpected_extract(*_args: object, **_kwargs: object) -> None:
        nonlocal extracted
        extracted = True

    monkeypatch.setattr(zipfile.ZipFile, "extractall", unexpected_extract)
    staging = tmp_path / "staging"
    staging.mkdir()

    with pytest.raises(RegistryError, match="invalid path"):
        WorkflowRegistry._materialize(archive_path, staging)

    assert extracted is False


def test_only_root_metadata_files_are_excluded_from_signed_digest(tmp_path: Path) -> None:
    package = tmp_path / "package"
    nested = package / "graphs"
    nested.mkdir(parents=True)
    for name in ("artifact.sig", "checksums.sha256", "workflow.lock"):
        (package / name).write_text("root metadata", encoding="utf-8")
        (nested / name).write_text("signed nested content", encoding="utf-8")

    assert {path.relative_to(package).as_posix() for path in package_files(package)} == {
        "graphs/artifact.sig",
        "graphs/checksums.sha256",
        "graphs/workflow.lock",
    }


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


def test_nested_metadata_named_payload_cannot_change_after_signing(tmp_path: Path) -> None:
    package = make_package(tmp_path / "package", signed=False)
    graph_directory = package / "graphs"
    graph_directory.mkdir()
    payload = graph_directory / "artifact.sig"
    payload.write_text('{"safe":true}', encoding="utf-8")
    raw = yaml.safe_load((package / "manifest.yaml").read_text(encoding="utf-8"))
    raw["variants"][0]["payload"] = "graphs/artifact.sig"
    (package / "manifest.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    sign_package(package, Ed25519PrivateKey.generate())
    original_digest = package_digest(package)

    payload.write_text('{"safe":false}', encoding="utf-8")

    assert package_digest(package) != original_digest
    with pytest.raises(RegistryError, match="checksum mismatch"):
        validate_package(package)


def test_install_failure_never_exposes_a_partial_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = make_package(tmp_path / "package", signed=True)
    registry_root = tmp_path / "installed"
    target = registry_root / "market" / "vgen" / "example" / "1.0.0"

    def interrupted_copy(_source: Path, destination: Path, **_kwargs: object) -> None:
        (destination / "partial.txt").write_text("partial", encoding="utf-8")
        raise OSError("injected staging failure")

    monkeypatch.setattr(shutil, "copytree", interrupted_copy)

    with pytest.raises(RegistryError, match="staged safely"):
        WorkflowRegistry(registry_root).install(package)

    assert not target.exists()
    assert not list(target.parent.glob(".1.0.0.vgen-staging-*"))


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
    source = "https://market.example/vgen-example-1.0.0.zip?temporary=secret#fragment"

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
    assert lock["source"] == "https://market.example"


def test_remote_package_cannot_choose_custom_provenance_to_bypass_key_pin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = make_package(tmp_path / "package", signed=True)
    raw = yaml.safe_load((package / "manifest.yaml").read_text(encoding="utf-8"))
    raw["provenance"] = "custom"
    (package / "manifest.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    key = Ed25519PrivateKey.generate()
    sign_package(package, key)
    monkeypatch.setattr(
        WorkflowRegistry,
        "_materialize",
        staticmethod(lambda _source, _temp: package),
    )

    with pytest.raises(RegistryError, match="publisher-key pin"):
        WorkflowRegistry(tmp_path / "installed").install(
            "https://untrusted.example/self-signed.zip"
        )


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
    [
        "../escape.safetensors",
        r"..\\escape.safetensors",
        r"C:\\models\\escape.ckpt",
        "/etc/passwd",
        "CONIN$",
        "COM¹.safetensors",
        "CON .txt",
    ],
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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", "vgen/con"),
        ("id", "vgen/foo."),
        ("version", "1.0.0-alpha."),
    ],
)
def test_manifest_identity_components_are_windows_portable(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    package = make_package(tmp_path / "package", signed=False)
    raw = yaml.safe_load((package / "manifest.yaml").read_text(encoding="utf-8"))
    raw[field] = value
    (package / "manifest.yaml").write_text(
        yaml.safe_dump(raw, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        WorkflowManifest.load(package / "manifest.yaml")


@pytest.mark.parametrize(
    "value",
    [
        "artifact.sig",
        "checksums.sha256",
        "workflow.lock",
        "ARTIFACT.SIG",
        "Checksums.SHA256",
        "WORKFLOW.LOCK",
    ],
)
def test_manifest_rejects_reserved_root_metadata_as_workflow_file(value: str) -> None:
    with pytest.raises(ValueError, match="reserved package metadata"):
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


def test_license_provenance_is_optional_and_never_blocks_manifest_loading() -> None:
    model = ModelRequirement(
        filename="model.safetensors",
        folder="diffusion_models",
        source="https://models.example.test/model.safetensors",
        revision="immutable-revision",
        sha256="0" * 64,
        size=1,
    )
    node = CustomNodeRequirement(
        name="reviewed-node",
        source="https://github.com/example/reviewed-node",
        revision="1" * 40,
        node_types=["ReviewedNode"],
        manual_install=True,
    )
    manifest = WorkflowManifest(
        schema_version=1,
        id="vgen/no-license-required",
        version="1.0.0",
        title="No license gate",
        summary="License metadata is informational only.",
        provenance="market",
        publisher={"id": "vgen"},
        variants=[
            WorkflowVariant(
                name="default",
                executor_type="comfyui",
                payload_format="comfyui-api-graph/v1",
                payload="workflow.json",
                operations=["t2v"],
                models=[model],
                custom_nodes=[node],
            )
        ],
    )

    assert manifest.license is None
    assert manifest.variants[0].models[0].license is None
    assert manifest.variants[0].custom_nodes[0].license is None


def test_variant_rejects_windows_model_placement_collisions() -> None:
    first = ModelRequirement(
        filename="Shared.safetensors",
        folder="vae",
        sha256="1" * 64,
        size=1,
    )
    second = ModelRequirement(
        filename="shared.safetensors",
        folder="VAE",
        sha256="2" * 64,
        size=1,
    )

    with pytest.raises(ValueError, match="placements must be unique"):
        WorkflowVariant(
            name="collision",
            executor_type="comfyui",
            payload_format="comfyui-api-graph/v1",
            payload="workflow.json",
            operations=["t2v"],
            models=[first, second],
        )


def test_variant_rejects_ambiguous_graph_visible_model_filenames() -> None:
    first = ModelRequirement(
        filename="shared.safetensors",
        folder="vae",
        sha256="1" * 64,
        size=1,
    )
    second = ModelRequirement(
        filename="shared.safetensors",
        folder="text_encoders",
        sha256="2" * 64,
        size=1,
    )

    with pytest.raises(ValueError, match="filenames must be unique"):
        WorkflowVariant(
            name="ambiguous",
            executor_type="comfyui",
            payload_format="comfyui-api-graph/v1",
            payload="workflow.json",
            operations=["t2v"],
            models=[first, second],
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


def test_ltx_2_5_reference_is_canonical_native_and_buildable() -> None:
    root = Path(__file__).parents[2]
    package = root / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0"
    manifest, _, signed = validate_package(package, allow_unsigned=True)
    variant = manifest.variants[0]

    assert signed is False
    assert manifest.id == "vgen/ltx-2.5-distilled-t2v"
    assert variant.operations == ["t2v"]
    assert variant.executor_min_version == "1.2.0"
    assert variant.runtime_min_version == "0.32.0"
    assert variant.custom_nodes == []
    assert len(variant.models) == 5
    assert sum(model.size for model in variant.models) == 39_709_872_236
    assert all(model.gated and not model.manual_download for model in variant.models)
    assert {model.revision for model in variant.models} == {
        "6c7e5e573ac1667efc83407806fe9b0b93730e60"
    }
    pins = {(model.folder, model.filename): (model.size, model.sha256) for model in variant.models}
    assert pins == {
        (
            "diffusion_models",
            "ltx-2.5-22b-distilled-transformer-comfy-int8-convrot.safetensors",
        ): (
            21_504_034_224,
            "c4279eeff115cbeaca494bd2183e7d768c38fe85a184dc6afbb7159157c44334",
        ),
        (
            "text_encoders",
            "gemma4-12b-with-proj-ltx-2.5-comfy-int8-convrot.safetensors",
        ): (
            15_372_969_374,
            "6ce688a0aa98a5fa36a9f1e6c3f42152a498cc2b53ee8c15674c64244f91487f",
        ),
        ("vae", "ltx-2.5-video-vae-bf16.safetensors"): (
            1_472_223_346,
            "847e14ca7f3355debca0cea4eaa24ac0fbcdf0061da054ac89ca638a869ddba3",
        ),
        ("vae", "ltx-2.5-audio-vae-bf16.safetensors"): (
            364_866_540,
            "c52733d37f6a7fb7949c3dc0fb468c6cb2169e4d836983a73babb9f0d54837a5",
        ),
        (
            "latent_upscale_models",
            "ltx-2.5-latent-spatial-upscaler-x2-bf16-1.0.safetensors",
        ): (
            995_778_752,
            "eb5a71fe4068ee87ccdb1c3aa635e547ca76bd2d30ae20ae889f2c325c0677e8",
        ),
    }
    assert all(
        model.source
        == (
            "https://huggingface.co/Lightricks/LTX-2.5/resolve/"
            f"{model.revision}/{model.folder}/{model.filename}"
        )
        for model in variant.models
    )

    workflow_path = package / variant.payload
    graph = json.loads(workflow_path.read_bytes())
    mapping = json.loads((package / variant.mapping).read_bytes())
    assert workflow_path.read_bytes() == canonical_json(graph)
    assert len(graph) == 38
    assert "ResolutionSelector" not in {node["class_type"] for node in graph.values()}
    assert "TextGenerateLTX2Prompt" not in {node["class_type"] for node in graph.values()}

    built, effective, operation = build_comfy_graph(
        graph,
        mapping,
        {
            "prompt": "A lighthouse in a winter storm",
            "seed": 123,
            "duration": 3,
            "width": 1024,
            "height": 576,
            "fps": 24,
        },
    )
    assert operation == "t2v"
    assert effective["duration"] == 3
    assert built["405:376"]["inputs"]["value"] == "A lighthouse in a winter storm"
    assert built["405:339"]["inputs"]["noise_seed"] == 123
    assert built["405:362"]["inputs"]["value"] == 3
    assert built["405:372"]["inputs"]["value"] == 1024
    assert built["405:360"]["inputs"]["value"] == 576
    assert built["405:361"]["inputs"]["value"] == 24

    node_classes = frozenset(node["class_type"] for node in built.values())
    assert len(node_classes) == 23
    ComfyUIExecutionPolicy(allowed_node_classes=node_classes).authorize_graph(built, [])


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


@pytest.mark.parametrize(
    "members",
    [
        ("workflow.json", "./workflow.json"),
        ("Graph.json", "graph.json"),
        ("payload.json", "payload.json "),
        ("safe.json", "safe.json:stream"),
        ("CON/file.json", "other.json"),
    ],
)
def test_archive_rejects_cross_platform_path_aliases(
    tmp_path: Path, members: tuple[str, str]
) -> None:
    archive_path = tmp_path / "aliases.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for index, member in enumerate(members):
            archive.writestr(member, str(index))

    with pytest.raises(RegistryError, match="path|duplicate|conflict"):
        WorkflowRegistry(tmp_path / "installed").install(archive_path, allow_unsigned=True)


def test_archive_crc_failure_is_normalized_as_registry_error(tmp_path: Path) -> None:
    archive_path = tmp_path / "corrupt.zip"
    marker = b"manifest-content-marker"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("manifest.yaml", marker)
    content = bytearray(archive_path.read_bytes())
    offset = content.index(marker)
    content[offset] ^= 0x01
    archive_path.write_bytes(content)
    assert zipfile.is_zipfile(archive_path)

    with pytest.raises(RegistryError, match="invalid or unreadable"):
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


def test_invalid_manifest_yaml_is_normalized_as_registry_error(tmp_path: Path) -> None:
    package = make_package(tmp_path / "package", signed=False)
    (package / "manifest.yaml").write_text("publisher: [unterminated\n", encoding="utf-8")

    with pytest.raises(RegistryError, match="invalid or unreadable"):
        validate_package(package, allow_unsigned=True)


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

    with zipfile.ZipFile(archive) as built:
        assert built.namelist() == sorted(built.namelist(), key=lambda name: name.encode("utf-8"))
        assert {info.create_system for info in built.infolist()} == {3}


def test_archive_output_inside_package_is_rejected(tmp_path: Path) -> None:
    package = make_package(tmp_path / "package", signed=True)

    with pytest.raises(RegistryError, match="outside the package"):
        build_archive(package, package / "workflow.zip")


def test_archive_failure_keeps_previous_output_intact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = make_package(tmp_path / "package", signed=True)
    output = tmp_path / "workflow.zip"
    output.write_bytes(b"previous-good-archive")
    original = zipfile.ZipFile.writestr
    writes = 0

    def interrupted_write(self: zipfile.ZipFile, *args: object, **kwargs: object) -> None:
        nonlocal writes
        writes += 1
        if writes > 1:
            raise OSError("injected archive failure")
        original(self, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "writestr", interrupted_write)

    with pytest.raises(OSError, match="injected archive failure"):
        build_archive(package, output)

    assert output.read_bytes() == b"previous-good-archive"
    assert not list(tmp_path.glob(".vgen-archive-*"))


def test_remote_download_follows_only_bounded_same_origin_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class PublicStream:
        @staticmethod
        def get_extra_info(name: str) -> tuple[str, int] | None:
            return ("93.184.216.34", 443) if name == "server_addr" else None

    responses = {
        "https://market.example/start": SimpleNamespace(
            status_code=302,
            headers={"Location": "/package"},
            raise_for_status=lambda: None,
            iter_bytes=lambda: iter(()),
            extensions={"network_stream": PublicStream()},
        ),
        "https://market.example/package": SimpleNamespace(
            status_code=200,
            headers={"Content-Length": "7"},
            raise_for_status=lambda: None,
            iter_bytes=lambda: iter((b"package",)),
            extensions={"network_stream": PublicStream()},
        ),
    }

    class StreamContext:
        def __init__(self, response: object) -> None:
            self.response = response

        def __enter__(self) -> object:
            return self.response

        def __exit__(self, *_args: object) -> None:
            return None

    def stream(_method: str, url: str, **kwargs: object) -> StreamContext:
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        calls.append(url)
        return StreamContext(responses[url])

    monkeypatch.setattr(httpx, "stream", stream)
    monkeypatch.setattr(
        WorkflowRegistry,
        "_resolve_remote",
        staticmethod(lambda _host, _port: ("93.184.216.34",)),
    )

    assert (
        WorkflowRegistry._download("https://market.example/start", max_bytes=32, timeout=1)
        == b"package"
    )
    assert calls == ["https://market.example/start", "https://market.example/package"]


def test_remote_download_rejects_cross_origin_redirect_before_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    stream_info = SimpleNamespace(
        get_extra_info=lambda name: ("93.184.216.34", 443) if name == "server_addr" else None
    )
    response = SimpleNamespace(
        status_code=302,
        headers={"Location": "https://other.example/package"},
        raise_for_status=lambda: None,
        iter_bytes=lambda: iter(()),
        extensions={"network_stream": stream_info},
    )

    class StreamContext:
        def __enter__(self) -> object:
            return response

        def __exit__(self, *_args: object) -> None:
            return None

    def stream(_method: str, url: str, **_kwargs: object) -> StreamContext:
        calls.append(url)
        return StreamContext()

    monkeypatch.setattr(httpx, "stream", stream)
    monkeypatch.setattr(
        WorkflowRegistry,
        "_resolve_remote",
        staticmethod(lambda _host, _port: ("93.184.216.34",)),
    )

    with pytest.raises(RegistryError, match="changed origin"):
        WorkflowRegistry._download("https://market.example/start", max_bytes=32, timeout=1)
    assert calls == ["https://market.example/start"]


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/private",
        "https://10.0.0.7/admin",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/private",
        "https://[fc00::1]/private",
    ],
)
def test_remote_download_rejects_non_public_targets_before_network(
    url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = False

    def unexpected_stream(*_args: object, **_kwargs: object) -> None:
        nonlocal requested
        requested = True
        raise AssertionError("private target must be rejected before HTTP")

    monkeypatch.setattr(httpx, "stream", unexpected_stream)

    with pytest.raises(RegistryError, match="public addresses"):
        WorkflowRegistry._download(url, max_bytes=32, timeout=1)

    assert requested is False


def test_remote_download_rejects_hostname_resolving_to_private_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        WorkflowRegistry,
        "_resolve_remote",
        staticmethod(lambda _host, _port: ("93.184.216.34", "10.0.0.7")),
    )
    monkeypatch.setattr(
        httpx,
        "stream",
        lambda *_args, **_kwargs: pytest.fail("HTTP must not be attempted"),
    )

    with pytest.raises(RegistryError, match="public addresses"):
        WorkflowRegistry._download(
            "https://market.example/private",
            max_bytes=32,
            timeout=1,
        )


def test_inspect_source_supports_directory_zip_and_https_without_installing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = make_package(tmp_path / "package", signed=True)
    archive = build_archive(package, tmp_path / "workflow.zip")
    archive_bytes = archive.read_bytes()
    registry = WorkflowRegistry(tmp_path / "installed")

    def download(url: str, *, max_bytes: int, timeout: float) -> bytes:
        assert url == "https://market.example/vgen-example-1.0.0.zip"
        assert max_bytes == 64 * 1024**2
        assert timeout == 60
        return archive_bytes

    monkeypatch.setattr(WorkflowRegistry, "_download", staticmethod(download))

    inspected = [
        registry.inspect_source(package),
        registry.inspect_source(archive),
        registry.inspect_source("https://market.example/vgen-example-1.0.0.zip"),
    ]

    assert {manifest.id for manifest, _, _ in inspected} == {"vgen/example"}
    assert {digest for _, digest, _ in inspected} == {package_digest(package)}
    assert all(signed for _, _, signed in inspected)
    assert registry.installed() == []
    assert not registry.root.exists()


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
