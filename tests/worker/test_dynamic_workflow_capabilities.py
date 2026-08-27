from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vgen.artifacts import TransferTicket
from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    build_maintenance_intent_payload,
    derive_identity_keys,
    issue_device_certificate,
    sign_maintenance_intent,
)
from vgen.executors import ExecutionContext, ExecutionRequest, ExecutorFailure
from vgen.executors.comfyui import (
    COMFYUI_PAYLOAD_FORMAT,
    ComfyUIExecutionPolicy,
    ComfyUIExecutor,
    ComfyUIPolicyError,
)
from vgen.market.capabilities import comfyui_capability_facts
from vgen.market.models import WorkflowManifest
from vgen.market.registry import (
    InstallResult,
    build_archive,
    package_digest,
    sign_package,
    validate_package,
    write_checksums,
)
from vgen.protocol import ErrorCode, RetryAction
from vgen.worker import WorkerCredentials
from vgen.worker.capabilities import CapabilityInstallError, WorkerCapabilityStore
from vgen.worker.maintenance import WorkerMaintenanceController


class _ComfyClient:
    def __init__(self, node_classes: set[str] | None = None) -> None:
        self._node_classes = node_classes or {"SafeNode"}

    def gpu_info(self) -> list[dict[str, Any]]:
        return [{"name": "test", "vram_total_mb": 1024}]

    def system_info(self) -> dict[str, Any]:
        return {"ram_bytes": 8 * 1024**3, "runtime_version": "0.30.1"}

    def node_classes(self) -> set[str]:
        return set(self._node_classes)


class _CapabilitySource:
    def __init__(self, releases: tuple[InstallResult, ...]) -> None:
        self.releases = releases

    def active(self) -> tuple[InstallResult, ...]:
        return self.releases

    def generation(self) -> tuple[int, int, int]:
        return (1, len(self.releases), 1)


def _write_workflow(
    directory: Path,
    *,
    workflow_id: str,
    model_folder: str | None = None,
    model_filename: str = "shared.safetensors",
    model_digest: str | None = None,
    model_size: int = 0,
    node_class: str = "SafeNode",
    min_vram_bytes: int | None = None,
    min_ram_bytes: int | None = None,
    include_license: bool = True,
    custom_nodes: list[dict[str, Any]] | None = None,
) -> WorkflowManifest:
    directory.mkdir(parents=True)
    node_inputs = {"model_name": model_filename} if model_folder is not None else {}
    (directory / "workflow.json").write_text(
        json.dumps({"1": {"class_type": node_class, "inputs": node_inputs}}),
        encoding="utf-8",
    )
    models = []
    if model_folder is not None and model_digest is not None:
        model = {
            "filename": model_filename,
            "folder": model_folder,
            "sha256": model_digest,
            "size": model_size,
        }
        if include_license:
            model["license"] = "Apache-2.0"
        models.append(model)
    variant = {
        "name": "comfyui",
        "executor_type": "comfyui",
        "payload_format": "comfyui-api-graph/v1",
        "payload": "workflow.json",
        "operations": ["t2v"],
        "models": models,
        "custom_nodes": custom_nodes or [],
    }
    if min_vram_bytes is not None:
        variant["min_vram_bytes"] = min_vram_bytes
    if min_ram_bytes is not None:
        variant["min_ram_bytes"] = min_ram_bytes
    manifest = {
        "schema_version": 1,
        "id": workflow_id,
        "version": "1.0.0",
        "title": workflow_id,
        "summary": "Tiny reviewed ComfyUI capability used by Worker tests.",
        "provenance": "custom",
        "publisher": {"id": "test-reviewer", "public_key": None},
        "parameters": {},
        "variants": [variant],
    }
    if include_license:
        manifest["license"] = "Apache-2.0"
    (directory / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    return WorkflowManifest.load(directory / "manifest.yaml")


def test_license_free_package_validates_and_activates_as_ready(tmp_path: Path) -> None:
    contents = b"license metadata is not an install gate"
    digest = hashlib.sha256(contents).hexdigest()
    package = tmp_path / "package"
    _write_workflow(
        package,
        workflow_id="test/license-free",
        model_folder="vae",
        model_digest=digest,
        model_size=len(contents),
        include_license=False,
    )
    write_checksums(package)
    manifest, package_hash, signed = validate_package(package, allow_unsigned=True)
    assert manifest.license is None
    assert manifest.variants[0].models[0].license is None

    model_root = tmp_path / "models"
    placement = model_root / "vae/shared.safetensors"
    placement.parent.mkdir(parents=True)
    placement.write_bytes(contents)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),
        capability_source=_CapabilitySource(
            (InstallResult(manifest, package, package_hash, signed),)
        ),
        model_root=model_root,
    )

    report = _readiness(executor.capabilities())
    assert report["test/license-free@1.0.0"]["state"] == "ready"


def _readiness(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["workflow_ref"]: item for item in report["workflow_readiness"]}


def _reviewed_custom_node(
    root: Path,
    *,
    source: str,
    directory_name: str = "ComfyUI-GGUF",
) -> tuple[Path, str]:
    repository = root / directory_name
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "config", "user.name", "VGen Tests"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "config", "user.email", "tests@example.invalid"],
        check=True,
    )
    (repository / "node.py").write_text("NODE_CLASS_MAPPINGS = {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "node.py"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "reviewed"], check=True)
    subprocess.run(["git", "-C", str(repository), "remote", "add", "origin", source], check=True)
    revision = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return repository, revision


def test_custom_node_readiness_requires_exact_clean_git_provenance_and_survives_policy_merge(
    tmp_path: Path,
) -> None:
    source = "https://github.com/city96/ComfyUI-GGUF"
    custom_root = tmp_path / "custom_nodes"
    repository, revision = _reviewed_custom_node(custom_root, source=source)
    package = tmp_path / "package"
    manifest = _write_workflow(
        package,
        workflow_id="test/gguf",
        node_class="UnetLoaderGGUF",
        custom_nodes=[
            {
                "name": "ComfyUI-GGUF",
                "source": source,
                "revision": revision,
                "node_types": ["UnetLoaderGGUF"],
                "manual_install": True,
            }
        ],
    )
    write_checksums(package)
    digest = package_digest(package)
    release = InstallResult(manifest, package, digest, False)
    policy = ComfyUIExecutionPolicy.from_mapping(
        {
            "version": 1,
            "allowed_node_classes": [],
            "allowed_custom_node_classes": ["UnetLoaderGGUF"],
            "allowed_workflow_digests": [f"sha256:{digest}"],
            "maintenance_workflows": {"test/gguf@1.0.0": f"sha256:{digest}"},
            "models": [],
            "custom_nodes": [
                {
                    "name": "ComfyUI-GGUF",
                    "source": source,
                    "revision": revision,
                    "node_types": ["UnetLoaderGGUF"],
                }
            ],
        }
    )

    def executor(root: Path | None) -> ComfyUIExecutor:
        return ComfyUIExecutor(
            "http://127.0.0.1:8188",
            tmp_path / "outputs",
            client=_ComfyClient({"UnetLoaderGGUF"}),  # type: ignore[arg-type]
            policy=policy,
            capability_source=_CapabilitySource((release,)),
            model_root=tmp_path / "models",
            custom_nodes_root=root,
        )

    missing = _readiness(executor(None).capabilities())["test/gguf@1.0.0"]
    assert missing["state"] == "missing_nodes"
    assert missing["missing_node_classes"] == ["UnetLoaderGGUF"]
    assert _readiness(executor(custom_root).capabilities())["test/gguf@1.0.0"]["state"] == "ready"

    (repository / "node.py").write_text("NODE_CLASS_MAPPINGS = {'changed': object()}\n")
    changed = _readiness(executor(custom_root).capabilities())["test/gguf@1.0.0"]
    assert changed["state"] == "missing_nodes"
    assert changed["missing_node_classes"] == ["UnetLoaderGGUF"]


def test_custom_node_readiness_rejects_extra_provider_repository_or_root_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "https://github.com/city96/ComfyUI-GGUF"
    custom_root = tmp_path / "custom_nodes"
    _, revision = _reviewed_custom_node(custom_root, source=source)
    package = tmp_path / "package"
    manifest = _write_workflow(
        package,
        workflow_id="test/closed-custom-root",
        node_class="UnetLoaderGGUF",
        custom_nodes=[
            {
                "name": "ComfyUI-GGUF",
                "source": source,
                "revision": revision,
                "node_types": ["UnetLoaderGGUF"],
                "manual_install": True,
            }
        ],
    )
    write_checksums(package)
    release = InstallResult(manifest, package, package_digest(package), False)

    def readiness() -> dict[str, Any]:
        executor = ComfyUIExecutor(
            "http://127.0.0.1:8188",
            tmp_path / "outputs",
            client=_ComfyClient({"UnetLoaderGGUF"}),  # type: ignore[arg-type]
            capability_source=_CapabilitySource((release,)),
            model_root=tmp_path / "models",
            custom_nodes_root=custom_root,
        )
        return _readiness(executor.capabilities())["test/closed-custom-root@1.0.0"]

    assert readiness()["state"] == "ready"

    extra_repository, _ = _reviewed_custom_node(
        custom_root,
        source="https://github.com/example/forged-provider",
        directory_name="ForgedProvider",
    )
    with_extra_provider = readiness()
    assert with_extra_provider["state"] == "missing_nodes"
    assert with_extra_provider["missing_node_classes"] == ["UnetLoaderGGUF"]

    shutil.rmtree(extra_repository)
    extra_file = custom_root / "forged_provider.py"
    extra_file.write_text(
        "NODE_CLASS_MAPPINGS = {'UnetLoaderGGUF': object()}\n",
        encoding="utf-8",
    )
    with_extra_file = readiness()
    assert with_extra_file["state"] == "missing_nodes"
    assert with_extra_file["missing_node_classes"] == ["UnetLoaderGGUF"]

    extra_file.unlink()
    reviewed_repository = custom_root / "ComfyUI-GGUF"
    monkeypatch.setattr(
        "vgen.executors.comfyui._is_reparse_point",
        lambda path: Path(path) == reviewed_repository,
    )
    with_reparse_entry = readiness()
    assert with_reparse_entry["state"] == "missing_nodes"
    assert with_reparse_entry["missing_node_classes"] == ["UnetLoaderGGUF"]


def test_unpinned_provider_repository_blocks_core_workflow_in_shared_root(
    tmp_path: Path,
) -> None:
    custom_root = tmp_path / "custom_nodes"
    _reviewed_custom_node(
        custom_root,
        source="https://github.com/example/unpinned-provider",
        directory_name="UnpinnedProvider",
    )
    package = tmp_path / "package"
    manifest = _write_workflow(package, workflow_id="test/core-with-unclosed-root")
    write_checksums(package)
    release = InstallResult(manifest, package, package_digest(package), False)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient({"SafeNode"}),  # type: ignore[arg-type]
        capability_source=_CapabilitySource((release,)),
        model_root=tmp_path / "models",
        custom_nodes_root=custom_root,
    )

    report = _readiness(executor.capabilities())["test/core-with-unclosed-root@1.0.0"]
    assert report["state"] == "missing_nodes"
    assert report["missing_node_classes"] == ["SafeNode"]


def test_custom_node_provenance_rejects_hidden_index_flags(tmp_path: Path) -> None:
    repository, _ = _reviewed_custom_node(
        tmp_path / "custom_nodes",
        source="https://github.com/city96/ComfyUI-GGUF",
    )

    subprocess.run(
        ["git", "-C", str(repository), "update-index", "--assume-unchanged", "node.py"],
        check=True,
    )
    assert (
        ComfyUIExecutor._verified_custom_node_repository(
            repository, deadline=time.monotonic() + 5
        )
        is None
    )
    subprocess.run(
        ["git", "-C", str(repository), "update-index", "--no-assume-unchanged", "node.py"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "update-index", "--skip-worktree", "node.py"],
        check=True,
    )
    assert (
        ComfyUIExecutor._verified_custom_node_repository(
            repository, deadline=time.monotonic() + 5
        )
        is None
    )


def test_custom_node_provenance_rejects_ignored_code_and_sanitizes_git_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = "https://github.com/city96/ComfyUI-GGUF"
    repository, _ = _reviewed_custom_node(tmp_path / "custom_nodes", source=source)
    (repository / ".gitignore").write_text("*.py\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", ".gitignore"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "ignore Python"], check=True)
    revision = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    hostile_git_dir = tmp_path / "hostile-git-dir"
    subprocess.run(["git", "init", "-q", str(hostile_git_dir)], check=True)
    monkeypatch.setenv("GIT_DIR", str(hostile_git_dir / ".git"))
    monkeypatch.setenv("GIT_INDEX_FILE", str(tmp_path / "hostile-index"))
    assert ComfyUIExecutor._verified_custom_node_repository(
        repository, deadline=time.monotonic() + 5
    ) == (source, revision)

    (repository / "ignored_payload.py").write_text(
        "NODE_CLASS_MAPPINGS = {'forged': object()}\n",
        encoding="utf-8",
    )
    assert (
        ComfyUIExecutor._verified_custom_node_repository(
            repository, deadline=time.monotonic() + 5
        )
        is None
    )


def test_unpinned_static_custom_node_class_never_reports_ready(tmp_path: Path) -> None:
    digest = "sha256:" + "a" * 64
    policy = ComfyUIExecutionPolicy.from_mapping(
        {
            "version": 1,
            "allowed_node_classes": [],
            "allowed_custom_node_classes": ["UnetLoaderGGUF"],
            "allowed_workflow_digests": [digest],
            "maintenance_workflows": {"test/unpinned@1.0.0": digest},
            "models": [],
        }
    )
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient({"UnetLoaderGGUF"}),  # type: ignore[arg-type]
        policy=policy,
        model_root=tmp_path / "models",
        custom_nodes_root=tmp_path / "custom_nodes",
    )

    readiness = _readiness(executor.capabilities())["test/unpinned@1.0.0"]
    assert readiness["state"] == "missing_nodes"
    assert readiness["missing_node_classes"] == ["UnetLoaderGGUF"]


def test_custom_node_provenance_rejects_gitdir_indirection_and_tracked_links(
    tmp_path: Path,
) -> None:
    separate_worktree = tmp_path / "separate-worktree"
    separate_git = tmp_path / "separate-git"
    subprocess.run(
        [
            "git",
            "init",
            "-q",
            f"--separate-git-dir={separate_git}",
            str(separate_worktree),
        ],
        check=True,
    )
    assert (
        ComfyUIExecutor._verified_custom_node_repository(
            separate_worktree, deadline=time.monotonic() + 5
        )
        is None
    )

    repository, _ = _reviewed_custom_node(
        tmp_path / "linked-custom-nodes",
        source="https://github.com/city96/ComfyUI-GGUF",
    )
    outside = tmp_path / "outside.py"
    outside.write_text("NODE_CLASS_MAPPINGS = {'outside': object()}\n", encoding="utf-8")
    (repository / "node.py").unlink()
    (repository / "node.py").symlink_to(outside)
    subprocess.run(["git", "-C", str(repository), "add", "node.py"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "tracked link"], check=True)
    assert (
        ComfyUIExecutor._verified_custom_node_repository(
            repository, deadline=time.monotonic() + 5
        )
        is None
    )


def test_dynamic_workflows_share_digest_but_keep_placement_readiness(
    tmp_path: Path,
) -> None:
    contents = b"one shared model payload"
    model_digest = hashlib.sha256(contents).hexdigest()
    first_dir = tmp_path / "packages/first"
    second_dir = tmp_path / "packages/second"
    first_manifest = _write_workflow(
        first_dir,
        workflow_id="test/shared-first",
        model_folder="text_encoders",
        model_digest=model_digest,
        model_size=len(contents),
    )
    second_manifest = _write_workflow(
        second_dir,
        workflow_id="test/shared-second",
        model_folder="clip",
        model_digest=model_digest,
        model_size=len(contents),
    )
    releases = (
        InstallResult(first_manifest, first_dir, package_digest(first_dir), False),
        InstallResult(second_manifest, second_dir, package_digest(second_dir), False),
    )
    model_root = tmp_path / "models"
    first_placement = model_root / "text_encoders/shared.safetensors"
    first_placement.parent.mkdir(parents=True)
    first_placement.write_bytes(contents)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource(releases),
        model_root=model_root,
    )

    first_report = dict(executor.capabilities())
    first_readiness = _readiness(first_report)

    assert first_report["model_digests"] == [f"sha256:{model_digest}"]
    assert first_readiness["test/shared-first@1.0.0"]["state"] == "ready"
    assert first_readiness["test/shared-second@1.0.0"] == {
        "workflow_ref": "test/shared-second@1.0.0",
        "workflow_digest": f"sha256:{releases[1].digest}",
        "state": "missing_models",
        "missing_model_digests": [f"sha256:{model_digest}"],
        "missing_node_classes": [],
    }

    second_placement = model_root / "clip/shared.safetensors"
    second_placement.parent.mkdir(parents=True)
    second_placement.write_bytes(contents)
    executor.invalidate_model_digest_cache()
    second_report = dict(executor.capabilities())
    second_readiness = _readiness(second_report)

    assert second_report["model_digests"] == [f"sha256:{model_digest}"]
    assert second_readiness["test/shared-first@1.0.0"]["state"] == "ready"
    assert second_readiness["test/shared-second@1.0.0"]["state"] == "ready"
    assert set(second_report["ready_workflow_digests"]) == {
        f"sha256:{release.digest}" for release in releases
    }


def test_conflicting_dynamic_model_placements_are_all_quarantined(
    tmp_path: Path,
) -> None:
    first_contents = b"first immutable model"
    second_contents = b"other immutable model"
    first_dir = tmp_path / "packages/first"
    second_dir = tmp_path / "packages/second"
    first_manifest = _write_workflow(
        first_dir,
        workflow_id="test/path-owner-first",
        model_folder="vae",
        model_digest=hashlib.sha256(first_contents).hexdigest(),
        model_size=len(first_contents),
    )
    second_manifest = _write_workflow(
        second_dir,
        workflow_id="test/path-owner-second",
        model_folder="VAE",
        model_digest=hashlib.sha256(second_contents).hexdigest(),
        model_size=len(second_contents),
    )
    releases = (
        InstallResult(first_manifest, first_dir, package_digest(first_dir), False),
        InstallResult(second_manifest, second_dir, package_digest(second_dir), False),
    )
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource(releases),
        model_root=tmp_path / "models",
    )

    assert executor.maintenance_workflows == ()
    assert executor.maintenance_model_pins == ()
    assert executor.capabilities()["workflow_readiness"] == []


def test_staged_capability_cannot_replace_an_active_model_path(
    tmp_path: Path,
) -> None:
    first_contents = b"active bytes"
    second_contents = b"staged bytes"
    first_dir = tmp_path / "packages/first"
    second_dir = tmp_path / "packages/second"
    first_manifest = _write_workflow(
        first_dir,
        workflow_id="test/active-path-owner",
        model_folder="vae",
        model_digest=hashlib.sha256(first_contents).hexdigest(),
        model_size=len(first_contents),
    )
    second_manifest = _write_workflow(
        second_dir,
        workflow_id="test/staged-path-owner",
        model_folder="VAE",
        model_digest=hashlib.sha256(second_contents).hexdigest(),
        model_size=len(second_contents),
    )
    first = InstallResult(first_manifest, first_dir, package_digest(first_dir), False)
    second = InstallResult(second_manifest, second_dir, package_digest(second_dir), False)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource((first,)),
        model_root=tmp_path / "models",
    )

    with pytest.raises(ComfyUIPolicyError, match="already bound"):
        executor.validate_capability_release(second)

    assert executor.maintenance_workflows == (
        ("test/active-path-owner@1.0.0", f"sha256:{first.digest}"),
    )


def test_store_activation_keeps_existing_release_when_model_path_conflicts(
    tmp_path: Path,
) -> None:
    packages = (tmp_path / "packages/first", tmp_path / "packages/second")
    contents = (b"first store model", b"second store model")
    workflow_ids = ("test/store-first", "test/store-second")
    folders = ("vae", "VAE")
    archives: list[Path] = []
    specs: list[dict[str, Any]] = []
    for index, package in enumerate(packages):
        manifest = _write_workflow(
            package,
            workflow_id=workflow_ids[index],
            model_folder=folders[index],
            model_digest=hashlib.sha256(contents[index]).hexdigest(),
            model_size=len(contents[index]),
        )
        workflow_hash = write_checksums(package)
        archive = build_archive(
            package,
            tmp_path / f"store-{index}.zip",
            allow_unsigned=True,
        )
        archives.append(archive)
        specs.append(
            {
                "kind": "capability_install",
                "workflow_ref": f"{manifest.id}@{manifest.version}",
                "workflow_digest": f"sha256:{workflow_hash}",
                "artifact_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "artifact_size": archive.stat().st_size,
                "node_classes_digest": comfyui_capability_facts(
                    manifest,
                    package,
                ).node_classes_digest,
                "publisher_key": None,
                "allow_unsigned_workflow": True,
                "apply": "on_idle",
            }
        )

    first_job, credentials = _signed_job(specs[0])
    second_job, _ = _signed_job(specs[1])
    store = WorkerCapabilityStore(
        tmp_path / "capabilities",
        owner_root_signing_public_key=credentials.owner_root_signing_public_key,
        worker_id=credentials.worker_id,
    )
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=store,
        model_root=tmp_path / "models",
    )
    first = specs[0]
    store.activate(
        archives[0],
        workflow_ref=first["workflow_ref"],
        workflow_digest=first["workflow_digest"],
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=first["node_classes_digest"],
        authorization=first_job["authorization"],
        validator=executor.validate_capability_release,
    )
    executor.reload_capabilities()
    index_before = store.index_path.read_bytes()
    generation_before = store.generation()
    second = specs[1]

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_COMPILE_INVALID"):
        store.activate(
            archives[1],
            workflow_ref=second["workflow_ref"],
            workflow_digest=second["workflow_digest"],
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=second["node_classes_digest"],
            authorization=second_job["authorization"],
            validator=executor.validate_capability_release,
        )

    assert store.index_path.read_bytes() == index_before
    assert store.generation() == generation_before
    assert executor.maintenance_workflows == ((first["workflow_ref"], first["workflow_digest"]),)
    assert not (store.releases / second["workflow_digest"].removeprefix("sha256:")).exists()


def test_same_model_digest_cannot_claim_different_sizes_across_workflows(
    tmp_path: Path,
) -> None:
    model_digest = hashlib.sha256(b"one immutable payload").hexdigest()
    first_dir = tmp_path / "packages/first"
    second_dir = tmp_path / "packages/second"
    first_manifest = _write_workflow(
        first_dir,
        workflow_id="test/digest-size-first",
        model_folder="vae",
        model_digest=model_digest,
        model_size=21,
    )
    second_manifest = _write_workflow(
        second_dir,
        workflow_id="test/digest-size-second",
        model_folder="clip",
        model_digest=model_digest,
        model_size=22,
    )
    first = InstallResult(first_manifest, first_dir, package_digest(first_dir), False)
    second = InstallResult(second_manifest, second_dir, package_digest(second_dir), False)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource((first,)),
        model_root=tmp_path / "models",
    )

    with pytest.raises(ComfyUIPolicyError, match="already bound"):
        executor.validate_capability_release(second)


def test_same_model_bytes_may_be_shared_at_the_same_placement(tmp_path: Path) -> None:
    contents = b"shared placement bytes"
    model_digest = hashlib.sha256(contents).hexdigest()
    first_dir = tmp_path / "packages/first"
    second_dir = tmp_path / "packages/second"
    first_manifest = _write_workflow(
        first_dir,
        workflow_id="test/shared-path-first",
        model_folder="vae",
        model_digest=model_digest,
        model_size=len(contents),
    )
    second_manifest = _write_workflow(
        second_dir,
        workflow_id="test/shared-path-second",
        model_folder="VAE",
        model_digest=model_digest,
        model_size=len(contents),
    )
    releases = (
        InstallResult(first_manifest, first_dir, package_digest(first_dir), False),
        InstallResult(second_manifest, second_dir, package_digest(second_dir), False),
    )
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource(releases),
        model_root=tmp_path / "models",
    )

    assert {item[0] for item in executor.maintenance_workflows} == {
        "test/shared-path-first@1.0.0",
        "test/shared-path-second@1.0.0",
    }


def test_hardlinked_shared_model_is_hashed_once_per_capability_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contents = b"one CAS blob with two workflow placements"
    model_digest = hashlib.sha256(contents).hexdigest()
    first_dir = tmp_path / "packages/first"
    second_dir = tmp_path / "packages/second"
    first_manifest = _write_workflow(
        first_dir,
        workflow_id="test/hardlink-first",
        model_folder="text_encoders",
        model_digest=model_digest,
        model_size=len(contents),
    )
    second_manifest = _write_workflow(
        second_dir,
        workflow_id="test/hardlink-second",
        model_folder="clip",
        model_digest=model_digest,
        model_size=len(contents),
    )
    releases = (
        InstallResult(first_manifest, first_dir, package_digest(first_dir), False),
        InstallResult(second_manifest, second_dir, package_digest(second_dir), False),
    )
    model_root = tmp_path / "models"
    first = model_root / "text_encoders/shared.safetensors"
    second = model_root / "clip/shared.safetensors"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    first.write_bytes(contents)
    second.hardlink_to(first)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource(releases),
        model_root=model_root,
    )
    model_paths = {first.resolve(), second.resolve()}
    original_open = Path.open
    reads: list[Path] = []

    def counting_open(path: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if "b" in mode and path.resolve() in model_paths:
            reads.append(path.resolve())
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counting_open)

    report = executor.capabilities()

    assert report["execution_policy"]["models_verified"] == 1
    assert len(reads) == 1


def test_invalid_dynamic_capability_does_not_suppress_legacy_h3_policy(
    tmp_path: Path,
) -> None:
    legacy_ref = "vgen/minimax-h3-8step@1.0.0"
    legacy_digest = "sha256:" + "b" * 64
    legacy_policy = ComfyUIExecutionPolicy.from_mapping(
        {
            "version": 1,
            "allowed_node_classes": ["SafeNode"],
            "allowed_workflow_digests": [legacy_digest],
            "maintenance_workflows": {legacy_ref: legacy_digest},
        }
    )
    invalid_dir = tmp_path / "invalid-capability"
    invalid_manifest = _write_workflow(
        invalid_dir,
        workflow_id="test/invalid-dynamic",
        node_class="Invalid Node Class",
    )
    invalid_release = InstallResult(
        invalid_manifest,
        invalid_dir,
        package_digest(invalid_dir),
        False,
    )
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        policy=legacy_policy,
        capability_source=_CapabilitySource((invalid_release,)),
        model_root=tmp_path / "models",
    )

    report = dict(executor.capabilities())

    assert executor.maintenance_workflows == ((legacy_ref, legacy_digest),)
    assert report["execution_policy"]["configured"] is True
    assert report["ready_workflow_digests"] == [legacy_digest]
    assert report["workflow_readiness"] == [
        {
            "workflow_ref": legacy_ref,
            "workflow_digest": legacy_digest,
            "state": "ready",
            "missing_model_digests": [],
            "missing_node_classes": [],
        }
    ]


def test_invalid_dynamic_release_does_not_suppress_healthy_release_and_retries(
    tmp_path: Path,
) -> None:
    good_dir = tmp_path / "good"
    bad_dir = tmp_path / "bad"
    good_manifest = _write_workflow(good_dir, workflow_id="test/good")
    bad_manifest = _write_workflow(
        bad_dir,
        workflow_id="test/repairable",
        node_class="Invalid Node Class",
    )
    good = InstallResult(good_manifest, good_dir, package_digest(good_dir), False)
    repairable = InstallResult(bad_manifest, bad_dir, package_digest(bad_dir), False)
    source = _CapabilitySource((good, repairable))
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=source,
        model_root=tmp_path / "models",
    )

    assert executor.maintenance_workflows == (("test/good@1.0.0", f"sha256:{good.digest}"),)

    (bad_dir / "workflow.json").write_text(
        json.dumps({"1": {"class_type": "SafeNode", "inputs": {}}}),
        encoding="utf-8",
    )

    assert executor.maintenance_workflows == (
        ("test/good@1.0.0", f"sha256:{good.digest}"),
        ("test/repairable@1.0.0", f"sha256:{repairable.digest}"),
    )


def test_dynamic_release_binds_operation_graph_parameters_and_model_loader(
    tmp_path: Path,
) -> None:
    contents = b"reviewed model"
    model_digest = hashlib.sha256(contents).hexdigest()
    package = tmp_path / "package"
    manifest = _write_workflow(
        package,
        workflow_id="test/graph-bound",
        model_folder="diffusion_models",
        model_digest=model_digest,
        model_size=len(contents),
    )
    release = InstallResult(manifest, package, package_digest(package), False)
    model_root = tmp_path / "models"
    model_path = model_root / "diffusion_models/shared.safetensors"
    model_path.parent.mkdir(parents=True)
    model_path.write_bytes(contents)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource((release,)),
        model_root=model_root,
    )
    digest = f"sha256:{release.digest}"
    graph = json.loads((package / "workflow.json").read_text(encoding="utf-8"))
    capability = executor._capability_for_digest(digest)
    assert capability is not None
    executor._authorize_capability_payload(capability, "t2v", graph, [], {})

    changed_loader = json.loads(json.dumps(graph))
    changed_loader["1"]["inputs"]["model_name"] = "other/private.safetensors"
    payload = json.dumps(
        {
            "workflow": changed_loader,
            "input_bindings": [],
            "effective_parameters": {},
        }
    ).encode()
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(
            ExecutionRequest(
                "tsk_test",
                "atm_test",
                digest,
                "t2v",
                COMFYUI_PAYLOAD_FORMAT,
                payload,
            ),
            ExecutionContext(tmp_path / "work"),
        )
    assert raised.value.details == {"reason": "workflow_graph_mismatch"}

    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(
            ExecutionRequest(
                "tsk_test",
                "atm_test",
                digest,
                "i2v",
                COMFYUI_PAYLOAD_FORMAT,
                json.dumps(
                    {
                        "workflow": graph,
                        "input_bindings": [],
                        "effective_parameters": {},
                    }
                ).encode(),
            ),
            ExecutionContext(tmp_path / "work"),
        )
    assert raised.value.details == {"reason": "operation_not_allowed_by_workflow"}


@pytest.mark.parametrize(
    ("minimums", "expected_state", "expected_code"),
    [
        (
            {"min_vram_bytes": 2 * 1024**3},
            "insufficient_vram",
            ErrorCode.GPU_OUT_OF_MEMORY,
        ),
        (
            {"min_ram_bytes": 9 * 1024**3},
            "insufficient_ram",
            ErrorCode.SYSTEM_OUT_OF_MEMORY,
        ),
    ],
)
def test_dynamic_readiness_binds_manifest_resource_minimums(
    tmp_path: Path,
    minimums: dict[str, int],
    expected_state: str,
    expected_code: ErrorCode,
) -> None:
    package = tmp_path / expected_state
    manifest = _write_workflow(
        package,
        workflow_id=f"test/{expected_state}",
        **minimums,
    )
    release = InstallResult(manifest, package, package_digest(package), False)
    executor = ComfyUIExecutor(
        "http://127.0.0.1:8188",
        tmp_path / "outputs",
        client=_ComfyClient(),  # type: ignore[arg-type]
        capability_source=_CapabilitySource((release,)),
        model_root=tmp_path / "models",
    )

    readiness = executor.capabilities()["workflow_readiness"]

    assert readiness[0]["state"] == expected_state
    assert executor.capabilities()["ready_workflow_digests"] == []
    graph = json.loads((package / "workflow.json").read_text(encoding="utf-8"))
    with pytest.raises(ExecutorFailure) as raised:
        executor.execute(
            ExecutionRequest(
                "tsk_resource_floor",
                "atm_resource_floor",
                f"sha256:{release.digest}",
                "t2v",
                COMFYUI_PAYLOAD_FORMAT,
                json.dumps(
                    {
                        "workflow": graph,
                        "input_bindings": [],
                        "effective_parameters": {},
                    }
                ).encode(),
            ),
            ExecutionContext(tmp_path / "work"),
        )
    assert raised.value.code == expected_code
    assert raised.value.retry_action is RetryAction.ANOTHER_WORKER
    assert raised.value.details == {"reason": expected_state}


class _Gateway:
    def __init__(self, job: dict[str, Any]) -> None:
        self.job = job
        self.heartbeats: list[dict[str, Any]] = []
        self.completions: list[dict[str, Any]] = []

    def claim_maintenance(self, *, ttl_seconds: int = 60) -> dict[str, Any]:
        assert ttl_seconds == 60
        return self.job

    def heartbeat_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
        self.heartbeats.append({"job_id": job_id, **value})
        return {"ok": True, "cancelled": False}

    def complete_maintenance(self, job_id: str, **value: Any) -> dict[str, Any]:
        self.completions.append({"job_id": job_id, **value})
        return {"ok": True}

    def maintenance_artifact_ticket(self, job: dict[str, Any]) -> TransferTicket:
        return job["ticket"]


class _CapabilityExecutor:
    def __init__(self, workflow_ref: str, workflow_digest: str) -> None:
        self.workflow_ref = workflow_ref
        self.workflow_digest = workflow_digest
        self.validated: list[tuple[str, str]] = []
        self.reloads = 0

    def validate_capability_release(self, installed: InstallResult) -> None:
        self.validated.append(
            (
                f"{installed.manifest.id}@{installed.manifest.version}",
                f"sha256:{installed.digest}",
            )
        )

    def reload_capabilities(self) -> None:
        self.reloads += 1

    def capabilities(self) -> dict[str, Any]:
        return {
            "workflow_readiness": [
                {
                    "workflow_ref": self.workflow_ref,
                    "workflow_digest": self.workflow_digest,
                    "state": "ready",
                }
            ]
        }


def _signed_job(
    spec: dict[str, Any],
) -> tuple[dict[str, Any], WorkerCredentials]:
    now = int(time.time())
    root = derive_identity_keys(b"r" * 64)
    broker_device = DeviceKeys.generate()
    certificate = issue_device_certificate(
        root,
        broker_device,
        device_id="dev_owner",
        issued_at=now - 5,
        expires_at=now + 3600,
    )
    payload = build_maintenance_intent_payload(
        worker_id="wrk_test",
        broker_id="brk_test",
        kind=spec["kind"],
        spec=spec,
        device_id="dev_owner",
        issued_at=now - 1,
        expires_at=now + 600,
        nonce="capability_nonce_1234",
    )
    job = {
        "id": "mtn_capability_test",
        "worker_id": "wrk_test",
        "broker_id": "brk_test",
        "kind": spec["kind"],
        "spec": spec,
        "authorization": sign_maintenance_intent(broker_device, certificate, payload),
        "fencing_token": 3,
    }
    credentials = WorkerCredentials(
        "wrk_test",
        DeviceKeys.generate(),
        "session",
        owner_root_signing_public_key=b64url_encode(root.signing_public_bytes()),
    )
    return job, credentials


@pytest.mark.parametrize("signed", [False, True], ids=["owner-approved-unsigned", "signed"])
def test_controller_activates_reviewed_capability_and_binds_completion_result(
    tmp_path: Path,
    signed: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = tmp_path / ("signed-package" if signed else "unsigned-package")
    manifest = _write_workflow(
        package,
        workflow_id=f"test/reviewed-{'signed' if signed else 'unsigned'}",
    )
    if signed:
        workflow_hash = sign_package(package, Ed25519PrivateKey.generate())
        manifest = WorkflowManifest.load(package / "manifest.yaml")
        publisher_key = manifest.publisher.public_key
    else:
        workflow_hash = write_checksums(package)
        publisher_key = None
    archive = build_archive(
        package,
        tmp_path / "reviewed.zip",
        allow_unsigned=not signed,
    )
    archive_bytes = archive.read_bytes()
    artifact_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    workflow_ref = f"{manifest.id}@{manifest.version}"
    workflow_digest = f"sha256:{workflow_hash}"
    node_classes_digest = comfyui_capability_facts(
        manifest,
        package,
    ).node_classes_digest
    spec = {
        "kind": "capability_install",
        "workflow_ref": workflow_ref,
        "workflow_digest": workflow_digest,
        "artifact_sha256": artifact_sha256,
        "artifact_size": len(archive_bytes),
        "node_classes_digest": node_classes_digest,
        "publisher_key": publisher_key,
        "allow_unsigned_workflow": not signed,
        "apply": "on_idle",
    }
    job, credentials = _signed_job(spec)
    job["ticket"] = TransferTicket(
        "https://artifacts.example.test/reviewed.zip",
        "GET",
        expected_size=len(archive_bytes),
        expected_sha256=artifact_sha256,
    )
    work_root = tmp_path / "work"
    cached_archive = work_root / "capability-downloads" / f"{artifact_sha256}.zip"
    cached_archive.parent.mkdir(parents=True)
    shutil.copyfile(archive, cached_archive)
    gateway = _Gateway(job)
    executor = _CapabilityExecutor(workflow_ref, workflow_digest)
    store = WorkerCapabilityStore(tmp_path / "capability-store")
    renewed = threading.Event()
    original_heartbeat = gateway.heartbeat_maintenance

    def renewing_heartbeat(job_id: str, **value: Any) -> dict[str, Any]:
        response = original_heartbeat(job_id, **value)
        if len(gateway.heartbeats) >= 3:
            renewed.set()
        return response

    gateway.heartbeat_maintenance = renewing_heartbeat  # type: ignore[method-assign]
    original_probe = executor.capabilities

    def slow_capability_probe() -> dict[str, Any]:
        assert renewed.wait(timeout=1), "activation lease was not renewed"
        return original_probe()

    executor.capabilities = slow_capability_probe  # type: ignore[method-assign]
    monkeypatch.setattr("vgen.worker.maintenance._LEASE_RENEW_INTERVAL_SECONDS", 0.001)

    outcome = WorkerMaintenanceController(
        credentials,
        gateway,  # type: ignore[arg-type]
        executor,  # type: ignore[arg-type]
        work_root=work_root,
        model_root=None,
        capability_store=store,
        ticket_resolver=lambda _host, _port: ("93.184.216.34",),
    ).run_one()

    assert outcome is not None and outcome.succeeded
    assert outcome.mode == "maintenance_capability_activated"
    assert executor.validated == [(workflow_ref, workflow_digest)]
    assert executor.reloads == 1
    active = store.active()
    assert len(active) == 1
    assert active[0].signed is signed
    assert gateway.completions == [
        {
            "job_id": "mtn_capability_test",
            "fencing_token": 3,
            "succeeded": True,
            "result": {
                "kind": "capability_install",
                "status": "activated",
                "workflow_ref": workflow_ref,
                "workflow_digest": workflow_digest,
                "artifact_sha256": artifact_sha256,
                "ready": True,
            },
        }
    ]
    stages = [item["progress"]["stage"] for item in gateway.heartbeats]
    assert stages[:2] == ["validating", "activating"]
    assert stages[2:] and set(stages[2:]) == {"activating"}
