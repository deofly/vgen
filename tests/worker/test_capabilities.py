from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from vgen.market.capabilities import comfyui_capability_facts
from vgen.market.models import WorkflowManifest
from vgen.market.registry import build_archive, package_digest, write_checksums
from vgen.worker.capabilities import CapabilityInstallError, WorkerCapabilityStore


def _h3_workflow() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "workflows/vgen/minimax-h3-8step/1.0.0"
    )


def _ltx_workflow() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0"
    )


def _node_digest(workflow: Path) -> str:
    manifest = WorkflowManifest.load(workflow / "manifest.yaml")
    return comfyui_capability_facts(manifest, workflow).node_classes_digest


def test_unsigned_release_requires_explicit_owner_authorization_and_activates_atomically(
    tmp_path: Path,
) -> None:
    workflow = _h3_workflow()
    archive = build_archive(workflow, tmp_path / "h3.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_SPEC_INVALID"):
        store.activate(
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest=digest,
            publisher_key=None,
            allow_unsigned=False,
            node_classes_digest=_node_digest(workflow),
        )

    activated = store.activate(
        archive,
        workflow_ref="vgen/minimax-h3-8step@1.0.0",
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )
    repeated = store.activate(
        archive,
        workflow_ref="vgen/minimax-h3-8step@1.0.0",
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )

    assert activated.status == "activated"
    assert not (activated.path / "workflow.lock").exists()
    assert repeated.status == "already_active"
    assert [f"{item.manifest.id}@{item.manifest.version}" for item in store.active()] == [
        "vgen/minimax-h3-8step@1.0.0"
    ]
    index = json.loads((store.root / "active.json").read_text(encoding="utf-8"))
    assert index == {
        "schema_version": 1,
        "workflows": {"vgen/minimax-h3-8step@1.0.0": digest},
    }


def test_release_binding_mismatch_never_changes_active_generation(tmp_path: Path) -> None:
    workflow = _h3_workflow()
    archive = build_archive(workflow, tmp_path / "h3.zip", allow_unsigned=True)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_BINDING_MISMATCH"):
        store.activate(
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest="sha256:" + "0" * 64,
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=_node_digest(workflow),
        )

    assert store.active() == ()
    assert not store.index_path.exists()


def test_readme_prefix_cannot_smuggle_executable_content(tmp_path: Path) -> None:
    workflow = tmp_path / "workflow"
    shutil.copytree(_h3_workflow(), workflow)
    (workflow / "README.py").write_text("raise SystemExit('never run')\n", encoding="utf-8")
    digest = "sha256:" + write_checksums(workflow)
    archive = build_archive(workflow, tmp_path / "workflow.zip", allow_unsigned=True)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    with pytest.raises(
        CapabilityInstallError, match="CAPABILITY_CONTAINS_EXECUTABLE_CONTENT"
    ):
        store.activate(
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest=digest,
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=_node_digest(workflow),
        )

    assert store.active() == ()


def test_one_corrupt_release_is_isolated_and_repairs_without_index_rewrite(
    tmp_path: Path,
) -> None:
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    activations = []
    archives: list[Path] = []
    for index, workflow in enumerate((_h3_workflow(), _ltx_workflow())):
        manifest = WorkflowManifest.load(workflow / "manifest.yaml")
        archive = build_archive(
            workflow,
            tmp_path / f"workflow-{index}.zip",
            allow_unsigned=True,
        )
        archives.append(archive)
        activations.append(
            store.activate(
                archive,
                workflow_ref=f"{manifest.id}@{manifest.version}",
                workflow_digest="sha256:" + package_digest(workflow),
                publisher_key=None,
                allow_unsigned=True,
                node_classes_digest=_node_digest(workflow),
            )
        )

    damaged = activations[1].path / "workflow.json"
    original = damaged.read_bytes()
    before_damage = store.generation()
    damaged.write_bytes(original + b"\n")

    assert store.generation() != before_damage
    assert [item.manifest.id for item in store.active()] == [
        "vgen/minimax-h3-8step"
    ]
    assert store.active_errors == 1

    repaired = store.activate(
        archives[1],
        workflow_ref=activations[1].workflow_ref,
        workflow_digest=activations[1].workflow_digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(_ltx_workflow()),
    )

    assert repaired.status == "repaired"
    assert [item.manifest.id for item in store.active()] == [
        "vgen/ltx-2.5-distilled-t2v",
        "vgen/minimax-h3-8step",
    ]
    assert store.active_errors == 0


def test_invalid_manifest_yaml_is_isolated_and_remote_reinstall_repairs_it(
    tmp_path: Path,
) -> None:
    workflow = _ltx_workflow()
    archive = build_archive(workflow, tmp_path / "ltx.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    workflow_ref = "vgen/ltx-2.5-distilled-t2v@1.0.0"
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    activated = store.activate(
        archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )
    (activated.path / "manifest.yaml").write_text(
        "publisher: [unterminated\n",
        encoding="utf-8",
    )

    assert store.active() == ()
    assert store.active_errors == 1

    repaired = store.activate(
        archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )

    assert repaired.status == "repaired"
    assert [item.manifest.id for item in store.active()] == [
        "vgen/ltx-2.5-distilled-t2v"
    ]
    assert store.active_errors == 0


def test_executor_validation_failure_is_distinct_from_invalid_archive(
    tmp_path: Path,
) -> None:
    workflow = _ltx_workflow()
    archive = build_archive(workflow, tmp_path / "ltx.zip", allow_unsigned=True)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    def reject(_installed: object) -> None:
        raise ValueError("bounded executor validation failure")

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_COMPILE_INVALID"):
        store.activate(
            archive,
            workflow_ref="vgen/ltx-2.5-distilled-t2v@1.0.0",
            workflow_digest="sha256:" + package_digest(workflow),
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=_node_digest(workflow),
            validator=reject,
        )
