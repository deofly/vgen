from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    build_maintenance_intent_payload,
    derive_identity_keys,
    issue_device_certificate,
    sign_maintenance_intent,
)
from vgen.market.capabilities import comfyui_capability_facts
from vgen.market.models import WorkflowManifest
from vgen.market.registry import (
    build_archive,
    package_digest,
    sign_package,
    write_checksums,
)
from vgen.worker.capabilities import (
    CapabilityInstallError,
    WorkerCapabilityStore,
    _is_reparse_point,
)

_WORKER_ID = "wrk_capability_store_test"
_BROKER_ID = "brk_capability_store_test"


def _activate(
    store: WorkerCapabilityStore,
    archive: Path,
    **kwargs: object,
):
    """Exercise the store through the same owner-signed boundary as production."""

    root = derive_identity_keys(b"capability-store-tests" * 4)
    store.configure_trust(b64url_encode(root.signing_public_bytes()), _WORKER_ID)
    try:
        artifact_size = archive.stat().st_size
        artifact_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
    except OSError:
        # The store rejects an invalid archive before consulting the receipt.
        artifact_size = 1
        artifact_sha256 = "0" * 64
    spec = {
        "kind": "capability_install",
        "workflow_ref": kwargs["workflow_ref"],
        "workflow_digest": kwargs["workflow_digest"],
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
        "node_classes_digest": kwargs["node_classes_digest"],
        "publisher_key": kwargs["publisher_key"],
        "allow_unsigned_workflow": kwargs["allow_unsigned"],
        "apply": "on_idle",
    }
    if kwargs.get("model_digests") is not None or kwargs.get("node_classes") is not None:
        spec["model_digests"] = list(kwargs["model_digests"])
        spec["node_classes"] = list(kwargs["node_classes"])
    now = int(time.time())
    device = DeviceKeys.generate()
    certificate = issue_device_certificate(
        root,
        device,
        device_id="dev_capability_store_test",
        issued_at=now - 5,
        expires_at=now + 3600,
    )
    payload = build_maintenance_intent_payload(
        worker_id=_WORKER_ID,
        broker_id=_BROKER_ID,
        kind="capability_install",
        spec=spec,
        device_id="dev_capability_store_test",
        issued_at=now - 1,
        expires_at=now + 600,
        nonce="capability_store_test_nonce",
    )
    return store.activate(
        archive,
        **kwargs,
        authorization=sign_maintenance_intent(device, certificate, payload),
    )


def _synchronize_next_index_read(
    store: WorkerCapabilityStore,
    barrier: Any,
    *,
    delay: float,
) -> None:
    original = store._read_index

    def synchronized() -> dict[str, Any]:
        value = original()
        try:
            barrier.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass
        time.sleep(delay)
        return value

    store._read_index = synchronized  # type: ignore[method-assign]


def _concurrent_deactivate(
    root: Path,
    workflow_ref: str,
    workflow_digest: str,
    barrier: Any,
    results: Any,
) -> None:
    try:
        store = WorkerCapabilityStore(root)
        _synchronize_next_index_read(store, barrier, delay=0)
        results.put(("deactivate", store.deactivate(workflow_ref, workflow_digest)))
    except Exception as exc:  # pragma: no cover - returned to the parent process
        results.put(("error", type(exc).__name__, str(exc)))


def _concurrent_activate(
    root: Path,
    archive: Path,
    activation: dict[str, object],
    barrier: Any,
    results: Any,
) -> None:
    try:
        store = WorkerCapabilityStore(root)
        _synchronize_next_index_read(store, barrier, delay=0.2)
        activated = _activate(store, archive, **activation)
        results.put(("activate", activated.status))
    except Exception as exc:  # pragma: no cover - returned to the parent process
        results.put(("error", type(exc).__name__, str(exc)))


def _h3_workflow() -> Path:
    return Path(__file__).resolve().parents[2] / "workflows/vgen/minimax-h3-8step/1.0.0"


def _ltx_workflow() -> Path:
    return Path(__file__).resolve().parents[2] / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0"


def _node_digest(workflow: Path) -> str:
    manifest = WorkflowManifest.load(workflow / "manifest.yaml")
    return comfyui_capability_facts(manifest, workflow).node_classes_digest


def _signed_and_unsigned_twins(tmp_path: Path) -> tuple[Path, Path, str]:
    signed = tmp_path / "signed-workflow"
    shutil.copytree(_h3_workflow(), signed)
    key = Ed25519PrivateKey.generate()
    sign_package(signed, key)
    unsigned = tmp_path / "unsigned-workflow"
    shutil.copytree(signed, unsigned)
    (unsigned / "artifact.sig").unlink()
    public_key = base64.b64encode(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    assert package_digest(signed) == package_digest(unsigned)
    return signed, unsigned, public_key


def test_authorization_reconcile_atomically_deactivates_but_retains_release_bytes(
    tmp_path: Path,
) -> None:
    workflow = _ltx_workflow()
    archive = build_archive(workflow, tmp_path / "ltx.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    workflow_ref = "vgen/ltx-2.5-distilled-t2v@1.0.0"
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    activation = _activate(
        store,
        archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )
    snapshot = [
        {"workflow_ref": workflow_ref, "workflow_digest": digest},
        *(
            {
                "workflow_ref": f"test/bootstrap-{index}@1.0.0",
                "workflow_digest": f"sha256:{index:064x}",
            }
            for index in range(1, 257)
        ),
    ]

    assert store.reconcile_authorizations(snapshot) == ()
    assert len(store.active()) == 1
    assert store.reconcile_authorizations(snapshot[1:]) == ((workflow_ref, digest),)
    assert store.active() == ()
    assert activation.path.is_dir()


def test_cross_process_activation_and_deactivation_cannot_lose_index_updates(
    tmp_path: Path,
) -> None:
    root = tmp_path / "capabilities"
    h3 = _h3_workflow()
    h3_archive = build_archive(h3, tmp_path / "h3.zip", allow_unsigned=True)
    h3_ref = "vgen/minimax-h3-8step@1.0.0"
    h3_digest = "sha256:" + package_digest(h3)
    _activate(
        WorkerCapabilityStore(root),
        h3_archive,
        workflow_ref=h3_ref,
        workflow_digest=h3_digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(h3),
    )

    ltx = _ltx_workflow()
    ltx_archive = build_archive(ltx, tmp_path / "ltx.zip", allow_unsigned=True)
    ltx_ref = "vgen/ltx-2.5-distilled-t2v@1.0.0"
    ltx_digest = "sha256:" + package_digest(ltx)
    activation: dict[str, object] = {
        "workflow_ref": ltx_ref,
        "workflow_digest": ltx_digest,
        "publisher_key": None,
        "allow_unsigned": True,
        "node_classes_digest": _node_digest(ltx),
    }
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    deactivate = context.Process(
        target=_concurrent_deactivate,
        args=(root, h3_ref, h3_digest, barrier, results),
    )
    activate = context.Process(
        target=_concurrent_activate,
        args=(root, ltx_archive, activation, barrier, results),
    )
    deactivate.start()
    activate.start()
    deactivate.join(timeout=15)
    activate.join(timeout=15)
    for process in (deactivate, activate):
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
        assert process.exitcode == 0
    outcomes = {results.get(timeout=2), results.get(timeout=2)}
    assert outcomes == {("deactivate", True), ("activate", "activated")}
    index = json.loads((root / "active.json").read_text(encoding="utf-8"))
    assert set(index["workflows"]) == {ltx_ref}
    assert (root / "releases" / h3_digest.removeprefix("sha256:")).is_dir()


def test_capability_store_rejects_reparse_roots_releases_index_and_lock(tmp_path: Path) -> None:
    class WindowsReparsePath:
        @staticmethod
        def lstat() -> object:
            return type("Metadata", (), {"st_file_attributes": 0x400})()

        @staticmethod
        def is_symlink() -> bool:
            return False

    assert _is_reparse_point(WindowsReparsePath())  # type: ignore[arg-type]

    outside = tmp_path / "outside"
    outside.mkdir()
    root_link = tmp_path / "root-link"
    root_link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_ROOT_UNSAFE"):
        WorkerCapabilityStore(root_link)

    release_root = tmp_path / "release-root"
    release_root.mkdir()
    (release_root / "releases").symlink_to(outside, target_is_directory=True)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_ROOT_UNSAFE"):
        WorkerCapabilityStore(release_root)

    store = WorkerCapabilityStore(tmp_path / "safe-root")
    external_index = tmp_path / "external-index.json"
    external_index.write_text('{"schema_version":2,"workflows":{}}\n', encoding="utf-8")
    store.index_path.symlink_to(external_index)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_INDEX_INVALID"):
        store.active()
    store.index_path.unlink()
    external_lock = tmp_path / "external-lock"
    external_lock.write_bytes(b"\0")
    store.index_lock_path.symlink_to(external_lock)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_ROOT_UNSAFE"):
        store.deactivate(
            "vgen/minimax-h3-8step@1.0.0",
            "sha256:" + "0" * 64,
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
def test_capability_store_rejects_shared_writable_release_index_and_lock(tmp_path: Path) -> None:
    release_root = tmp_path / "shared-release-root"
    release_store = WorkerCapabilityStore(release_root)
    release_store.releases.chmod(0o777)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_ROOT_UNSAFE"):
        WorkerCapabilityStore(release_root)

    index_store = WorkerCapabilityStore(tmp_path / "shared-index-root")
    index_store.index_path.write_text(
        '{"schema_version":2,"workflows":{}}\n', encoding="utf-8"
    )
    index_store.index_path.chmod(0o666)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_INDEX_INVALID"):
        index_store.active()

    lock_store = WorkerCapabilityStore(tmp_path / "shared-lock-root")
    assert lock_store.reconcile_authorizations([]) == ()
    lock_store.index_lock_path.chmod(0o666)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_ROOT_UNSAFE"):
        lock_store.reconcile_authorizations([])


def test_unsigned_release_requires_explicit_owner_authorization_and_activates_atomically(
    tmp_path: Path,
) -> None:
    workflow = _h3_workflow()
    archive = build_archive(workflow, tmp_path / "h3.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_SPEC_INVALID"):
        _activate(
            store,
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest=digest,
            publisher_key=None,
            allow_unsigned=False,
            node_classes_digest=_node_digest(workflow),
        )

    activated = _activate(
        store,
        archive,
        workflow_ref="vgen/minimax-h3-8step@1.0.0",
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )
    repeated = _activate(
        store,
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
    assert index["schema_version"] == 2
    entry = index["workflows"]["vgen/minimax-h3-8step@1.0.0"]
    assert entry["spec"]["workflow_digest"] == digest
    assert entry["spec"]["allow_unsigned_workflow"] is True
    assert set(entry["authorization"]) == {
        "payload",
        "device_certificate",
        "signature",
    }


def test_v2_owner_spec_binds_exact_models_and_node_classes(tmp_path: Path) -> None:
    workflow = _h3_workflow()
    manifest = WorkflowManifest.load(workflow / "manifest.yaml")
    facts = comfyui_capability_facts(manifest, workflow)
    archive = build_archive(workflow, tmp_path / "h3-v2.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    models = tuple(
        sorted("sha256:" + model.sha256.removeprefix("sha256:") for model in facts.variant.models)
    )
    nodes = tuple(sorted(facts.node_classes))
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    activated = _activate(
        store,
        archive,
        workflow_ref="vgen/minimax-h3-8step@1.0.0",
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=facts.node_classes_digest,
        model_digests=models,
        node_classes=nodes,
    )
    assert activated.status == "activated"
    index = json.loads((store.root / "active.json").read_text(encoding="utf-8"))
    stored_spec = index["workflows"]["vgen/minimax-h3-8step@1.0.0"]["spec"]
    assert stored_spec["model_digests"] == list(models)
    assert stored_spec["node_classes"] == list(nodes)

    forged_models = (*models[:-1], "sha256:" + "f" * 64)
    with pytest.raises(CapabilityInstallError, match="CAPABILITY_MODEL_APPROVAL_MISMATCH"):
        _activate(
            WorkerCapabilityStore(tmp_path / "forged-models"),
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest=digest,
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=facts.node_classes_digest,
            model_digests=tuple(sorted(forged_models)),
            node_classes=nodes,
        )


def test_release_binding_mismatch_never_changes_active_generation(tmp_path: Path) -> None:
    workflow = _h3_workflow()
    archive = build_archive(workflow, tmp_path / "h3.zip", allow_unsigned=True)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_BINDING_MISMATCH"):
        _activate(
            store,
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

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_CONTAINS_EXECUTABLE_CONTENT"):
        _activate(
            store,
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
            _activate(
                store,
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
    assert [item.manifest.id for item in store.active()] == ["vgen/minimax-h3-8step"]
    assert store.active_errors == 1

    repaired = _activate(
        store,
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


def test_one_tampered_activation_receipt_does_not_hide_other_workflows(
    tmp_path: Path,
) -> None:
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    references: list[str] = []
    for index, workflow in enumerate((_h3_workflow(), _ltx_workflow())):
        manifest = WorkflowManifest.load(workflow / "manifest.yaml")
        archive = build_archive(
            workflow,
            tmp_path / f"receipt-{index}.zip",
            allow_unsigned=True,
        )
        workflow_ref = f"{manifest.id}@{manifest.version}"
        references.append(workflow_ref)
        _activate(
            store,
            archive,
            workflow_ref=workflow_ref,
            workflow_digest="sha256:" + package_digest(workflow),
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=_node_digest(workflow),
        )
    index = json.loads(store.index_path.read_text(encoding="utf-8"))
    index["workflows"][references[1]]["authorization"]["signature"] = "tampered"
    store.index_path.write_text(json.dumps(index), encoding="utf-8")

    assert [item.manifest.id for item in store.active()] == ["vgen/minimax-h3-8step"]
    assert store.active_errors == 1


def test_invalid_manifest_yaml_is_isolated_and_remote_reinstall_repairs_it(
    tmp_path: Path,
) -> None:
    workflow = _ltx_workflow()
    archive = build_archive(workflow, tmp_path / "ltx.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    workflow_ref = "vgen/ltx-2.5-distilled-t2v@1.0.0"
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    activated = _activate(
        store,
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

    repaired = _activate(
        store,
        archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )

    assert repaired.status == "repaired"
    assert [item.manifest.id for item in store.active()] == ["vgen/ltx-2.5-distilled-t2v"]
    assert store.active_errors == 0


def test_signed_reinstall_repairs_weaker_active_release(tmp_path: Path) -> None:
    signed, unsigned, public_key = _signed_and_unsigned_twins(tmp_path)
    signed_archive = build_archive(signed, tmp_path / "signed.zip")
    unsigned_archive = build_archive(
        unsigned,
        tmp_path / "unsigned.zip",
        allow_unsigned=True,
    )
    digest = "sha256:" + package_digest(signed)
    workflow_ref = "vgen/minimax-h3-8step@1.0.0"
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    _activate(
        store,
        unsigned_archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(unsigned),
    )
    assert store.active()[0].signed is False

    repaired = _activate(
        store,
        signed_archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=public_key,
        allow_unsigned=False,
        node_classes_digest=_node_digest(signed),
    )

    assert repaired.status == "repaired"
    assert store.active()[0].signed is True
    manifest = yaml.safe_load((repaired.path / "manifest.yaml").read_text(encoding="utf-8"))
    assert manifest["publisher"]["public_key"] == public_key


def test_signed_release_is_quarantined_if_its_signature_is_removed(tmp_path: Path) -> None:
    signed, _unsigned, public_key = _signed_and_unsigned_twins(tmp_path)
    archive = build_archive(signed, tmp_path / "signed.zip")
    digest = "sha256:" + package_digest(signed)
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    activated = _activate(
        store,
        archive,
        workflow_ref="vgen/minimax-h3-8step@1.0.0",
        workflow_digest=digest,
        publisher_key=public_key,
        allow_unsigned=False,
        node_classes_digest=_node_digest(signed),
    )

    (activated.path / "artifact.sig").unlink()

    assert store.active() == ()
    assert store.active_errors == 1


def test_v1_index_fails_closed_until_fresh_owner_authorization(tmp_path: Path) -> None:
    workflow = _h3_workflow()
    archive = build_archive(workflow, tmp_path / "h3.zip", allow_unsigned=True)
    digest = "sha256:" + package_digest(workflow)
    workflow_ref = "vgen/minimax-h3-8step@1.0.0"
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    shutil.copytree(workflow, store.releases / digest.removeprefix("sha256:"))
    store.index_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "workflows": {workflow_ref: digest},
            }
        ),
        encoding="utf-8",
    )
    root = derive_identity_keys(b"capability-store-tests" * 4)
    store.configure_trust(b64url_encode(root.signing_public_bytes()), _WORKER_ID)

    assert store.active() == ()
    assert store.active_errors == 1

    activation = _activate(
        store,
        archive,
        workflow_ref=workflow_ref,
        workflow_digest=digest,
        publisher_key=None,
        allow_unsigned=True,
        node_classes_digest=_node_digest(workflow),
    )

    assert activation.status == "activated"
    assert [item.manifest.id for item in store.active()] == ["vgen/minimax-h3-8step"]
    assert json.loads(store.index_path.read_text(encoding="utf-8"))["schema_version"] == 2


def test_signed_install_does_not_overwrite_weaker_orphan_release(tmp_path: Path) -> None:
    signed, unsigned, public_key = _signed_and_unsigned_twins(tmp_path)
    archive = build_archive(signed, tmp_path / "signed.zip")
    digest = "sha256:" + package_digest(signed)
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    orphan = store.releases / digest.removeprefix("sha256:")
    shutil.copytree(unsigned, orphan)

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_RELEASE_CONFLICT"):
        _activate(
            store,
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest=digest,
            publisher_key=public_key,
            allow_unsigned=False,
            node_classes_digest=_node_digest(signed),
        )

    assert not store.index_path.exists()
    assert not (orphan / "artifact.sig").exists()


def test_concurrent_weaker_release_cannot_satisfy_signed_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed, unsigned, public_key = _signed_and_unsigned_twins(tmp_path)
    archive = build_archive(signed, tmp_path / "signed.zip")
    digest = "sha256:" + package_digest(signed)
    store = WorkerCapabilityStore(tmp_path / "capabilities")
    target = store.releases / digest.removeprefix("sha256:")
    original_replace = os.replace

    def concurrent_replace(source: str | Path, destination: str | Path) -> None:
        if Path(destination) == target and Path(source).name == "release":
            shutil.copytree(unsigned, target)
            raise FileExistsError("concurrent weaker release")
        original_replace(source, destination)

    monkeypatch.setattr(os, "replace", concurrent_replace)

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_RELEASE_CONFLICT"):
        _activate(
            store,
            archive,
            workflow_ref="vgen/minimax-h3-8step@1.0.0",
            workflow_digest=digest,
            publisher_key=public_key,
            allow_unsigned=False,
            node_classes_digest=_node_digest(signed),
        )

    assert not store.index_path.exists()
    assert not (target / "artifact.sig").exists()


def test_executor_validation_failure_is_distinct_from_invalid_archive(
    tmp_path: Path,
) -> None:
    workflow = _ltx_workflow()
    archive = build_archive(workflow, tmp_path / "ltx.zip", allow_unsigned=True)
    store = WorkerCapabilityStore(tmp_path / "capabilities")

    def reject(_installed: object) -> None:
        raise ValueError("bounded executor validation failure")

    with pytest.raises(CapabilityInstallError, match="CAPABILITY_COMPILE_INVALID"):
        _activate(
            store,
            archive,
            workflow_ref="vgen/ltx-2.5-distilled-t2v@1.0.0",
            workflow_digest="sha256:" + package_digest(workflow),
            publisher_key=None,
            allow_unsigned=True,
            node_classes_digest=_node_digest(workflow),
            validator=reject,
        )
