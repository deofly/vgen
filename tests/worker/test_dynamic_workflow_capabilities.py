from __future__ import annotations

import hashlib
import json
import shutil
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
)
from vgen.market.capabilities import comfyui_capability_facts
from vgen.market.models import WorkflowManifest
from vgen.market.registry import (
    InstallResult,
    build_archive,
    package_digest,
    sign_package,
    write_checksums,
)
from vgen.worker import WorkerCredentials
from vgen.worker.capabilities import WorkerCapabilityStore
from vgen.worker.maintenance import WorkerMaintenanceController


class _ComfyClient:
    def gpu_info(self) -> list[dict[str, Any]]:
        return [{"name": "test", "vram_total_mb": 1024}]

    def system_info(self) -> dict[str, Any]:
        return {"ram_bytes": 8 * 1024**3, "runtime_version": "0.30.1"}

    def node_classes(self) -> set[str]:
        return {"SafeNode"}


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
) -> WorkflowManifest:
    directory.mkdir(parents=True)
    node_inputs = {"model_name": model_filename} if model_folder is not None else {}
    (directory / "workflow.json").write_text(
        json.dumps({"1": {"class_type": node_class, "inputs": node_inputs}}),
        encoding="utf-8",
    )
    models = []
    if model_folder is not None and model_digest is not None:
        models.append(
            {
                "filename": model_filename,
                "folder": model_folder,
                "sha256": model_digest,
                "size": model_size,
                "license": "Apache-2.0",
            }
        )
    variant = {
        "name": "comfyui",
        "executor_type": "comfyui",
        "payload_format": "comfyui-api-graph/v1",
        "payload": "workflow.json",
        "operations": ["t2v"],
        "models": models,
        "custom_nodes": [],
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
        "license": "Apache-2.0",
        "provenance": "custom",
        "publisher": {"id": "test-reviewer", "public_key": None},
        "parameters": {},
        "variants": [variant],
    }
    (directory / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
    )
    return WorkflowManifest.load(directory / "manifest.yaml")


def _readiness(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["workflow_ref"]: item for item in report["workflow_readiness"]}


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

    assert executor.maintenance_workflows == (
        ("test/good@1.0.0", f"sha256:{good.digest}"),
    )

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
    ("minimums", "expected_state"),
    [
        ({"min_vram_bytes": 2 * 1024**3}, "insufficient_vram"),
        ({"min_ram_bytes": 9 * 1024**3}, "insufficient_ram"),
    ],
)
def test_dynamic_readiness_binds_manifest_resource_minimums(
    tmp_path: Path,
    minimums: dict[str, int],
    expected_state: str,
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
    assert [item["progress"]["stage"] for item in gateway.heartbeats] == [
        "validating",
        "activating",
    ]
