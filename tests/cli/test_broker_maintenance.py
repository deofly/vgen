from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.main import (
    _apply_model_install,
    _apply_worker_update,
    _broker_command,
    _reject_known_insufficient_workflow_resources,
    _resolve_workflow,
    _unique_model_requirements,
    _worker_command,
    build_parser,
    main,
)
from vgen.crypto import verify_maintenance_intent
from vgen.market.models import WorkflowManifest
from vgen.market.registry import WorkflowRegistry, write_checksums
from vgen.protocol import ErrorCode


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


def _test_wheel(directory: Path, *, version: str = "0.2.0") -> Path:
    target = directory / f"vgen-{version}-py3-none-any.whl"
    dist_info = f"vgen-{version}.dist-info"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vgen/__init__.py", f'__version__ = "{version}"\n')
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: vgen\nVersion: {version}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    return target


class MaintenanceClient:
    def __init__(
        self,
        worker: dict[str, Any],
        *,
        terminal_job: dict[str, Any] | None = None,
        worker_after_commit: dict[str, Any] | None = None,
    ) -> None:
        self.profile = SimpleNamespace(
            name="default",
            principal_type="device",
            home_broker_id="brk_home",
        )
        self.worker = worker
        self.manager_calls: list[tuple[str, str | None]] = []
        self.created: list[dict[str, Any]] = []
        self.committed: list[str] = []
        self.terminal_job = terminal_job
        self.worker_after_commit = worker_after_commit
        self.closed = False

    def request(self, method: str, path: str, **_: Any) -> Any:
        assert method == "GET"
        assert path == "/api/v1/workers"
        return [dict(self.worker)]

    def set_worker_manager(self, worker_id: str, broker_id: str | None) -> dict[str, Any]:
        self.manager_calls.append((worker_id, broker_id))
        self.worker = {**self.worker, "manager_broker_id": broker_id}
        return dict(self.worker)

    def create_worker_maintenance(self, **values: Any) -> dict[str, Any]:
        self.created.append(values)
        uploads_artifact = values["spec"]["kind"] in {
            "worker_update",
            "capability_install",
        }
        response = {
            "id": "mtn_example",
            "state": "awaiting_upload" if uploads_artifact else "queued",
        }
        if uploads_artifact:
            response["artifact_id"] = "art_update"
            response["upload_ticket"] = {
                "artifact_id": "art_update",
                "method": "PUT",
                "url": "https://storage.example/update",
                "expires_at": 2_000_000_000,
                "max_bytes": values["spec"]["artifact_size"],
                "headers": {"Content-Type": "application/octet-stream"},
            }
        return response

    def commit_worker_maintenance(self, job_id: str) -> dict[str, Any]:
        self.committed.append(job_id)
        if self.worker_after_commit is not None:
            self.worker = dict(self.worker_after_commit)
        return {"id": job_id, "state": "queued"}

    def get_worker_maintenance(self, job_id: str) -> dict[str, Any]:
        assert job_id == "mtn_example"
        assert self.terminal_job is not None
        return dict(self.terminal_job)

    def close(self) -> None:
        self.closed = True


class RecordingArtifactAdapter:
    def __init__(self) -> None:
        self.uploads: list[tuple[Any, Path]] = []
        self.contents: list[bytes] = []

    def upload(self, ticket: Any, source: Path) -> None:
        self.uploads.append((ticket, source))
        self.contents.append(source.read_bytes())


def _identity():  # type: ignore[no-untyped-def]
    return DeviceIdentityStore(MemorySecrets()).initialize()[1]


def test_shared_model_placements_become_one_signed_download_request() -> None:
    shared = {
        "sha256": "a" * 64,
        "size": 123,
        "source": "https://models.example.test/shared.safetensors",
        "license": "Apache-2.0",
        "revision": "b" * 40,
        "gated": False,
        "manual_download": False,
    }
    first = SimpleNamespace(**shared, path="text_encoders/shared.safetensors")
    second = SimpleNamespace(**shared, path="clip/shared.safetensors")

    assert _unique_model_requirements([first, second]) == [first]

    conflicting = SimpleNamespace(
        **{**shared, "license": "LicenseRef-Different"},
        path="clip/shared.safetensors",
    )
    with pytest.raises(ValueError, match="conflicting source, size, or license"):
        _unique_model_requirements([first, conflicting])


def test_ltx_release_is_installed_from_digest_pinned_cli_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    monkeypatch.setattr("vgen.cli.main.WorkflowRegistry", lambda: registry)

    manifest, path, digest = _resolve_workflow("vgen/ltx-2.5-distilled-t2v")

    assert manifest.id == "vgen/ltx-2.5-distilled-t2v"
    assert manifest.version == "1.0.0"
    assert digest == "d782e1a99b360198f288f745932a23ac86a01b0357ec4728de8852b7754547fb"
    assert path.is_relative_to(registry.root)


def test_workflow_install_rejects_known_insufficient_vram_before_upload() -> None:
    manifest = WorkflowManifest.load(
        Path(__file__).parents[2]
        / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0/manifest.yaml"
    )
    worker = {
        "capabilities": {
            "executors": [
                {
                    "type": "comfyui",
                    "capabilities": {
                        "vram_bytes": 24 * 1024**3,
                        "ram_bytes": 64 * 1024**3,
                    },
                }
            ]
        }
    }

    with pytest.raises(ValueError, match="Worker VRAM.*workflow requires"):
        _reject_known_insufficient_workflow_resources(
            worker,
            manifest.variants[0],
        )


def test_model_install_rejects_known_insufficient_vram_before_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = (
        Path(__file__).parents[2]
        / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0"
    )
    manifest = WorkflowManifest.load(package / "manifest.yaml")
    worker = _worker()
    worker["capabilities"] = {
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "vram_bytes": 24 * 1024**3,
                    "ram_bytes": 64 * 1024**3,
                    "model_digests": [],
                },
            }
        ]
    }
    client = MaintenanceClient(worker)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, package, "a" * 64),
    )

    with pytest.raises(ValueError, match="Worker VRAM.*workflow requires"):
        _apply_model_install(
            client,
            argparse.Namespace(
                workflow="vgen/ltx-2.5-distilled-t2v@1.0.0",
                worker=None,
                broker=None,
                wait=False,
                interval=0.01,
                timeout=1,
            ),
        )

    assert client.created == []


def _worker(*, manager: str | None = "brk_home") -> dict[str, Any]:
    return {
        "id": "wrk_example",
        "name": "Windows GPU",
        "status": "active",
        "manager_broker_id": manager,
        "executor_type": "comfyui",
        "capabilities": {"model_digests": []},
    }


def _tiny_ltx_workflow(directory: Path) -> tuple[WorkflowManifest, str]:
    graph = {
        "1": {
            "inputs": {"sampler_name": "euler"},
            "class_type": "KSamplerSelect",
            "_meta": {"title": "SAMPLER"},
        }
    }
    (directory / "workflow.json").write_text(json.dumps(graph), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "id": "vgen/ltx-2.5-distilled-t2v",
        "version": "1.0.0",
        "title": "Tiny LTX capability fixture",
        "summary": "Tests remote capability activation.",
        "license": "Apache-2.0",
        "provenance": "market",
        "publisher": {"id": "vgen", "public_key": None},
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "properties": {},
        },
        "variants": [
            {
                "name": "comfyui",
                "executor_type": "comfyui",
                "payload_format": "comfyui-api-graph/v1",
                "payload": "workflow.json",
                "operations": ["t2v"],
                "executor_min_version": "1.2.0",
                "runtime_min_version": "0.32.0",
                "models": [
                    {
                        "filename": "ltx-model.safetensors",
                        "folder": "diffusion_models",
                        "source": (
                            "https://huggingface.co/Lightricks/LTX-2.5/resolve/"
                            + "1" * 40
                            + "/ltx-model.safetensors"
                        ),
                        "revision": "1" * 40,
                        "sha256": "2" * 64,
                        "size": 123,
                        "license": "LicenseRef-LTX-2-Community",
                        "gated": True,
                        "manual_download": False,
                    }
                ],
                "custom_nodes": [],
            }
        ],
    }
    (directory / "manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    digest = write_checksums(directory)
    return WorkflowManifest.load(directory / "manifest.yaml"), digest


def test_parser_exposes_simple_broker_maintenance_commands() -> None:
    update = build_parser().parse_args(
        ["broker", "worker-update", "vgen-0.2.0-py3-none-any.whl", "--wait"]
    )
    assert update.broker_action == "worker-update"
    assert update.worker is None
    assert update.wait is True

    models = build_parser().parse_args(["broker", "model-install"])
    assert models.workflow == "vgen/minimax-h3-8step"

    workflow = build_parser().parse_args(
        [
            "broker",
            "workflow-install",
            "vgen/ltx-2.5-distilled-t2v@1.0.0",
            "--approve-nodes",
            "--allow-unsigned",
        ]
    )
    assert workflow.broker_action == "workflow-install"
    assert workflow.approve_nodes is True
    assert workflow.allow_unsigned is True

    manager = build_parser().parse_args(["worker", "manager-set"])
    assert manager.worker is None
    assert manager.broker is None

    stable_update = build_parser().parse_args(["worker", "upgrade", "--wait"])
    assert stable_update.worker_action == "upgrade"
    assert stable_update.worker is None
    assert stable_update.wait is True


def test_worker_update_uploads_verified_wheel_before_commit_and_signs_policy_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    client = MaintenanceClient(_worker())
    adapter = RecordingArtifactAdapter()
    wheel = _test_wheel(tmp_path)
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", lambda: adapter)

    _broker_command(
        argparse.Namespace(
            broker_action="worker-update",
            wheel=wheel,
            worker=None,
            broker=None,
            wait=False,
            interval=0.01,
            timeout=1,
            profile=None,
        )
    )

    assert client.manager_calls == []
    assert len(client.created) == 1
    created = client.created[0]
    spec = created["spec"]
    assert spec == {
        "kind": "worker_update",
        "target_version": "0.2.0",
        "artifact_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "artifact_size": wheel.stat().st_size,
        "apply": "on_idle",
    }
    assert set(created["authorization"]) == {"payload", "device_certificate", "signature"}
    assert verify_maintenance_intent(
        created["authorization"],
        identity.root_signing_public_key,
        expected_worker_id="wrk_example",
        expected_broker_id="brk_home",
        expected_kind="worker_update",
        expected_spec=spec,
    )
    assert len(adapter.uploads) == 1
    assert adapter.uploads[0][1] == wheel
    assert client.committed == ["mtn_example"]
    assert client.closed


def test_worker_upgrade_downloads_stable_wheel_and_reuses_broker_update(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    client = MaintenanceClient(_worker())
    adapter = RecordingArtifactAdapter()
    wheel = _test_wheel(tmp_path, version="0.3.0")

    @contextmanager
    def stable_worker_wheel(_profile):  # type: ignore[no-untyped-def]
        yield "0.3.0", wheel

    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", lambda: adapter)
    monkeypatch.setattr("vgen.cli.main.stable_worker_wheel", stable_worker_wheel)

    _worker_command(
        argparse.Namespace(
            worker_action="upgrade",
            worker=None,
            broker=None,
            wait=False,
            interval=0.01,
            timeout=1,
            profile=None,
        )
    )

    assert client.created[0]["spec"]["target_version"] == "0.3.0"
    assert adapter.uploads[0][1] == wheel
    assert client.committed == ["mtn_example"]
    assert client.closed


def test_worker_upgrade_is_idempotent_when_worker_already_reports_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    worker = _worker()
    worker["capabilities"]["worker_runtime_version"] = "0.3.0"
    client = MaintenanceClient(worker)
    wheel = _test_wheel(tmp_path, version="0.3.0")
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))

    result = _apply_worker_update(
        client,
        argparse.Namespace(
            worker=None,
            broker=None,
            wait=True,
            interval=0.01,
            timeout=1,
        ),
        wheel,
    )

    assert result == {
        "worker_id": "wrk_example",
        "state": "already_up_to_date",
        "current_version": "0.3.0",
        "target_version": "0.3.0",
    }
    assert client.created == []


@pytest.mark.parametrize("readiness_state", ["missing_models", "missing_nodes"])
def test_model_install_only_sends_missing_digests(
    readiness_state: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    root = Path(__file__).resolve().parents[2]
    manifest_path = root / "workflows/vgen/minimax-h3-8step/1.0.0/manifest.yaml"
    manifest = WorkflowManifest.model_validate(yaml.safe_load(manifest_path.read_text()))
    models = manifest.variants[0].models
    missing = models[1]
    worker = _worker()
    worker["capabilities"] = {
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [
                        f"sha256:{model.sha256}" for model in models if model != missing
                    ]
                    + [f"sha256:{missing.sha256}"],
                    "workflow_readiness": [
                        {
                            "workflow_ref": f"{manifest.id}@{manifest.version}",
                            "workflow_digest": f"sha256:{'a' * 64}",
                            "state": readiness_state,
                            "missing_model_digests": [f"sha256:{missing.sha256}"],
                            "missing_node_classes": [],
                        }
                    ],
                },
            }
        ]
    }
    client = MaintenanceClient(worker)
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, manifest_path.parent, "a" * 64),
    )

    _broker_command(
        argparse.Namespace(
            broker_action="model-install",
            workflow="vgen/minimax-h3-8step",
            worker=None,
            broker=None,
            wait=False,
            interval=0.01,
            timeout=1,
            profile=None,
        )
    )

    spec = client.created[0]["spec"]
    assert set(spec) == {
        "kind",
        "workflow_ref",
        "workflow_digest",
        "model_digests",
    }
    assert spec["model_digests"] == [f"sha256:{missing.sha256}"]
    serialized = json.dumps(spec)
    assert "source" not in serialized
    assert "filename" not in serialized
    assert "https://" not in serialized
    assert client.committed == []


def test_workflow_install_uploads_reviewed_pack_then_requests_only_reported_models(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    manifest, digest = _tiny_ltx_workflow(tmp_path)
    workflow_ref = f"{manifest.id}@{manifest.version}"
    model_digest = "sha256:" + manifest.variants[0].models[0].sha256
    worker_after_commit = _worker()
    worker_after_commit["capabilities"] = {
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [model_digest],
                    "workflow_readiness": [
                        {
                            "workflow_ref": workflow_ref,
                            "workflow_digest": f"sha256:{digest}",
                            "state": "missing_models",
                            "missing_model_digests": [model_digest],
                            "missing_node_classes": [],
                        }
                    ],
                },
            }
        ],
    }
    worker = _worker()
    worker["capabilities"] = {
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [model_digest],
                    "workflow_readiness": [],
                },
            }
        ],
    }
    client = MaintenanceClient(
        worker,
        terminal_job={
            "id": "mtn_example",
            "state": "succeeded",
            "result": {"kind": "capability_install", "status": "activated"},
        },
        worker_after_commit=worker_after_commit,
    )
    adapter = RecordingArtifactAdapter()
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", lambda: adapter)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, tmp_path, digest),
    )

    _broker_command(
        argparse.Namespace(
            broker_action="workflow-install",
            workflow=workflow_ref,
            worker=None,
            broker=None,
            approve_nodes=True,
            allow_unsigned=True,
            wait=False,
            interval=0.01,
            timeout=1,
            profile=None,
        )
    )

    assert len(client.created) == 2
    capability = client.created[0]["spec"]
    assert capability["kind"] == "capability_install"
    assert capability["workflow_ref"] == workflow_ref
    assert capability["workflow_digest"] == f"sha256:{digest}"
    assert capability["allow_unsigned_workflow"] is True
    assert capability["publisher_key"] is None
    assert len(capability["node_classes_digest"]) == 64
    assert len(adapter.contents) == 1
    assert hashlib.sha256(adapter.contents[0]).hexdigest() == capability["artifact_sha256"]
    assert len(adapter.contents[0]) == capability["artifact_size"]
    assert client.committed == ["mtn_example"]

    models = client.created[1]["spec"]
    assert models["kind"] == "model_install"
    assert models["model_digests"] == [model_digest]
    serialized = json.dumps(client.created)
    assert "HF_TOKEN" not in serialized
    assert "Bearer " not in serialized
    assert verify_maintenance_intent(
        client.created[0]["authorization"],
        identity.root_signing_public_key,
        expected_worker_id="wrk_example",
        expected_broker_id="brk_home",
        expected_kind="capability_install",
        expected_spec=capability,
    )


def test_workflow_install_requires_upgraded_worker_before_local_packaging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MaintenanceClient(_worker())
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: pytest.fail("workflow should not be resolved for an old Worker"),
    )

    with pytest.raises(ValueError, match="worker upgrade"):
        _broker_command(
            argparse.Namespace(
                broker_action="workflow-install",
                workflow="vgen/ltx-2.5-distilled-t2v@1.0.0",
                worker=None,
                broker=None,
                approve_nodes=True,
                allow_unsigned=True,
                wait=False,
                interval=0.01,
                timeout=1,
                profile=None,
            )
        )

    assert client.created == []


def test_workflow_install_skips_upload_when_exact_release_is_already_ready(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest, digest = _tiny_ltx_workflow(tmp_path)
    workflow_ref = f"{manifest.id}@{manifest.version}"
    worker = _worker()
    worker["capabilities"] = {
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": ["sha256:" + "2" * 64],
                    "workflow_readiness": [
                        {
                            "workflow_ref": workflow_ref,
                            "workflow_digest": f"sha256:{digest}",
                            "state": "ready",
                            "missing_model_digests": [],
                            "missing_node_classes": [],
                        }
                    ],
                },
            }
        ],
    }
    client = MaintenanceClient(worker)
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, tmp_path, digest),
    )
    monkeypatch.setattr(
        "vgen.cli.main._approve_capability_nodes",
        lambda *_args, **_kwargs: pytest.fail("already-active workflow needs no new approval"),
    )

    _broker_command(
        argparse.Namespace(
            broker_action="workflow-install",
            workflow=workflow_ref,
            worker=None,
            broker=None,
            approve_nodes=False,
            allow_unsigned=False,
            wait=False,
            interval=0.01,
            timeout=1,
            profile=None,
        )
    )

    assert client.created == []
    assert client.committed == []


@pytest.mark.parametrize(
    ("manager", "message"),
    [
        (None, "no manager Broker"),
        ("brk_other", "managed by another Broker"),
    ],
)
def test_maintenance_requires_explicit_manager_binding(
    manager: str | None,
    message: str,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = MaintenanceClient(_worker(manager=manager))
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)

    with pytest.raises(ValueError, match=message):
        _broker_command(
            argparse.Namespace(
                broker_action="worker-update",
                wheel=_test_wheel(tmp_path),
                worker=None,
                broker=None,
                wait=False,
                interval=0.01,
                timeout=1,
                profile=None,
            )
        )
    assert client.created == []
    assert client.manager_calls == []
    assert client.closed


def test_worker_update_wait_failure_returns_nonzero_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    identity = _identity()
    client = MaintenanceClient(
        _worker(),
        terminal_job={
            "id": "mtn_example",
            "state": "failed",
            "result": {"error_code": int(ErrorCode.DOWNLOAD_INTERRUPTED)},
        },
    )
    adapter = RecordingArtifactAdapter()
    wheel = _test_wheel(tmp_path)
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", lambda: adapter)

    exit_code = main(
        [
            "broker",
            "worker-update",
            str(wheel),
            "--wait",
            "--interval",
            "0.01",
            "--timeout",
            "1",
        ]
    )

    assert exit_code == 5
    assert f"{int(ErrorCode.DOWNLOAD_INTERRUPTED)} DOWNLOAD_INTERRUPTED" in capsys.readouterr().err
    assert client.closed


def test_worker_manager_set_is_the_explicit_rebinding_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = MaintenanceClient(_worker(manager="brk_other"))
    monkeypatch.setattr("vgen.cli.main._client", lambda _: client)

    _worker_command(
        argparse.Namespace(
            worker_action="manager-set",
            worker=None,
            broker=None,
            profile=None,
        )
    )

    assert client.manager_calls == [("wrk_example", "brk_home")]
    assert client.closed
