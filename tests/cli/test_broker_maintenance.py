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
    _apply_workflow_install,
    _broker_command,
    _install_workflow_node_packs,
    _is_trusted_bundled_workflow_release,
    _maintenance_intent_owns_job,
    _reject_known_insufficient_workflow_resources,
    _resolve_workflow,
    _unique_model_requirements,
    _worker_command,
    _worker_supports_bound_capability_spec,
    _workflow_readiness_error,
    build_parser,
    main,
)
from vgen.crypto import verify_maintenance_intent
from vgen.market.models import CustomNodeRequirement, WorkflowManifest, WorkflowVariant
from vgen.market.node_packs import build_node_pack_archive
from vgen.market.registry import (
    RegistryError,
    WorkflowRegistry,
    validate_package,
    write_checksums,
)
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


def test_workflow_readiness_error_preserves_bounded_missing_details() -> None:
    error = _workflow_readiness_error(
        "missing_nodes",
        {
            "custom_node_provenance_error": "provider_unverified:ComfyUI-GGUF",
            "missing_node_classes": ["MissingNode", "OtherNode"],
            "missing_model_digests": ["sha256:" + "a" * 64],
        },
    )

    assert str(error) == (
        "Worker cannot activate this workflow: missing_nodes; "
        "custom node provenance: provider_unverified:ComfyUI-GGUF; "
        "missing nodes: MissingNode, OtherNode; missing models: sha256:" + "a" * 64
    )


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
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.terminal_job = terminal_job
        self.worker_after_commit = worker_after_commit
        self.closed = False

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        self.requests.append((method, path, kwargs))
        if method == "GET" and path == "/api/v1/workers":
            return [dict(self.worker)]
        if method == "POST" and path.endswith("/workflows/deactivate"):
            body = kwargs.get("json_body")
            source_scoped = isinstance(body, dict) and body.get("authorization_source_id")
            return {
                "state": ("authorization_source_revoked" if source_scoped else "deactivated"),
                "scope": "authorization_source" if source_scoped else "workflow",
            }
        raise AssertionError(f"unexpected request: {method} {path}")

    def set_worker_manager(self, worker_id: str, broker_id: str | None) -> dict[str, Any]:
        self.manager_calls.append((worker_id, broker_id))
        self.worker = {**self.worker, "manager_broker_id": broker_id}
        return dict(self.worker)

    def create_worker_maintenance(self, **values: Any) -> dict[str, Any]:
        self.created.append(values)
        uploads_artifact = values["spec"]["kind"] in {
            "worker_update",
            "capability_install",
            "node_pack_install",
        }
        response = {
            "id": "mtn_example",
            "state": "awaiting_upload" if uploads_artifact else "queued",
            "creation_disposition": "created",
            "intent_owns_job": True,
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


def test_maintenance_job_ownership_is_fail_closed_for_legacy_or_invalid_metadata() -> None:
    assert _maintenance_intent_owns_job({"id": "mtj_legacy"}) is False
    with pytest.raises(ValueError, match="invalid maintenance job ownership"):
        _maintenance_intent_owns_job(
            {
                "id": "mtj_invalid",
                "creation_disposition": "deduplicated",
                "intent_owns_job": True,
            }
        )


def test_workflow_node_pack_is_verified_uploaded_and_installed_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "__init__.py").write_text("NODE_CLASS_MAPPINGS = {}\n", encoding="utf-8")
    archive = tmp_path / "node-pack.zip"
    _manifest, digest = build_node_pack_archive(
        source,
        archive,
        node_pack_id="vgen/comfyui-gguf",
        version="1.0.0",
        directory="ComfyUI-GGUF",
        source="https://github.com/city96/ComfyUI-GGUF",
        revision="6ea2651e7df66d7585f6ffee804b20e92fb38b8a",
        node_classes=["UnetLoaderGGUF"],
    )
    variant = WorkflowVariant(
        name="comfyui",
        executor_type="comfyui",
        payload_format="comfyui-api-graph/v1",
        payload="workflow.json",
        operations=["t2v"],
        custom_nodes=[
            CustomNodeRequirement(
                name="ComfyUI-GGUF",
                source="https://github.com/city96/ComfyUI-GGUF",
                revision="6ea2651e7df66d7585f6ffee804b20e92fb38b8a",
                node_types=["UnetLoaderGGUF"],
                node_pack="vgen/comfyui-gguf@1.0.0",
                node_pack_source="https://market.example/node-pack.zip",
                node_pack_sha256=digest,
                manual_install=False,
            )
        ],
    )
    worker = _worker()
    worker["gateway_protocol_features"] = {
        "capability_install_spec_version": 2,
        "node_pack_install_spec_version": 1,
    }
    worker["capabilities"] = {
        "capability_install_spec_version": 2,
        "node_pack_install_spec_version": 1,
        "maintenance_actions": [
            "worker_update",
            "model_install",
            "capability_install",
            "node_pack_install",
        ],
        "executors": [],
    }
    client = MaintenanceClient(
        worker,
        terminal_job={
            "id": "mtn_example",
            "state": "succeeded",
            "result": {
                "kind": "node_pack_install",
                "status": "installed",
                "loaded": True,
            },
        },
    )
    adapter = RecordingArtifactAdapter()
    monkeypatch.setattr(
        "vgen.cli.main._profile_and_identity",
        lambda _: (client.profile, _identity()),
    )
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", lambda: adapter)

    def fetch(_source: str, output: Path, *, expected_sha256: str) -> Path:
        assert expected_sha256 == digest
        output.write_bytes(archive.read_bytes())
        return output

    monkeypatch.setattr("vgen.cli.main.fetch_node_pack", fetch)

    results = _install_workflow_node_packs(
        client,
        argparse.Namespace(interval=0.01, timeout=1),
        broker_id="brk_home",
        worker=worker,
        variant=variant,
    )

    assert results[0]["result"]["status"] == "installed"
    assert client.created[0]["spec"] == {
        "kind": "node_pack_install",
        "node_pack_ref": "vgen/comfyui-gguf@1.0.0",
        "artifact_sha256": digest,
        "artifact_size": archive.stat().st_size,
        "node_classes": ["UnetLoaderGGUF"],
        "apply": "on_idle",
    }
    assert adapter.contents == [archive.read_bytes()]


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

    corrected_provenance = SimpleNamespace(
        **{**shared, "license": "LicenseRef-Different"},
        path="clip/shared.safetensors",
    )
    assert _unique_model_requirements([first, corrected_provenance]) == [first]

    conflicting_size = SimpleNamespace(
        **{**shared, "size": 456},
        path="clip/shared.safetensors",
    )
    with pytest.raises(ValueError, match="conflicting byte sizes"):
        _unique_model_requirements([first, conflicting_size])


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


def test_exact_external_workflow_is_discovered_without_a_cli_code_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = Path(__file__).parents[2] / "workflows/vgen/ltx-2.5-gguf-q4-t2v/1.0.4"
    manifest, digest, _signed = validate_package(package, allow_unsigned=True)
    source = "https://market.example.test/workflows/vgen/ltx-2.5-gguf-q4-t2v/1.0.4/workflow.zip"
    calls: list[tuple[str, dict[str, Any]]] = []

    class ExternalRegistry:
        def installed(self) -> list[object]:
            return []

        def search_index(self, index: str, query: str) -> list[dict[str, str]]:
            assert index == "https://vgen.zcbiz.com/marketplace/index.json"
            assert query == manifest.id
            return [
                {
                    "id": manifest.id,
                    "version": manifest.version,
                    "source": source,
                    "digest": f"sha256:{digest}",
                }
            ]

        def install(self, value: str, **kwargs: Any) -> object:
            calls.append((value, kwargs))
            return SimpleNamespace(
                manifest=manifest,
                path=package,
                digest=digest,
            )

    monkeypatch.setattr("vgen.cli.main.WorkflowRegistry", ExternalRegistry)
    resolved, path, resolved_digest = _resolve_workflow("vgen/ltx-2.5-gguf-q4-t2v@1.0.4")

    assert resolved is manifest
    assert path == package
    assert resolved_digest == digest
    assert calls == [
        (
            source,
            {
                "allow_unsigned": True,
                "expected_digest": f"sha256:{digest}",
                "expected_workflow_id": manifest.id,
                "expected_version": manifest.version,
            },
        )
    ]


def test_workflow_resolution_fails_closed_when_custom_can_shadow_market(
    tmp_path: Path,
) -> None:
    registry = WorkflowRegistry(tmp_path / "registry")
    custom = registry.root / "custom" / "vgen" / "ltx-2.5-distilled-t2v" / "9.0.0"
    custom.mkdir(parents=True)
    _tiny_ltx_workflow(custom)
    raw = yaml.safe_load((custom / "manifest.yaml").read_text(encoding="utf-8"))
    raw["version"] = "9.0.0"
    raw["provenance"] = "custom"
    (custom / "manifest.yaml").write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    write_checksums(custom)

    with pytest.raises(RegistryError, match="both market and custom workflow releases"):
        _resolve_workflow("vgen/ltx-2.5-distilled-t2v", registry=registry)

    # An exact version that exists only in custom is unambiguous and must not
    # depend on registry glob order.
    manifest, path, _digest = _resolve_workflow(
        "vgen/ltx-2.5-distilled-t2v@9.0.0", registry=registry
    )
    assert manifest.provenance == "custom"
    assert path == custom


def test_workflow_install_rejects_known_insufficient_vram_before_upload() -> None:
    manifest = WorkflowManifest.load(
        Path(__file__).parents[2] / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0/manifest.yaml"
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
    package = Path(__file__).parents[2] / "workflows/vgen/ltx-2.5-distilled-t2v/1.0.0"
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
        "gateway_protocol_features": {"capability_install_spec_version": 2},
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
    deactivate = build_parser().parse_args(
        ["broker", "workflow-deactivate", "vgen/ltx-2.5-gguf-q4-t2v@1.0.2"]
    )
    assert deactivate.broker_action == "workflow-deactivate"
    assert deactivate.workflow == "vgen/ltx-2.5-gguf-q4-t2v@1.0.2"
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


def test_bundled_workflow_install_uses_exact_cli_digest_as_local_trust_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-8step/1.0.0"
    manifest, digest, signed = validate_package(package, allow_unsigned=True)
    assert signed is False
    assert _is_trusted_bundled_workflow_release(manifest, digest) is True

    workflow_ref = f"{manifest.id}@{manifest.version}"
    model_digests = [f"sha256:{model.sha256}" for model in manifest.variants[0].models]
    worker_after_commit = _worker()
    worker_after_commit["capabilities"] = {
        "capability_install_spec_version": 2,
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": model_digests,
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
    worker = _worker()
    worker["capabilities"] = {
        "capability_install_spec_version": 2,
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": model_digests,
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
    identity = _identity()
    adapter = RecordingArtifactAdapter()
    monkeypatch.setattr(
        "vgen.cli.main._profile_and_identity",
        lambda _: (client.profile, identity),
    )
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", lambda: adapter)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, package, digest),
    )

    result = _apply_workflow_install(
        client,
        argparse.Namespace(
            workflow=workflow_ref,
            worker=None,
            broker=None,
            approve_nodes=False,
            allow_unsigned=False,
            wait=False,
            interval=0.01,
            timeout=1,
        ),
    )

    assert result["models"]["state"] == "already_satisfied"
    assert len(client.created) == 1
    capability = client.created[0]["spec"]
    assert capability["workflow_digest"] == f"sha256:{digest}"
    assert capability["allow_unsigned_workflow"] is True
    assert capability["publisher_key"] is None
    assert len(adapter.contents) == 1


def test_bundled_workflow_trust_rejects_custom_legacy_or_changed_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = Path(__file__).parents[2] / "workflows/vgen/minimax-h3-8step/1.0.0"
    official, digest, _ = validate_package(package, allow_unsigned=True)
    assert _is_trusted_bundled_workflow_release(official, "0" * 64) is False
    assert (
        _is_trusted_bundled_workflow_release(
            official.model_copy(update={"provenance": "custom"}),
            digest,
        )
        is False
    )
    assert (
        _is_trusted_bundled_workflow_release(
            official.model_copy(update={"version": "0.9.0"}),
            digest,
        )
        is False
    )

    changed_manifest, changed_digest = _tiny_ltx_workflow(tmp_path)
    worker = _worker()
    worker["capabilities"] = {
        "capability_install_spec_version": 2,
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
    }
    client = MaintenanceClient(worker)
    approvals: list[bool] = []

    def require_explicit_approval(
        _workflow_ref: str,
        _node_classes: list[str],
        *,
        approved: bool,
    ) -> None:
        approvals.append(approved)
        if not approved:
            raise ValueError("explicit node approval is required")

    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (changed_manifest, tmp_path, changed_digest),
    )
    monkeypatch.setattr(
        "vgen.cli.main._approve_capability_nodes",
        require_explicit_approval,
    )

    with pytest.raises(ValueError, match="explicit node approval"):
        _apply_workflow_install(
            client,
            argparse.Namespace(
                workflow=f"{changed_manifest.id}@{changed_manifest.version}",
                worker=None,
                broker=None,
                approve_nodes=False,
                allow_unsigned=False,
                wait=False,
                interval=0.01,
                timeout=1,
            ),
        )

    with pytest.raises(RegistryError, match="workflow is unsigned"):
        _apply_workflow_install(
            client,
            argparse.Namespace(
                workflow=f"{changed_manifest.id}@{changed_manifest.version}",
                worker=None,
                broker=None,
                approve_nodes=True,
                allow_unsigned=False,
                wait=False,
                interval=0.01,
                timeout=1,
            ),
        )

    assert approvals == [False, True]
    assert client.created == []


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
        "worker_runtime_version": "0.13.11",
        "capability_install_spec_version": 2,
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
    assert capability["model_digests"] == [model_digest]
    assert capability["node_classes"]
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


@pytest.mark.parametrize("activation_status", ["activated", "already_active", "repaired"])
def test_failed_workflow_install_rolls_back_only_its_maintenance_authorization(
    activation_status: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, digest = _tiny_ltx_workflow(tmp_path)
    workflow_ref = f"{manifest.id}@{manifest.version}"
    worker = _worker()
    worker["capabilities"] = {
        "worker_runtime_version": "0.13.11",
        "capability_install_spec_version": 2,
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [],
                    "workflow_readiness": [],
                },
            }
        ],
    }
    worker_after_commit = json.loads(json.dumps(worker))
    worker_after_commit["capabilities"]["executors"][0]["capabilities"]["workflow_readiness"] = [
        {
            "workflow_ref": workflow_ref,
            "workflow_digest": f"sha256:{digest}",
            "state": "missing_nodes",
            "missing_model_digests": [],
            "missing_node_classes": ["UntrustedNode"],
        }
    ]
    client = MaintenanceClient(
        worker,
        terminal_job={
            "id": "mtn_example",
            "state": "succeeded",
            "result": {"kind": "capability_install", "status": activation_status},
        },
        worker_after_commit=worker_after_commit,
    )
    identity = _identity()
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", RecordingArtifactAdapter)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, tmp_path, digest),
    )

    with pytest.raises(ValueError, match="missing_nodes"):
        _apply_workflow_install(
            client,
            argparse.Namespace(
                workflow=workflow_ref,
                worker=None,
                broker=None,
                approve_nodes=True,
                allow_unsigned=True,
                wait=True,
                interval=0.01,
                timeout=1,
            ),
        )

    rollback_requests = [
        request
        for request in client.requests
        if request[0] == "POST" and request[1].endswith("/workflows/deactivate")
    ]
    assert len(rollback_requests) == 1
    assert rollback_requests[0][2]["json_body"] == {
        "workflow_ref": workflow_ref,
        "workflow_digest": f"sha256:{digest}",
        "authorization_source_id": "mtn_example",
    }


def test_failed_legacy_deduplicated_workflow_install_does_not_rollback_shared_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, digest = _tiny_ltx_workflow(tmp_path)
    workflow_ref = f"{manifest.id}@{manifest.version}"
    worker = _worker()
    worker["capabilities"] = {
        "worker_runtime_version": "0.13.11",
        "capability_install_spec_version": 2,
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [],
                    "workflow_readiness": [],
                },
            }
        ],
    }
    worker_after_commit = json.loads(json.dumps(worker))
    worker_after_commit["capabilities"]["executors"][0]["capabilities"]["workflow_readiness"] = [
        {
            "workflow_ref": workflow_ref,
            "workflow_digest": f"sha256:{digest}",
            "state": "missing_nodes",
            "missing_model_digests": [],
            "missing_node_classes": ["UntrustedNode"],
        }
    ]

    class DeduplicatedMaintenanceClient(MaintenanceClient):
        """Model an older Gateway that may share an active capability job."""

        def create_worker_maintenance(self, **values: Any) -> dict[str, Any]:
            response = super().create_worker_maintenance(**values)
            self.worker = json.loads(json.dumps(worker_after_commit))
            response.pop("artifact_id", None)
            response.pop("upload_ticket", None)
            response.update(
                {
                    "state": "queued",
                    "creation_disposition": "deduplicated",
                    "intent_owns_job": False,
                }
            )
            return response

    client = DeduplicatedMaintenanceClient(
        worker,
        terminal_job={
            "id": "mtn_example",
            "state": "succeeded",
            "result": {"kind": "capability_install", "status": "activated"},
        },
        worker_after_commit=worker_after_commit,
    )
    identity = _identity()
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, tmp_path, digest),
    )

    with pytest.raises(ValueError, match="missing_nodes"):
        _apply_workflow_install(
            client,
            argparse.Namespace(
                workflow=workflow_ref,
                worker=None,
                broker=None,
                approve_nodes=True,
                allow_unsigned=True,
                wait=True,
                interval=0.01,
                timeout=1,
            ),
        )

    assert not any(
        request[0] == "POST" and request[1].endswith("/workflows/deactivate")
        for request in client.requests
    )


def test_final_readiness_failure_rolls_back_succeeded_capability_and_model_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, digest = _tiny_ltx_workflow(tmp_path)
    workflow_ref = f"{manifest.id}@{manifest.version}"
    workflow_digest = f"sha256:{digest}"
    model_digest = "sha256:" + manifest.variants[0].models[0].sha256
    capability_job_id = "mtj_" + "a" * 26
    model_job_id = "mtj_" + "b" * 26
    worker = _worker()
    worker["capabilities"] = {
        "worker_runtime_version": "0.13.11",
        "capability_install_spec_version": 2,
        "maintenance_actions": ["worker_update", "model_install", "capability_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [],
                    "workflow_readiness": [],
                },
            }
        ],
    }
    after_capability = json.loads(json.dumps(worker))
    after_capability["capabilities"]["executors"][0]["capabilities"]["workflow_readiness"] = [
        {
            "workflow_ref": workflow_ref,
            "workflow_digest": workflow_digest,
            "state": "missing_models",
            "missing_model_digests": [model_digest],
            "missing_node_classes": [],
        }
    ]
    after_model = json.loads(json.dumps(after_capability))
    after_model["capabilities"]["executors"][0]["capabilities"]["workflow_readiness"] = [
        {
            "workflow_ref": workflow_ref,
            "workflow_digest": workflow_digest,
            "state": "missing_nodes",
            "missing_model_digests": [],
            "missing_node_classes": ["UntrustedNode"],
        }
    ]

    class SequencedMaintenanceClient(MaintenanceClient):
        def create_worker_maintenance(self, **values: Any) -> dict[str, Any]:
            response = super().create_worker_maintenance(**values)
            job_id = (
                capability_job_id
                if values["spec"]["kind"] == "capability_install"
                else model_job_id
            )
            response["id"] = job_id
            return response

        def get_worker_maintenance(self, job_id: str) -> dict[str, Any]:
            if job_id == capability_job_id:
                return {
                    "id": capability_job_id,
                    "state": "succeeded",
                    "result": {"kind": "capability_install", "status": "activated"},
                }
            if job_id == model_job_id:
                self.worker = json.loads(json.dumps(after_model))
                return {
                    "id": model_job_id,
                    "state": "succeeded",
                    "result": {"kind": "model_install", "status": "installed"},
                }
            raise AssertionError(f"unexpected maintenance job: {job_id}")

    client = SequencedMaintenanceClient(
        worker,
        worker_after_commit=after_capability,
    )
    identity = _identity()
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr("vgen.cli.main.HttpArtifactAdapter", RecordingArtifactAdapter)
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, tmp_path, digest),
    )

    with pytest.raises(ValueError, match="missing_nodes"):
        _apply_workflow_install(
            client,
            argparse.Namespace(
                workflow=workflow_ref,
                worker=None,
                broker=None,
                approve_nodes=True,
                allow_unsigned=True,
                wait=True,
                interval=0.01,
                timeout=1,
            ),
        )

    rollback_sources = {
        request[2]["json_body"]["authorization_source_id"]
        for request in client.requests
        if request[0] == "POST" and request[1].endswith("/workflows/deactivate")
    }
    assert rollback_sources == {capability_job_id, model_job_id}


def test_model_install_exposes_created_source_before_wait_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, digest = _tiny_ltx_workflow(tmp_path)
    workflow_ref = f"{manifest.id}@{manifest.version}"
    model_digest = "sha256:" + manifest.variants[0].models[0].sha256
    worker = _worker()
    worker["capabilities"] = {
        "worker_runtime_version": "0.13.11",
        "maintenance_actions": ["model_install"],
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "workflow_readiness": [
                        {
                            "workflow_ref": workflow_ref,
                            "workflow_digest": f"sha256:{digest}",
                            "state": "missing_models",
                            "missing_model_digests": [model_digest],
                            "missing_node_classes": [],
                        }
                    ]
                },
            }
        ],
    }
    client = MaintenanceClient(worker)
    identity = _identity()
    monkeypatch.setattr("vgen.cli.main._profile_and_identity", lambda _: (client.profile, identity))
    monkeypatch.setattr(
        "vgen.cli.main._resolve_workflow",
        lambda _: (manifest, tmp_path, digest),
    )

    def fail_wait(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise TimeoutError("maintenance wait timed out")

    monkeypatch.setattr("vgen.cli.main._wait_for_maintenance", fail_wait)
    created_sources: list[str] = []

    with pytest.raises(TimeoutError, match="maintenance wait timed out"):
        _apply_model_install(
            client,
            argparse.Namespace(
                workflow=workflow_ref,
                worker=None,
                broker=None,
                wait=True,
                interval=0.01,
                timeout=1,
            ),
            created_authorization_source_ids=created_sources,
        )

    assert created_sources == ["mtn_example"]


@pytest.mark.parametrize(
    ("gateway_feature", "worker_feature", "supported"),
    [
        (None, None, False),  # old Gateway, old Worker
        (2, None, False),  # new Gateway, old Worker
        (None, 2, False),  # old Gateway, new Worker
        (2, 2, True),  # new Gateway, new Worker
        (1, 2, False),
        (2, 1, False),
    ],
)
def test_bound_capability_spec_requires_gateway_and_worker_feature_bits(
    gateway_feature, worker_feature, supported
) -> None:
    worker = _worker()
    worker.pop("gateway_protocol_features")
    if gateway_feature is not None:
        worker["gateway_protocol_features"] = {"capability_install_spec_version": gateway_feature}
    if worker_feature is not None:
        worker["capabilities"]["capability_install_spec_version"] = worker_feature
    assert _worker_supports_bound_capability_spec(worker) is supported


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
    manager: str | None, message: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
