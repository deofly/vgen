from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import vgen.cli.main as cli_main
from vgen.artifacts import ArtifactTransferError
from vgen.cli.artifacts import LocalTaskInput
from vgen.cli.main import (
    _comfy_input_bindings,
    _effective_parameters,
    _resolve_pool_id,
    _verify_prepared_allocation,
    _verify_prepared_worker_certificate,
    _wait_for_task,
    build_parser,
)
from vgen.cli.workspace_authorities import WorkspaceAuthorityError, WorkspaceAuthorityStore
from vgen.crypto import (
    DeviceKeys,
    b64url_encode,
    build_allocation_proof_payload,
    derive_identity_keys,
    encrypted_stream_size,
    sign_allocation_proof,
    sign_key_manifest,
)
from vgen.market.models import WorkflowManifest


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))


def test_input_descriptor_hides_private_basename_and_has_exact_encrypted_size(tmp_path) -> None:
    private = tmp_path / "customer-alice-secret-frame.png"
    private.write_bytes(b"image" * 100)
    value = LocalTaskInput.from_path("image", private).prepare_descriptor()

    assert value["kind"] == "image"
    assert value["encrypted_size"] == encrypted_stream_size(private.stat().st_size)
    assert value["media_metadata"]["filename"] == "first-frame.png"
    assert "alice" not in str(value)


def test_comfy_bindings_use_logical_artifact_names() -> None:
    mapping = {
        "image": {"title": "INPUT_IMAGE", "input": "image"},
        "last_image": {"node": "42", "input": ["image", "fallback"]},
    }
    assert _comfy_input_bindings(
        mapping,
        [{"input": "image", "artifact_id": "art_first"}, {"input": "last_image"}],
    ) == [
        {"input": "image", "field": "image", "node_title": "INPUT_IMAGE"},
        {"input": "last_image", "field": "image", "node_id": "42"},
    ]


def test_cli_exposes_worker_and_encrypted_task_lifecycle() -> None:
    parser = build_parser()
    worker = parser.parse_args(
        [
            "worker",
            "serve",
            "--gateway-url",
            "http://localhost:8000",
            "--worker-id",
            "wrk_example",
            "--credentials-keyring",
            "--once",
        ]
    )
    assert worker.worker_action == "serve"
    assert worker.credentials_keyring is True
    assert worker.once is True

    retry = parser.parse_args(["task", "retry", "tsk_example"])
    get = parser.parse_args(["task", "get", "tsk_example", "--output-dir", "results"])
    submit = parser.parse_args(
        [
            "task",
            "submit",
            "make a calm ocean",
            "--wait",
            "--output-dir",
            "results",
        ]
    )
    assert retry.task_action == "retry"
    assert get.task_action == "get"
    assert submit.pool is None
    assert submit.wait is True
    assert submit.output_dir == "results"
    preflight = parser.parse_args(
        [
            "task",
            "preflight",
            "sample",
            "--image",
            "first.png",
            "--last-image",
            "last.png",
        ]
    )
    assert preflight.task_action == "preflight"
    assert preflight.image == "first.png"
    assert preflight.last_image == "last.png"


def test_task_preflight_uses_submit_requirements_without_sending_private_inputs(
    monkeypatch, capsys
) -> None:
    root = Path(__file__).resolve().parents[2] / "workflows/vgen/minimax-h3-8step/1.0.0"
    manifest = WorkflowManifest.model_validate(
        yaml.safe_load((root / "manifest.yaml").read_text(encoding="utf-8"))
    )

    class PreflightClient:
        profile = SimpleNamespace(default_workspace="wsp_shared", default_pool="GPU")

        def __init__(self) -> None:
            self.payloads: list[dict] = []

        def request(self, method: str, path: str):
            assert method == "GET"
            assert path == "/api/v1/workspaces/wsp_shared/pools"
            return [{"id": "pol_gpu", "name": "GPU"}]

        def preflight_task(self, payload):
            self.payloads.append(payload)
            return {
                "ready": True,
                "state": "ready",
                "reason": "A matching Worker is ready.",
                "workspace_id": "wsp_shared",
                "pool_id": "pol_gpu",
                "executor_type": "comfyui",
            }

        def close(self) -> None:
            pass

    client = PreflightClient()
    monkeypatch.setattr(cli_main, "_client", lambda _profile=None: client)
    monkeypatch.setattr(
        cli_main,
        "_resolve_workflow",
        lambda _reference: (manifest, root, "c" * 64),
    )
    modes = [
        ([], "t2v"),
        (["--image", "/private/customer-first.png"], "i2v"),
        (
            [
                "--image",
                "/private/customer-first.png",
                "--last-image",
                "/private/customer-last.png",
            ],
            "flf",
        ),
    ]
    for extra, operation in modes:
        assert (
            cli_main.main(
                ["task", "preflight", "PRIVATE_PROMPT_must_stay_local", *extra]
            )
            == 0
        )
        payload = client.payloads[-1]
        assert payload["public_requirements"]["operation"] == operation
        serialized = json.dumps(payload)
        assert "PRIVATE_PROMPT" not in serialized
        assert "customer-first" not in serialized
        assert "customer-last" not in serialized

    output = capsys.readouterr().out
    assert "可以提交任务" in output


def test_wait_for_task_returns_only_after_terminal_state(monkeypatch, capsys) -> None:
    class TaskClient:
        def __init__(self) -> None:
            self.states = iter(("queued", "running", "succeeded"))

        def get_task(self, task_id: str):
            assert task_id == "tsk_example"
            return {"id": task_id, "state": next(self.states)}

    monkeypatch.setattr(cli_main.time, "sleep", lambda _seconds: None)
    result = _wait_for_task(TaskClient(), "tsk_example", interval=0.1, timeout=10)
    assert result["state"] == "succeeded"
    status = capsys.readouterr().err
    assert "queued" in status
    assert "running" in status
    assert "succeeded" in status


def test_task_download_repairs_legacy_bin_extension_from_allowlisted_media_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TaskClient:
        def get_task(self, task_id: str):
            assert task_id == "tsk_example"
            return {
                "id": task_id,
                "artifacts": [
                    {
                        "id": "art_output",
                        "attempt_id": "atm_example",
                        "direction": "output",
                        "state": "available",
                        "download_ticket": {"url": "https://storage.invalid/ciphertext"},
                        "media_metadata": {
                            "filename": "output-00.bin",
                            "media_type": "video/mp4",
                        },
                    }
                ],
            }

    monkeypatch.setattr(
        cli_main,
        "_task_reader_context",
        lambda _client, _task_id: (
            {"workspace_id": "wsp_example"},
            b"k" * 32,
            "atm_example",
            1,
        ),
    )

    def download(_artifact, destination: Path, **_kwargs):
        destination.write_bytes(b"video")
        return SimpleNamespace(size_bytes=5)

    monkeypatch.setattr(cli_main, "download_and_decrypt_output", download)
    result = cli_main._download_task_outputs(
        TaskClient(),
        "tsk_example",
        output_dir=tmp_path,
        overwrite=False,
    )

    output = tmp_path / "output-00.mp4"
    assert output.read_bytes() == b"video"
    assert result == {
        "task_id": "tsk_example",
        "outputs": [{"artifact_id": "art_output", "path": str(output), "size": 5}],
    }


def test_task_pool_resolution_uses_explicit_then_profile_default_then_unique() -> None:
    class PoolClient:
        def __init__(self, default_pool: str | None) -> None:
            self.profile = SimpleNamespace(default_pool=default_pool)

        def request(self, method: str, path: str):
            assert method == "GET"
            assert path == "/api/v1/workspaces/wsp_example/pools"
            return [
                {"id": "pol_a", "name": "Home 3090"},
                {"id": "pol_b", "name": "Office 4090"},
            ]

    assert (
        _resolve_pool_id(
            PoolClient("Home 3090"), workspace_id="wsp_example", requested="Office 4090"
        )
        == "pol_b"
    )
    assert (
        _resolve_pool_id(PoolClient("pol_a"), workspace_id="wsp_example", requested=None) == "pol_a"
    )


def test_worker_owner_certificate_binds_selected_encryption_key() -> None:
    owner = derive_identity_keys(b"owner" * 16)
    worker_keys = DeviceKeys.generate()
    worker = {
        "id": "wrk_example",
        "signing_public_key": b64url_encode(worker_keys.signing_public_bytes()),
        "encryption_public_key": b64url_encode(worker_keys.encryption_public_bytes()),
        "owner_root_signing_public_key": b64url_encode(owner.signing_public_bytes()),
    }
    worker["certificate"] = json.dumps(
        sign_key_manifest(
            owner,
            {
                "version": 1,
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": owner.root_key_id,
                "worker_key_id": worker_keys.key_id,
                "worker_signing_public_key": worker["signing_public_key"],
                "worker_encryption_public_key": worker["encryption_public_key"],
            },
        )
    )
    _verify_prepared_worker_certificate(worker)
    worker["encryption_public_key"] = "gateway-substituted-key"
    with pytest.raises(ValueError, match="does not bind"):
        _verify_prepared_worker_certificate(worker)


def test_workspace_allocation_proof_binds_pool_and_worker_certificate() -> None:
    admin = derive_identity_keys(b"admin" * 16)
    owner = derive_identity_keys(b"owner" * 16)
    worker_keys = DeviceKeys.generate()
    worker = {
        "id": "wrk_example",
        "signing_public_key": b64url_encode(worker_keys.signing_public_bytes()),
        "encryption_public_key": b64url_encode(worker_keys.encryption_public_bytes()),
        "owner_root_signing_public_key": b64url_encode(owner.signing_public_bytes()),
    }
    worker["certificate"] = json.dumps(
        sign_key_manifest(
            owner,
            {
                "version": 1,
                "kind": "vgen-worker-owner-certificate",
                "owner_root_key_id": owner.root_key_id,
                "worker_key_id": worker_keys.key_id,
                "worker_signing_public_key": worker["signing_public_key"],
                "worker_encryption_public_key": worker["encryption_public_key"],
            },
        )
    )
    payload = build_allocation_proof_payload(
        allocation_id="alc_example",
        workspace_id="wsp_example",
        pool_id="pol_example",
        worker_id=worker["id"],
        worker_signing_public_key=worker["signing_public_key"],
        worker_encryption_public_key=worker["encryption_public_key"],
        worker_certificate=worker["certificate"],
        owner_consent_at=1_700_000_000.125,
        approver_root_key_id=admin.root_key_id,
        issued_at=1_700_000_001,
    )
    prepared = {
        "allocation": {
            "id": "alc_example",
            "owner_consent_at": 1_700_000_000.125,
            "proof": sign_allocation_proof(admin, payload),
            "admin_user_id": "usr_admin",
            "admin_root_signing_public_key": b64url_encode(admin.signing_public_bytes()),
        }
    }
    authorities = WorkspaceAuthorityStore(backend=MemoryKeyring())
    authorities.pin(
        workspace_id="wsp_example",
        user_id="usr_admin",
        root_signing_public_key=b64url_encode(admin.signing_public_bytes()),
        root_key_id=admin.root_key_id,
        source="test",
    )
    _verify_prepared_allocation(
        prepared,
        workspace_id="wsp_example",
        pool_id="pol_example",
        worker=worker,
        authority_store=authorities,
    )
    with pytest.raises(ValueError, match="does not authorize"):
        _verify_prepared_allocation(
            prepared,
            workspace_id="wsp_example",
            pool_id="pol_gateway_substitution",
            worker=worker,
            authority_store=authorities,
        )

    attacker = derive_identity_keys(b"attacker" * 8)
    prepared["allocation"]["admin_root_signing_public_key"] = b64url_encode(
        attacker.signing_public_bytes()
    )
    with pytest.raises(WorkspaceAuthorityError, match="substituted"):
        _verify_prepared_allocation(
            prepared,
            workspace_id="wsp_example",
            pool_id="pol_example",
            worker=worker,
            authority_store=authorities,
        )


def test_workflow_parameters_use_json_schema_and_allow_zero_seed() -> None:
    manifest_path = (
        Path(__file__).parents[2] / "workflows/vgen/minimax-h3-8step/1.0.0/manifest.yaml"
    )
    manifest = WorkflowManifest.model_validate(
        yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    )
    arguments = SimpleNamespace(
        prompt="test",
        parameter=["seed=0"],
        image=None,
        last_image=None,
    )
    assert _effective_parameters(manifest, arguments)["seed"] == 0

    arguments.parameter = ["steps=0"]
    with pytest.raises(ValueError, match=r"steps \(minimum\)"):
        _effective_parameters(manifest, arguments)


def test_artifact_transport_error_maps_to_safe_storage_exit(monkeypatch, capsys) -> None:
    def fail(_args) -> None:
        raise ArtifactTransferError("upload", "Artifact upload failed.")

    monkeypatch.setattr(cli_main, "dispatch", fail)
    assert cli_main.main(["profile", "list"]) == 5
    error = capsys.readouterr().err
    assert "700002 STORAGE_UNAVAILABLE" in error
    assert "http" not in error
