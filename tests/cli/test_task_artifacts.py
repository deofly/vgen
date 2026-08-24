from __future__ import annotations

import json
import re
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
    _normalize_task_list_sort,
    _print_task_list,
    _print_worker_list,
    _resolve_pool_id,
    _task_list_datetime,
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
    show = parser.parse_args(["task", "show", "tsk_example"])
    get = parser.parse_args(["task", "get", "tsk_example", "--output-dir", "results"])
    listing = parser.parse_args(
        [
            "task",
            "list",
            "--limit",
            "10",
            "--cursor",
            "cursor-example",
            "--state",
            "queued",
            "--sort",
            "priority",
            "--order",
            "asc",
        ]
    )
    json_listing = parser.parse_args(["task", "list", "--format=json"])
    worker_listing = parser.parse_args(["worker", "list"])
    worker_json_listing = parser.parse_args(["worker", "list", "--format=json"])
    members = parser.parse_args(["workspace", "member-list", "--include-revoked"])
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
    assert show.task_action == "show"
    assert get.task_action == "get"
    assert listing.limit == 10
    assert listing.cursor == "cursor-example"
    assert listing.state == "queued"
    assert listing.sort == "priority"
    assert listing.order == "asc"
    assert listing.format == "text"
    assert json_listing.format == "json"
    assert worker_listing.format == "text"
    assert worker_json_listing.format == "json"
    assert members.workspace_action == "member-list"
    assert members.include_revoked is True
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


def test_task_list_prints_compact_local_time_and_pagination(capsys) -> None:
    _print_task_list(
        {
            "items": [
                {
                    "id": "tsk_example",
                    "state": "queued",
                    "queue_position": 2,
                    "priority": 8,
                    "created_at": 1_787_552_404.159,
                    "updated_at": 1_787_552_500.0,
                    "submitted_by": {"display_name": "Alice\nAdmin"},
                    "worker": {"name": "GPU\x1bWorker"},
                    "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
                }
            ],
            "total": 21,
            "sort": "priority",
            "order": "desc",
            "next": "vgen task list --cursor next-page --limit 20",
        }
    )

    output = capsys.readouterr().out
    assert "TASK ID" in output
    assert "tsk_example" in output
    assert "queued #2" in output
    assert "PRI" in output
    assert "  8 " in output
    assert "Alice Admin" in output
    assert "GPU Worker" in output
    assert "\x1b" not in output
    assert "1787552404.159" not in output
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", output)
    assert "本页 1 条，共 21 条（排序：priority desc）" in output
    assert "下一页：vgen task list --cursor next-page --limit 20" in output
    assert "查看明细：vgen task show <task_id>" in output


def test_task_list_datetime_rejects_invalid_values() -> None:
    assert _task_list_datetime(None) == "-"
    assert _task_list_datetime("not-a-timestamp") == "-"


def test_worker_list_prints_runtime_summary_and_owned_upgrade_command(capsys) -> None:
    _print_worker_list(
        [
            {
                "id": "wrk_example",
                "owner_user_id": "usr_me",
                "name": "HONEYLONG\nGPU Worker",
                "status": "active",
                "last_seen_at": 1_787_552_404.159,
                "capacity": 1,
                "executor_type": "comfyui",
                "signing_public_key": "must-not-be-printed",
                "capabilities": {
                    "worker_runtime_version": "0.1.0",
                    "executors": [
                        {
                            "type": "comfyui",
                            "capabilities": {
                                "runtime_version": "0.33.0",
                                "gpus": [
                                    {
                                        "name": (
                                            "cuda:0 NVIDIA GeForce RTX 3090 : cudaMallocAsync"
                                        ),
                                        "vram_total_mb": 24_576,
                                    }
                                ],
                            },
                        }
                    ],
                },
            }
        ],
        current_user_id="usr_me",
        profile_name="home",
        stamp=1_787_552_410,
    )

    output = capsys.readouterr().out
    assert "WORKER ID" in output
    assert "HONEYLONG GPU Worker" in output
    assert "online" in output
    assert f"0.1.0 → {cli_main.__version__}" in output
    assert "0.33.0" in output
    assert "NVIDIA GeForce RTX 3090" in output
    assert "24 GB" in output
    assert _task_list_datetime(1_787_552_404.159) in output
    assert "共 1 台，在线 1 台" in output
    assert (
        "vgen worker upgrade --worker wrk_example --wait --profile home" in output
    )
    assert "vgen worker list --format=json" in output
    assert "must-not-be-printed" not in output


def test_worker_list_marks_stale_active_worker_offline_without_foreign_upgrade(capsys) -> None:
    _print_worker_list(
        [
            {
                "id": "wrk_foreign",
                "owner_user_id": "usr_other",
                "name": "Shared Worker",
                "status": "active",
                "last_seen_at": 1_000,
                "capabilities": {"worker_runtime_version": "0.1.0"},
            }
        ],
        current_user_id="usr_me",
        stamp=1_121,
    )

    output = capsys.readouterr().out
    assert "offline" in output
    assert "共 1 台，在线 0 台" in output
    assert "vgen worker upgrade --worker" not in output


def test_task_list_uses_updated_time_when_sorted_by_updated(capsys) -> None:
    _print_task_list(
        {
            "items": [
                {
                    "id": "tsk_updated",
                    "state": "running",
                    "priority": 0,
                    "created_at": 1_700_000_000,
                    "updated_at": 1_787_552_404.159,
                    "submitted_by": {"display_name": "Alice"},
                    "worker": None,
                    "workflow_ref": "vgen/example@1.0.0",
                }
            ],
            "total": 1,
            "sort": "updated",
            "order": "desc",
            "next": None,
        }
    )

    output = capsys.readouterr().out
    assert "UPDATED" in output
    assert _task_list_datetime(1_787_552_404.159) in output
    assert _task_list_datetime(1_700_000_000) not in output


def test_task_list_sort_requires_gateway_support_for_non_default_order() -> None:
    legacy_page: dict = {"items": [], "next_cursor": None}
    _normalize_task_list_sort(legacy_page, sort="created", order="desc")
    assert legacy_page["sort"] == "created"
    assert legacy_page["order"] == "desc"

    with pytest.raises(ValueError, match="upgrade the Gateway"):
        _normalize_task_list_sort({}, sort="priority", order="desc")
    with pytest.raises(ValueError, match="different task list sort"):
        _normalize_task_list_sort(
            {"sort": "created", "order": "desc"}, sort="priority", order="desc"
        )


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
            self.tasks = iter(
                (
                    {"state": "committed", "attempts": []},
                    {
                        "state": "running",
                        "attempts": [
                            {
                                "id": "atm_example",
                                "progress": {
                                    "fraction": 0.08,
                                    "stage": "downloading_inputs",
                                },
                            }
                        ],
                    },
                    {
                        "state": "running",
                        "attempts": [
                            {
                                "id": "atm_example",
                                "progress": {"fraction": 0.1, "stage": "node:10"},
                            }
                        ],
                    },
                    {
                        "state": "running",
                        "attempts": [
                            {
                                "id": "atm_example",
                                "progress": '{"fraction":0.34,"stage":"sampling"}',
                            }
                        ],
                    },
                    {
                        "state": "running",
                        "attempts": [
                            {
                                "id": "atm_example",
                                "progress": {"fraction": 0.35, "stage": "sampling"},
                            }
                        ],
                    },
                    {
                        "state": "running",
                        "attempts": [
                            {
                                "id": "atm_example",
                                "progress": {"fraction": 0.57, "stage": "sampling"},
                            }
                        ],
                    },
                    {
                        "state": "succeeded",
                        "attempts": [
                            {
                                "id": "atm_example",
                                "progress": {
                                    "fraction": 1.0,
                                    "stage": "uploading_outputs",
                                },
                            }
                        ],
                    },
                )
            )

        def get_task(self, task_id: str):
            assert task_id == "tsk_example"
            return {"id": task_id, **next(self.tasks)}

    monkeypatch.setattr(cli_main.time, "sleep", lambda _seconds: None)
    result = _wait_for_task(TaskClient(), "tsk_example", interval=0.1, timeout=10)
    assert result["state"] == "succeeded"
    status = capsys.readouterr().err
    assert "committed" in status
    assert "running" in status
    assert "succeeded" in status
    assert "准备输入：8%" in status
    assert "生成采样：34%" in status
    assert "生成采样：35%" not in status
    assert "生成处理中：当前节点暂无细分进度" in status
    assert "生成处理：10%" not in status
    assert "生成采样：57%" in status
    assert "上传结果：100%" in status


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


def test_task_download_preserves_different_output_and_reuses_identical_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TaskClient:
        def get_task(self, task_id: str):
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
                            "filename": "output-00.mp4",
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
        destination.write_bytes(b"new-video")
        return SimpleNamespace(size_bytes=9)

    monkeypatch.setattr(cli_main, "download_and_decrypt_output", download)
    original = tmp_path / "output-00.mp4"
    original.write_bytes(b"old-video")

    first = cli_main._download_task_outputs(
        TaskClient(), "tsk_example", output_dir=tmp_path, overwrite=False
    )
    unique = tmp_path / "output-00-01.mp4"
    assert original.read_bytes() == b"old-video"
    assert unique.read_bytes() == b"new-video"
    assert first["outputs"][0]["path"] == str(unique)

    second = cli_main._download_task_outputs(
        TaskClient(), "tsk_example", output_dir=tmp_path, overwrite=False
    )
    assert second["outputs"][0]["path"] == str(unique)
    assert not (tmp_path / "output-00-02.mp4").exists()
    assert not list(tmp_path.glob(".vgen-output-*.part"))


def test_task_download_overwrites_only_when_explicitly_requested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class TaskClient:
        def get_task(self, task_id: str):
            return {
                "id": task_id,
                "artifacts": [
                    {
                        "id": "art_output",
                        "attempt_id": "atm_example",
                        "direction": "output",
                        "state": "available",
                        "download_ticket": {"url": "https://storage.invalid/ciphertext"},
                        "media_metadata": {"filename": "output.mp4"},
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
        destination.write_bytes(b"replacement")
        return SimpleNamespace(size_bytes=11)

    monkeypatch.setattr(cli_main, "download_and_decrypt_output", download)
    output = tmp_path / "output.mp4"
    output.write_bytes(b"original")

    result = cli_main._download_task_outputs(
        TaskClient(), "tsk_example", output_dir=tmp_path, overwrite=True
    )

    assert output.read_bytes() == b"replacement"
    assert result["outputs"][0]["path"] == str(output)


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
