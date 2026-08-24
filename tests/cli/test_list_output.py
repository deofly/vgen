from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vgen.cli import main as cli_main
from vgen.cli.main import build_parser, dispatch
from vgen.cli.profile import GatewayProfile


@pytest.mark.parametrize(
    "argv",
    (
        ["profile", "list"],
        ["workspace", "list"],
        ["workspace", "member-list"],
        ["workspace", "user-list"],
        ["workspace", "pool-list"],
        ["workspace", "enrollment-list"],
        ["workspace", "allocation-list"],
        ["broker", "list"],
        ["broker", "maintenance-list"],
        ["worker", "list"],
        ["workflow", "list"],
        ["task", "list"],
        ["usage", "list"],
    ),
)
def test_every_list_command_defaults_to_text_and_accepts_json(argv: list[str]) -> None:
    parser = build_parser()

    assert parser.parse_args(argv).format == "text"
    assert parser.parse_args([*argv, "--format=json"]).format == "json"


class ListClient:
    def __init__(self) -> None:
        self.profile = SimpleNamespace(
            default_workspace="wsp_example",
            user_id="usr_owner",
            principal_type="device",
            home_broker_id="brk_home",
        )
        self.closed = False

    def request(self, _method: str, path: str, **_kwargs: Any) -> Any:
        if path == "/api/v1/workspaces":
            return [
                {
                    "id": "wsp_example",
                    "name": "Studio",
                    "role": "owner",
                    "status": "active",
                    "key_version": 2,
                    "created_at": 1_700_000_000,
                }
            ]
        if path.endswith("/members"):
            return {
                "total": 1,
                "active_total": 1,
                "members": [
                    {
                        "user_id": "usr_owner",
                        "display_name": "Owner",
                        "role": "owner",
                        "current_status": "online",
                        "active_device_count": 1,
                        "running_task_count": 0,
                        "queued_task_count": 0,
                        "last_seen_at": 1_700_000_001,
                    }
                ],
            }
        if path.endswith("/pools"):
            return [
                {
                    "id": "pol_gpu",
                    "workspace_id": "wsp_example",
                    "name": "GPU",
                    "status": "active",
                    "created_at": 1_700_000_002,
                }
            ]
        if path.endswith("/enrollments"):
            return [
                {
                    "id": "enr_example",
                    "kind": "user",
                    "method": "invite_approval",
                    "state": "pending",
                    "subject_user_id": "usr_joining",
                    "created_at": 1_700_000_003,
                    "expires_at": 1_700_003_600,
                }
            ]
        if path.endswith("/worker-allocations"):
            return [
                {
                    "id": "all_example",
                    "worker_id": "wrk_example",
                    "pool_id": "pol_gpu",
                    "status": "active",
                    "created_at": 1_700_000_004,
                }
            ]
        if path == "/api/v1/brokers":
            return [
                {
                    "id": "brk_home",
                    "name": "Home Broker",
                    "created_at": 1_700_000_005,
                    "devices": [
                        {
                            "runtime_version": "0.8.4",
                            "heartbeat_at": 1_700_000_006,
                        }
                    ],
                }
            ]
        if path == "/api/v1/workers":
            return [{"id": "wrk_example", "name": "GPU", "status": "active"}]
        if path.endswith("/usage"):
            return [
                {
                    "id": "use_example",
                    "entry_type": "charge",
                    "task_id": "tsk_example",
                    "worker_id": "wrk_example",
                    "total_microtokens": 0,
                    "billable": False,
                    "created_at": 1_700_000_007,
                }
            ]
        raise AssertionError(path)

    def list_worker_maintenance(self, worker_id: str) -> list[dict[str, Any]]:
        assert worker_id == "wrk_example"
        return [
            {
                "id": "mtn_example",
                "kind": "worker_update",
                "state": "succeeded",
                "spec": {"target_version": "0.8.4"},
                "updated_at": 1_700_000_008,
            }
        ]

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("argv", "heading", "value"),
    (
        (["workspace", "list"], "WORKSPACE ID", "Studio"),
        (["workspace", "member-list"], "USER ID", "Owner"),
        (["workspace", "user-list"], "USER ID", "Owner"),
        (["workspace", "pool-list"], "POOL ID", "pol_gpu"),
        (["workspace", "enrollment-list"], "ENROLLMENT ID", "enr_example"),
        (["workspace", "allocation-list"], "ALLOCATION ID", "all_example"),
        (["broker", "list"], "BROKER ID", "Home Broker"),
        (["broker", "maintenance-list"], "JOB ID", "mtn_example"),
        (["usage", "list"], "ENTRY ID", "use_example"),
    ),
)
def test_remote_lists_print_flat_rows_by_default(
    argv: list[str],
    heading: str,
    value: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = ListClient()
    monkeypatch.setattr(cli_main, "_client", lambda _profile: client)

    dispatch(build_parser().parse_args(argv))

    output = capsys.readouterr().out
    assert heading in output
    assert value in output
    assert not output.lstrip().startswith(("[", "{"))
    assert client.closed is True


def test_remote_list_json_preserves_original_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = ListClient()
    monkeypatch.setattr(cli_main, "_client", lambda _profile: client)

    dispatch(build_parser().parse_args(["workspace", "list", "--format=json"]))

    assert json.loads(capsys.readouterr().out)[0]["id"] == "wsp_example"


def test_profile_list_is_flat_but_json_keeps_current_wrapper(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    profile = GatewayProfile(
        name="home",
        endpoint="https://gateway.example",
        default_workspace="wsp_example",
        default_pool="pol_gpu",
    )
    store = SimpleNamespace(load=lambda: ("home", {"home": profile}))
    monkeypatch.setattr(cli_main, "ProfileStore", lambda: store)

    dispatch(build_parser().parse_args(["profile", "list"]))
    output = capsys.readouterr().out
    assert "PROFILE" in output
    assert "home" in output
    assert not output.lstrip().startswith("{")

    dispatch(build_parser().parse_args(["profile", "list", "--format=json"]))
    assert json.loads(capsys.readouterr().out)["current"] == "home"


def test_workflow_list_prints_flat_rows_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    installed = SimpleNamespace(
        manifest=SimpleNamespace(id="vgen/demo", version="1.0.0", provenance="market"),
        digest="a" * 64,
        signed=True,
        path=Path("/tmp/vgen-demo"),
    )
    monkeypatch.setattr(
        cli_main,
        "WorkflowRegistry",
        lambda: SimpleNamespace(installed=lambda: [installed]),
    )

    dispatch(build_parser().parse_args(["workflow", "list"]))

    output = capsys.readouterr().out
    assert "WORKFLOW" in output
    assert "vgen/demo" in output
    assert not output.lstrip().startswith("[")
