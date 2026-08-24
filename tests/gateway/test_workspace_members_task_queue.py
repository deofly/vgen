from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity, worker_owner_certificate
from vgen.crypto import DeviceKeys, IdentityKeys, b64url_encode, issue_device_certificate
from vgen.gateway.app import create_app
from vgen.gateway.database import json_text, new_id, now
from vgen.protocol.errors import ErrorCode


def _add_member(app, workspace_id: str) -> tuple[str, dict[str, str]]:  # type: ignore[no-untyped-def]
    stamp = now()
    user_id = new_id("usr")
    device_id = new_id("dev")
    identity = IdentityKeys(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())
    device = DeviceKeys.generate()
    certificate = issue_device_certificate(identity, device, device_id=device_id).to_dict()
    app.state.db.execute(
        """INSERT INTO users
           (id,display_name,root_signing_public_key,root_encryption_public_key,status,
            is_operator,created_at,updated_at)
           VALUES (?,? ,?,?,'active',0,?,?)""",
        (
            user_id,
            "Second User",
            b64url_encode(identity.signing_public_bytes()),
            b64url_encode(identity.encryption_public_bytes()),
            stamp,
            stamp,
        ),
    )
    app.state.db.execute(
        """INSERT INTO devices
           (id,user_id,name,signing_public_key,encryption_public_key,certificate,status,
            created_at,last_seen_at)
           VALUES (?,?,?,?,?,?,'active',?,?)""",
        (
            device_id,
            user_id,
            "second-mac",
            b64url_encode(device.signing_public_bytes()),
            b64url_encode(device.encryption_public_bytes()),
            json_text(certificate),
            stamp,
            stamp,
        ),
    )
    app.state.db.execute(
        """INSERT INTO memberships(workspace_id,user_id,role,status,created_at)
           VALUES (?,?,'member','active',?)""",
        (workspace_id, user_id, stamp),
    )
    token, _ = app.state.db.create_session(
        principal_type="device",
        principal_id=device_id,
        user_id=user_id,
        scopes=["*"],
    )
    return user_id, {"Authorization": f"Bearer {token}"}


def _add_worker(app, owner_id: str, workspace_id: str, pool_id: str, owner_identity):  # type: ignore[no-untyped-def]
    keys = DeviceKeys.generate()
    capabilities = {
        "executors": [
            {
                "type": "comfyui",
                "version": "1.0.0",
                "payload_formats": ["opaque/v1"],
                "operations": ["text-to-video"],
                "max_concurrency": 1,
                "capabilities": {"model_digests": []},
            }
        ]
    }
    worker = app.state.repository.create_worker(
        owner_user_id=owner_id,
        manager_broker_id=None,
        name="single-gpu",
        signing_public_key=b64url_encode(keys.signing_public_bytes()),
        encryption_public_key=b64url_encode(keys.encryption_public_bytes()),
        certificate=worker_owner_certificate(owner_identity, keys),
        executor_type="comfyui",
        executor_version="1.0.0",
        capabilities=capabilities,
        capacity=1,
    )
    stamp = now()
    app.state.db.execute(
        """UPDATE workers SET status='active',last_seen_at=?,updated_at=? WHERE id=?""",
        (stamp, stamp, worker["id"]),
    )
    app.state.db.execute(
        """INSERT INTO worker_allocations
           (id,worker_id,workspace_id,pool_id,owner_consent_at,workspace_approved_at,
            approved_by_user_id,allocation_proof,status,created_at,updated_at)
           VALUES (?,?,?,?,?,?,?,'{}','active',?,?)""",
        (
            new_id("alc"),
            worker["id"],
            workspace_id,
            pool_id,
            stamp,
            stamp,
            owner_id,
            stamp,
            stamp,
        ),
    )
    rate = app.state.repository.propose_rate(
        worker_id=worker["id"],
        workspace_id=workspace_id,
        user_id=owner_id,
        rate_microtokens_per_second=1,
    )
    app.state.repository.approve_rate(rate_id=rate["id"], admin_user_id=owner_id)
    return worker


def _submit(
    client: TestClient,
    headers: dict[str, str],
    workspace_id: str,
    pool_id: str,
    key: str,
    priority: int = 0,
) -> dict:
    prepared = client.post(
        "/api/v1/tasks/prepare",
        json={
            "workspace_id": workspace_id,
            "pool_id": pool_id,
            "workflow_ref": "vgen/test@1.0.0",
            "workflow_digest": "sha256:" + key[0] * 64,
            "executor_type": "comfyui",
            "public_requirements": {},
            "priority": priority,
        },
        headers={**headers, "Idempotency-Key": f"prepare-{key}"},
    )
    assert prepared.status_code == 200, prepared.text
    task_id = prepared.json()["id"]
    committed = client.post(
        f"/api/v1/tasks/{task_id}/commit",
        json={
            "encrypted_payload": f"payload-{key}",
            "worker_tdk_envelope": f"worker-key-{key}",
            "reader_envelope": f"reader-key-{key}",
            "key_algorithm": "test-hpke",
        },
        headers=headers,
    )
    assert committed.status_code == 200, committed.text
    return committed.json()


def test_single_worker_queues_tasks_and_reports_members_with_worker_usage(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner_identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Shared"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()
        member_id, member_headers = _add_member(app, workspace["id"])
        worker = _add_worker(
            app, boot["user"]["id"], workspace["id"], pool["id"], owner_identity
        )

        first = _submit(client, owner_headers, workspace["id"], pool["id"], "a-first")
        assert first["state"] == "queued"
        assert first["queue_position"] == 1

        preflight = client.post(
            "/api/v1/tasks/preflight",
            json={
                "workspace_id": workspace["id"],
                "pool_id": pool["id"],
                "workflow_ref": "vgen/test@1.0.0",
                "workflow_digest": "sha256:" + "b" * 64,
                "executor_type": "comfyui",
            },
            headers=member_headers,
        )
        assert preflight.status_code == 200, preflight.text
        assert preflight.json()["state"] == "queue_available"
        assert preflight.json()["ready"] is True

        second = _submit(client, member_headers, workspace["id"], pool["id"], "b-second")
        assert second["state"] == "queued"
        assert second["queue_position"] == 2

        lease = app.state.repository.lease(worker_id=worker["id"], ttl_seconds=60)
        assert lease is not None
        assert lease["task_id"] == first["id"]
        assert app.state.repository.lease(worker_id=worker["id"], ttl_seconds=60) is None

        roster = client.get(
            f"/api/v1/workspaces/{workspace['id']}/members", headers=owner_headers
        )
        assert roster.status_code == 200, roster.text
        assert roster.json()["active_total"] == 2
        members = {item["user_id"]: item for item in roster.json()["members"]}
        assert members[boot["user"]["id"]]["current_status"] == "starting"
        assert members[boot["user"]["id"]]["using_workers"] == [
            {
                "task_id": first["id"],
                "task_state": "reserved",
                "worker_id": worker["id"],
                "worker_name": "single-gpu",
            }
        ]
        assert members[member_id]["current_status"] == "queued"
        assert members[member_id]["queued_task_count"] == 1
        denied_roster = client.get(
            f"/api/v1/workspaces/{workspace['id']}/members", headers=member_headers
        )
        assert denied_roster.status_code == 403


@pytest.mark.parametrize(
    "terminal_state",
    ("succeeded", "failed", "cancelled_before_start", "cancelled_while_running"),
)
def test_single_worker_advances_queue_after_terminal_state(tmp_path, terminal_state: str) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner_identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Queue terminal"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()
        _, member_headers = _add_member(app, workspace["id"])
        worker = _add_worker(
            app, boot["user"]["id"], workspace["id"], pool["id"], owner_identity
        )
        first = _submit(client, owner_headers, workspace["id"], pool["id"], "a-first")
        second = _submit(client, member_headers, workspace["id"], pool["id"], "b-second")

        lease = app.state.repository.lease(worker_id=worker["id"], ttl_seconds=60)
        assert lease is not None
        assert lease["task_id"] == first["id"]
        reference = {
            "attempt_id": lease["attempt_id"],
            "worker_id": worker["id"],
            "fencing_token": lease["fencing_token"],
        }

        if terminal_state == "cancelled_before_start":
            app.state.repository.cancel_task(
                task_id=first["id"], user_id=boot["user"]["id"]
            )
        else:
            app.state.repository.heartbeat_attempt(
                **reference,
                ttl_seconds=60,
                started=True,
            )
            if terminal_state == "cancelled_while_running":
                app.state.repository.cancel_task(
                    task_id=first["id"], user_id=boot["user"]["id"]
                )
                assert (
                    app.state.repository.lease(worker_id=worker["id"], ttl_seconds=60)
                    is None
                )
                succeeded = False
                failure_code = int(ErrorCode.EXECUTION_CANCELLED)
                responsibility = "consumer"
            elif terminal_state == "failed":
                succeeded = False
                failure_code = int(ErrorCode.GPU_OUT_OF_MEMORY)
                responsibility = "provider"
            else:
                succeeded = True
                failure_code = None
                responsibility = "none"
            app.state.repository.finish_attempt(
                **reference,
                succeeded=succeeded,
                output_artifacts=[],
                metrics={"executor_wall_ms": 1, "gpu_count": 1},
                worker_signature="queue-terminal-test",
                failure_code=failure_code,
                responsibility=responsibility,
                safe_failure_details={},
            )

        next_lease = app.state.repository.lease(worker_id=worker["id"], ttl_seconds=60)
        assert next_lease is not None
        assert next_lease["task_id"] == second["id"]


def test_graceful_leave_rekeys_queued_task_then_revokes_after_running_attempt(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner_identity, _ = bootstrap_identity(client)
        owner_id = boot["user"]["id"]
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Graceful drain"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()
        _, member_headers = _add_member(app, workspace["id"])
        worker = _add_worker(app, owner_id, workspace["id"], pool["id"], owner_identity)
        running_task = _submit(
            client, owner_headers, workspace["id"], pool["id"], "a-running"
        )
        queued_task = _submit(
            client, member_headers, workspace["id"], pool["id"], "b-queued"
        )
        lease = app.state.repository.lease(worker_id=worker["id"], ttl_seconds=60)
        assert lease is not None
        app.state.repository.heartbeat_attempt(
            attempt_id=lease["attempt_id"],
            worker_id=worker["id"],
            fencing_token=lease["fencing_token"],
            ttl_seconds=60,
            started=True,
        )

        left = app.state.repository.leave_worker(
            worker_id=worker["id"], owner_user_id=owner_id, force=False
        )

        assert left["status"] == "draining"
        assert app.state.db.fetchone(
            "SELECT state FROM tasks WHERE id=?", (queued_task["id"],)
        )["state"] == "rekey_required"
        queued_attempt = app.state.db.fetchone(
            "SELECT state,responsibility,failure_code FROM task_attempts WHERE task_id=?",
            (queued_task["id"],),
        )
        assert dict(queued_attempt) == {
            "state": "cancelled",
            "responsibility": "provider",
            "failure_code": int(ErrorCode.WORKER_DRAINING),
        }

        app.state.repository.finish_attempt(
            attempt_id=lease["attempt_id"],
            worker_id=worker["id"],
            fencing_token=lease["fencing_token"],
            succeeded=True,
            output_artifacts=[],
            metrics={"executor_wall_ms": 1, "gpu_count": 1},
            worker_signature="graceful-drain-test",
            failure_code=None,
            responsibility="none",
            safe_failure_details={},
        )
        assert app.state.db.fetchone(
            "SELECT state FROM tasks WHERE id=?", (running_task["id"],)
        )["state"] == "succeeded"
        assert app.state.db.fetchone(
            "SELECT status FROM workers WHERE id=?", (worker["id"],)
        )["status"] == "revoked"


def test_graceful_leave_expires_prepared_task_and_rekeys_idle_queue(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner_identity, _ = bootstrap_identity(client)
        owner_id = boot["user"]["id"]
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Idle drain"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()
        worker = _add_worker(app, owner_id, workspace["id"], pool["id"], owner_identity)
        queued_task = _submit(
            client, owner_headers, workspace["id"], pool["id"], "a-queued"
        )
        pending_rekey_task = _submit(
            client, owner_headers, workspace["id"], pool["id"], "c-rekey"
        )
        app.state.db.execute(
            "UPDATE tasks SET state='rekey_required' WHERE id=?",
            (pending_rekey_task["id"],),
        )
        prepared_response = client.post(
            "/api/v1/tasks/prepare",
            json={
                "workspace_id": workspace["id"],
                "pool_id": pool["id"],
                "workflow_ref": "vgen/test@1.0.0",
                "workflow_digest": "sha256:" + "b" * 64,
                "executor_type": "comfyui",
                "public_requirements": {},
            },
            headers={**owner_headers, "Idempotency-Key": "prepare-before-idle-drain"},
        )
        assert prepared_response.status_code == 200, prepared_response.text
        prepared_task = prepared_response.json()

        left = app.state.repository.leave_worker(
            worker_id=worker["id"], owner_user_id=owner_id, force=False
        )

        assert left["status"] == "revoked"
        states = {
            row["id"]: row["state"]
            for row in app.state.db.fetchall(
                "SELECT id,state FROM tasks WHERE id IN (?,?,?)",
                (queued_task["id"], pending_rekey_task["id"], prepared_task["id"]),
            )
        }
        assert states == {
            queued_task["id"]: "rekey_required",
            pending_rekey_task["id"]: "rekey_required",
            prepared_task["id"]: "expired",
        }
        assert app.state.db.fetchone(
            "SELECT state FROM task_attempts WHERE task_id=?",
            (pending_rekey_task["id"],),
        )["state"] == "cancelled"
        assert app.state.db.fetchone(
            "SELECT state FROM task_attempts WHERE task_id=?", (prepared_task["id"],)
        )["state"] == "expired"


def test_task_page_is_short_paginated_and_member_cannot_read_other_users_tasks(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner_identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "History"}, headers=owner_headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=owner_headers,
        ).json()
        _member_id, member_headers = _add_member(app, workspace["id"])
        _add_worker(app, boot["user"]["id"], workspace["id"], pool["id"], owner_identity)
        owner_task = _submit(
            client, owner_headers, workspace["id"], pool["id"], "c-owner", priority=10
        )
        member_task = _submit(
            client, member_headers, workspace["id"], pool["id"], "d-member", priority=1
        )

        first_page = client.get(
            "/api/v1/tasks/page",
            params={"workspace_id": workspace["id"], "limit": 1},
            headers=owner_headers,
        )
        assert first_page.status_code == 200, first_page.text
        assert first_page.json()["total"] == 2
        assert first_page.json()["count"] == 1
        assert first_page.json()["next_cursor"]
        assert first_page.json()["sort"] == "created"
        assert first_page.json()["order"] == "desc"
        assert first_page.json()["items"][0]["id"] == member_task["id"]
        assert "updated_at" in first_page.json()["items"][0]
        assert "public_requirements" not in first_page.json()["items"][0]
        second_page = client.get(
            "/api/v1/tasks/page",
            params={
                "workspace_id": workspace["id"],
                "limit": 1,
                "cursor": first_page.json()["next_cursor"],
            },
            headers=owner_headers,
        )
        assert second_page.status_code == 200, second_page.text
        assert second_page.json()["count"] == 1
        assert second_page.json()["next_cursor"] is None
        assert second_page.json()["items"][0]["id"] == owner_task["id"]

        priority_page = client.get(
            "/api/v1/tasks/page",
            params={
                "workspace_id": workspace["id"],
                "limit": 1,
                "sort": "priority",
                "order": "desc",
            },
            headers=owner_headers,
        )
        assert priority_page.status_code == 200, priority_page.text
        assert priority_page.json()["items"][0]["id"] == owner_task["id"]
        assert priority_page.json()["sort"] == "priority"
        assert priority_page.json()["order"] == "desc"
        next_priority_page = client.get(
            "/api/v1/tasks/page",
            params={
                "workspace_id": workspace["id"],
                "limit": 1,
                "sort": "priority",
                "order": "desc",
                "cursor": priority_page.json()["next_cursor"],
            },
            headers=owner_headers,
        )
        assert next_priority_page.status_code == 200, next_priority_page.text
        assert next_priority_page.json()["items"][0]["id"] == member_task["id"]
        mismatched_cursor = client.get(
            "/api/v1/tasks/page",
            params={
                "workspace_id": workspace["id"],
                "limit": 1,
                "sort": "created",
                "order": "desc",
                "cursor": priority_page.json()["next_cursor"],
            },
            headers=owner_headers,
        )
        assert mismatched_cursor.status_code == 422
        assert {
            first_page.json()["items"][0]["id"],
            second_page.json()["items"][0]["id"],
        } == {owner_task["id"], member_task["id"]}

        member_page = client.get(
            "/api/v1/tasks/page",
            params={"workspace_id": workspace["id"]},
            headers=member_headers,
        )
        assert member_page.status_code == 200, member_page.text
        assert member_page.json()["total"] == 1
        assert [item["id"] for item in member_page.json()["items"]] == [member_task["id"]]

        hidden_detail = client.get(
            f"/api/v1/tasks/{owner_task['id']}", headers=member_headers
        )
        assert hidden_detail.status_code == 403
        visible_detail = client.get(
            f"/api/v1/tasks/{owner_task['id']}", headers=owner_headers
        )
        assert visible_detail.status_code == 200, visible_detail.text
        assert visible_detail.json()["id"] == owner_task["id"]
