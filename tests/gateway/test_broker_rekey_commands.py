from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vgen.gateway.app import create_app
from vgen.gateway.database import GatewayDatabase
from vgen.gateway.repository import GatewayRepository, RepositoryError


def test_existing_v1_database_adds_broker_command_idempotency_key(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v1.db"
    legacy = sqlite3.connect(path)
    legacy.executescript(
        """
        CREATE TABLE schema_meta (version INTEGER NOT NULL);
        INSERT INTO schema_meta(version) VALUES (1);
        CREATE TABLE broker_commands (
            id TEXT PRIMARY KEY,
            broker_device_id TEXT NOT NULL,
            command_type TEXT NOT NULL,
            payload TEXT NOT NULL DEFAULT '{}',
            state TEXT NOT NULL,
            result TEXT,
            created_at REAL NOT NULL,
            expires_at REAL,
            completed_at REAL
        );
        """
    )
    legacy.commit()
    legacy.close()

    db = GatewayDatabase(str(path))

    columns = {row["name"] for row in db.fetchall("PRAGMA table_info(broker_commands)")}
    indexes = {row["name"] for row in db.fetchall("PRAGMA index_list(broker_commands)")}
    assert "command_key" in columns
    assert "idx_broker_commands_key" in indexes
    db.close()


def seed_expired_leases(db: GatewayDatabase) -> None:
    stamp = time.time()
    with db.transaction(immediate=True) as conn:
        conn.executemany(
            """INSERT INTO users
               (id,display_name,root_signing_public_key,root_encryption_public_key,status,
                is_operator,created_at,updated_at)
               VALUES (?,?,?,?, 'active',0,?,?)""",
            [
                ("usr_broker", "broker user", "root-sign-1", "root-enc-1", stamp, stamp),
                ("usr_plain", "plain user", "root-sign-2", "root-enc-2", stamp, stamp),
                ("usr_worker", "worker user", "root-sign-3", "root-enc-3", stamp, stamp),
            ],
        )
        conn.execute(
            """INSERT INTO devices
               (id,user_id,name,signing_public_key,encryption_public_key,status,created_at,last_seen_at)
               VALUES ('dev_broker','usr_broker','broker','device-sign','device-enc','active',?,?)""",
            (stamp, stamp - 1),
        )
        conn.execute(
            """INSERT INTO devices
               (id,user_id,name,signing_public_key,encryption_public_key,status,created_at,last_seen_at)
               VALUES ('dev_broker_new','usr_broker','broker-new','device-sign-new',
                       'device-enc-new','active',?,?)""",
            (stamp, stamp),
        )
        conn.execute(
            """INSERT INTO brokers
               (id,owner_user_id,name,status,created_at,updated_at)
               VALUES ('brk_home','usr_broker','home','active',?,?)""",
            (stamp, stamp),
        )
        conn.execute(
            """INSERT INTO broker_devices
               (id,broker_id,device_id,status,approved_by_user_id,created_at)
               VALUES ('bdev_home','brk_home','dev_broker','active','usr_broker',?)""",
            (stamp,),
        )
        conn.execute(
            """INSERT INTO broker_devices
               (id,broker_id,device_id,status,approved_by_user_id,created_at)
               VALUES ('bdev_home_new','brk_home','dev_broker_new','active','usr_broker',?)""",
            (stamp + 1,),
        )
        conn.execute(
            """INSERT INTO workspaces
               (id,name,owner_user_id,enrollment_policy,key_version,status,created_at,updated_at)
               VALUES ('wsp_test','workspace','usr_broker','{}',1,'active',?,?)""",
            (stamp, stamp),
        )
        conn.execute(
            """INSERT INTO pools
               (id,workspace_id,name,policy,status,created_at,updated_at)
               VALUES ('pol_test','wsp_test','pool','{}','active',?,?)""",
            (stamp, stamp),
        )
        conn.execute(
            """INSERT INTO workers
               (id,owner_user_id,name,signing_public_key,encryption_public_key,executor_type,
                executor_version,capabilities,capacity,status,fencing_counter,last_seen_at,
                created_at,updated_at)
               VALUES ('wrk_test','usr_worker','worker','worker-sign','worker-enc','comfyui',
                       '1','{}',2,'draining',2,?,?,?)""",
            (stamp, stamp, stamp),
        )
        conn.execute(
            """INSERT INTO sessions
               (id,principal_type,principal_id,user_id,token_hash,scopes,expires_at,
                created_at,last_seen_at)
               VALUES ('ses_worker','worker','wrk_test','usr_worker','token-hash','[]',?,?,?)""",
            (stamp + 900, stamp, stamp),
        )
        for suffix, consumer, fencing in (
            ("broker", "usr_broker", 1),
            ("plain", "usr_plain", 2),
        ):
            task_id = f"tsk_{suffix}"
            attempt_id = f"atm_{suffix}"
            conn.execute(
                """INSERT INTO tasks
                   (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
                    consumer_principal_id,client_channel,workflow_ref,workflow_digest,
                    executor_type,public_requirements,content_key_version,encrypted_payload,
                    reader_envelope,assigned_worker_id,reservation_expires_at,state,created_at,
                    updated_at)
                   VALUES (?,?,?,?,'device',?,'cli','wf@1','sha256:test','comfyui','{}',1,
                           'opaque-payload','opaque-reader','wrk_test',?,'running',?,?)""",
                (
                    task_id,
                    "wsp_test",
                    "pol_test",
                    consumer,
                    f"dev_{suffix}",
                    stamp + 120,
                    stamp,
                    stamp,
                ),
            )
            conn.execute(
                """INSERT INTO task_attempts
                   (id,task_id,attempt_number,worker_id,provider_user_id,executor_type,
                    executor_version,state,rate_snapshot,fencing_token,reserved_at,leased_at,
                    started_at)
                   VALUES (?,?,1,'wrk_test','usr_worker','comfyui','1','running','{}',?,?,?,?)""",
                (attempt_id, task_id, fencing, stamp - 60, stamp - 60, stamp - 60),
            )
            conn.execute(
                """INSERT INTO leases
                   (id,attempt_id,worker_id,fencing_token,encrypted_tdk_envelope,issued_at,
                    expires_at,heartbeat_at)
                   VALUES (?,?, 'wrk_test',?,'opaque-worker-envelope',?,?,?)""",
                (
                    f"lse_{suffix}",
                    attempt_id,
                    fencing,
                    stamp - 60,
                    stamp - 1,
                    stamp - 60,
                ),
            )


def assert_swept(db: GatewayDatabase) -> None:
    broker_task = db.fetchone("SELECT state FROM tasks WHERE id='tsk_broker'")
    plain_task = db.fetchone("SELECT state FROM tasks WHERE id='tsk_plain'")
    assert broker_task["state"] == "rekey_required"
    assert plain_task["state"] == "rekey_required"
    assert db.fetchone("SELECT status FROM workers WHERE id='wrk_test'")["status"] == "revoked"
    assert (
        db.fetchone("SELECT revoked_at FROM sessions WHERE id='ses_worker'")["revoked_at"]
        is not None
    )
    commands = db.fetchall("SELECT * FROM broker_commands")
    assert len(commands) == 1
    command = commands[0]
    assert command["broker_device_id"] == "bdev_home_new"
    assert command["command_type"] == "task_rekey"
    payload = json.loads(command["payload"])
    assert payload == {
        "key_version": 1,
        "reason": "lease_expired",
        "source_attempt_id": "atm_broker",
        "task_id": "tsk_broker",
        "version": 1,
        "workspace_id": "wsp_test",
    }
    assert "opaque-payload" not in command["payload"]
    assert "opaque-reader" not in command["payload"]
    assert "opaque-worker-envelope" not in command["payload"]


def test_sweep_expires_leases_and_idempotently_queues_only_for_active_broker(
    tmp_path: Path,
) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    seed_expired_leases(db)
    repository = GatewayRepository(db)

    repository.sweep_expired()
    repository.sweep_expired()

    assert_swept(db)
    db.close()


def test_equal_timestamp_pending_command_survives_restart_cursor(tmp_path: Path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    seed_expired_leases(db)
    repository = GatewayRepository(db)
    repository.sweep_expired()
    first = db.fetchone("SELECT * FROM broker_commands")
    db.execute(
        """INSERT INTO broker_commands
           (id,broker_device_id,command_key,command_type,payload,state,created_at,expires_at)
           VALUES ('bcm_second','bdev_home_new','manual:second','noop','{}','pending',?,?)""",
        (first["created_at"], first["expires_at"]),
    )

    db.execute(
        "UPDATE broker_commands SET state='completed',completed_at=? WHERE id=?",
        (time.time(), first["id"]),
    )
    remaining = repository.broker_commands(
        broker_device_id="bdev_home_new",
        user_id="usr_broker",
        after=first["id"],
    )

    assert [item["id"] for item in remaining] == ["bcm_second"]
    db.close()


def test_rekey_command_result_rejects_arbitrary_sensitive_fields(tmp_path: Path) -> None:
    db = GatewayDatabase(str(tmp_path / "gateway.db"))
    seed_expired_leases(db)
    repository = GatewayRepository(db)
    repository.sweep_expired()
    command = db.fetchone("SELECT id FROM broker_commands")

    with pytest.raises(RepositoryError) as raised:
        repository.complete_broker_command(
            broker_device_id="bdev_home_new",
            command_id=command["id"],
            user_id="usr_broker",
            succeeded=True,
            result={"status": "done", "prompt": "must-not-be-stored"},
        )
    assert raised.value.name == "BROKER_COMMAND_RESULT_INVALID"

    stored = db.fetchone("SELECT result,state FROM broker_commands WHERE id=?", (command["id"],))
    assert stored["result"] is None
    assert stored["state"] == "pending"
    for database_file in tmp_path.glob("gateway.db*"):
        assert b"must-not-be-stored" not in database_file.read_bytes()
    db.close()


def test_gateway_lifespan_sweeps_when_no_requests_arrive(tmp_path: Path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        artifact_root=str(tmp_path / "artifacts"),
        require_request_signatures=False,
        sweep_interval_seconds=0.01,
    )
    with TestClient(app):
        seed_expired_leases(app.state.db)
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if (
                app.state.db.fetchone("SELECT state FROM tasks WHERE id='tsk_broker'")["state"]
                == "rekey_required"
            ):
                break
            time.sleep(0.01)
        assert_swept(app.state.db)
