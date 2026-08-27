from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from tests.gateway.test_gateway_api import bootstrap_identity, worker_owner_certificate
from vgen.crypto import (
    DeviceKeys,
    IdentityKeys,
    b64url_encode,
    build_maintenance_intent_payload,
    issue_device_certificate,
    sign_maintenance_intent,
    sign_message,
)
from vgen.gateway.app import create_app
from vgen.gateway.bootstrap_capabilities import COMFYUI_BOOTSTRAP_WORKFLOWS
from vgen.gateway.repository import GatewayRepository, RepositoryError
from vgen.gateway.schemas import CapabilityInstallSpec, ModelInstallSpec
from vgen.protocol.errors import ErrorCode
from vgen.protocol.ids import new_id


@pytest.mark.parametrize("single_field", ["model_digests", "node_classes"])
def test_capability_v2_dependency_identifiers_are_an_atomic_pair(single_field: str) -> None:
    spec: dict[str, Any] = {
        "kind": "capability_install",
        "workflow_ref": "vgen/test@1.0.0",
        "workflow_digest": "sha256:" + "a" * 64,
        "artifact_sha256": "b" * 64,
        "artifact_size": 1,
        "node_classes_digest": hashlib.sha256(b"[]").hexdigest(),
        "publisher_key": None,
        "allow_unsigned_workflow": True,
        "apply": "on_idle",
        single_field: [],
    }
    with pytest.raises(ValidationError, match="must both be omitted or both be present"):
        CapabilityInstallSpec.model_validate(spec)


def test_model_install_spec_canonicalizes_digest_order_before_signing() -> None:
    later = "sha256:" + "b" * 64
    earlier = "sha256:" + "a" * 64
    spec = ModelInstallSpec.model_validate(
        {
            "kind": "model_install",
            "workflow_ref": "vgen/test@1.0.0",
            "workflow_digest": "sha256:" + "c" * 64,
            "model_digests": [later, earlier],
        }
    )
    assert spec.model_digests == [earlier, later]


@dataclass
class MaintenanceEnvironment:
    client: TestClient
    app: Any
    owner_headers: dict[str, str]
    owner_identity: IdentityKeys
    owner_device: DeviceKeys
    owner_device_id: str
    broker: dict[str, Any]
    worker: dict[str, Any]
    worker_keys: DeviceKeys
    worker_headers: dict[str, str]


def _worker_session(client: TestClient, worker_id: str, worker_keys: DeviceKeys) -> dict[str, str]:
    challenge = client.post(
        "/api/v1/auth/challenges",
        json={"principal_type": "worker", "worker_id": worker_id},
    )
    assert challenge.status_code == 200, challenge.text
    challenge_value = challenge.json()
    session = client.post(
        "/api/v1/auth/sessions",
        json={
            "principal_type": "worker",
            "worker_id": worker_id,
            "challenge_id": challenge_value["challenge_id"],
            "signature": b64url_encode(
                sign_message(
                    worker_keys.signing_private_key,
                    challenge_value["challenge"].encode(),
                )
            ),
        },
    )
    assert session.status_code == 200, session.text
    return {"Authorization": f"Bearer {session.json()['session_token']}"}


def _environment(tmp_path, *, manager: bool = True) -> MaintenanceEnvironment:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    client = TestClient(app)
    client.__enter__()
    client.headers.update({"Vgen-Protocol-Version": "1"})
    boot, owner_headers, owner_identity, owner_device = bootstrap_identity(client)
    broker_response = client.post(
        "/api/v1/brokers",
        json={"name": "Home Broker", "device_id": boot["device"]["id"]},
        headers=owner_headers,
    )
    assert broker_response.status_code == 200, broker_response.text
    broker = broker_response.json()
    worker_keys = DeviceKeys.generate()
    worker_response = client.post(
        "/api/v1/workers",
        json={
            "name": "Windows GPU Worker",
            "manager_broker_id": broker["id"] if manager else None,
            "signing_public_key": b64url_encode(worker_keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(worker_keys.encryption_public_bytes()),
            "certificate": worker_owner_certificate(owner_identity, worker_keys),
            "executor_type": "comfyui",
            "executor_version": "0.33.0",
            "capabilities": {"executors": [{"type": "comfyui"}]},
        },
        headers=owner_headers,
    )
    assert worker_response.status_code == 200, worker_response.text
    worker = worker_response.json()
    worker_headers = _worker_session(client, worker["id"], worker_keys)
    heartbeat = client.post(
        f"/api/v1/workers/{worker['id']}/heartbeat",
        json={"capabilities": {"executors": [{"type": "comfyui"}]}},
        headers=worker_headers,
    )
    assert heartbeat.status_code == 200, heartbeat.text
    return MaintenanceEnvironment(
        client=client,
        app=app,
        owner_headers=owner_headers,
        owner_identity=owner_identity,
        owner_device=owner_device,
        owner_device_id=boot["device"]["id"],
        broker=broker,
        worker=worker,
        worker_keys=worker_keys,
        worker_headers=worker_headers,
    )


def _authorization(
    env: MaintenanceEnvironment,
    spec: dict[str, Any],
    *,
    device_keys: DeviceKeys | None = None,
    device_id: str | None = None,
    certificate: dict[str, Any] | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    resolved_device_id = device_id or env.owner_device_id
    if certificate is None:
        row = env.app.state.db.fetchone(
            "SELECT certificate FROM devices WHERE id=?", (resolved_device_id,)
        )
        assert row is not None
        certificate = json.loads(row["certificate"])
    issued_at = int(time.time())
    payload = build_maintenance_intent_payload(
        worker_id=env.worker["id"],
        broker_id=env.broker["id"],
        kind=spec["kind"],
        spec=spec,
        device_id=resolved_device_id,
        issued_at=issued_at,
        expires_at=issued_at + 3600,
        nonce=nonce or b64url_encode(secrets.token_bytes(24)),
    )
    return sign_maintenance_intent(device_keys or env.owner_device, certificate, payload)


def _create_job(
    env: MaintenanceEnvironment,
    spec: dict[str, Any],
    *,
    authorization: dict[str, Any] | None = None,
    idempotency_key: str | None = None,
):
    headers = dict(env.owner_headers)
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    return env.client.post(
        f"/api/v1/brokers/{env.broker['id']}/workers/{env.worker['id']}/maintenance-jobs",
        json={"spec": spec, "authorization": authorization or _authorization(env, spec)},
        headers=headers,
    )


def _model_spec(*, suffix: str = "a") -> dict[str, Any]:
    model_digest = "sha256:" + suffix * 64
    return {
        "kind": "model_install",
        "workflow_ref": "vgen/minimax-h3-8step@0.1.0",
        "workflow_digest": "sha256:" + "f" * 64,
        "model_digests": [model_digest],
    }


def _capability_spec(artifact: bytes, *, suffix: str = "c") -> dict[str, Any]:
    return {
        "kind": "capability_install",
        "workflow_ref": "vgen/ltx-2.5@1.0.0",
        "workflow_digest": "sha256:" + suffix * 64,
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "artifact_size": len(artifact),
        "node_classes_digest": "9" * 64,
        "publisher_key": base64.b64encode(b"p" * 32).decode("ascii"),
        "allow_unsigned_workflow": False,
        "apply": "on_idle",
    }


def _capability_spec_v2(artifact: bytes, *, suffix: str = "d") -> dict[str, Any]:
    node_classes = ["CLIPTextEncode", "VAEDecode"]
    return {
        **_capability_spec(artifact, suffix=suffix),
        "node_classes_digest": hashlib.sha256(
            json.dumps(node_classes, separators=(",", ":")).encode()
        ).hexdigest(),
        "model_digests": ["sha256:" + "a" * 64, "sha256:" + "b" * 64],
        "node_classes": node_classes,
    }


def _authorize_dynamic_workflow(
    env: MaintenanceEnvironment,
    *,
    source_id: str,
    workflow_ref: str,
    workflow_digest: str,
    model_digests: tuple[str, ...] = (),
    revoked_at: float | None = None,
) -> None:
    stamp = time.time()
    env.app.state.db.execute(
        """INSERT INTO worker_workflow_authorizations
           (worker_id,authorization_source_id,workflow_ref,workflow_digest,
            spec_digest,node_classes,authorized_at,revoked_at)
           VALUES (?,?,?,?,?,'[]',?,?)""",
        (
            env.worker["id"],
            source_id,
            workflow_ref,
            workflow_digest,
            workflow_digest,
            stamp,
            revoked_at,
        ),
    )
    for model_digest in model_digests:
        env.app.state.db.execute(
            """INSERT INTO worker_model_authorizations
               (worker_id,authorization_source_id,workflow_ref,workflow_digest,
                model_digest,spec_digest,authorized_at,revoked_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                env.worker["id"],
                source_id,
                workflow_ref,
                workflow_digest,
                model_digest,
                workflow_digest,
                stamp,
                revoked_at,
            ),
        )


def test_workflow_deactivate_revokes_only_exact_source_scoped_grants(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        shared_model = "sha256:" + "a" * 64
        target_ref = "vgen/ltx-2.5-gguf-q4-t2v@1.0.1"
        target_digest = "sha256:" + "b" * 64
        other_ref = "vgen/shared-model-consumer@1.0.0"
        other_digest = "sha256:" + "c" * 64
        _authorize_dynamic_workflow(
            env,
            source_id="mtj_target",
            workflow_ref=target_ref,
            workflow_digest=target_digest,
            model_digests=(shared_model,),
        )
        _authorize_dynamic_workflow(
            env,
            source_id="mtj_other",
            workflow_ref=other_ref,
            workflow_digest=other_digest,
            model_digests=(shared_model,),
        )

        deactivated = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={"workflow_ref": target_ref, "workflow_digest": target_digest},
            headers=env.owner_headers,
        )
        assert deactivated.status_code == 200, deactivated.text
        assert deactivated.json()["state"] == "deactivated"
        assert deactivated.json()["workflow_grants_revoked"] == 1
        assert deactivated.json()["model_grants_revoked"] == 1

        target_workflow = env.app.state.db.fetchone(
            """SELECT revoked_at FROM worker_workflow_authorizations
               WHERE worker_id=? AND authorization_source_id='mtj_target'""",
            (env.worker["id"],),
        )
        target_model = env.app.state.db.fetchone(
            """SELECT revoked_at FROM worker_model_authorizations
               WHERE worker_id=? AND authorization_source_id='mtj_target'""",
            (env.worker["id"],),
        )
        other_model = env.app.state.db.fetchone(
            """SELECT revoked_at FROM worker_model_authorizations
               WHERE worker_id=? AND authorization_source_id='mtj_other'""",
            (env.worker["id"],),
        )
        assert target_workflow["revoked_at"] is not None
        assert target_model["revoked_at"] is not None
        assert other_model["revoked_at"] is None

        heartbeat = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/heartbeat",
            json={"capabilities": {"executors": [{"type": "comfyui"}]}},
            headers=env.worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text
        snapshot = {
            (item["workflow_ref"], item["workflow_digest"])
            for item in heartbeat.json()["workflow_authorizations"]
        }
        assert (target_ref, target_digest) not in snapshot
        assert (other_ref, other_digest) in snapshot
    finally:
        env.client.__exit__(None, None, None)


def test_install_rollback_revokes_only_its_authorization_source(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        workflow_ref = "vgen/ltx-2.5-gguf-q4-t2v@1.0.1"
        workflow_digest = "sha256:" + "d" * 64
        shared_model = "sha256:" + "e" * 64
        existing_source = new_id("worker_maintenance_job")
        rollback_source = new_id("worker_maintenance_job")
        for source_id in (existing_source, rollback_source):
            _authorize_dynamic_workflow(
                env,
                source_id=source_id,
                workflow_ref=workflow_ref,
                workflow_digest=workflow_digest,
                model_digests=(shared_model,),
            )

        wrong_source = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={
                "workflow_ref": workflow_ref,
                "workflow_digest": workflow_digest,
                "authorization_source_id": new_id("worker_maintenance_job"),
            },
            headers=env.owner_headers,
        )
        assert wrong_source.status_code == 409, wrong_source.text
        assert wrong_source.json()["error"]["details"]["reason"] == (
            "WORKFLOW_AUTHORIZATION_SOURCE_MISMATCH"
        )

        rolled_back = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={
                "workflow_ref": workflow_ref,
                "workflow_digest": workflow_digest,
                "authorization_source_id": rollback_source,
            },
            headers=env.owner_headers,
        )
        assert rolled_back.status_code == 200, rolled_back.text
        assert rolled_back.json()["state"] == "authorization_source_revoked"
        assert rolled_back.json()["scope"] == "authorization_source"
        assert rolled_back.json()["still_authorized"] is True
        assert rolled_back.json()["authorization_source_id"] == rollback_source
        assert rolled_back.json()["workflow_grants_revoked"] == 1
        assert rolled_back.json()["model_grants_revoked"] == 1

        grants = env.app.state.db.fetchall(
            """SELECT authorization_source_id,revoked_at
               FROM worker_workflow_authorizations
               WHERE worker_id=? AND workflow_ref=? AND workflow_digest=?""",
            (env.worker["id"], workflow_ref, workflow_digest),
        )
        revoked_by_source = {
            row["authorization_source_id"]: row["revoked_at"] for row in grants
        }
        assert revoked_by_source[existing_source] is None
        assert revoked_by_source[rollback_source] is not None

        heartbeat = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/heartbeat",
            json={"capabilities": {"executors": [{"type": "comfyui"}]}},
            headers=env.worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text
        assert {
            (item["workflow_ref"], item["workflow_digest"])
            for item in heartbeat.json()["workflow_authorizations"]
        } >= {(workflow_ref, workflow_digest)}

        uninstalled = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={"workflow_ref": workflow_ref, "workflow_digest": workflow_digest},
            headers=env.owner_headers,
        )
        assert uninstalled.status_code == 200, uninstalled.text
        assert uninstalled.json()["state"] == "deactivated"
        assert uninstalled.json()["scope"] == "workflow"
        assert uninstalled.json()["still_authorized"] is False
        assert uninstalled.json()["workflow_grants_revoked"] == 1
        assert uninstalled.json()["model_grants_revoked"] == 1
    finally:
        env.client.__exit__(None, None, None)


@pytest.mark.parametrize("dynamic_revoked", [False, True])
def test_dynamic_source_cannot_bypass_bundled_workflow_protection(
    tmp_path,
    dynamic_revoked: bool,
) -> None:
    env = _environment(tmp_path)
    try:
        bundled = COMFYUI_BOOTSTRAP_WORKFLOWS[0]
        historical_source = new_id("worker_maintenance_job")
        _authorize_dynamic_workflow(
            env,
            source_id=historical_source,
            workflow_ref=bundled.workflow_ref,
            workflow_digest=bundled.workflow_digest,
            revoked_at=time.time() - 60 if dynamic_revoked else None,
        )

        if not dynamic_revoked:
            rolled_back = env.client.post(
                f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
                json={
                    "workflow_ref": bundled.workflow_ref,
                    "workflow_digest": bundled.workflow_digest,
                    "authorization_source_id": historical_source,
                },
                headers=env.owner_headers,
            )
            assert rolled_back.status_code == 200, rolled_back.text
            assert rolled_back.json()["state"] == "authorization_source_revoked"
            assert rolled_back.json()["still_authorized"] is True

        rejected = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={
                "workflow_ref": bundled.workflow_ref,
                "workflow_digest": bundled.workflow_digest,
            },
            headers=env.owner_headers,
        )
        assert rejected.status_code == 409, rejected.text
        assert rejected.json()["error"]["details"]["reason"] == (
            "BUNDLED_WORKFLOW_DEACTIVATE_UNSUPPORTED"
        )
    finally:
        env.client.__exit__(None, None, None)


def test_workflow_deactivate_cancels_and_fences_late_maintenance_completion(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        spec = _model_spec(suffix="7")
        created = _create_job(env, spec)
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        old_fencing_token = claim.json()["fencing_token"]

        deactivated = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={
                "workflow_ref": spec["workflow_ref"],
                "workflow_digest": spec["workflow_digest"],
                "authorization_source_id": job["id"],
            },
            headers=env.owner_headers,
        )
        assert deactivated.status_code == 200, deactivated.text
        assert deactivated.json()["state"] == "authorization_source_revoked"
        assert deactivated.json()["workflow_grants_revoked"] == 0
        assert deactivated.json()["model_grants_revoked"] == 0
        assert deactivated.json()["cancelled_jobs"] == [job["id"]]
        cancelled = env.app.state.db.fetchone(
            """SELECT state,fencing_token,lease_session_id,lease_expires_at
               FROM worker_maintenance_jobs WHERE id=?""",
            (job["id"],),
        )
        assert dict(cancelled) == {
            "state": "cancelled",
            "fencing_token": old_fencing_token + 1,
            "lease_session_id": None,
            "lease_expires_at": None,
        }

        late = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": old_fencing_token,
                "succeeded": True,
                "result": {
                    "kind": "model_install",
                    "status": "installed",
                    "installed_model_digests": spec["model_digests"],
                },
            },
            headers=env.worker_headers,
        )
        assert late.status_code == 409, late.text
        assert late.json()["error"]["code"] == int(ErrorCode.MAINTENANCE_LEASE_LOST)
        assert (
            env.app.state.db.fetchone(
                "SELECT state FROM worker_maintenance_jobs WHERE id=?", (job["id"],)
            )["state"]
            == "cancelled"
        )
    finally:
        env.client.__exit__(None, None, None)


def test_maintenance_heartbeat_refreshes_worker_liveness_after_lease_validation(
    tmp_path,
) -> None:
    env = _environment(tmp_path)
    try:
        created = _create_job(env, _model_spec(suffix="a"))
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        lease = claim.json()
        heartbeat_path = (
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/heartbeat"
        )
        stale_seen_at = time.time() - 300
        env.app.state.db.execute(
            "UPDATE workers SET last_seen_at=?,updated_at=? WHERE id=?",
            (stale_seen_at, stale_seen_at, env.worker["id"]),
        )
        before_job = dict(
            env.app.state.db.fetchone(
                """SELECT state,progress,heartbeat_at,lease_expires_at,updated_at
                   FROM worker_maintenance_jobs WHERE id=?""",
                (job["id"],),
            )
        )

        stale_lease = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": lease["fencing_token"] + 1,
                "ttl_seconds": 60,
                "state": "running",
                "progress": {"stage": "downloading", "completed_bytes": 1},
            },
            headers=env.worker_headers,
        )
        assert stale_lease.status_code == 409, stale_lease.text
        assert (
            env.app.state.db.fetchone(
                "SELECT last_seen_at FROM workers WHERE id=?", (env.worker["id"],)
            )["last_seen_at"]
            == stale_seen_at
        )
        assert (
            dict(
                env.app.state.db.fetchone(
                    """SELECT state,progress,heartbeat_at,lease_expires_at,updated_at
                       FROM worker_maintenance_jobs WHERE id=?""",
                    (job["id"],),
                )
            )
            == before_job
        )

        heartbeat = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": lease["fencing_token"],
                "ttl_seconds": 60,
                "state": "running",
                "progress": {"stage": "downloading", "completed_bytes": 1},
            },
            headers=env.worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text
        worker_row = env.app.state.db.fetchone(
            "SELECT status,last_seen_at,updated_at FROM workers WHERE id=?",
            (env.worker["id"],),
        )
        job_row = env.app.state.db.fetchone(
            "SELECT state,heartbeat_at,updated_at FROM worker_maintenance_jobs WHERE id=?",
            (job["id"],),
        )
        assert worker_row["status"] == "active"
        assert worker_row["last_seen_at"] > stale_seen_at
        assert worker_row["last_seen_at"] == worker_row["updated_at"]
        assert worker_row["last_seen_at"] == job_row["heartbeat_at"]
        assert worker_row["updated_at"] == job_row["updated_at"]
        assert job_row["state"] == "running"
    finally:
        env.client.__exit__(None, None, None)


@pytest.mark.parametrize(("worker_status", "digest_suffix"), [("draining", "b"), ("revoked", "c")])
def test_maintenance_heartbeat_does_not_revive_non_active_worker(
    tmp_path, worker_status: str, digest_suffix: str
) -> None:
    env = _environment(tmp_path)
    try:
        created = _create_job(env, _model_spec(suffix=digest_suffix))
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        lease = claim.json()
        lease_row = env.app.state.db.fetchone(
            "SELECT lease_session_id FROM worker_maintenance_jobs WHERE id=?",
            (job["id"],),
        )
        stale_seen_at = time.time() - 300
        env.app.state.db.execute(
            "UPDATE workers SET status=?,last_seen_at=?,updated_at=? WHERE id=?",
            (worker_status, stale_seen_at, stale_seen_at, env.worker["id"]),
        )
        before_job = dict(
            env.app.state.db.fetchone(
                """SELECT state,progress,heartbeat_at,lease_expires_at,updated_at
                   FROM worker_maintenance_jobs WHERE id=?""",
                (job["id"],),
            )
        )

        with pytest.raises(RepositoryError) as raised:
            env.app.state.repository.heartbeat_worker_maintenance(
                job_id=job["id"],
                worker_id=env.worker["id"],
                session_id=lease_row["lease_session_id"],
                fencing_token=lease["fencing_token"],
                ttl_seconds=60,
                state="running",
                progress=None,
            )
        assert raised.value.code == int(ErrorCode.MAINTENANCE_LEASE_LOST)
        worker_row = env.app.state.db.fetchone(
            "SELECT status,last_seen_at,updated_at FROM workers WHERE id=?",
            (env.worker["id"],),
        )
        assert dict(worker_row) == {
            "status": worker_status,
            "last_seen_at": stale_seen_at,
            "updated_at": stale_seen_at,
        }
        assert (
            dict(
                env.app.state.db.fetchone(
                    """SELECT state,progress,heartbeat_at,lease_expires_at,updated_at
                       FROM worker_maintenance_jobs WHERE id=?""",
                    (job["id"],),
                )
            )
            == before_job
        )
    finally:
        env.client.__exit__(None, None, None)


def test_maintenance_heartbeat_rolls_back_job_when_liveness_refresh_fails(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        created = _create_job(env, _model_spec(suffix="d"))
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        lease = claim.json()
        lease_row = env.app.state.db.fetchone(
            "SELECT lease_session_id FROM worker_maintenance_jobs WHERE id=?",
            (job["id"],),
        )
        before_job = dict(
            env.app.state.db.fetchone(
                """SELECT state,progress,heartbeat_at,lease_expires_at,updated_at
                   FROM worker_maintenance_jobs WHERE id=?""",
                (job["id"],),
            )
        )
        env.app.state.db.execute(
            """CREATE TRIGGER reject_worker_liveness
               BEFORE UPDATE OF last_seen_at ON workers
               BEGIN SELECT RAISE(ABORT,'liveness refresh rejected'); END"""
        )
        try:
            with pytest.raises(sqlite3.IntegrityError, match="liveness refresh rejected"):
                env.app.state.repository.heartbeat_worker_maintenance(
                    job_id=job["id"],
                    worker_id=env.worker["id"],
                    session_id=lease_row["lease_session_id"],
                    fencing_token=lease["fencing_token"],
                    ttl_seconds=60,
                    state="running",
                    progress={"stage": "downloading", "completed_bytes": 1},
                )
        finally:
            env.app.state.db.execute("DROP TRIGGER reject_worker_liveness")

        assert (
            dict(
                env.app.state.db.fetchone(
                    """SELECT state,progress,heartbeat_at,lease_expires_at,updated_at
                       FROM worker_maintenance_jobs WHERE id=?""",
                    (job["id"],),
                )
            )
            == before_job
        )
    finally:
        env.client.__exit__(None, None, None)


@pytest.mark.parametrize("kind", ["capability_install", "model_install"])
def test_concurrent_install_intents_have_independent_job_lifecycles(
    tmp_path, kind: str
) -> None:
    env = _environment(tmp_path)
    try:
        artifact = b"independent-capability-package"
        spec = _capability_spec(artifact) if kind == "capability_install" else _model_spec()
        authorizations = [_authorization(env, spec), _authorization(env, spec)]
        barrier = threading.Barrier(2)

        def submit(index: int):
            barrier.wait(timeout=5)
            return _create_job(
                env,
                spec,
                authorization=authorizations[index],
                idempotency_key=f"concurrent-install-{kind}-{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(submit, range(2)))

        assert all(response.status_code == 200 for response in responses)
        jobs = [response.json() for response in responses]
        assert len({job["id"] for job in jobs}) == 2
        assert {job["creation_disposition"] for job in jobs} == {"created"}
        assert all(job["intent_owns_job"] is True for job in jobs)

        first_id, second_id = (job["id"] for job in jobs)
        rolled_back = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/workflows/deactivate",
            json={
                "workflow_ref": spec["workflow_ref"],
                "workflow_digest": spec["workflow_digest"],
                "authorization_source_id": first_id,
            },
            headers=env.owner_headers,
        )
        assert rolled_back.status_code == 200, rolled_back.text
        assert rolled_back.json()["cancelled_jobs"] == [first_id]
        states = {
            row["id"]: row["state"]
            for row in env.app.state.db.fetchall(
                "SELECT id,state FROM worker_maintenance_jobs WHERE id IN (?,?)",
                (first_id, second_id),
            )
        }
        assert states[first_id] == "cancelled"
        assert states[second_id] in {"awaiting_upload", "queued"}
    finally:
        env.client.__exit__(None, None, None)


def test_worker_update_upload_claim_and_complete_is_ticket_safe(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        artifact_bytes = b"reviewed-vgen-worker-wheel"
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        spec = {
            "kind": "worker_update",
            "target_version": "0.1.1",
            "artifact_sha256": artifact_sha256,
            "artifact_size": len(artifact_bytes),
            "apply": "on_idle",
        }
        authorization = _authorization(env, spec)
        first = _create_job(
            env,
            spec,
            authorization=authorization,
            idempotency_key="create-worker-update",
        )
        assert first.status_code == 200, first.text
        created = first.json()
        assert created["state"] == "awaiting_upload"
        assert created["creation_disposition"] == "created"
        assert created["intent_owns_job"] is True
        assert created["artifact_id"].startswith("art_")
        assert created["upload_ticket"]["expected_sha256"] == artifact_sha256

        replay = _create_job(
            env,
            spec,
            authorization=authorization,
            idempotency_key="create-worker-update",
        )
        assert replay.status_code == 200, replay.text
        assert replay.headers["Idempotency-Replayed"] == "true"
        assert replay.json()["id"] == created["id"]
        assert replay.json()["creation_disposition"] == "created"
        assert replay.json()["intent_owns_job"] is True
        assert (
            replay.json()["upload_ticket"]["headers"]["Vgen-Artifact-Ticket"]
            != created["upload_ticket"]["headers"]["Vgen-Artifact-Ticket"]
        )
        cached_create = env.app.state.db.fetchone(
            """SELECT response_body FROM idempotency_records
               WHERE path LIKE '%/maintenance-jobs' AND idempotency_key=?""",
            ("create-worker-update",),
        )
        assert cached_create is not None
        cached_body = bytes(cached_create["response_body"])
        assert b'"url"' not in cached_body
        assert b"Vgen-Artifact-Ticket" not in cached_body
        cached_recipe = json.loads(cached_body)["_vgen_replay"]
        assert cached_recipe["creation_disposition"] == "created"
        assert cached_recipe["intent_owns_job"] is True

        # Simulate a process stop after the nonce and job transaction committed
        # but before the HTTP replay recipe became durable.
        env.app.state.db.execute(
            """DELETE FROM idempotency_records
               WHERE path LIKE '%/maintenance-jobs' AND idempotency_key=?""",
            ("create-worker-update",),
        )
        crash_boundary_replay = _create_job(
            env,
            spec,
            authorization=authorization,
            idempotency_key="create-worker-update",
        )
        assert crash_boundary_replay.status_code == 200, crash_boundary_replay.text
        assert crash_boundary_replay.json()["id"] == created["id"]
        assert crash_boundary_replay.json()["creation_disposition"] == "created"
        assert crash_boundary_replay.json()["intent_owns_job"] is True
        assert (
            env.app.state.db.fetchone(
                "SELECT COUNT(*) AS n FROM worker_maintenance_jobs WHERE worker_id=?",
                (env.worker["id"],),
            )["n"]
            == 1
        )

        # A distinct, valid intent for the same immutable spec is accepted as
        # a dedupe alias. It needs its own durable receipt as well.
        alias_authorization = _authorization(env, spec)
        alias_key = "create-worker-update-alias"
        alias = _create_job(
            env,
            spec,
            authorization=alias_authorization,
            idempotency_key=alias_key,
        )
        assert alias.status_code == 200, alias.text
        assert alias.json()["id"] == created["id"]
        assert alias.json()["creation_disposition"] == "deduplicated"
        assert alias.json()["intent_owns_job"] is False
        alias_replay = _create_job(
            env,
            spec,
            authorization=alias_authorization,
            idempotency_key=alias_key,
        )
        assert alias_replay.status_code == 200, alias_replay.text
        assert alias_replay.headers["Idempotency-Replayed"] == "true"
        assert alias_replay.json()["creation_disposition"] == "deduplicated"
        assert alias_replay.json()["intent_owns_job"] is False
        env.app.state.db.execute(
            """DELETE FROM idempotency_records
               WHERE path LIKE '%/maintenance-jobs' AND idempotency_key=?""",
            (alias_key,),
        )
        alias_crash_boundary_replay = _create_job(
            env,
            spec,
            authorization=alias_authorization,
            idempotency_key=alias_key,
        )
        assert alias_crash_boundary_replay.status_code == 200, alias_crash_boundary_replay.text
        assert alias_crash_boundary_replay.json()["id"] == created["id"]
        assert alias_crash_boundary_replay.json()["creation_disposition"] == "deduplicated"
        assert alias_crash_boundary_replay.json()["intent_owns_job"] is False

        reused_nonce_spec = _model_spec(suffix="9")
        reused_nonce = _authorization(
            env,
            reused_nonce_spec,
            nonce=str(alias_authorization["payload"]["nonce"]),
        )
        rejected_nonce_reuse = _create_job(
            env,
            reused_nonce_spec,
            authorization=reused_nonce,
            idempotency_key="reused-maintenance-intent-nonce",
        )
        assert rejected_nonce_reuse.status_code == 409, rejected_nonce_reuse.text
        assert rejected_nonce_reuse.json()["error"]["code"] == int(ErrorCode.REPLAY_DETECTED)

        upload_ticket = crash_boundary_replay.json()["upload_ticket"]
        upload = env.client.put(
            upload_ticket["url"],
            content=artifact_bytes,
            headers=upload_ticket["headers"],
        )
        assert upload.status_code == 204, upload.text
        committed = env.client.post(
            f"/api/v1/maintenance-jobs/{created['id']}/commit",
            json={},
            headers=env.owner_headers,
        )
        assert committed.status_code == 200, committed.text
        assert committed.json()["state"] == "queued"

        claim_headers = {**env.worker_headers, "Idempotency-Key": "claim-worker-update"}
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=claim_headers,
        )
        assert claim.status_code == 200, claim.text
        leased = claim.json()
        assert leased["state"] == "leased"
        assert leased["authorization"] == authorization
        assert leased["artifact_download_ticket"]["expected_sha256"] == artifact_sha256
        downloaded = env.client.get(
            leased["artifact_download_ticket"]["url"],
            headers=leased["artifact_download_ticket"]["headers"],
        )
        assert downloaded.status_code == 200
        assert downloaded.content == artifact_bytes

        claim_replay = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=claim_headers,
        )
        assert claim_replay.status_code == 200, claim_replay.text
        assert claim_replay.headers["Idempotency-Replayed"] == "true"
        assert (
            claim_replay.json()["artifact_download_ticket"]["headers"]["Vgen-Artifact-Ticket"]
            != leased["artifact_download_ticket"]["headers"]["Vgen-Artifact-Ticket"]
        )
        cached_claim = env.app.state.db.fetchone(
            """SELECT response_body FROM idempotency_records
               WHERE path LIKE '%/maintenance-jobs/claim' AND idempotency_key=?""",
            ("claim-worker-update",),
        )
        assert cached_claim is not None
        assert b"Vgen-Artifact-Ticket" not in bytes(cached_claim["response_body"])

        heartbeat_path = (
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/heartbeat"
        )
        replacement_headers = _worker_session(env.client, env.worker["id"], env.worker_keys)
        invalid_adoption_state = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "running",
                "adopt_restart_session": True,
            },
            headers=replacement_headers,
        )
        assert invalid_adoption_state.status_code == 422

        adoption_before_restart = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
                "adopt_restart_session": True,
            },
            headers=replacement_headers,
        )
        assert adoption_before_restart.status_code == 409
        assert adoption_before_restart.json()["error"]["code"] == int(
            ErrorCode.MAINTENANCE_LEASE_LOST
        )

        heartbeat = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
                "progress": {
                    "stage": "staging",
                    "completed_bytes": len(artifact_bytes),
                    "total_bytes": len(artifact_bytes),
                },
            },
            headers=env.worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text

        ordinary_cross_session = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
            },
            headers=replacement_headers,
        )
        assert ordinary_cross_session.status_code == 409

        wrong_fence = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"] + 1,
                "ttl_seconds": 60,
                "state": "restarting",
                "adopt_restart_session": True,
            },
            headers=replacement_headers,
        )
        assert wrong_fence.status_code == 409

        env.app.state.db.execute(
            "UPDATE worker_maintenance_jobs SET lease_expires_at=0 WHERE id=?",
            (created["id"],),
        )
        expired_adoption = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
                "adopt_restart_session": True,
            },
            headers=replacement_headers,
        )
        assert expired_adoption.status_code == 409
        env.app.state.db.execute(
            "UPDATE worker_maintenance_jobs SET lease_expires_at=? WHERE id=?",
            (time.time() + 60, created["id"]),
        )

        adopted = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
                "adopt_restart_session": True,
                "progress": {
                    "stage": "activating",
                    "completed_bytes": len(artifact_bytes),
                    "total_bytes": len(artifact_bytes),
                },
            },
            headers=replacement_headers,
        )
        assert adopted.status_code == 200, adopted.text
        replacement_token = replacement_headers["Authorization"].removeprefix("Bearer ")
        replacement_session = env.app.state.db.fetchone(
            "SELECT id FROM sessions WHERE token_hash=?",
            (hashlib.sha256(replacement_token.encode()).hexdigest(),),
        )
        adopted_job = env.app.state.db.fetchone(
            "SELECT lease_session_id,progress FROM worker_maintenance_jobs WHERE id=?",
            (created["id"],),
        )
        assert replacement_session is not None
        assert adopted_job is not None
        assert adopted_job["lease_session_id"] == replacement_session["id"]
        assert json.loads(adopted_job["progress"])["stage"] == "activating"

        stale_session = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
            },
            headers=env.worker_headers,
        )
        assert stale_session.status_code == 409

        adopted_heartbeat = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "running",
                "progress": {
                    "stage": "activating",
                    "completed_bytes": len(artifact_bytes),
                    "total_bytes": len(artifact_bytes),
                },
            },
            headers=replacement_headers,
        )
        assert adopted_heartbeat.status_code == 200, adopted_heartbeat.text
        complete = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/complete",
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": True,
                "result": {
                    "kind": "worker_update",
                    "status": "activated",
                    "target_version": "0.1.1",
                    "artifact_sha256": artifact_sha256,
                },
            },
            headers=replacement_headers,
        )
        assert complete.status_code == 200, complete.text
        assert complete.json()["state"] == "succeeded"
        listed = env.client.get(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs",
            headers=env.owner_headers,
        )
        assert listed.status_code == 200
        assert "authorization" not in listed.json()[0]
    finally:
        env.client.__exit__(None, None, None)


def test_worker_update_rollback_can_complete_from_previous_runtime_session(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        artifact = b"worker-update-that-rolls-back"
        artifact_sha256 = hashlib.sha256(artifact).hexdigest()
        spec = {
            "kind": "worker_update",
            "target_version": "0.1.2",
            "artifact_sha256": artifact_sha256,
            "artifact_size": len(artifact),
            "apply": "on_idle",
        }
        created_response = _create_job(env, spec)
        assert created_response.status_code == 200, created_response.text
        created = created_response.json()
        upload = env.client.put(
            created["upload_ticket"]["url"],
            content=artifact,
            headers=created["upload_ticket"]["headers"],
        )
        assert upload.status_code == 204, upload.text
        committed = env.client.post(
            f"/api/v1/maintenance-jobs/{created['id']}/commit",
            json={},
            headers=env.owner_headers,
        )
        assert committed.status_code == 200, committed.text
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        leased = claim.json()
        heartbeat_path = (
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/heartbeat"
        )
        complete_path = (
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/complete"
        )
        target_headers = _worker_session(env.client, env.worker["id"], env.worker_keys)
        rollback_result = {
            "kind": "worker_update",
            "status": "rolled_back",
            "target_version": spec["target_version"],
            "artifact_sha256": artifact_sha256,
        }

        before_restart = env.client.post(
            complete_path,
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": False,
                "result": rollback_result,
            },
            headers=target_headers,
        )
        assert before_restart.status_code == 409

        restarting = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
                "progress": {"stage": "staging", "completed_bytes": len(artifact)},
            },
            headers=env.worker_headers,
        )
        assert restarting.status_code == 200, restarting.text
        adopted = env.client.post(
            heartbeat_path,
            json={
                "fencing_token": leased["fencing_token"],
                "ttl_seconds": 60,
                "state": "restarting",
                "adopt_restart_session": True,
                "progress": {"stage": "activating", "completed_bytes": len(artifact)},
            },
            headers=target_headers,
        )
        assert adopted.status_code == 200, adopted.text

        ordinary_failure = env.client.post(
            complete_path,
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": False,
                "result": {**rollback_result, "status": "failed"},
            },
            headers=env.worker_headers,
        )
        assert ordinary_failure.status_code == 409
        wrong_fence = env.client.post(
            complete_path,
            json={
                "fencing_token": leased["fencing_token"] + 1,
                "succeeded": False,
                "result": rollback_result,
            },
            headers=env.worker_headers,
        )
        assert wrong_fence.status_code == 409
        invalid_result = env.client.post(
            complete_path,
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": False,
                "result": {**rollback_result, "target_version": "0.1.3"},
            },
            headers=env.worker_headers,
        )
        assert invalid_result.status_code == 422

        env.app.state.db.execute(
            "UPDATE worker_maintenance_jobs SET lease_expires_at=0 WHERE id=?",
            (created["id"],),
        )
        expired = env.client.post(
            complete_path,
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": False,
                "result": rollback_result,
            },
            headers=env.worker_headers,
        )
        assert expired.status_code == 409
        env.app.state.db.execute(
            "UPDATE worker_maintenance_jobs SET lease_expires_at=? WHERE id=?",
            (time.time() + 60, created["id"]),
        )

        rolled_back = env.client.post(
            complete_path,
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": False,
                "result": rollback_result,
            },
            headers=env.worker_headers,
        )
        assert rolled_back.status_code == 200, rolled_back.text
        assert rolled_back.json()["state"] == "failed"
        assert rolled_back.json()["result"]["status"] == "rolled_back"
    finally:
        env.client.__exit__(None, None, None)


def test_capability_install_upload_download_and_bound_not_ready_result(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        artifact = b"signed-ltx-2.5-capability-pack"
        spec = _capability_spec(artifact)
        created_response = _create_job(env, spec)
        assert created_response.status_code == 200, created_response.text
        created = created_response.json()
        assert created["state"] == "awaiting_upload"
        assert created["artifact"]["kind"] == "capability_install"
        assert created["upload_ticket"]["expected_sha256"] == spec["artifact_sha256"]

        upload = env.client.put(
            created["upload_ticket"]["url"],
            content=artifact,
            headers=created["upload_ticket"]["headers"],
        )
        assert upload.status_code == 204, upload.text
        committed = env.client.post(
            f"/api/v1/maintenance-jobs/{created['id']}/commit",
            json={},
            headers=env.owner_headers,
        )
        assert committed.status_code == 200, committed.text
        assert committed.json()["state"] == "queued"

        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={
                "ttl_seconds": 60,
                "supported_actions": [
                    "worker_update",
                    "model_install",
                    "capability_install",
                ],
            },
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        leased = claim.json()
        download = env.client.get(
            leased["artifact_download_ticket"]["url"],
            headers=leased["artifact_download_ticket"]["headers"],
        )
        assert download.status_code == 200
        assert download.content == artifact

        identifiers = {
            "kind": "capability_install",
            "status": "repaired",
            "workflow_ref": spec["workflow_ref"],
            "workflow_digest": spec["workflow_digest"],
            "artifact_sha256": spec["artifact_sha256"],
            "ready": False,
        }
        mismatched = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/complete",
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": True,
                "result": {**identifiers, "workflow_digest": "sha256:" + "d" * 64},
            },
            headers=env.worker_headers,
        )
        assert mismatched.status_code == 422, mismatched.text

        completed = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/complete",
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": True,
                "result": identifiers,
            },
            headers=env.worker_headers,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "succeeded"
        assert completed.json()["result"] == identifiers
        assert (
            env.app.state.db.fetchone(
                "SELECT capability_auth_enforced_at FROM workers WHERE id=?",
                (env.worker["id"],),
            )["capability_auth_enforced_at"]
            is not None
        )
        artifact_row = env.app.state.db.fetchone(
            "SELECT state FROM maintenance_artifacts WHERE job_id=?", (created["id"],)
        )
        assert artifact_row["state"] == "available"
        workflow_authorization = env.app.state.db.fetchone(
            """SELECT workflow_ref,workflow_digest,node_classes
               FROM worker_workflow_authorizations WHERE authorization_source_id=?""",
            (created["id"],),
        )
        assert workflow_authorization["workflow_ref"] == spec["workflow_ref"]
        assert workflow_authorization["workflow_digest"] == spec["workflow_digest"]
        # A legacy v1 spec authorizes only the immutable workflow identity;
        # dependency names remain undisclosed until a v2 spec binds them.
        assert json.loads(workflow_authorization["node_classes"]) == []
        assert (
            env.app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM worker_model_authorizations
                   WHERE authorization_source_id=?""",
                (created["id"],),
            )["n"]
            == 0
        )
    finally:
        env.client.__exit__(None, None, None)


def test_v2_capability_authorization_filters_worker_report_and_rebuilds(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        h3 = COMFYUI_BOOTSTRAP_WORKFLOWS[0]
        artifact = b"signed-v2-capability-pack"
        spec = _capability_spec_v2(artifact)
        created = _create_job(env, spec).json()
        upload = env.client.put(
            created["upload_ticket"]["url"],
            content=artifact,
            headers=created["upload_ticket"]["headers"],
        )
        assert upload.status_code == 204, upload.text
        assert (
            env.client.post(
                f"/api/v1/maintenance-jobs/{created['id']}/commit",
                json={},
                headers=env.owner_headers,
            ).status_code
            == 200
        )
        leased = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={
                "ttl_seconds": 60,
                "supported_actions": ["capability_install"],
            },
            headers=env.worker_headers,
        ).json()
        result = {
            "kind": "capability_install",
            "status": "activated",
            "workflow_ref": spec["workflow_ref"],
            "workflow_digest": spec["workflow_digest"],
            "artifact_sha256": spec["artifact_sha256"],
            "ready": True,
        }
        completed = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{created['id']}/complete",
            json={
                "fencing_token": leased["fencing_token"],
                "succeeded": True,
                "result": result,
            },
            headers=env.worker_headers,
        )
        assert completed.status_code == 200, completed.text
        assert (
            env.app.state.db.fetchone(
                "SELECT capability_auth_enforced_at FROM workers WHERE id=?",
                (env.worker["id"],),
            )["capability_auth_enforced_at"]
            is not None
        )

        forged_digest = "sha256:" + "f" * 64
        heartbeat = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/heartbeat",
            json={
                "capabilities": {
                    "executors": [
                        {
                            "type": "comfyui",
                            "version": "1.0.0",
                            "payload_formats": ["comfyui-api-graph/v1"],
                            "operations": ["t2v"],
                            "capabilities": {
                                "capability_schema_version": 2,
                                "model_digests": [
                                    *h3.model_digests,
                                    *spec["model_digests"],
                                    forged_digest,
                                ],
                                "workflow_readiness": [
                                    {
                                        "workflow_ref": h3.workflow_ref,
                                        "workflow_digest": h3.workflow_digest,
                                        "state": "ready",
                                        "missing_model_digests": [],
                                        "missing_node_classes": [],
                                    },
                                    {
                                        "workflow_ref": spec["workflow_ref"],
                                        "workflow_digest": spec["workflow_digest"],
                                        "state": "missing_models",
                                        "missing_model_digests": [
                                            spec["model_digests"][0],
                                            forged_digest,
                                        ],
                                        "missing_node_classes": [
                                            spec["node_classes"][0],
                                            "ForgedPrivateNode",
                                        ],
                                    },
                                    {
                                        "workflow_ref": "vgen/forged-private@1.0.0",
                                        "workflow_digest": forged_digest,
                                        "state": "ready",
                                        "missing_model_digests": [],
                                        "missing_node_classes": [],
                                    },
                                ],
                            },
                        }
                    ]
                }
            },
            headers=env.worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text
        stored = env.app.state.repository.list_workers(user_id=env.worker["owner_user_id"])[0][
            "capabilities"
        ]["executors"][0]["capabilities"]
        assert stored["model_digests"] == [*h3.model_digests, *spec["model_digests"]]
        assert stored["workflow_readiness"] == [
            {
                "workflow_ref": h3.workflow_ref,
                "workflow_digest": h3.workflow_digest,
                "state": "ready",
                "missing_model_digests": [],
                "missing_node_classes": [],
            },
            {
                "workflow_ref": spec["workflow_ref"],
                "workflow_digest": spec["workflow_digest"],
                "state": "missing_models",
                "missing_model_digests": [spec["model_digests"][0]],
                "missing_node_classes": [spec["node_classes"][0]],
            },
        ]
        serialized = json.dumps(stored)
        assert forged_digest not in serialized
        assert "ForgedPrivateNode" not in serialized

        ready_heartbeat = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/heartbeat",
            json={
                "capabilities": {
                    "executors": [
                        {
                            "type": "comfyui",
                            "version": "1.0.0",
                            "payload_formats": ["comfyui-api-graph/v1"],
                            "operations": ["t2v"],
                            "capabilities": {
                                "capability_schema_version": 2,
                                "model_digests": [
                                    *h3.model_digests,
                                    *spec["model_digests"],
                                ],
                                "workflow_readiness": [
                                    {
                                        "workflow_ref": h3.workflow_ref,
                                        "workflow_digest": h3.workflow_digest,
                                        "state": "ready",
                                        "missing_model_digests": [],
                                        "missing_node_classes": [],
                                    },
                                    {
                                        "workflow_ref": spec["workflow_ref"],
                                        "workflow_digest": spec["workflow_digest"],
                                        "state": "ready",
                                        "missing_model_digests": [],
                                        "missing_node_classes": [],
                                    },
                                ],
                            },
                        }
                    ]
                }
            },
            headers=env.worker_headers,
        )
        assert ready_heartbeat.status_code == 200, ready_heartbeat.text
        worker_row = env.app.state.db.fetchone(
            "SELECT * FROM workers WHERE id=?", (env.worker["id"],)
        )
        assert env.app.state.repository._matches_requirements(
            worker_row,
            {},
            workflow_ref=h3.workflow_ref,
            workflow_digest=h3.workflow_digest,
        )
        assert env.app.state.repository._matches_requirements(
            worker_row,
            {},
            workflow_ref=spec["workflow_ref"],
            workflow_digest=spec["workflow_digest"],
        )

        # Simulate the one-time upgrade of an existing database. Only the
        # historically verifiable successful maintenance intent is rebuilt.
        env.app.state.db.execute("DELETE FROM worker_model_authorizations")
        env.app.state.db.execute("DELETE FROM worker_workflow_authorizations")
        env.app.state.db.execute(
            "DELETE FROM schema_migrations WHERE name=?",
            ("gateway-public-metadata-and-capability-auth-v2",),
        )
        GatewayRepository(env.app.state.db)
        assert (
            env.app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM worker_workflow_authorizations
               WHERE authorization_source_id=?""",
                (created["id"],),
            )["n"]
            == 1
        )
        assert (
            env.app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM worker_model_authorizations
                   WHERE authorization_source_id=?""",
                (created["id"],),
            )["n"]
            == 2
        )
        assert (
            env.app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM worker_workflow_authorizations
               WHERE authorization_source_id=? AND workflow_ref=?""",
                (f"bundled-bootstrap:{h3.workflow_ref}", h3.workflow_ref),
            )["n"]
            == 1
        )
    finally:
        env.client.__exit__(None, None, None)


def test_capability_install_wrong_digest_records_bound_failure(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        expected = b"expected capability"
        spec = _capability_spec(expected, suffix="e")
        created = _create_job(env, spec)
        assert created.status_code == 200, created.text
        ticket = created.json()["upload_ticket"]
        rejected = env.client.put(
            ticket["url"], content=b"x" * len(expected), headers=ticket["headers"]
        )
        assert rejected.status_code == 422, rejected.text
        shown = env.client.get(
            f"/api/v1/maintenance-jobs/{created.json()['id']}",
            headers=env.owner_headers,
        )
        assert shown.status_code == 200, shown.text
        assert shown.json()["result"] == {
            "kind": "capability_install",
            "status": "failed",
            "workflow_ref": spec["workflow_ref"],
            "workflow_digest": spec["workflow_digest"],
            "artifact_sha256": spec["artifact_sha256"],
            "error_code": int(ErrorCode.ARTIFACT_INTEGRITY_FAILED),
        }
    finally:
        env.client.__exit__(None, None, None)


def test_legacy_worker_skips_capability_job_without_starving_supported_jobs(
    tmp_path,
) -> None:
    env = _environment(tmp_path)
    try:
        artifact = b"capability for an upgraded worker"
        capability = _create_job(env, _capability_spec(artifact))
        assert capability.status_code == 200, capability.text
        upload_ticket = capability.json()["upload_ticket"]
        uploaded = env.client.put(
            upload_ticket["url"],
            content=artifact,
            headers=upload_ticket["headers"],
        )
        assert uploaded.status_code == 204, uploaded.text
        committed = env.client.post(
            f"/api/v1/maintenance-jobs/{capability.json()['id']}/commit",
            json={},
            headers=env.owner_headers,
        )
        assert committed.status_code == 200, committed.text

        model = _create_job(env, _model_spec(suffix="d"))
        assert model.status_code == 200, model.text
        assert model.json()["state"] == "queued"

        # Missing supported_actions is the old Worker wire contract. It must
        # never lease unknown capability code and must still reach the later
        # model job instead of being blocked by queue order.
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        assert claim.json()["id"] == model.json()["id"]
        assert claim.json()["kind"] == "model_install"

        capability_row = env.app.state.db.fetchone(
            "SELECT state FROM worker_maintenance_jobs WHERE id=?",
            (capability.json()["id"],),
        )
        assert capability_row["state"] == "queued"
    finally:
        env.client.__exit__(None, None, None)


def test_manager_and_exact_broker_device_are_required(tmp_path) -> None:
    env = _environment(tmp_path, manager=False)
    try:
        spec = _model_spec()
        no_manager = _create_job(env, spec)
        assert no_manager.status_code == 403, no_manager.text

        manager = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/manager",
            json={"broker_id": env.broker["id"]},
            headers=env.owner_headers,
        )
        assert manager.status_code == 200, manager.text
        assert manager.json()["manager_broker_id"] == env.broker["id"]

        unbound_keys = DeviceKeys.generate()
        unbound_device_id = new_id("device")
        unbound_certificate = issue_device_certificate(
            env.owner_identity, unbound_keys, device_id=unbound_device_id
        ).to_dict()
        stamp = time.time()
        env.app.state.db.execute(
            """INSERT INTO devices
               (id,user_id,name,signing_public_key,encryption_public_key,certificate,
                status,created_at,last_seen_at)
               VALUES (?,?,?,?,?,?,'active',?,?)""",
            (
                unbound_device_id,
                env.worker["owner_user_id"],
                "unbound-device",
                b64url_encode(unbound_keys.signing_public_bytes()),
                b64url_encode(unbound_keys.encryption_public_bytes()),
                json.dumps(unbound_certificate, separators=(",", ":")),
                stamp,
                stamp,
            ),
        )
        unbound_token, _ = env.app.state.db.create_session(
            principal_type="device",
            principal_id=unbound_device_id,
            user_id=env.worker["owner_user_id"],
            scopes=["*"],
        )
        unbound_authorization = _authorization(
            env,
            spec,
            device_keys=unbound_keys,
            device_id=unbound_device_id,
            certificate=unbound_certificate,
        )
        rejected = env.client.post(
            f"/api/v1/brokers/{env.broker['id']}/workers/{env.worker['id']}/maintenance-jobs",
            json={"spec": spec, "authorization": unbound_authorization},
            headers={"Authorization": f"Bearer {unbound_token}"},
        )
        assert rejected.status_code == 403, rejected.text
        assert rejected.json()["error"]["code"] == int(ErrorCode.PERMISSION_DENIED)

        accepted = _create_job(env, spec)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["state"] == "queued"
        blocked_manager_change = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/manager",
            json={"broker_id": None},
            headers=env.owner_headers,
        )
        assert blocked_manager_change.status_code == 409
        assert blocked_manager_change.json()["error"]["code"] == int(
            ErrorCode.WORKER_MAINTENANCE_STATE_CONFLICT
        )
    finally:
        env.client.__exit__(None, None, None)


def test_model_job_fencing_strict_result_and_inference_exclusion(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        workspace = env.client.post(
            "/api/v1/workspaces", json={"name": "Maintenance Test"}, headers=env.owner_headers
        ).json()
        pool = env.client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=env.owner_headers,
        ).json()
        stamp = time.time()
        task_id = new_id("task")
        attempt_id = new_id("attempt")
        env.app.state.db.execute(
            """INSERT INTO tasks
               (id,workspace_id,pool_id,consumer_user_id,consumer_principal_type,
                consumer_principal_id,client_channel,workflow_ref,workflow_digest,
                executor_type,public_requirements,content_key_version,encrypted_payload,
                reader_envelope,assigned_worker_id,reservation_expires_at,state,priority,
                created_at,committed_at,updated_at)
               VALUES (?,?,?,?,? ,?,?,?,?,? ,'{}',1,?,?,?,?,'committed',0,?,?,?)""",
            (
                task_id,
                workspace["id"],
                pool["id"],
                env.worker["owner_user_id"],
                "device",
                env.owner_device_id,
                "cli",
                "vgen/minimax-h3-8step@0.1.0",
                "sha256:" + "e" * 64,
                "comfyui",
                "ciphertext",
                "reader-envelope",
                env.worker["id"],
                stamp + 300,
                stamp,
                stamp,
                stamp,
            ),
        )
        env.app.state.db.execute(
            """INSERT INTO task_attempts
               (id,task_id,attempt_number,worker_id,provider_user_id,manager_broker_id,
                executor_type,executor_version,state,progress,rate_snapshot,fencing_token,
                reserved_at)
               VALUES (?,?,?,?,?,?,?,?,'reserved','{}','{}',1,?)""",
            (
                attempt_id,
                task_id,
                1,
                env.worker["id"],
                env.worker["owner_user_id"],
                env.broker["id"],
                "comfyui",
                "0.33.0",
                stamp,
            ),
        )

        spec = _model_spec(suffix="b")
        created = _create_job(env, spec)
        assert created.status_code == 200, created.text
        job = created.json()
        assert env.app.state.repository.lease(worker_id=env.worker["id"], ttl_seconds=60) is None

        first_claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert first_claim.status_code == 200, first_claim.text
        first = first_claim.json()
        assert first["fencing_token"] == 1

        env.app.state.db.execute(
            "UPDATE worker_maintenance_jobs SET lease_expires_at=0 WHERE id=?", (job["id"],)
        )
        second_token, second_session = env.app.state.db.create_session(
            principal_type="worker",
            principal_id=env.worker["id"],
            user_id=env.worker["owner_user_id"],
            scopes=["worker:maintenance:lease", "worker:maintenance:report"],
        )
        second_headers = {"Authorization": f"Bearer {second_token}"}
        second_claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=second_headers,
        )
        assert second_claim.status_code == 200, second_claim.text
        second = second_claim.json()
        assert second["fencing_token"] == 2
        assert (
            second_session["id"]
            == env.app.state.db.fetchone(
                "SELECT lease_session_id FROM worker_maintenance_jobs WHERE id=?", (job["id"],)
            )["lease_session_id"]
        )

        restarting_model_job = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/heartbeat",
            json={
                "fencing_token": 2,
                "ttl_seconds": 60,
                "state": "restarting",
                "progress": {"stage": "installing", "completed_bytes": 0},
            },
            headers=second_headers,
        )
        assert restarting_model_job.status_code == 200, restarting_model_job.text
        third_token, _ = env.app.state.db.create_session(
            principal_type="worker",
            principal_id=env.worker["id"],
            user_id=env.worker["owner_user_id"],
            scopes=["worker:maintenance:report"],
        )
        rejected_model_adoption = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/heartbeat",
            json={
                "fencing_token": 2,
                "ttl_seconds": 60,
                "state": "restarting",
                "adopt_restart_session": True,
            },
            headers={"Authorization": f"Bearer {third_token}"},
        )
        assert rejected_model_adoption.status_code == 409
        assert rejected_model_adoption.json()["error"]["code"] == int(
            ErrorCode.MAINTENANCE_LEASE_LOST
        )
        rejected_model_completion = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": 2,
                "succeeded": False,
                "result": {
                    "kind": "model_install",
                    "status": "failed",
                    "installed_model_digests": [],
                    "failed_model_digest": spec["model_digests"][0],
                },
            },
            headers={"Authorization": f"Bearer {third_token}"},
        )
        assert rejected_model_completion.status_code == 409
        assert rejected_model_completion.json()["error"]["code"] == int(
            ErrorCode.MAINTENANCE_LEASE_LOST
        )

        stale = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/heartbeat",
            json={
                "fencing_token": 1,
                "ttl_seconds": 60,
                "state": "running",
                "progress": {"stage": "downloading", "completed_bytes": 0},
            },
            headers=env.worker_headers,
        )
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == int(ErrorCode.MAINTENANCE_LEASE_LOST)

        leaked_result = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": 2,
                "succeeded": True,
                "result": {
                    "kind": "model_install",
                    "status": "installed",
                    "installed_model_digests": spec["model_digests"],
                    "path": "C:\\models\\private-location",
                },
            },
            headers=second_headers,
        )
        assert leaked_result.status_code == 422
        assert leaked_result.json()["error"]["code"] == int(ErrorCode.VALIDATION_FAILED)

        incomplete_result = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": 2,
                "succeeded": True,
                "result": {
                    "kind": "model_install",
                    "status": "installed",
                    "installed_model_digests": [],
                },
            },
            headers=second_headers,
        )
        assert incomplete_result.status_code == 422

        completed = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": 2,
                "succeeded": True,
                "result": {
                    "kind": "model_install",
                    "status": "installed",
                    "installed_model_digests": spec["model_digests"],
                },
            },
            headers=second_headers,
        )
        assert completed.status_code == 200, completed.text
        assert completed.json()["state"] == "succeeded"
    finally:
        env.client.__exit__(None, None, None)


def test_worker_update_wrong_digest_fails_closed(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        expected = b"expected artifact"
        spec = {
            "kind": "worker_update",
            "target_version": "0.1.2",
            "artifact_sha256": hashlib.sha256(expected).hexdigest(),
            "artifact_size": len(expected),
            "apply": "on_idle",
        }
        created = _create_job(env, spec)
        assert created.status_code == 200, created.text
        ticket = created.json()["upload_ticket"]
        bad_upload = env.client.put(
            ticket["url"], content=b"x" * len(expected), headers=ticket["headers"]
        )
        assert bad_upload.status_code == 422, bad_upload.text
        assert bad_upload.json()["error"]["code"] == int(ErrorCode.ARTIFACT_INTEGRITY_FAILED)
        shown = env.client.get(
            f"/api/v1/maintenance-jobs/{created.json()['id']}",
            headers=env.owner_headers,
        )
        assert shown.status_code == 200
        assert shown.json()["state"] == "failed"
        assert shown.json()["result"] == {
            "kind": "worker_update",
            "status": "failed",
            "target_version": "0.1.2",
            "artifact_sha256": spec["artifact_sha256"],
            "error_code": int(ErrorCode.ARTIFACT_INTEGRITY_FAILED),
        }
    finally:
        env.client.__exit__(None, None, None)


def test_maintenance_completion_is_idempotent_after_worker_session_refresh(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        spec = _model_spec(suffix="c")
        created = _create_job(env, spec)
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text
        fencing_token = claim.json()["fencing_token"]
        result = {
            "kind": "model_install",
            "status": "installed",
            "installed_model_digests": spec["model_digests"],
        }
        first = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": fencing_token,
                "succeeded": True,
                "result": result,
            },
            headers=env.worker_headers,
        )
        assert first.status_code == 200, first.text
        assert first.json()["state"] == "succeeded"

        refreshed_token, refreshed_session = env.app.state.db.create_session(
            principal_type="worker",
            principal_id=env.worker["id"],
            user_id=env.worker["owner_user_id"],
            scopes=["worker:maintenance:report"],
        )
        assert (
            refreshed_session["id"]
            != env.app.state.db.fetchone(
                "SELECT lease_session_id FROM worker_maintenance_jobs WHERE id=?", (job["id"],)
            )["lease_session_id"]
        )
        refreshed_headers = {"Authorization": f"Bearer {refreshed_token}"}

        replay = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": fencing_token,
                "succeeded": True,
                "result": result,
            },
            headers=refreshed_headers,
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["state"] == "succeeded"

        conflict = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": fencing_token,
                "succeeded": False,
                "result": {
                    "kind": "model_install",
                    "status": "failed",
                    "installed_model_digests": [],
                    "failed_model_digest": spec["model_digests"][0],
                    "error_code": int(ErrorCode.DOWNLOAD_INTERRUPTED),
                },
            },
            headers=refreshed_headers,
        )
        assert conflict.status_code == 409, conflict.text
        assert conflict.json()["error"]["code"] == int(ErrorCode.WORKER_MAINTENANCE_STATE_CONFLICT)
    finally:
        env.client.__exit__(None, None, None)


def test_revoking_issuing_device_cancels_and_fences_leased_maintenance(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        created = _create_job(env, _model_spec(suffix="d"))
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text

        revoked = env.client.post(
            f"/api/v1/devices/{env.owner_device_id}/revoke",
            headers=env.owner_headers,
        )
        assert revoked.status_code == 200, revoked.text
        row = env.app.state.db.fetchone(
            "SELECT state,lease_session_id,lease_expires_at FROM worker_maintenance_jobs "
            "WHERE id=?",
            (job["id"],),
        )
        assert row is not None
        assert dict(row) == {
            "state": "cancelled",
            "lease_session_id": None,
            "lease_expires_at": None,
        }

        late = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/complete",
            json={
                "fencing_token": claim.json()["fencing_token"],
                "succeeded": True,
                "result": {
                    "kind": "model_install",
                    "status": "installed",
                    "installed_model_digests": job["spec"]["model_digests"],
                },
            },
            headers=env.worker_headers,
        )
        assert late.status_code == 409, late.text
        assert late.json()["error"]["code"] == int(ErrorCode.MAINTENANCE_LEASE_LOST)
    finally:
        env.client.__exit__(None, None, None)


def test_worker_leave_cancels_and_fences_leased_maintenance(tmp_path) -> None:
    env = _environment(tmp_path)
    try:
        created = _create_job(env, _model_spec(suffix="e"))
        assert created.status_code == 200, created.text
        job = created.json()
        claim = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/claim",
            json={"ttl_seconds": 60},
            headers=env.worker_headers,
        )
        assert claim.status_code == 200, claim.text

        left = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/leave",
            json={"force": False},
            headers=env.owner_headers,
        )
        assert left.status_code == 200, left.text
        assert left.json()["status"] == "revoked"
        row = env.app.state.db.fetchone(
            "SELECT state,lease_session_id,lease_expires_at FROM worker_maintenance_jobs "
            "WHERE id=?",
            (job["id"],),
        )
        assert row is not None
        assert dict(row) == {
            "state": "cancelled",
            "lease_session_id": None,
            "lease_expires_at": None,
        }

        late = env.client.post(
            f"/api/v1/workers/{env.worker['id']}/maintenance-jobs/{job['id']}/heartbeat",
            json={
                "fencing_token": claim.json()["fencing_token"],
                "ttl_seconds": 60,
                "state": "running",
            },
            headers=env.worker_headers,
        )
        assert late.status_code in {401, 403}, late.text
    finally:
        env.client.__exit__(None, None, None)
