from __future__ import annotations

import json

from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity, worker_owner_certificate
from vgen.crypto import DeviceKeys, b64url_encode
from vgen.gateway.app import create_app
from vgen.gateway.database import json_text, new_id, now

MODEL_DIGEST = "sha256:" + "a" * 64
REQUIREMENTS = {
    "operation": "i2v",
    "payload_format": "comfyui-api-graph/v1",
    "executor_min_version": "1.0.0",
    "runtime_min_version": "0.33.0",
    "min_vram_bytes": 16_000_000_000,
    "min_ram_bytes": 16_000_000_000,
    "model_digests": [MODEL_DIGEST],
}


def _payload(workspace_id: str, pool_id: str) -> dict[str, object]:
    return {
        "workspace_id": workspace_id,
        "pool_id": pool_id,
        "workflow_ref": "vgen/minimax-h3-8step@1.0.0",
        "workflow_digest": "sha256:" + "b" * 64,
        "executor_type": "comfyui",
        "public_requirements": REQUIREMENTS,
    }


def _assert_aggregate(result: dict[str, object], *, state: str, ready: bool) -> None:
    assert set(result) == {
        "ready",
        "state",
        "reason",
        "workspace_id",
        "pool_id",
        "executor_type",
    }
    assert result["state"] == state
    assert result["ready"] is ready
    serialized = json.dumps(result)
    assert "worker_id" not in serialized
    assert "capabilities" not in serialized
    assert MODEL_DIGEST not in serialized


def test_preflight_reports_safe_states_and_never_reserves_or_bills(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, owner_identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Preflight"}, headers=headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=headers,
        ).json()
        payload = _payload(workspace["id"], pool["id"])

        none = client.post("/api/v1/tasks/preflight", json=payload, headers=headers)
        assert none.status_code == 200, none.text
        assert none.headers["Cache-Control"] == "no-store"
        _assert_aggregate(none.json(), state="no_allocated_worker", ready=False)

        worker_keys = DeviceKeys.generate()
        worker = app.state.repository.create_worker(
            owner_user_id=boot["user"]["id"],
            manager_broker_id=None,
            name="gpu-01",
            signing_public_key=b64url_encode(worker_keys.signing_public_bytes()),
            encryption_public_key=b64url_encode(worker_keys.encryption_public_bytes()),
            certificate=worker_owner_certificate(owner_identity, worker_keys),
            executor_type="comfyui",
            executor_version="1.0.0",
            capabilities={},
            capacity=1,
        )
        stamp = now()
        app.state.db.execute(
            """INSERT INTO worker_allocations
               (id,worker_id,workspace_id,pool_id,owner_consent_at,
                workspace_approved_at,approved_by_user_id,allocation_proof,status,
                created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,'{}','active',?,?)""",
            (
                new_id("alc"),
                worker["id"],
                workspace["id"],
                pool["id"],
                stamp,
                stamp,
                boot["user"]["id"],
                stamp,
                stamp,
            ),
        )

        offline = client.post("/api/v1/tasks/preflight", json=payload, headers=headers)
        assert offline.status_code == 200, offline.text
        _assert_aggregate(offline.json(), state="worker_offline_or_busy", ready=False)

        mismatched_capabilities = {
            "executors": [
                {
                    "type": "comfyui",
                    "version": "1.0.0",
                    "payload_formats": ["comfyui-api-graph/v1"],
                    "operations": ["i2v"],
                    "max_concurrency": 1,
                    "capabilities": {
                        "runtime_version": "0.33.0",
                        "model_digests": [],
                        "vram_bytes": 24_000_000_000,
                        "ram_bytes": 32_000_000_000,
                    },
                }
            ]
        }
        app.state.db.execute(
            """UPDATE workers SET status='active',last_seen_at=?,capabilities=?,updated_at=?
               WHERE id=?""",
            (stamp, json_text(mismatched_capabilities), stamp, worker["id"]),
        )
        mismatch = client.post("/api/v1/tasks/preflight", json=payload, headers=headers)
        assert mismatch.status_code == 200, mismatch.text
        _assert_aggregate(mismatch.json(), state="capability_mismatch", ready=False)

        matching_capabilities = json.loads(json.dumps(mismatched_capabilities))
        matching_capabilities["executors"][0]["capabilities"]["model_digests"] = [MODEL_DIGEST]
        app.state.db.execute(
            "UPDATE workers SET capabilities=?,last_seen_at=? WHERE id=?",
            (json_text(matching_capabilities), now(), worker["id"]),
        )
        unrated = client.post("/api/v1/tasks/preflight", json=payload, headers=headers)
        assert unrated.status_code == 200, unrated.text
        _assert_aggregate(unrated.json(), state="rate_not_approved", ready=False)

        rate = app.state.repository.propose_rate(
            worker_id=worker["id"],
            workspace_id=workspace["id"],
            user_id=boot["user"]["id"],
            rate_microtokens_per_second=1_000_000,
        )
        app.state.repository.approve_rate(
            rate_id=rate["id"], admin_user_id=boot["user"]["id"]
        )

        before = {
            table: app.state.db.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"]
            for table in ("tasks", "task_attempts", "leases", "usage_events", "usage_ledger")
        }
        fencing_before = app.state.db.fetchone(
            "SELECT fencing_counter FROM workers WHERE id=?", (worker["id"],)
        )["fencing_counter"]
        ready = client.post(
            "/api/v1/tasks/preflight",
            json=payload,
            headers={**headers, "Idempotency-Key": "must-not-cache-live-readiness"},
        )
        assert ready.status_code == 200, ready.text
        _assert_aggregate(ready.json(), state="ready", ready=True)
        assert (
            app.state.db.fetchone(
                "SELECT COUNT(*) AS n FROM idempotency_records WHERE path=?",
                ("/api/v1/tasks/preflight",),
            )["n"]
            == 0
        )
        after = {
            table: app.state.db.fetchone(f"SELECT COUNT(*) AS n FROM {table}")["n"]
            for table in before
        }
        assert after == before
        assert (
            app.state.db.fetchone(
                "SELECT fencing_counter FROM workers WHERE id=?", (worker["id"],)
            )["fencing_counter"]
            == fencing_before
        )


def test_v2_workflow_readiness_is_exact_unique_and_fail_closed(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, owner_identity, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Exact readiness"}, headers=headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=headers,
        ).json()
        payload = _payload(workspace["id"], pool["id"])
        worker_keys = DeviceKeys.generate()
        worker = app.state.repository.create_worker(
            owner_user_id=boot["user"]["id"],
            manager_broker_id=None,
            name="gpu-v2",
            signing_public_key=b64url_encode(worker_keys.signing_public_bytes()),
            encryption_public_key=b64url_encode(worker_keys.encryption_public_bytes()),
            certificate=worker_owner_certificate(owner_identity, worker_keys),
            executor_type="comfyui",
            executor_version="1.0.0",
            capabilities={},
            capacity=1,
        )
        stamp = now()
        app.state.db.execute(
            """INSERT INTO worker_allocations
               (id,worker_id,workspace_id,pool_id,owner_consent_at,
                workspace_approved_at,approved_by_user_id,allocation_proof,status,
                created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,'{}','active',?,?)""",
            (
                new_id("alc"),
                worker["id"],
                workspace["id"],
                pool["id"],
                stamp,
                stamp,
                boot["user"]["id"],
                stamp,
                stamp,
            ),
        )
        rate = app.state.repository.propose_rate(
            worker_id=worker["id"],
            workspace_id=workspace["id"],
            user_id=boot["user"]["id"],
            rate_microtokens_per_second=1,
        )
        app.state.repository.approve_rate(
            rate_id=rate["id"], admin_user_id=boot["user"]["id"]
        )

        exact = {
            "workflow_ref": payload["workflow_ref"],
            "workflow_digest": payload["workflow_digest"],
            "state": "ready",
            "missing_model_digests": [],
            "missing_node_classes": [],
        }
        base_nested = {
            "runtime_version": "0.33.0",
            "model_digests": [MODEL_DIGEST],
            "vram_bytes": 24_000_000_000,
            "ram_bytes": 32_000_000_000,
        }

        def set_capabilities(nested: dict[str, object]) -> None:
            capabilities = {
                "executors": [
                    {
                        "type": "comfyui",
                        "version": "1.0.0",
                        "payload_formats": ["comfyui-api-graph/v1"],
                        "operations": ["i2v"],
                        "max_concurrency": 1,
                        "capabilities": nested,
                    }
                ]
            }
            app.state.db.execute(
                """UPDATE workers SET status='active',last_seen_at=?,capabilities=?,updated_at=?
                   WHERE id=?""",
                (now(), json_text(capabilities), now(), worker["id"]),
            )

        def preflight_state(nested: dict[str, object]) -> str:
            set_capabilities(nested)
            response = client.post("/api/v1/tasks/preflight", json=payload, headers=headers)
            assert response.status_code == 200, response.text
            return response.json()["state"]

        v2 = {
            **base_nested,
            "capability_schema_version": 2,
            "workflow_readiness": [exact],
        }
        assert preflight_state(v2) == "ready"
        assert preflight_state(
            {
                **v2,
                "workflow_readiness": [{**exact, "workflow_ref": "vgen/other@1.0.0"}],
            }
        ) == "capability_mismatch"
        assert preflight_state(
            {
                **v2,
                "workflow_readiness": [
                    {**exact, "workflow_digest": "sha256:" + "c" * 64}
                ],
            }
        ) == "capability_mismatch"
        assert preflight_state(
            {**v2, "workflow_readiness": [{**exact, "state": "missing_models"}]}
        ) == "capability_mismatch"
        for state in ("insufficient_vram", "insufficient_ram"):
            assert preflight_state(
                {**v2, "workflow_readiness": [{**exact, "state": state}]}
            ) == "capability_mismatch"
        assert preflight_state(
            {**v2, "workflow_readiness": [exact, dict(exact)]}
        ) == "capability_mismatch"
        assert preflight_state(
            {**v2, "workflow_readiness": [exact, "malformed"]}
        ) == "capability_mismatch"
        assert preflight_state(
            {
                **v2,
                "workflow_readiness": [
                    {
                        key: value
                        for key, value in exact.items()
                        if key != "missing_node_classes"
                    }
                ],
            }
        ) == "capability_mismatch"
        assert preflight_state(
            {
                **v2,
                "workflow_readiness": [
                    {**exact, "missing_model_digests": [MODEL_DIGEST]}
                ],
            }
        ) == "capability_mismatch"
        assert preflight_state({**v2, "capability_schema_version": 3}) == (
            "capability_mismatch"
        )

        # A pre-v2 Worker has no per-workflow readiness list. Preserve the
        # model/resource matcher until that Worker upgrades its heartbeat.
        assert preflight_state(dict(base_nested)) == "ready"

        set_capabilities(
            {
                **v2,
                "workflow_readiness": [{**exact, "workflow_ref": "vgen/other@1.0.0"}],
            }
        )
        rejected = client.post(
            "/api/v1/tasks/prepare",
            json=payload,
            headers={**headers, "Idempotency-Key": "wrong-workflow-readiness"},
        )
        assert rejected.status_code == 503, rejected.text

        set_capabilities(v2)
        prepared = client.post(
            "/api/v1/tasks/prepare",
            json=payload,
            headers={**headers, "Idempotency-Key": "exact-workflow-readiness"},
        )
        assert prepared.status_code == 200, prepared.text
        assert prepared.json()["worker"]["id"] == worker["id"]


def test_preflight_service_requires_submit_scope_and_workspace_binding(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, headers, _, _ = bootstrap_identity(client)
        workspace = client.post(
            "/api/v1/workspaces", json={"name": "Service preflight"}, headers=headers
        ).json()
        pool = client.post(
            f"/api/v1/workspaces/{workspace['id']}/pools",
            json={"name": "GPU"},
            headers=headers,
        ).json()
        service_id = new_id("svc")
        stamp = now()
        app.state.db.execute(
            """INSERT INTO services
               (id,workspace_id,name,signing_public_key,encryption_public_key,scopes,status,
                created_by_user_id,created_at,updated_at)
               VALUES (?,?,?,?,?,'["task:submit"]','active',?,?,?)""",
            (
                service_id,
                workspace["id"],
                "automation",
                "service-signing-preflight",
                "service-encryption-preflight",
                boot["user"]["id"],
                stamp,
                stamp,
            ),
        )
        denied_token, _ = app.state.db.create_session(
            principal_type="service",
            principal_id=service_id,
            user_id=None,
            scopes=["task:read"],
        )
        denied = client.post(
            "/api/v1/tasks/preflight",
            json=_payload(workspace["id"], pool["id"]),
            headers={"Authorization": f"Bearer {denied_token}"},
        )
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == 120002

        allowed_token, _ = app.state.db.create_session(
            principal_type="service",
            principal_id=service_id,
            user_id=None,
            scopes=["task:submit"],
        )
        allowed = client.post(
            "/api/v1/tasks/preflight",
            json=_payload(workspace["id"], pool["id"]),
            headers={"Authorization": f"Bearer {allowed_token}"},
        )
        assert allowed.status_code == 200, allowed.text
        _assert_aggregate(allowed.json(), state="no_allocated_worker", ready=False)
