from __future__ import annotations

import json
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity, worker_owner_certificate
from vgen.crypto import DeviceKeys, IdentityKeys, b64url_encode, sign_message
from vgen.gateway.app import create_app
from vgen.gateway.repository import RepositoryError


def _register_worker(
    client: TestClient,
    *,
    owner_headers: dict[str, str],
    owner_identity: IdentityKeys,
    capabilities: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    worker_keys = DeviceKeys.generate()
    response = client.post(
        "/api/v1/workers",
        json={
            "name": "Versioned GPU Worker",
            "signing_public_key": b64url_encode(worker_keys.signing_public_bytes()),
            "encryption_public_key": b64url_encode(worker_keys.encryption_public_bytes()),
            "certificate": worker_owner_certificate(owner_identity, worker_keys),
            "executor_type": "comfyui",
            "executor_version": "1.1.0",
            "capabilities": capabilities or {},
        },
        headers=owner_headers,
    )
    assert response.status_code == 200, response.text
    worker = response.json()
    challenge = client.post(
        "/api/v1/auth/challenges",
        json={"principal_type": "worker", "worker_id": worker["id"]},
    )
    assert challenge.status_code == 200, challenge.text
    challenge_value = challenge.json()
    session = client.post(
        "/api/v1/auth/sessions",
        json={
            "principal_type": "worker",
            "worker_id": worker["id"],
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
    return worker, {"Authorization": f"Bearer {session.json()['session_token']}"}


def test_direct_comfyui_registration_persists_only_the_authorized_projection(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    forged_digest = "sha256:" + "f" * 64
    forged_capabilities = {
        "executors": [
            {
                "type": "comfyui",
                "capabilities": {
                    "capability_schema_version": 2,
                    "model_digests": [forged_digest],
                    "workflow_readiness": [
                        {
                            "workflow_ref": "vgen/forged-private@1.0.0",
                            "workflow_digest": forged_digest,
                            "state": "ready",
                            "missing_model_digests": [],
                            "missing_node_classes": [],
                        }
                    ],
                },
            }
        ]
    }
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        _, owner_headers, owner_identity, _ = bootstrap_identity(client)
        worker, _ = _register_worker(
            client,
            owner_headers=owner_headers,
            owner_identity=owner_identity,
            capabilities=forged_capabilities,
        )

        assert worker["gateway_protocol_features"] == {"capability_install_spec_version": 2}
        assert forged_digest not in json.dumps(worker["capabilities"])
        row = app.state.db.fetchone(
            "SELECT capabilities,capability_auth_enforced_at FROM workers WHERE id=?",
            (worker["id"],),
        )
        assert row["capability_auth_enforced_at"] is not None
        assert forged_digest not in row["capabilities"]


def test_worker_heartbeat_syncs_only_a_unique_bounded_matching_executor_version(
    tmp_path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        _, owner_headers, owner_identity, _ = bootstrap_identity(client)
        worker, worker_headers = _register_worker(
            client,
            owner_headers=owner_headers,
            owner_identity=owner_identity,
        )
        heartbeat_path = f"/api/v1/workers/{worker['id']}/heartbeat"

        tolerated_reports = [
            [{"type": "comfyui"}],
            [{"type": "other", "version": "9.9.9"}],
        ]
        for executors in tolerated_reports:
            heartbeat = client.post(
                heartbeat_path,
                json={"capabilities": {"executors": executors}},
                headers=worker_headers,
            )
            assert heartbeat.status_code == 200, heartbeat.text
            assert (
                app.state.db.fetchone(
                    "SELECT executor_version FROM workers WHERE id=?", (worker["id"],)
                )["executor_version"]
                == "1.1.0"
            )

        fail_closed_reports = [
            [{"type": "comfyui", "version": None}],
            [{"type": "comfyui", "version": ""}],
            [{"type": "comfyui", "version": "   "}],
            [{"type": "comfyui", "version": "x" * 121}],
            [{"type": "comfyui", "version": "1.2.0\n"}],
            [{"type": "comfyui", "version": "1.2.0\t"}],
            [{"type": "comfyui", "version": "版本-1.2.0"}],
            [{"type": "comfyui", "version": "1.2.0\u00a0"}],
            [
                {"type": "comfyui", "version": "2.0.0"},
                {"type": "comfyui", "version": "3.0.0"},
            ],
        ]
        for executors in fail_closed_reports:
            heartbeat = client.post(
                heartbeat_path,
                json={"capabilities": {"executors": executors}},
                headers=worker_headers,
            )
            assert heartbeat.status_code == 200, heartbeat.text
            assert (
                app.state.db.fetchone(
                    "SELECT executor_version FROM workers WHERE id=?", (worker["id"],)
                )["executor_version"]
                == "1.1.0"
            )
            assert (
                json.loads(
                    app.state.db.fetchone(
                        "SELECT capabilities FROM workers WHERE id=?", (worker["id"],)
                    )["capabilities"]
                )["executors"]
                == []
            )

        untrusted_version = "customer_secret_123456789"
        boundary = client.post(
            heartbeat_path,
            json={
                "capabilities": {
                    "worker_runtime_version": untrusted_version,
                    "executors": [
                        {
                            "type": "comfyui",
                            "version": untrusted_version,
                            "payload_formats": [untrusted_version],
                            "operations": [untrusted_version],
                            "capabilities": {"runtime_version": untrusted_version},
                        }
                    ],
                }
            },
            headers={**worker_headers, "Idempotency-Key": "heartbeat-must-not-cache"},
        )
        assert boundary.status_code == 200, boundary.text
        assert boundary.headers["Cache-Control"] == "no-store"
        assert (
            app.state.db.fetchone(
                """SELECT COUNT(*) AS n FROM idempotency_records
                   WHERE path=? AND idempotency_key=?""",
                (heartbeat_path, "heartbeat-must-not-cache"),
            )["n"]
            == 0
        )
        boundary_row = app.state.db.fetchone(
            "SELECT executor_version,capabilities FROM workers WHERE id=?", (worker["id"],)
        )
        assert boundary_row["executor_version"] == "1.1.0"
        assert untrusted_version not in boundary_row["capabilities"]

        live = client.post(
            heartbeat_path,
            json={
                "capabilities": {
                    "executors": [
                        {"type": "other", "version": "9.9.9"},
                        {
                            "type": "comfyui",
                            "version": " 1.2.0 ",
                            "payload_formats": [
                                "comfyui-api-graph/v1",
                                "customer_secret_payload",
                            ],
                            "operations": ["t2v", "customer_secret_operation"],
                            "private_prompt": "must-not-persist",
                            "capabilities": {
                                "system": {"os": "must-not-persist"},
                                "gpus": [{"name": "must-not-persist", "vram_total_mb": 24576}],
                                "execution_policy": {"private": "must-not-persist"},
                            },
                        },
                    ],
                    "private_prompt": "must-not-persist",
                },
            },
            headers=worker_headers,
        )
        assert live.status_code == 200, live.text
        row = app.state.db.fetchone(
            "SELECT executor_version,capabilities,last_seen_at FROM workers WHERE id=?",
            (worker["id"],),
        )
        assert row["executor_version"] == "1.2.0"
        assert row["last_seen_at"] is not None
        stored = json.loads(row["capabilities"])
        assert stored["executors"][0]["version"] == "1.2.0"
        assert stored["executors"][0]["payload_formats"] == ["comfyui-api-graph/v1"]
        assert stored["executors"][0]["operations"] == ["t2v"]
        assert stored["executors"][0]["capabilities"]["vram_bytes"] == 24_576 * 1024 * 1024
        assert "must-not-persist" not in row["capabilities"]
        assert "customer_secret" not in row["capabilities"]


def test_revoked_worker_heartbeat_cannot_restore_status_or_runtime_version(tmp_path) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as client:
        client.headers.update({"Vgen-Protocol-Version": "1"})
        _, owner_headers, owner_identity, _ = bootstrap_identity(client)
        worker, _ = _register_worker(
            client,
            owner_headers=owner_headers,
            owner_identity=owner_identity,
        )
        stale_seen_at = time.time() - 300
        app.state.db.execute(
            """UPDATE workers SET status='revoked',executor_version='1.1.0',
                      last_seen_at=?,updated_at=? WHERE id=?""",
            (stale_seen_at, stale_seen_at, worker["id"]),
        )

        with pytest.raises(RepositoryError) as raised:
            app.state.repository.worker_heartbeat(
                worker_id=worker["id"],
                capabilities={"executors": [{"type": "comfyui", "version": "2.0.0"}]},
            )
        assert raised.value.name == "WORKER_REVOKED"

        row = app.state.db.fetchone(
            """SELECT status,executor_version,last_seen_at,updated_at
               FROM workers WHERE id=?""",
            (worker["id"],),
        )
        assert dict(row) == {
            "status": "revoked",
            "executor_version": "1.1.0",
            "last_seen_at": stale_seen_at,
            "updated_at": stale_seen_at,
        }
