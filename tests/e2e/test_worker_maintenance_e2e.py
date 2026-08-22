from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import httpx
import requests
from fastapi.testclient import TestClient

from tests.gateway.test_gateway_api import bootstrap_identity, worker_owner_certificate
from vgen.cli.client import GatewayClient
from vgen.cli.identity_store import DeviceIdentity
from vgen.cli.main import _create_maintenance_job
from vgen.cli.profile import GatewayProfile
from vgen.crypto import (
    DeviceCertificate,
    DeviceKeys,
    b64url_encode,
    sign_message,
)
from vgen.gateway.app import create_app
from vgen.worker import GatewayV1Client, WorkerCredentials
from vgen.worker.maintenance import WorkerMaintenanceController
from vgen.worker.model_installer import ModelInstaller


class _GatewayCliTransport(httpx.BaseTransport):
    """Route the real CLI HTTP client into the in-process Gateway."""

    def __init__(self, client: TestClient) -> None:
        self._client = client

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._client.request(
            request.method,
            request.url.raw_path.decode("ascii"),
            content=request.read(),
            headers=dict(request.headers),
        )
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=response.content,
            request=request,
        )


class _GatewayWorkerSession:
    """Route the production Worker adapter into the same Gateway."""

    def __init__(self, client: TestClient) -> None:
        self._client = client
        self.paths: list[str] = []

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        parsed = urlsplit(url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        self.paths.append(path)
        response = self._client.request(
            method,
            path,
            content=kwargs.get("data"),
            headers=kwargs.get("headers"),
        )
        result = requests.Response()
        result.status_code = response.status_code
        result.headers.update(response.headers)
        result._content = response.content
        result.url = url
        return result


class _PinnedExecutor:
    def __init__(self, pin: Any, workflow_ref: str, workflow_digest: str) -> None:
        self.maintenance_model_pins = (pin,)
        self.maintenance_workflows = ((workflow_ref, workflow_digest),)
        self.cache_invalidations = 0

    def invalidate_model_digest_cache(self) -> None:
        self.cache_invalidations += 1


class _ModelDownloadSession:
    def __init__(self, content: bytes) -> None:
        self._content = content
        self.requests = 0

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        assert method == "GET"
        assert url == "https://models.example.test/revisions/pinned/tiny-model.bin"
        assert kwargs["allow_redirects"] is False
        self.requests += 1
        return SimpleNamespace(
            status_code=200,
            headers={"Content-Length": str(len(self._content))},
            iter_content=lambda chunk_size: (
                self._content[index : index + chunk_size]
                for index in range(0, len(self._content), chunk_size)
            ),
            close=lambda: None,
        )


def _worker_session(
    client: TestClient, worker_id: str, worker_keys: DeviceKeys
) -> tuple[str, dict[str, str]]:
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
    token = str(session.json()["session_token"])
    return token, {"Authorization": f"Bearer {token}"}


def test_broker_model_job_runs_through_gateway_and_worker_with_pinned_trust(
    tmp_path: Path,
) -> None:
    app = create_app(
        database_path=str(tmp_path / "gateway.db"),
        bootstrap_code="test-bootstrap",
        require_request_signatures=False,
        artifact_root=str(tmp_path / "artifacts"),
    )
    with TestClient(app) as test_client:
        test_client.headers.update({"Vgen-Protocol-Version": "1"})
        boot, owner_headers, owner_identity, owner_device = bootstrap_identity(test_client)
        owner_token = owner_headers["Authorization"].removeprefix("Bearer ")
        owner_device_id = str(boot["device"]["id"])

        broker_response = test_client.post(
            "/api/v1/brokers",
            json={"name": "Home Broker", "device_id": owner_device_id},
            headers=owner_headers,
        )
        assert broker_response.status_code == 200, broker_response.text
        broker = broker_response.json()

        worker_keys = DeviceKeys.generate()
        worker_response = test_client.post(
            "/api/v1/workers",
            json={
                "name": "Windows GPU Worker",
                "manager_broker_id": broker["id"],
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
        worker_token, worker_headers = _worker_session(test_client, worker["id"], worker_keys)
        heartbeat = test_client.post(
            f"/api/v1/workers/{worker['id']}/heartbeat",
            json={"capabilities": {"executors": [{"type": "comfyui"}]}},
            headers=worker_headers,
        )
        assert heartbeat.status_code == 200, heartbeat.text

        device_row = app.state.db.fetchone(
            "SELECT certificate FROM devices WHERE id=?", (owner_device_id,)
        )
        assert device_row is not None
        broker_identity = DeviceIdentity(
            alias="e2e",
            root_key_id=owner_identity.root_key_id,
            root_signing_public_key=b64url_encode(owner_identity.signing_public_bytes()),
            root_encryption_public_key=b64url_encode(owner_identity.encryption_public_bytes()),
            root_keys=owner_identity,
            device_id=owner_device_id,
            device_keys=owner_device,
            certificate=DeviceCertificate.from_dict(json.loads(device_row["certificate"])),
        )
        cli_client = GatewayClient(
            GatewayProfile(
                name="e2e",
                endpoint="http://localhost",
                user_id=boot["user"]["id"],
                device_id=owner_device_id,
                home_broker_id=broker["id"],
            ),
            session_token=owner_token,
            transport=_GatewayCliTransport(test_client),
        )

        model_bytes = b"tiny deterministic model fixture"
        model_sha256 = hashlib.sha256(model_bytes).hexdigest()
        model_digest = f"sha256:{model_sha256}"
        workflow_ref = "vgen/minimax-h3-8step@1.0.0"
        workflow_digest = "sha256:" + "b" * 64
        spec = {
            "kind": "model_install",
            "workflow_ref": workflow_ref,
            "workflow_digest": workflow_digest,
            "model_digests": [model_digest],
            "license_acceptances": [
                {
                    "model_digest": model_digest,
                    "license_id": "Apache-2.0",
                    "revision": "pinned",
                    "accepted_at": int(time.time()),
                }
            ],
        }
        try:
            created = _create_maintenance_job(
                cli_client,
                broker_identity,
                broker_id=broker["id"],
                worker=worker,
                spec=spec,
            )
            assert created["state"] == "queued"
            assert created["issued_by_device_id"] == owner_device_id

            worker_credentials = WorkerCredentials(
                worker["id"],
                worker_keys,
                worker_token,
                owner_root_signing_public_key=b64url_encode(
                    owner_identity.signing_public_bytes()
                ),
            )
            worker_session = _GatewayWorkerSession(test_client)
            worker_gateway = GatewayV1Client(
                "http://localhost",
                worker_credentials,
                session=worker_session,  # type: ignore[arg-type]
                allow_http=True,
            )
            model_root = tmp_path / "models"
            model_root.mkdir()
            pin = SimpleNamespace(
                path="checkpoints/tiny-model.bin",
                sha256=model_sha256,
                size=len(model_bytes),
                source="https://models.example.test/revisions/pinned/tiny-model.bin",
                revision="pinned",
                license="Apache-2.0",
                license_url="https://licenses.example.test/apache-2.0",
                gated=False,
                manual_download=False,
            )
            executor = _PinnedExecutor(pin, workflow_ref, workflow_digest)
            download_session = _ModelDownloadSession(model_bytes)
            installer = ModelInstaller(
                model_root,
                session=download_session,  # type: ignore[arg-type]
                resolver=lambda _host, _port: ("93.184.216.34",),
            )
            outcome = WorkerMaintenanceController(
                worker_credentials,
                worker_gateway,
                executor,
                work_root=tmp_path / "worker-maintenance",
                model_root=model_root,
                model_installer=installer,
            ).run_one()

            assert outcome is not None and outcome.succeeded
            assert (model_root / "checkpoints" / "tiny-model.bin").read_bytes() == model_bytes
            assert download_session.requests == 1
            assert executor.cache_invalidations == 1
            completed = cli_client.get_worker_maintenance(created["id"])
            assert completed["state"] == "succeeded"
            assert completed["result"]["kind"] == "model_install"
            assert completed["result"]["status"] == "installed"
            assert completed["result"]["installed_model_digests"] == [model_digest]
            assert completed["result"]["error_code"] is None
            assert any(path.endswith("/maintenance-jobs/claim") for path in worker_session.paths)
            assert any(path.endswith("/heartbeat") for path in worker_session.paths)
            assert any(path.endswith("/complete") for path in worker_session.paths)

            queued_for_new_worker = _create_maintenance_job(
                cli_client,
                broker_identity,
                broker_id=broker["id"],
                worker=worker,
                spec=spec,
            )
            assert queued_for_new_worker["state"] == "queued"
            legacy_credentials = WorkerCredentials(worker["id"], worker_keys, worker_token)
            legacy_outcome = WorkerMaintenanceController(
                legacy_credentials,
                GatewayV1Client(
                    "http://localhost",
                    legacy_credentials,
                    session=worker_session,  # type: ignore[arg-type]
                    allow_http=True,
                ),
                executor,
                work_root=tmp_path / "legacy-worker-maintenance",
                model_root=model_root,
                model_installer=installer,
            ).run_one()
            assert legacy_outcome is None
            still_queued = cli_client.get_worker_maintenance(queued_for_new_worker["id"])
            assert still_queued["state"] == "queued"
            assert app.state.db.fetchone(
                "SELECT lease_session_id FROM worker_maintenance_jobs WHERE id=?",
                (queued_for_new_worker["id"],),
            )["lease_session_id"] is None
        finally:
            cli_client.close()
