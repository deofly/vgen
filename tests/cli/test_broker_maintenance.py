from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.main import _broker_command, _worker_command, build_parser, main
from vgen.crypto import verify_maintenance_intent
from vgen.market.models import WorkflowManifest
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
        self.terminal_job = terminal_job
        self.closed = False

    def request(self, method: str, path: str, **_: Any) -> Any:
        assert method == "GET"
        assert path == "/api/v1/workers"
        return [dict(self.worker)]

    def set_worker_manager(self, worker_id: str, broker_id: str | None) -> dict[str, Any]:
        self.manager_calls.append((worker_id, broker_id))
        self.worker = {**self.worker, "manager_broker_id": broker_id}
        return dict(self.worker)

    def create_worker_maintenance(self, **values: Any) -> dict[str, Any]:
        self.created.append(values)
        response = {
            "id": "mtn_example",
            "state": "awaiting_upload"
            if values["spec"]["kind"] == "worker_update"
            else "queued",
        }
        if values["spec"]["kind"] == "worker_update":
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

    def upload(self, ticket: Any, source: Path) -> None:
        self.uploads.append((ticket, source))


def _identity():  # type: ignore[no-untyped-def]
    return DeviceIdentityStore(MemorySecrets()).initialize()[1]


def _worker(*, manager: str | None = "brk_home") -> dict[str, Any]:
    return {
        "id": "wrk_example",
        "name": "Windows GPU",
        "status": "active",
        "manager_broker_id": manager,
        "executor_type": "comfyui",
        "capabilities": {"model_digests": []},
    }


def test_parser_exposes_simple_broker_maintenance_commands() -> None:
    update = build_parser().parse_args(
        ["broker", "worker-update", "vgen-0.2.0-py3-none-any.whl", "--wait"]
    )
    assert update.broker_action == "worker-update"
    assert update.worker is None
    assert update.wait is True

    models = build_parser().parse_args(
        ["broker", "model-install", "--accept-license", "Apache-2.0"]
    )
    assert models.workflow == "vgen/minimax-h3-8step"
    assert models.accept_license == ["Apache-2.0"]

    manager = build_parser().parse_args(["worker", "manager-set"])
    assert manager.worker is None
    assert manager.broker is None


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


def test_model_install_only_sends_missing_digests_and_license_acceptances(
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
                    "model_digests": [
                        f"sha256:{model.sha256}" for model in models if model != missing
                    ]
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
            accept_license=["Apache-2.0"],
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
        "license_acceptances",
    }
    assert spec["model_digests"] == [f"sha256:{missing.sha256}"]
    assert spec["license_acceptances"][0]["license_id"] == "Apache-2.0"
    serialized = json.dumps(spec)
    assert "source" not in serialized
    assert "filename" not in serialized
    assert "https://" not in serialized
    assert client.committed == []


@pytest.mark.parametrize(
    ("manager", "message"),
    [
        (None, "no manager Broker"),
        ("brk_other", "managed by another Broker"),
    ],
)
def test_maintenance_requires_explicit_manager_binding(
    manager: str | None,
    message: str,
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
