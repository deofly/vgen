from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from vgen import __version__
from vgen.cli.identity_store import DeviceIdentityStore
from vgen.cli.main import build_parser
from vgen.cli.worker_bundle import (
    WorkerBundleError,
    create_public_windows_worker_installer_bundle,
    create_windows_worker_bundle,
    inspect_worker_update_wheel,
    load_worker_wheel,
    select_pool,
)
from vgen.worker.credentials import WorkerCredentials

WHEEL_NAME = f"vgen-{__version__}-py3-none-any.whl"


def _write_test_wheel(directory: Path, *, version: str = __version__) -> Path:
    target = directory / f"vgen-{version}-py3-none-any.whl"
    dist_info = f"vgen-{version}.dist-info"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vgen/__init__.py", f'__version__ = "{version}"\n')
        archive.writestr("vgen/cli/main.py", "# test CLI\n")
        archive.writestr("vgen/cli/worker_enrollment.py", "# test enrollment\n")
        archive.writestr("vgen/assets/worker/enroll-worker.ps1", "# test enrollment script\n")
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: vgen\nVersion: {version}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: vgen-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    return target


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self.values.pop((service, username), None)


class BundleClient:
    def __init__(self) -> None:
        self.profile = SimpleNamespace(endpoint="https://gateway.example")
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.worker_payload: dict[str, Any] | None = None

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        del idempotency_key
        self.calls.append((method, path, json_body))
        if method == "GET" and path == "/api/v1/workspaces/wsp_example/pools":
            return [{"id": "pol_private", "name": "My 3090"}]
        if method == "POST" and path == "/api/v1/workers":
            self.worker_payload = dict(json_body or {})
            return {"id": "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa", "status": "offline"}
        if method == "POST" and path.endswith("/offer"):
            return {"id": "wal_aaaaaaaaaaaaaaaaaaaaaaaaaa"}
        if method == "GET" and path.startswith("/api/v1/worker-allocations/"):
            assert self.worker_payload is not None
            return {
                "id": "wal_aaaaaaaaaaaaaaaaaaaaaaaaaa",
                "workspace_id": "wsp_example",
                "pool_id": "pol_private",
                "worker_id": "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa",
                "owner_consent_at": 1_700_000_000.125,
                "worker": {
                    "signing_public_key": self.worker_payload["signing_public_key"],
                    "encryption_public_key": self.worker_payload["encryption_public_key"],
                    "certificate": self.worker_payload["certificate"],
                },
            }
        if method == "POST" and path.endswith("/rates"):
            return {"id": "rtc_aaaaaaaaaaaaaaaaaaaaaaaaaa"}
        return {"status": "active"}


def test_parser_exposes_single_worker_bundle_command_without_resource_ids() -> None:
    args = build_parser().parse_args(["worker", "bundle"])
    assert args.worker_action == "bundle"
    assert args.name == "Windows GPU Worker"
    assert args.pool is None
    assert args.compute_rate == 1_000_000
    assert args.traffic_rate == 0


def test_public_installer_bundle_contains_no_principal_credentials(tmp_path: Path) -> None:
    target = tmp_path / "public-worker-installer.zip"
    wheel_path = _write_test_wheel(tmp_path)

    result = create_public_windows_worker_installer_bundle(
        gateway_url="https://gateway.example",
        output=target,
        wheel_path=wheel_path,
    )

    assert result.path == target
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    with zipfile.ZipFile(target) as archive:
        names = set(archive.namelist())
        assert names == {
            "INSTALL.txt",
            "enroll-worker.ps1",
            "start-worker.cmd",
            "setup-worker.ps1",
            "vgen-worker-bundle.json",
            "comfyui-minimax-h3-policy.yaml",
            WHEEL_NAME,
            "SHA256SUMS",
        }
        assert "worker-credentials.json" not in names
        config = json.loads(archive.read("vgen-worker-bundle.json"))
        assert config["gateway_url"] == "https://gateway.example"
        assert config["enrollment"]["identity"] == "generated_on_worker"
        assert "worker_id" not in config
        assert "session_token" not in config
        enrollment_script = archive.read("enroll-worker.ps1").decode("utf-8")
        assert "InviteSecret" not in enrollment_script
        assert "claim-invite" in enrollment_script
        assert "Assert-ClosedBundleDirectory $PSScriptRoot" in enrollment_script
        assert "-I -B -m vgen worker claim-invite" in enrollment_script
        install = archive.read("INSTALL.txt").decode("utf-8")
        assert "verification code" in install
        assert "approve-enrollment <id> --code <displayed-code>" in install


def test_public_installer_refuses_a_stale_wheel_without_local_enrollment(tmp_path: Path) -> None:
    wheel_path = _write_test_wheel(tmp_path)
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        dist_info = f"vgen-{__version__}.dist-info"
        archive.writestr("vgen/__init__.py", f'__version__ = "{__version__}"\n')
        archive.writestr(
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.4\nName: vgen\nVersion: {__version__}\n",
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )

    with pytest.raises(WorkerBundleError, match="predates credential-free enrollment"):
        create_public_windows_worker_installer_bundle(
            gateway_url="https://gateway.example",
            output=tmp_path / "worker.zip",
            wheel_path=wheel_path,
        )


@pytest.mark.parametrize(
    "gateway",
    [
        "http://gateway.example",
        "https://user:password@gateway.example",
        "https://gateway.example/releases",
        "https://gateway.example?invite=secret",
    ],
)
def test_public_installer_rejects_non_origin_or_insecure_gateway(
    tmp_path: Path, gateway: str
) -> None:
    wheel_path = _write_test_wheel(tmp_path)
    with pytest.raises(WorkerBundleError, match="Gateway URL"):
        create_public_windows_worker_installer_bundle(
            gateway_url=gateway,
            output=tmp_path / "worker.zip",
            wheel_path=wheel_path,
        )


def test_select_pool_prefers_name_default_then_unique_and_never_requires_id() -> None:
    pools = [
        {"id": "pol_private_a", "name": "3090"},
        {"id": "pol_private_b", "name": "4090"},
    ]
    assert select_pool(pools, requested="4090", default="3090")["name"] == "4090"
    assert select_pool(pools, requested=None, default="3090")["name"] == "3090"
    assert select_pool([pools[0]], requested=None)["name"] == "3090"
    with pytest.raises(WorkerBundleError, match=r"--pool.*3090, 4090") as caught:
        select_pool(pools, requested=None)
    assert "pol_private" not in str(caught.value)


def test_worker_wheel_filename_must_match_the_product_version(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path)
    mismatched = tmp_path / "vgen-9.9.9-py3-none-any.whl"
    wheel.rename(mismatched)

    with pytest.raises(WorkerBundleError, match=f"must be named {re.escape(WHEEL_NAME)}"):
        load_worker_wheel(mismatched)


def test_worker_update_wheel_can_target_a_newer_reviewed_release(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path, version="0.2.0")

    artifact = inspect_worker_update_wheel(wheel)

    assert artifact.path == wheel
    assert artifact.version == "0.2.0"
    assert artifact.size_bytes == wheel.stat().st_size
    assert artifact.sha256 == hashlib.sha256(wheel.read_bytes()).hexdigest()


def test_worker_update_wheel_requires_three_part_release_version(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path, version="0.2")

    with pytest.raises(WorkerBundleError, match="MAJOR.MINOR.PATCH"):
        inspect_worker_update_wheel(wheel)


def test_worker_update_wheel_refuses_a_symbolic_link(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path, version="0.2.0")
    link = tmp_path / "linked-update.whl"
    link.symlink_to(wheel)

    with pytest.raises(WorkerBundleError, match="symbolic link"):
        inspect_worker_update_wheel(link)


def test_create_bundle_provisions_full_lifecycle_and_contains_one_click_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, owner = DeviceIdentityStore(MemorySecrets()).initialize()
    client = BundleClient()
    monkeypatch.setattr(
        "vgen.cli.worker_bundle.login_worker_session",
        lambda profile, worker_id, keys: {
            "token": "private-worker-session",
            "expires_at": 1_800_000_000,
            "worker_id": worker_id,
        },
    )
    target = tmp_path / "private-worker.zip"
    wheel_path = _write_test_wheel(tmp_path)
    result = create_windows_worker_bundle(
        client,
        owner,
        worker_name="Home GPU",
        workspace_id="wsp_example",
        pool=None,
        default_pool=None,
        output=target,
        comfyui_root=None,
        compute_rate=1_000_000,
        traffic_rate=0,
        manager_broker_id="brk_home",
        wheel_path=wheel_path,
    )

    assert result.path == target
    assert result.pool_name == "My 3090"
    if stat.S_IMODE(target.stat().st_mode):
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with zipfile.ZipFile(target) as archive:
        names = set(archive.namelist())
        assert names == {
            "start-worker.cmd",
            "setup-worker.ps1",
            "vgen-worker-bundle.json",
            "comfyui-minimax-h3-policy.yaml",
            WHEEL_NAME,
            "worker-credentials.json",
        }
        config_bytes = archive.read("vgen-worker-bundle.json")
        config = json.loads(config_bytes)
        credentials = WorkerCredentials.from_bytes(archive.read("worker-credentials.json"))
        assert config["format"] == "vgen-windows-worker-bundle"
        assert config["gateway_url"] == "https://gateway.example"
        assert config["comfyui_root"] is None
        assert config["wheel"]["name"] == WHEEL_NAME
        assert config["wheel"]["version"] == __version__
        assert credentials.worker_id == "wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
        assert credentials.owner_root_signing_public_key == owner.root_signing_public_key
        assert b"private-worker-session" not in config_bytes
        assert b"wrk_" not in config_bytes

    paths = [path for _, path, _ in client.calls]
    assert paths == [
        "/api/v1/workspaces/wsp_example/pools",
        "/api/v1/workers",
        "/api/v1/workers/wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa/offer",
        "/api/v1/worker-allocations/wal_aaaaaaaaaaaaaaaaaaaaaaaaaa",
        "/api/v1/worker-allocations/wal_aaaaaaaaaaaaaaaaaaaaaaaaaa/approve",
        "/api/v1/workers/wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa/rates",
        "/api/v1/rates/rtc_aaaaaaaaaaaaaaaaaaaaaaaaaa/approve",
    ]
    assert client.worker_payload is not None
    assert client.worker_payload["manager_broker_id"] == "brk_home"


def test_bundle_refuses_existing_output_before_mutating_gateway(tmp_path: Path) -> None:
    _, owner = DeviceIdentityStore(MemorySecrets()).initialize()
    client = BundleClient()
    target = tmp_path / "already-there.zip"
    target.write_bytes(b"keep")
    wheel_path = _write_test_wheel(tmp_path)

    with pytest.raises(WorkerBundleError, match="Refusing to overwrite"):
        create_windows_worker_bundle(
            client,
            owner,
            worker_name="Home GPU",
            workspace_id="wsp_example",
            pool=None,
            default_pool=None,
            output=target,
            comfyui_root=None,
            compute_rate=1_000_000,
            traffic_rate=0,
            wheel_path=wheel_path,
        )
    assert client.calls == []
