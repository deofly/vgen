from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path

import pytest

from vgen import __version__
from vgen.cli.main import build_parser
from vgen.cli.worker_bundle import (
    WorkerBundleError,
    create_public_windows_worker_installer_bundle,
    inspect_worker_update_wheel,
    load_worker_wheel,
    select_pool,
)

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


def test_parser_exposes_single_interactive_worker_add_command() -> None:
    args = build_parser().parse_args(["worker", "add"])
    assert args.worker_action == "add"
    assert args.name == "Windows GPU Worker"
    assert args.pool is None
    assert args.rate == 0
    for removed in (
        "bundle",
        "installer-bundle",
        "invite",
        "claim-invite",
        "approve-enrollment",
        "enroll",
    ):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["worker", removed])


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
        assert "vgen.cli.worker_enrollment" in enrollment_script
        assert "Assert-ClosedBundleDirectory $PSScriptRoot" in enrollment_script
        assert "-I -B -m vgen.cli.worker_enrollment" in enrollment_script
        launcher = archive.read("start-worker.cmd").decode("utf-8")
        assert "enroll-worker.ps1" in launcher
        assert "setup-worker.ps1" not in launcher
        install = archive.read("INSTALL.txt").decode("utf-8")
        assert "verification code" in install
        assert "vgen worker add" in install


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
