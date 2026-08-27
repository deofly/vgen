from __future__ import annotations

import hashlib
import json
import os
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
TEST_RUNTIME_LOCK_SET_SHA256 = "0" * 64


def _write_test_wheel(
    directory: Path,
    *,
    version: str = __version__,
    requirements: tuple[str, ...] = (),
    requires_python: str | None = None,
) -> Path:
    target = directory / f"vgen-{version}-py3-none-any.whl"
    dist_info = f"vgen-{version}.dist-info"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vgen/__init__.py", f'__version__ = "{version}"\n')
        archive.writestr("vgen/cli/main.py", "# test CLI\n")
        archive.writestr("vgen/cli/worker_enrollment.py", "# test enrollment\n")
        archive.writestr("vgen/assets/worker/enroll-worker.ps1", "# test enrollment script\n")
        archive.writestr("vgen/assets/worker/supervise-worker.ps1", "# test supervisor script\n")
        metadata = f"Metadata-Version: 2.4\nName: vgen\nVersion: {version}\n"
        metadata += "".join(f"Requires-Dist: {item}\n" for item in requirements)
        if requires_python is not None:
            metadata += f"Requires-Python: {requires_python}\n"
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: vgen-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    return target


def _write_dependency_wheel(
    directory: Path,
    *,
    distribution: str,
    version: str,
    requirements: tuple[str, ...] = (),
    requires_python: str | None = None,
) -> Path:
    filename_distribution = distribution.replace("-", "_")
    target = directory / f"{filename_distribution}-{version}-py3-none-any.whl"
    dist_info = f"{filename_distribution}-{version}.dist-info"
    metadata = f"Metadata-Version: 2.4\nName: {distribution}\nVersion: {version}\n"
    metadata += "".join(f"Requires-Dist: {item}\n" for item in requirements)
    if requires_python is not None:
        metadata += f"Requires-Python: {requires_python}\n"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{filename_distribution}/__init__.py", "")
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(
            f"{dist_info}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: vgen-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
    return target


def _write_test_wheelhouse(directory: Path) -> Path:
    wheelhouse = directory / "wheelhouse"
    wheelhouse.mkdir()
    _write_dependency_wheel(wheelhouse, distribution="pip", version="26.2")
    return wheelhouse


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
    wheelhouse = _write_test_wheelhouse(tmp_path)

    result = create_public_windows_worker_installer_bundle(
        gateway_url="https://gateway.example",
        wheelhouse_path=wheelhouse,
        runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
        output=target,
        wheel_path=wheel_path,
    )

    assert result.path == target
    if os.name != "nt":
        assert stat.S_IMODE(target.stat().st_mode) == 0o644
    with zipfile.ZipFile(target) as archive:
        names = set(archive.namelist())
        assert names == {
            "INSTALL.txt",
            "enroll-worker.ps1",
            "start-worker.cmd",
            "setup-worker.ps1",
            "supervise-worker.ps1",
            "vgen-worker-bundle.json",
            "comfyui-minimax-h3-policy.yaml",
            "pip-26.2-py3-none-any.whl",
            "vgen-worker-requirements.txt",
            WHEEL_NAME,
            "SHA256SUMS",
        }
        for info in archive.infolist():
            mode = info.external_attr >> 16
            assert info.date_time == (2020, 2, 2, 0, 0, 0)
            assert info.create_system == 3
            assert stat.S_IFMT(mode) == stat.S_IFREG
            assert stat.S_IMODE(mode) == (0o755 if info.filename == "start-worker.cmd" else 0o644)
        assert "worker-credentials.json" not in names
        config = json.loads(archive.read("vgen-worker-bundle.json"))
        assert config["gateway_url"] == "https://gateway.example"
        assert config["enrollment"]["identity"] == "generated_on_worker"
        assert config["version"] == 2
        assert config["python_runtime"]["bootstrap_pip"]["name"] == (
            "pip-26.2-py3-none-any.whl"
        )
        assert config["python_runtime"]["lock_set_sha256"] == (
            TEST_RUNTIME_LOCK_SET_SHA256
        )
        requirements = archive.read("vgen-worker-requirements.txt").decode("ascii")
        assert f"vgen[worker-comfyui]=={__version__} --hash=sha256:" in requirements
        assert "pip==26.2 --hash=sha256:" in requirements
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


def test_public_installer_rejects_an_unbound_runtime_lock_set(tmp_path: Path) -> None:
    with pytest.raises(WorkerBundleError, match="lock-set digest"):
        create_public_windows_worker_installer_bundle(
            gateway_url="https://gateway.example",
            wheelhouse_path=_write_test_wheelhouse(tmp_path),
            runtime_lock_set_sha256="not-a-sha256",
            output=tmp_path / "worker.zip",
            wheel_path=_write_test_wheel(tmp_path),
        )


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
            wheelhouse_path=_write_test_wheelhouse(tmp_path),
            runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
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
            wheelhouse_path=_write_test_wheelhouse(tmp_path),
            runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
            output=tmp_path / "worker.zip",
            wheel_path=wheel_path,
        )


def test_public_installer_rejects_unrelated_wheelhouse_distribution(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path)
    wheelhouse = _write_test_wheelhouse(tmp_path)
    _write_dependency_wheel(wheelhouse, distribution="unrelated", version="1.0.0")

    with pytest.raises(WorkerBundleError, match="unrelated distributions: unrelated"):
        create_public_windows_worker_installer_bundle(
            gateway_url="https://gateway.example",
            wheelhouse_path=wheelhouse,
            runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
            output=tmp_path / "worker.zip",
            wheel_path=wheel,
        )


def test_public_installer_checks_dependency_markers_at_every_python_311_patch(
    tmp_path: Path,
) -> None:
    wheel = _write_test_wheel(
        tmp_path,
        requirements=("patch-only==1.0.0; python_full_version == '3.11.50'",),
    )

    with pytest.raises(WorkerBundleError, match="does not satisfy.*patch-only"):
        create_public_windows_worker_installer_bundle(
            gateway_url="https://gateway.example",
            wheelhouse_path=_write_test_wheelhouse(tmp_path),
            runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
            output=tmp_path / "worker.zip",
            wheel_path=wheel,
        )


def test_public_installer_rejects_requires_python_middle_patch_exclusion(
    tmp_path: Path,
) -> None:
    wheel = _write_test_wheel(tmp_path, requires_python="!=3.11.50")

    with pytest.raises(WorkerBundleError, match="complete Python 3.11 target"):
        create_public_windows_worker_installer_bundle(
            gateway_url="https://gateway.example",
            wheelhouse_path=_write_test_wheelhouse(tmp_path),
            runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
            output=tmp_path / "worker.zip",
            wheel_path=wheel,
        )


def test_public_installer_rejects_unknown_dependency_marker(tmp_path: Path) -> None:
    wheel = _write_test_wheel(
        tmp_path,
        requirements=("dependency==1.0.0; unknown_runtime == 'anything'",),
    )

    with pytest.raises(WorkerBundleError, match="invalid dependency"):
        create_public_windows_worker_installer_bundle(
            gateway_url="https://gateway.example",
            wheelhouse_path=_write_test_wheelhouse(tmp_path),
            runtime_lock_set_sha256=TEST_RUNTIME_LOCK_SET_SHA256,
            output=tmp_path / "worker.zip",
            wheel_path=wheel,
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


def test_worker_update_wheel_rejects_unbounded_version_components(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path, version="1000000000.2.0")

    with pytest.raises(WorkerBundleError, match="MAJOR.MINOR.PATCH"):
        inspect_worker_update_wheel(wheel)


def test_worker_update_wheel_refuses_a_symbolic_link(tmp_path: Path) -> None:
    wheel = _write_test_wheel(tmp_path, version="0.2.0")
    link = tmp_path / "linked-update.whl"
    link.symlink_to(wheel)

    with pytest.raises(WorkerBundleError, match="symbolic link"):
        inspect_worker_update_wheel(link)
