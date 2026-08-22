from __future__ import annotations

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "repack_worker_bundle", ROOT / "tools" / "repack_worker_bundle.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _wheel(path: Path, version: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"vgen-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.3\nName: vgen\nVersion: {version}\n",
        )
        archive.writestr(
            f"vgen-{version}.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )


def test_repack_preserves_worker_identity_and_replaces_only_release_code(tmp_path: Path) -> None:
    credential = b'{"private_key":"must-stay-byte-identical"}\n'
    old_wheel = tmp_path / "vgen-9.9.9-py3-none-any.whl"
    _wheel(old_wheel, "9.9.9")
    policy = b"unchanged-policy"
    source = tmp_path / "source.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("worker-credentials.json", credential)
        archive.writestr("start-worker.cmd", b"unchanged-start")
        archive.writestr("comfyui-minimax-h3-policy.yaml", policy)
        archive.writestr("setup-worker.ps1", b"old-setup")
        archive.writestr(old_wheel.name, old_wheel.read_bytes())
        archive.writestr(
            "vgen-worker-bundle.json",
            json.dumps(
                {
                    "format": "vgen-windows-worker-bundle",
                    "version": 1,
                    "worker_credentials": "worker-credentials.json",
                    "policy": {
                        "name": "comfyui-minimax-h3-policy.yaml",
                        "sha256": MODULE._sha256(policy),
                    },
                    "wheel": {
                        "name": old_wheel.name,
                        "sha256": MODULE._sha256(old_wheel.read_bytes()),
                    },
                }
            ),
        )

    wheel = tmp_path / "vgen-0.1.0-py3-none-any.whl"
    _wheel(wheel, "0.1.0")
    setup = tmp_path / "setup-worker.ps1"
    setup.write_bytes(b"new-setup")
    output = tmp_path / "output.zip"

    version, fingerprint = MODULE.repack_bundle(source, wheel, setup, output)

    assert version == "0.1.0"
    assert fingerprint == MODULE._sha256(credential)
    with zipfile.ZipFile(output) as archive:
        assert archive.read("worker-credentials.json") == credential
        assert archive.read("start-worker.cmd") == b"unchanged-start"
        assert archive.read("comfyui-minimax-h3-policy.yaml") == policy
        assert archive.read("setup-worker.ps1") == b"new-setup"
        assert "vgen-9.9.9-py3-none-any.whl" not in archive.namelist()
        assert archive.read(wheel.name) == wheel.read_bytes()
        manifest = json.loads(archive.read("vgen-worker-bundle.json"))
    assert manifest["wheel"] == {
        "name": wheel.name,
        "sha256": MODULE._sha256(wheel.read_bytes()),
        "version": "0.1.0",
    }


def test_repack_same_version_refreshes_setup_without_changing_worker_identity(
    tmp_path: Path,
) -> None:
    version = "0.2.2"
    credential = b'{"worker_id":"same-worker","private_key":"byte-identical"}\n'
    wheel = tmp_path / f"vgen-{version}-py3-none-any.whl"
    _wheel(wheel, version)
    policy = b"same-policy"
    launcher = b"same-launcher"
    source = tmp_path / "source-0.2.2.zip"
    original_manifest = {
        "comfyui_root": None,
        "format": "vgen-windows-worker-bundle",
        "gateway_url": "https://gateway.example.test",
        "version": 1,
        "worker_credentials": "worker-credentials.json",
        "policy": {
            "name": "comfyui-minimax-h3-policy.yaml",
            "sha256": MODULE._sha256(policy),
        },
        "wheel": {
            "name": wheel.name,
            "sha256": MODULE._sha256(wheel.read_bytes()),
            "version": version,
        },
    }
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("worker-credentials.json", credential)
        archive.writestr("start-worker.cmd", launcher)
        archive.writestr("comfyui-minimax-h3-policy.yaml", policy)
        archive.writestr("setup-worker.ps1", b"old-setup")
        archive.writestr(wheel.name, wheel.read_bytes())
        archive.writestr("vgen-worker-bundle.json", json.dumps(original_manifest))

    setup = tmp_path / "setup-worker.ps1"
    setup.write_bytes(b"same-version-fixed-setup")
    output = tmp_path / "output-0.2.2.zip"

    repacked_version, fingerprint = MODULE.repack_bundle(source, wheel, setup, output)

    assert repacked_version == version
    assert fingerprint == MODULE._sha256(credential)
    with zipfile.ZipFile(output) as archive:
        assert len(archive.infolist()) == 6
        assert len(archive.namelist()) == len(set(archive.namelist()))
        assert archive.read("worker-credentials.json") == credential
        assert archive.read("start-worker.cmd") == launcher
        assert archive.read("comfyui-minimax-h3-policy.yaml") == policy
        assert archive.read("setup-worker.ps1") == b"same-version-fixed-setup"
        assert archive.read(wheel.name) == wheel.read_bytes()
        manifest = json.loads(archive.read("vgen-worker-bundle.json"))
    assert manifest["gateway_url"] == original_manifest["gateway_url"]
    assert manifest["comfyui_root"] is None
    assert manifest["wheel"] == original_manifest["wheel"]


@pytest.mark.parametrize("unsafe_name", ["nested/file", "..\\escape"])
def test_repack_rejects_non_top_level_bundle_entries(tmp_path: Path, unsafe_name: str) -> None:
    bundle = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr(unsafe_name, b"unexpected")
    with zipfile.ZipFile(bundle) as archive:
        with pytest.raises(MODULE.RepackError, match="unsafe bundle entry"):
            MODULE._safe_entries(archive)


def test_repack_rejects_wheel_without_a_wheel_contract(tmp_path: Path) -> None:
    wheel = tmp_path / "vgen-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "vgen-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.3\nName: vgen\nVersion: 0.1.0\n",
        )
    with pytest.raises(MODULE.RepackError, match="exactly one WHEEL"):
        MODULE._wheel_identity(wheel)
