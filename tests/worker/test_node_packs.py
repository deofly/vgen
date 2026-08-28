from __future__ import annotations

import contextlib
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from vgen.market.node_packs import build_node_pack_archive
from vgen.worker.host_control import ComfyUIHostControlError
from vgen.worker.node_packs import NodePackInstaller, NodePackInstallError


class HostControl:
    def __init__(self) -> None:
        self.pauses = 0

    @contextlib.contextmanager
    def paused(self, **_kwargs: object) -> Iterator[None]:
        self.pauses += 1
        yield


class UnavailableHostControl:
    @contextlib.contextmanager
    def paused(self, **_kwargs: object) -> Iterator[None]:
        raise ComfyUIHostControlError("COMFYUI_HOST_PAUSE_TIMEOUT")
        yield


def _archive(
    tmp_path: Path,
    *,
    wheel_name: str = "gguf-0.17.1-py3-none-any.whl",
) -> tuple[Path, str]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "__init__.py").write_text("NODE_CLASS_MAPPINGS = {}\n", encoding="utf-8")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / wheel_name).write_bytes(b"wheel")
    archive = tmp_path / "pack.zip"
    build_node_pack_archive(
        source,
        archive,
        node_pack_id="vgen/comfyui-gguf",
        version="1.0.0",
        directory="ComfyUI-GGUF",
        source="https://github.com/city96/ComfyUI-GGUF.git",
        revision="6ea2651e7df66d7585f6ffee804b20e92fb38b8a",
        node_classes=["UnetLoaderGGUF"],
        wheel_root=wheels,
    )
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


def test_installs_offline_dependencies_activates_and_reuses(tmp_path: Path) -> None:
    archive, digest = _archive(tmp_path)
    custom_nodes = tmp_path / "custom_nodes"
    custom_nodes.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    host = HostControl()
    wheel_calls: list[tuple[tuple[str, ...], Path]] = []
    stages: list[str] = []
    loaded: set[str] = set()
    python = tmp_path / "python.exe"
    python.write_bytes(b"python")

    def install_wheels(_python: Path, wheels: tuple[Path, ...], target: Path) -> None:
        wheel_calls.append((tuple(item.name for item in wheels), target))
        target.mkdir()
        (target / "gguf.py").write_text("VERSION = '0.17.1'\n", encoding="utf-8")
        loaded.add("UnetLoaderGGUF")

    installer = NodePackInstaller(
        work,
        custom_nodes,
        python,
        host,  # type: ignore[arg-type]
        lambda: set(loaded),
        pure_python_only=True,
        wheel_installer=install_wheels,
    )
    result = installer.install(
        archive,
        expected_sha256=digest,
        expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
        expected_node_classes=("UnetLoaderGGUF",),
        stage=stages.append,
    )

    target = custom_nodes / "ComfyUI-GGUF"
    assert result.status == "installed"
    assert host.pauses == 1
    assert wheel_calls[0][0] == ("gguf-0.17.1-py3-none-any.whl",)
    assert stages == [
        "validating",
        "installing_dependencies",
        "pausing_comfyui",
        "probing_nodes",
    ]
    assert (target / ".vgen-deps/gguf.py").is_file()
    assert (
        (target / "__init__.py")
        .read_text(encoding="utf-8")
        .startswith("# VGen managed dependency path")
    )
    compile(
        (target / "__init__.py").read_text(encoding="utf-8"),
        str(target / "__init__.py"),
        "exec",
    )

    legacy_cache = custom_nodes / "ComfyUI-VideoHelperSuite" / "__pycache__"
    legacy_cache.mkdir(parents=True)
    stale_bytecode = legacy_cache / "nodes.cpython-311.pyc"
    stale_bytecode.write_bytes(b"stale")
    preserved = legacy_cache / "keep.txt"
    preserved.write_text("not bytecode", encoding="utf-8")
    managed_cache = target / ".vgen-deps" / "__pycache__"
    managed_cache.mkdir()
    managed_bytecode = managed_cache / "gguf.cpython-311.pyc"
    managed_bytecode.write_bytes(b"receipt-governed")

    # Extend the synthetic receipt so reuse proves the managed cache before
    # legacy cleanup deliberately skips the entire Node Pack directory.
    marker_path = target / ".vgen-node-pack.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["files"].append(
        {
            "path": ".vgen-deps/__pycache__/gguf.cpython-311.pyc",
            "sha256": hashlib.sha256(managed_bytecode.read_bytes()).hexdigest(),
            "size": managed_bytecode.stat().st_size,
        }
    )
    marker_path.write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    reused = installer.install(
        archive,
        expected_sha256=digest,
        expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
        expected_node_classes=("UnetLoaderGGUF",),
    )
    assert reused.status == "already_installed"
    assert host.pauses == 2
    assert not stale_bytecode.exists()
    assert preserved.is_file()
    assert managed_bytecode.is_file()
    assert len(wheel_calls) == 1

    (target / ".vgen-deps/gguf.py").write_text("tampered\n", encoding="utf-8")
    repaired = installer.install(
        archive,
        expected_sha256=digest,
        expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
        expected_node_classes=("UnetLoaderGGUF",),
    )
    assert repaired.status == "installed"
    assert host.pauses == 3
    assert len(wheel_calls) == 2


def test_failed_node_validation_rolls_back_previous_directory(tmp_path: Path) -> None:
    archive, digest = _archive(tmp_path)
    custom_nodes = tmp_path / "custom_nodes"
    existing = custom_nodes / "ComfyUI-GGUF"
    existing.mkdir(parents=True)
    (existing / "old.py").write_text("old\n", encoding="utf-8")
    work = tmp_path / "work"
    work.mkdir()
    host = HostControl()
    ticks = iter([0.0, 0.0, 2.0])
    python = tmp_path / "python.exe"
    python.write_bytes(b"python")

    installer = NodePackInstaller(
        work,
        custom_nodes,
        python,
        host,  # type: ignore[arg-type]
        lambda: set(),
        wheel_installer=lambda _python, _wheels, target: target.mkdir(),
        sleeper=lambda _seconds: None,
        monotonic=lambda: next(ticks),
    )

    with pytest.raises(NodePackInstallError, match="NODE_PACK_NODE_VALIDATION_FAILED"):
        installer.install(
            archive,
            expected_sha256=digest,
            expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
            expected_node_classes=("UnetLoaderGGUF",),
            probe_timeout=1,
        )
    assert host.pauses == 2
    assert (existing / "old.py").read_text(encoding="utf-8") == "old\n"
    assert not (existing / ".vgen-node-pack.json").exists()


def test_host_control_failure_is_reported_as_bounded_node_pack_reason(tmp_path: Path) -> None:
    archive, digest = _archive(tmp_path)
    custom_nodes = tmp_path / "custom_nodes"
    custom_nodes.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    python = tmp_path / "python.exe"
    python.write_bytes(b"python")
    installer = NodePackInstaller(
        work,
        custom_nodes,
        python,
        UnavailableHostControl(),  # type: ignore[arg-type]
        lambda: set(),
        wheel_installer=lambda _python, _wheels, target: target.mkdir(),
    )

    with pytest.raises(
        NodePackInstallError,
        match="NODE_PACK_COMFYUI_HOST_PAUSE_TIMEOUT",
    ):
        installer.install(
            archive,
            expected_sha256=digest,
            expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
            expected_node_classes=("UnetLoaderGGUF",),
        )


def test_rejects_wrong_artifact_digest_before_pause(tmp_path: Path) -> None:
    archive, _digest = _archive(tmp_path)
    custom_nodes = tmp_path / "custom_nodes"
    custom_nodes.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    host = HostControl()
    python = tmp_path / "python.exe"
    python.write_bytes(b"python")
    installer = NodePackInstaller(
        work,
        custom_nodes,
        python,
        host,  # type: ignore[arg-type]
        lambda: set(),
    )

    with pytest.raises(NodePackInstallError, match="NODE_PACK_ARTIFACT_DIGEST_MISMATCH"):
        installer.install(
            archive,
            expected_sha256="0" * 64,
            expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
            expected_node_classes=("UnetLoaderGGUF",),
        )
    assert host.pauses == 0


def test_fallback_runtime_rejects_native_wheel_before_install_or_pause(
    tmp_path: Path,
) -> None:
    archive, digest = _archive(
        tmp_path,
        wheel_name="gguf-0.17.1-cp311-cp311-win_amd64.whl",
    )
    custom_nodes = tmp_path / "custom_nodes"
    custom_nodes.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    host = HostControl()
    python = tmp_path / "python.exe"
    python.write_bytes(b"python")
    wheel_calls = 0

    def install_wheels(_python: Path, _wheels: tuple[Path, ...], _target: Path) -> None:
        nonlocal wheel_calls
        wheel_calls += 1

    installer = NodePackInstaller(
        work,
        custom_nodes,
        python,
        host,  # type: ignore[arg-type]
        lambda: set(),
        pure_python_only=True,
        wheel_installer=install_wheels,
    )

    with pytest.raises(NodePackInstallError, match="NODE_PACK_RUNTIME_INCOMPATIBLE"):
        installer.install(
            archive,
            expected_sha256=digest,
            expected_node_pack_ref="vgen/comfyui-gguf@1.0.0",
            expected_node_classes=("UnetLoaderGGUF",),
        )
    assert wheel_calls == 0
    assert host.pauses == 0
