from __future__ import annotations

from pathlib import Path

import pytest

from vgen.worker.support_assets import refresh_windows_support_assets
from vgen.worker.updater import WorkerUpdateError

_NAMES = ("enroll-worker.ps1", "setup-worker.ps1", "start-worker.cmd")


def _assets(path: Path, prefix: str) -> None:
    path.mkdir(parents=True)
    for name in _NAMES:
        (path / name).write_text(f"{prefix}:{name}\n", encoding="utf-8")


def test_refresh_windows_support_assets_is_atomic_and_idempotent(tmp_path: Path) -> None:
    allowed = tmp_path / "VGen" / "installer"
    target = allowed / "0.9.5-example"
    source = tmp_path / "reviewed"
    _assets(target, "old")
    _assets(source, "new")

    launcher = target / "start-worker.cmd"
    assert refresh_windows_support_assets(
        launcher=launcher,
        asset_root=source,
        allowed_root=allowed,
    ) == launcher.resolve()
    assert {name: (target / name).read_text() for name in _NAMES} == {
        name: f"new:{name}\n" for name in _NAMES
    }
    assert (
        refresh_windows_support_assets(
            launcher=launcher,
            asset_root=source,
            allowed_root=allowed,
        )
        is None
    )


def test_refresh_windows_support_assets_rejects_outside_launcher(tmp_path: Path) -> None:
    allowed = tmp_path / "VGen" / "installer"
    allowed.mkdir(parents=True)
    target = tmp_path / "outside"
    source = tmp_path / "reviewed"
    _assets(target, "old")
    _assets(source, "new")

    with pytest.raises(WorkerUpdateError, match="WORKER_SUPPORT_LAUNCHER_INVALID"):
        refresh_windows_support_assets(
            launcher=target / "start-worker.cmd",
            asset_root=source,
            allowed_root=allowed,
        )


def test_refresh_windows_support_assets_rejects_target_symlink(tmp_path: Path) -> None:
    allowed = tmp_path / "VGen" / "installer"
    target = allowed / "0.9.5-example"
    source = tmp_path / "reviewed"
    _assets(target, "old")
    _assets(source, "new")
    (target / "setup-worker.ps1").unlink()
    (target / "setup-worker.ps1").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(WorkerUpdateError, match="WORKER_SUPPORT_ASSET_CONFLICT"):
        refresh_windows_support_assets(
            launcher=target / "start-worker.cmd",
            asset_root=source,
            allowed_root=allowed,
        )


def test_refresh_uses_stable_launcher_pointer_when_environment_is_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    vgen_root = tmp_path / "VGen"
    allowed = vgen_root / "installer"
    target = allowed / "0.13.6-0123456789ab"
    source = tmp_path / "reviewed"
    _assets(target, "old")
    _assets(source, "new")
    stable = vgen_root / "start-worker.cmd"
    stable.write_text(
        '@echo off\r\nset "VGEN_WORKER_VERSION_LAUNCHER=%~dp0installer\\0.13.6-0123456789ab\\start-worker.cmd"\r\n',
        encoding="ascii",
    )
    monkeypatch.delenv("VGEN_WORKER_VERSION_LAUNCHER", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    assert refresh_windows_support_assets(asset_root=source) == (
        target / "start-worker.cmd"
    ).resolve()
