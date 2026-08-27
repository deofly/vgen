from __future__ import annotations

import hashlib
import json
from pathlib import Path

from vgen.worker.windows_supervisor import prepare_windows_supervisor


def test_non_windows_runtime_does_not_require_managed_host(tmp_path: Path) -> None:
    assert prepare_windows_supervisor(tmp_path, platform="posix") is True


def test_stages_reviewed_supervisor_and_waits_for_fresh_host_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    local_app_data = tmp_path / "LocalAppData"
    vgen_root = local_app_data / "VGen"
    supervisor_root = vgen_root / "supervisor"
    work_root = vgen_root / "workers" / "wrk_test"
    supervisor_root.mkdir(parents=True)
    work_root.mkdir(parents=True)
    target = supervisor_root / "supervise-worker.ps1"
    target.write_bytes(b"old supervisor")
    reviewed = b"reviewed supervisor"
    digest = hashlib.sha256(reviewed).hexdigest()
    monkeypatch.setattr(
        "vgen.worker.windows_supervisor._bundled_supervisor",
        lambda: reviewed,
    )

    assert (
        prepare_windows_supervisor(
            work_root,
            platform="nt",
            local_app_data=str(local_app_data),
            clock=lambda: 1000,
        )
        is False
    )
    assert target.read_bytes() == reviewed

    (work_root / "host-control-status.json").write_text(
        json.dumps(
            {
                "format": "vgen-windows-worker-host-control",
                "version": 1,
                "process_id": 123,
                "script_sha256": digest,
                "heartbeat_at": 995,
            }
        ),
        encoding="utf-8",
    )
    assert (
        prepare_windows_supervisor(
            work_root,
            platform="nt",
            local_app_data=str(local_app_data),
            clock=lambda: 1000,
        )
        is True
    )


def test_rejects_stale_or_wrong_supervisor_receipt(tmp_path: Path, monkeypatch) -> None:
    local_app_data = tmp_path / "LocalAppData"
    vgen_root = local_app_data / "VGen"
    supervisor_root = vgen_root / "supervisor"
    work_root = vgen_root / "workers" / "wrk_test"
    supervisor_root.mkdir(parents=True)
    work_root.mkdir(parents=True)
    reviewed = b"reviewed supervisor"
    (supervisor_root / "supervise-worker.ps1").write_bytes(reviewed)
    monkeypatch.setattr(
        "vgen.worker.windows_supervisor._bundled_supervisor",
        lambda: reviewed,
    )
    (work_root / "host-control-status.json").write_text(
        json.dumps(
            {
                "format": "vgen-windows-worker-host-control",
                "version": 1,
                "process_id": 123,
                "script_sha256": "0" * 64,
                "heartbeat_at": 900,
            }
        ),
        encoding="utf-8",
    )

    assert (
        prepare_windows_supervisor(
            work_root,
            platform="nt",
            local_app_data=str(local_app_data),
            clock=lambda: 1000,
        )
        is False
    )
