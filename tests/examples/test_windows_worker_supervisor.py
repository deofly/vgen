from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR = ROOT / "examples" / "windows-worker" / "supervise-worker.ps1"
SETUP = ROOT / "examples" / "windows-worker" / "setup-worker.ps1"
ENROLL = ROOT / "examples" / "windows-worker" / "enroll-worker.ps1"


def test_supervisor_uses_task_scheduler_without_system_or_detached_restart() -> None:
    text = SUPERVISOR.read_text(encoding="utf-8")
    assert "New-ScheduledTaskTrigger -AtLogOn -User $identity.Name" in text
    assert "-LogonType Interactive" in text
    assert "-RunLevel Limited" in text
    assert "-MultipleInstances IgnoreNew" in text
    assert "-WindowStyle Hidden" in text
    assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in text
    assert "-RestartCount 999" in text
    assert 'if ($identity.User.Value -eq "S-1-5-18")' in text
    assert "LocalSystem" in text
    assert "-LogonType S4U" not in text
    assert "-RunLevel Highest" not in text
    assert "os.startfile" not in text


def test_supervisor_starts_worker_before_comfy_and_restarts_them_independently() -> None:
    text = SUPERVISOR.read_text(encoding="utf-8")
    assert '$env:PYTHONDONTWRITEBYTECODE = "1"' in text
    worker_start = text.index('Start-OwnedProcess $launch.Worker "worker"')
    comfy_start = text.index('Start-OwnedProcess $launch.ComfyUI "comfyui"')
    assert worker_start < comfy_start
    assert "Worker launch failed" in text
    assert "ComfyUI launch failed" in text
    assert "while Worker control stays online" in text
    assert "Stop-OwnedProcessTree $ownedProcess $ownedName" in text
    assert "& $taskKill /PID ([string]$ownedProcessId) /T /F" in text
    assert 'Join-Path $env:SystemRoot "System32\\taskkill.exe"' not in text
    assert '"System32", "taskkill.exe"' in text
    assert "Get-Process" not in text
    assert "Stop-Process" not in text
    assert "$MaxLogBytes = [Int64](8 * 1024 * 1024)" in text
    assert "$MaxChildLogFiles = 12" in text
    assert "Remove-StaleChildLogs $LogRoot $Name" in text
    assert '-RedirectStandardOutput "NUL"' in text
    assert "log limit reached" not in text
    assert "$forcedDeadline = [DateTimeOffset]::Now.AddSeconds(10)" in text


def test_setup_persists_closed_launch_config_then_hands_off_to_task() -> None:
    text = SETUP.read_text(encoding="utf-8")
    config_write = text.index("Write-WorkerLaunchConfig")
    install = text.index("-Mode Install", config_write)
    stop_comfy = text.index("Stop-VGenManagedComfyUI", install)
    start = text.index("-Mode Start", stop_comfy)
    assert config_write < install < stop_comfy < start
    assert 'format = "vgen-windows-worker-launch-config"' in text
    assert 'Join-Path $workRoot "launch-config.json"' in text
    assert "[Text.UTF8Encoding]::new($false)" in text
    assert "Replace-FileAtomically $temporary $Path" in text
    assert "[IO.File]::Replace($Source, $Destination, $backup)" in text
    assert "[IO.File]::Replace($temporary, $Path, $null)" not in text
    assert "private_key" not in text
    assert "session_token" not in text


def test_enrollment_requires_and_checksums_the_supervisor_asset() -> None:
    text = ENROLL.read_text(encoding="utf-8")
    assert text.count('"supervise-worker.ps1"') == 3
    assert "Worker installer integrity check failed" in text
    assert "$supervisorStoppedForRepair = $supervisorWasRunning" in text
    assert "-File $bundledSupervisor" in text
    assert "-Mode Status" in text
    assert "Repairing the persistent supervisor controller before stopping its task" in text
    assert "$supervisorHostConfigSnapshot = [IO.File]::ReadAllBytes" in text
    assert "$supervisorLaunchConfigSnapshot = [IO.File]::ReadAllBytes" in text
    assert "Restore-FileSnapshot" in text
    assert "restarting the previously installed supervisor" in text
    assert "-Mode Start" in text
    assert "Replace-FileAtomically $temporary $Path" in text
    assert "[IO.File]::Replace($Source, $Destination, $backup)" in text
    assert "[IO.File]::Replace($temporary, $Path, $null)" not in text


def test_windows_atomic_file_replacement_never_discards_a_failure_backup() -> None:
    for path in (ENROLL, SETUP, SUPERVISOR):
        text = path.read_text(encoding="utf-8")
        start = text.index("function Replace-FileAtomically")
        end = text.index("\nfunction ", start + 1)
        helper = text[start:end]

        replace = helper.index("[IO.File]::Replace($Source, $Destination, $backup)")
        committed = helper.index("$replacementCommitted = $true", replace)
        restore = helper.index("[IO.File]::Move($backup, $Destination)", committed)
        guarded_cleanup = helper.index(
            "$replacementCommitted -and (Test-Path -LiteralPath $backup -PathType Leaf)",
            restore,
        )
        delete = helper.index("[IO.File]::Delete($backup)", guarded_cleanup)

        assert replace < committed < restore < guarded_cleanup < delete
        assert "original file backup remains at $backup" in helper
        assert "if (Test-Path -LiteralPath $backup) {\n            try" not in helper


def test_runtime_update_no_longer_mutates_or_relaunches_installer_scripts() -> None:
    worker_root = ROOT / "src" / "vgen" / "worker"
    combined = "\n".join(path.read_text(encoding="utf-8") for path in worker_root.glob("*.py"))
    assert "schedule_windows_launcher_restart" not in combined
    assert "refresh_windows_support_assets" not in combined
    assert "os.startfile" not in combined
    assert "EXIT_LAUNCHER_RESTART" not in combined
