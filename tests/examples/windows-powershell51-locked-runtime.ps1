#requires -Version 5.1

param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,

    [Parameter(Mandatory = $true)]
    [string]$BootstrapPython
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$env:PYTHONDONTWRITEBYTECODE = "1"

. (Join-Path $RepositoryRoot "examples\windows-worker\setup-worker.ps1")

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw $Message
    }
}

$config = [IO.File]::ReadAllText((Join-Path $BundleRoot "vgen-worker-bundle.json")) |
    ConvertFrom-Json
$requirements = Join-Path $BundleRoot ([string]$config.python_runtime.requirements.name)
$bootstrapPip = Join-Path $BundleRoot ([string]$config.python_runtime.bootstrap_pip.name)
$runtimeRoot = Join-Path $env:RUNNER_TEMP `
    "vgen-locked-runtime-$([Guid]::NewGuid().ToString('N'))"
$runtimeParent = Split-Path -Parent $runtimeRoot
$runtimeLeaf = Split-Path -Leaf $runtimeRoot

function Get-RuntimeDirectoryCount {
    return @(
        Get-ChildItem -LiteralPath $runtimeParent -Directory -Force |
            Where-Object { $_.Name -like "$runtimeLeaf*" }
    ).Count
}

$first = [string](Ensure-WorkerRuntime `
    $runtimeRoot `
    $BootstrapPython `
    ([string]$config.wheel.version) `
    $BundleRoot `
    $bootstrapPip `
    $requirements)
$expectedPython = Join-Path $runtimeRoot "Scripts\python.exe"
Assert-Condition ($first -ceq $expectedPython) "First install did not activate the canonical runtime."
$launcherHashCode = @'
import hashlib
import sys
import sysconfig
from pathlib import Path

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def launcher(root, base, installed, packaged, fallback):
    for candidate in (
        root / installed,
        root / packaged,
        base / fallback,
    ):
        if candidate.is_file():
            return candidate
    raise SystemExit(1)

target = Path(sys.argv[1])
trusted = Path(sys.executable)
launcher_root = Path(sysconfig.get_path("stdlib")) / "venv" / "scripts" / "nt"
console = launcher(launcher_root, trusted.parent, "python.exe", "venvlauncher.exe", "venvlauncher.exe")
windowed = launcher(launcher_root, trusted.parent, "pythonw.exe", "venvwlauncher.exe", "venvwlauncher.exe")
print(digest(target))
print(digest(console))
print(digest(target.with_name("pythonw.exe")))
print(digest(windowed))
'@
$launcherHashes = @(
    $launcherHashCode | & $BootstrapPython -I -B -S - $expectedPython
)
Assert-Condition ($LASTEXITCODE -eq 0 -and $launcherHashes.Count -eq 4) `
    "The trusted CPython venv launcher hashes could not be inspected."
Assert-Condition ($launcherHashes[0] -ceq $launcherHashes[1]) `
    "Scripts/python.exe is not the trusted CPython venv console launcher."
Assert-Condition ($launcherHashes[2] -ceq $launcherHashes[3]) `
    "Scripts/pythonw.exe is not the trusted CPython venv windowed launcher."
$basePythonHash = (Get-FileHash -LiteralPath $BootstrapPython -Algorithm SHA256).Hash.ToLowerInvariant()
Assert-Condition ($launcherHashes[0] -cne $basePythonHash) `
    "The native test did not distinguish the venv launcher from base python.exe."
Assert-Condition (Test-LockedWorkerRuntime $first $requirements $BootstrapPython) `
    "Fresh runtime did not match the lock."
$invalidRequirements = Join-Path $env:RUNNER_TEMP `
    "vgen-invalid-requirements-$([Guid]::NewGuid().ToString('N')).txt"
try {
    [IO.File]::WriteAllBytes($invalidRequirements, [byte[]]@(0xff))
    Assert-Condition (-not (Test-LockedWorkerRuntime `
        $first $invalidRequirements $BootstrapPython)) `
        "A verifier traceback escaped the fail-closed boolean contract."
    Assert-Condition ($ErrorActionPreference -ceq "Stop") `
        "Runtime verification changed the caller's error policy."
}
finally {
    if (Test-Path -LiteralPath $invalidRequirements -PathType Leaf) {
        Remove-Item -LiteralPath $invalidRequirements -Force
    }
}
$firstCount = Get-RuntimeDirectoryCount

$second = [string](Ensure-WorkerRuntime `
    $runtimeRoot `
    $BootstrapPython `
    ([string]$config.wheel.version) `
    $BundleRoot `
    $bootstrapPip `
    $requirements)
Assert-Condition ($second -ceq $first) "Second install selected a different runtime."
Assert-Condition ((Get-RuntimeDirectoryCount) -eq $firstCount) `
    "Second install leaked another runtime directory."

$runtimeScripts = Join-Path $runtimeRoot "Scripts"
foreach ($activationName in @(
        "activate",
        "activate.bat",
        "activate.fish",
        "Activate.ps1",
        "deactivate.bat"
    )) {
    Assert-Condition (-not (Test-Path -LiteralPath (Join-Path $runtimeScripts $activationName))) `
        "The closed Worker runtime retained activation script $activationName."
}
$unexpectedActivation = Join-Path $runtimeScripts "Activate.ps1"
[IO.File]::WriteAllText($unexpectedActivation, "Write-Host 'stale staging environment'`n")
Assert-Condition (-not (Test-LockedWorkerRuntime $first $requirements $BootstrapPython)) `
    "A recreated or modified Activate.ps1 was accepted."
[IO.File]::Delete($unexpectedActivation)

$sitePackages = (& $first -I -B -c "import sysconfig; print(sysconfig.get_path('purelib'))").Trim()
$untrackedPth = Join-Path $sitePackages "vgen-untracked-test.pth"
[IO.File]::WriteAllText($untrackedPth, "import definitely_unreviewed`n")
Assert-Condition (-not (Test-LockedWorkerRuntime $first $requirements $BootstrapPython)) `
    "An untracked .pth file was accepted."
[IO.File]::Delete($untrackedPth)

$untrackedModule = Join-Path $sitePackages "definitely_unreviewed.py"
[IO.File]::WriteAllText($untrackedModule, "VALUE = 1`n")
Assert-Condition (-not (Test-LockedWorkerRuntime $first $requirements $BootstrapPython)) `
    "An untracked module was accepted."
[IO.File]::Delete($untrackedModule)

$trackedModule = Join-Path $sitePackages "packaging\__init__.py"
[IO.File]::AppendAllText($trackedModule, "`n# tampered`n")
Assert-Condition (-not (Test-LockedWorkerRuntime $first $requirements $BootstrapPython)) `
    "A modified RECORD-tracked module was accepted."

$repaired = [string](Ensure-WorkerRuntime `
    $runtimeRoot `
    $BootstrapPython `
    ([string]$config.wheel.version) `
    $BundleRoot `
    $bootstrapPip `
    $requirements)
Assert-Condition ($repaired -ceq $expectedPython) `
    "Repair did not converge on the canonical runtime path."
Assert-Condition (Test-LockedWorkerRuntime $repaired $requirements $BootstrapPython) `
    "Repaired runtime did not match the lock."
$repairedCount = Get-RuntimeDirectoryCount
$afterRepair = [string](Ensure-WorkerRuntime `
    $runtimeRoot `
    $BootstrapPython `
    ([string]$config.wheel.version) `
    $BundleRoot `
    $bootstrapPip `
    $requirements)
Assert-Condition ($afterRepair -ceq $repaired) "Repeated repair selected a new runtime."
Assert-Condition ((Get-RuntimeDirectoryCount) -eq $repairedCount) `
    "Repeated repair leaked another runtime directory."

$runtimeConfiguration = Join-Path $runtimeRoot "pyvenv.cfg"
[IO.File]::AppendAllText($runtimeConfiguration, "unexpected = value`n")
Assert-Condition (-not (Test-LockedWorkerRuntime $repaired $requirements $BootstrapPython)) `
    "A modified pyvenv.cfg was accepted."
$configurationRepair = [string](Ensure-WorkerRuntime `
    $runtimeRoot `
    $BootstrapPython `
    ([string]$config.wheel.version) `
    $BundleRoot `
    $bootstrapPip `
    $requirements)
Assert-Condition ($configurationRepair -ceq $expectedPython) `
    "pyvenv.cfg repair did not converge on the canonical runtime path."
Assert-Condition ((Get-RuntimeDirectoryCount) -eq $firstCount) `
    "pyvenv.cfg repair leaked a quarantine or staging directory."

[IO.File]::AppendAllText($configurationRepair, "tamper")
Assert-Condition (-not (Test-LockedWorkerRuntime `
    $configurationRepair $requirements $BootstrapPython)) `
    "A modified Scripts/python.exe was accepted."
$executableRepair = [string](Ensure-WorkerRuntime `
    $runtimeRoot `
    $BootstrapPython `
    ([string]$config.wheel.version) `
    $BundleRoot `
    $bootstrapPip `
    $requirements)
Assert-Condition ($executableRepair -ceq $expectedPython) `
    "python.exe repair did not converge on the canonical runtime path."
Assert-Condition ((Get-RuntimeDirectoryCount) -eq $firstCount) `
    "Repeated executable repair leaked a quarantine or staging directory."

$outsideJunctionTarget = Join-Path $env:RUNNER_TEMP `
    "vgen-runtime-junction-target-$([Guid]::NewGuid().ToString('N'))"
[IO.Directory]::CreateDirectory($outsideJunctionTarget) | Out-Null
$runtimeJunction = Join-Path $sitePackages "vgen-runtime-reparse-test"
New-Item -ItemType Junction -Path $runtimeJunction -Target $outsideJunctionTarget | Out-Null
Assert-Condition (-not (Test-LockedWorkerRuntime `
    $executableRepair $requirements $BootstrapPython)) `
    "A runtime reparse-point descendant was accepted."
[IO.Directory]::Delete($runtimeJunction, $false)
[IO.Directory]::Delete($outsideJunctionTarget, $false)

$unexpectedRootFile = Join-Path $runtimeRoot "sitecustomize.py"
[IO.File]::WriteAllText($unexpectedRootFile, "raise RuntimeError('unreviewed')`n")
Assert-Condition (-not (Test-LockedWorkerRuntime `
    $executableRepair $requirements $BootstrapPython)) `
    "An unexpected runtime-root file was accepted."
[IO.File]::Delete($unexpectedRootFile)

$rogue = Join-Path $sitePackages "rogue-1.0.dist-info"
[IO.Directory]::CreateDirectory($rogue) | Out-Null
[IO.File]::WriteAllText(
    (Join-Path $rogue "METADATA"),
    "Metadata-Version: 2.4`nName: rogue`nVersion: 1.0`n"
)
[IO.File]::WriteAllText((Join-Path $rogue "RECORD"), "rogue-1.0.dist-info/RECORD,,`n")
Assert-Condition (-not (Test-LockedWorkerRuntime `
    $executableRepair $requirements $BootstrapPython)) `
    "An extra installed distribution was accepted."

Write-Host "Windows PowerShell 5.1 locked-runtime checks passed."
