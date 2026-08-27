#requires -Version 5.1

<#
.SYNOPSIS
Enrolls a credential-free VGen Windows Worker, then starts reviewed setup.

.DESCRIPTION
This public bootstrap contains no Worker ID, session, private key, or Invite
secret.  It generates a Worker key on this Windows host and asks for the
one-time Invite URI through VGen's hidden console prompt.  The secret is never
accepted as a PowerShell parameter or command-line argument.
#>

[CmdletBinding()]
param(
    [string]$WorkerName,
    [string]$ComfyUIRoot,
    [string]$ComfyUIDataRoot,
    [switch]$Reenroll,
    [switch]$Repair
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:PYTHONDONTWRITEBYTECODE = "1"
$managedSupervisorForRecovery = $null
$powerShellForRecovery = $null
$supervisorStoppedForRepair = $false
$supervisorHostConfigPath = $null
$supervisorHostConfigSnapshot = $null
$supervisorLaunchConfigPath = $null
$supervisorLaunchConfigSnapshot = $null

function Write-Step {
    param([string]$Message)
    Write-Host "[vgen] $Message"
}

function Resolve-WindowsSystemTool {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        throw "The Windows system directory could not be located."
    }
    $path = [System.IO.Path]::Combine($env:SystemRoot, "System32", $Name)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Windows system tool is missing: $Name"
    }
    return $path
}

function Assert-RegularLocalFile {
    param([string]$Path, [string]$Description)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description is missing from the Worker installer."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a symbolic link or reparse point."
    }
    return $item.FullName
}

function Test-PathInside {
    param([string]$Path, [string]$Root)

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd("\")
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd("\")
    return $fullPath.Equals($fullRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($fullRoot + "\", [StringComparison]::OrdinalIgnoreCase)
}

function Replace-FileAtomically {
    param([string]$Source, [string]$Destination)

    $parent = Split-Path -Parent $Destination
    $backup = Join-Path $parent ".$([IO.Path]::GetFileName($Destination)).$([Guid]::NewGuid().ToString('N')).bak"
    $replacementCommitted = $false
    try {
        # Windows PowerShell 5.1 requires a real backup path here.
        [IO.File]::Replace($Source, $Destination, $backup)
        $replacementCommitted = $true
    }
    catch {
        $replacementFailure = $_
        if ((Test-Path -LiteralPath $backup -PathType Leaf) -and
            -not (Test-Path -LiteralPath $Destination)) {
            try {
                [IO.File]::Move($backup, $Destination)
            }
            catch {
                throw "Atomic file replacement failed and the original file could not be restored; its backup remains at $backup"
            }
        }
        if (Test-Path -LiteralPath $backup) {
            throw "Atomic file replacement failed; the original file backup remains at $backup"
        }
        throw $replacementFailure
    }
    finally {
        # ReplaceFile can fail after moving the old destination to Backup. Only
        # discard that recovery copy after the replacement definitely committed.
        if ($replacementCommitted -and (Test-Path -LiteralPath $backup -PathType Leaf)) {
            try { [IO.File]::Delete($backup) }
            catch { Write-Warning "A temporary VGen replacement backup could not be removed: $backup" }
        }
    }
}

function Restore-FileSnapshot {
    param([string]$Path, [byte[]]$Value, [string]$Description)

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "$Description parent directory is missing."
    }
    $parentItem = Get-Item -LiteralPath $parent -Force
    if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description parent directory is unsafe."
    }
    $temporary = Join-Path $parent ".$([IO.Path]::GetFileName($Path)).$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($temporary, $Value)
        if (Test-Path -LiteralPath $Path) {
            $existing = Get-Item -LiteralPath $Path -Force
            if ($existing.PSIsContainer -or
                ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Description path is unsafe."
            }
            Replace-FileAtomically $temporary $Path
        }
        else {
            [IO.File]::Move($temporary, $Path)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Assert-CredentialAcl {
    param([string]$Path)

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentSid = $identity.User.Value
        $allowedSids = @(
            $currentSid,
            "S-1-5-18",       # NT AUTHORITY\SYSTEM
            "S-1-5-32-544"   # BUILTIN\Administrators
        )
        $acl = Get-Acl -LiteralPath $Path
        $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $rules = $acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        )
    }
    catch {
        throw "Worker credential access rules could not be verified."
    }
    if (-not $acl.AreAccessRulesProtected) {
        throw "Worker credential must disable inherited access rules."
    }
    if ($ownerSid -notin $allowedSids) {
        throw "Worker credential has an unapproved owner."
    }
    $currentUserAllowed = $false
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $ruleSid = $rule.IdentityReference.Value
        if ($ruleSid -notin $allowedSids) {
            throw "Worker credential grants access to an unapproved principal."
        }
        if ($ruleSid -eq $currentSid -and
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
                [System.Security.AccessControl.FileSystemRights]::FullControl)) {
            $currentUserAllowed = $true
        }
    }
    if (-not $currentUserAllowed) {
        throw "Worker credential does not grant full control to the current Windows user."
    }
}

function Protect-CredentialAcl {
    param([string]$Path)

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentSid = $identity.User.Value
    }
    catch {
        throw "The current Windows user could not be identified for credential protection."
    }
    $icaclsPath = Resolve-WindowsSystemTool "icacls.exe"
    & $icaclsPath $Path /setowner "*$currentSid" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Worker credential owner could not be secured."
    }
    & $icaclsPath $Path /inheritance:r /grant:r "*$($currentSid):F" `
        "*S-1-5-18:F" "*S-1-5-32-544:F" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Worker credential access rules could not be secured."
    }
    Assert-CredentialAcl $Path
}

function Assert-ClosedBundleDirectory {
    param([string]$Root)
    $allowedNames = @(
        "INSTALL.txt",
        "enroll-worker.ps1",
        "start-worker.cmd",
        "setup-worker.ps1",
        "supervise-worker.ps1",
        "vgen-worker-bundle.json",
        "comfyui-minimax-h3-policy.yaml",
        "vgen-worker-requirements.txt",
        "SHA256SUMS"
    )
    $wheelCount = 0
    foreach ($item in @(Get-ChildItem -LiteralPath $Root -Force)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.PSIsContainer) {
            throw "The Worker installer folder contains an unsafe entry: $($item.Name)"
        }
        if ($allowedNames -ccontains $item.Name) {
            continue
        }
        if ($item.Name -cmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.whl$') {
            $wheelCount += 1
            continue
        }
        throw "The Worker installer folder contains an unexpected entry: $($item.Name)"
    }
    if ($wheelCount -lt 2 -or $wheelCount -gt 128) {
        throw "The Worker installer folder has an invalid reviewed wheel count."
    }
}

function Resolve-Python311 {
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates.Add((Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates.Add((Join-Path $env:ProgramFiles "Python311\python.exe"))
    }
    $programFilesX86 = [System.Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $candidates.Add((Join-Path $programFilesX86 "Python311\python.exe"))
    }
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        try {
            $launcherPath = (& $py.Source -3.11 -I -B -c "import sys; print(sys.executable)" 2>$null |
                Select-Object -Last 1).Trim()
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($launcherPath)) {
                $candidates.Insert(0, $launcherPath)
            }
        }
        catch {
            # Continue through fixed, reviewable locations.
        }
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        $item = Get-Item -LiteralPath $candidate -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            continue
        }
        & $item.FullName -I -B -c "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $item.FullName
        }
    }
    return $null
}

function Ensure-Python311 {
    $python = Resolve-Python311
    if (-not [string]::IsNullOrWhiteSpace($python)) {
        return $python
    }
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        throw "Python 3.11 is required and Windows Package Manager (winget) is unavailable."
    }
    Write-Step "Installing Python 3.11 for the current user"
    & $winget.Source install --id Python.Python.3.11 --exact --scope user --silent `
        --disable-interactivity --accept-package-agreements --accept-source-agreements | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "winget could not install Python 3.11."
    }
    $python = Resolve-Python311
    if ([string]::IsNullOrWhiteSpace($python)) {
        throw "Python 3.11 was installed but could not be found in a reviewed location."
    }
    return $python
}

function Remove-WorkerRuntimeActivationScripts {
    param([string]$StagingRoot)

    $scriptsRoot = Join-Path $StagingRoot "Scripts"
    if (-not (Test-Path -LiteralPath $scriptsRoot -PathType Container)) {
        throw "The new Worker Python runtime has no Scripts directory."
    }
    $scriptsItem = Get-Item -LiteralPath $scriptsRoot -Force
    if (($scriptsItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The new Worker Python Scripts directory is unsafe."
    }
    foreach ($activationName in @(
            "activate",
            "activate.bat",
            "Activate.ps1",
            "deactivate.bat"
        )) {
        $activationPath = Join-Path $scriptsRoot $activationName
        if (-not (Test-Path -LiteralPath $activationPath -PathType Leaf)) {
            throw "The new Worker Python runtime has an unexpected activation-script layout."
        }
        $activationItem = Get-Item -LiteralPath $activationPath -Force
        if ($activationItem.PSIsContainer -or
            ($activationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The new Worker Python runtime contains an unsafe activation script."
        }
        [System.IO.File]::Delete($activationItem.FullName)
    }

    $requiredLaunchers = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $null = $requiredLaunchers.Add("python.exe")
    $null = $requiredLaunchers.Add("pythonw.exe")
    foreach ($remaining in @(Get-ChildItem -LiteralPath $scriptsRoot -Force)) {
        if ($remaining.PSIsContainer -or
            ($remaining.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not $requiredLaunchers.Remove($remaining.Name)) {
            throw "The new Worker Python Scripts directory is not closed before package installation."
        }
    }
    if ($requiredLaunchers.Count -ne 0) {
        throw "The new Worker Python runtime is missing a required CPython launcher."
    }
}

function Test-LockedWorkerRuntime {
    param(
        [string]$Python,
        [string]$Requirements,
        [string]$TrustedPython
    )
    if ([string]::IsNullOrWhiteSpace($TrustedPython) -or
        -not (Test-Path -LiteralPath $Python -PathType Leaf) -or
        -not (Test-Path -LiteralPath $Requirements -PathType Leaf) -or
        -not (Test-Path -LiteralPath $TrustedPython -PathType Leaf)) {
        return $false
    }
    foreach ($verificationInput in @($Python, $Requirements, $TrustedPython)) {
        try {
            $verificationItem = Get-Item -LiteralPath $verificationInput -Force
            if ($verificationItem.PSIsContainer -or
                ($verificationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
        }
        catch {
            return $false
        }
    }
    $verificationCode = @'
import base64
import csv
import hashlib
import io
import os
import platform
import re
import sys
import sysconfig
from importlib import metadata
from pathlib import Path

def is_reparse(path):
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        raise SystemExit(1)
    return path.is_symlink() or bool(attributes & 0x400)

def canonicalize_name(value):
    return re.sub(r"[-_.]+", "-", value).lower()

def same_path(left, right):
    return os.path.normcase(str(left.resolve(strict=True))) == os.path.normcase(
        str(right.resolve(strict=True))
    )

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()

if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11):
    raise SystemExit(1)
trusted_python = Path(sys.executable)
target_python = Path(sys.argv[1])
requirements_path = Path(sys.argv[2])
if target_python.name != "python.exe" or target_python.parent.name != "Scripts":
    raise SystemExit(1)
runtime_path = target_python.parent.parent
runtime_root = runtime_path.resolve(strict=True)
if is_reparse(runtime_path) or same_path(trusted_python, target_python):
    raise SystemExit(1)
if not same_path(target_python, runtime_path / "Scripts" / "python.exe"):
    raise SystemExit(1)

root_entries = {entry.name: entry for entry in runtime_path.iterdir()}
if set(root_entries) != {"Include", "Lib", "Scripts", "pyvenv.cfg"}:
    raise SystemExit(1)
for directory_name in ("Include", "Lib", "Scripts"):
    directory = root_entries[directory_name]
    if is_reparse(directory) or not directory.is_dir():
        raise SystemExit(1)
if set(entry.name for entry in (runtime_path / "Lib").iterdir()) != {"site-packages"}:
    raise SystemExit(1)

site_path = runtime_path / "Lib" / "site-packages"
site_root = site_path.resolve(strict=True)
try:
    site_root.relative_to(runtime_root)
except ValueError:
    raise SystemExit(1)
if is_reparse(site_path) or not site_root.is_dir():
    raise SystemExit(1)

target_pythonw = runtime_path / "Scripts" / "pythonw.exe"
for executable in (target_python, target_pythonw, trusted_python):
    if is_reparse(executable) or not executable.is_file():
        raise SystemExit(1)
if (
    trusted_python.name.casefold() != "python.exe"
    or bool(sysconfig.get_config_var("Py_DEBUG"))
    or sysconfig.is_python_build()
):
    raise SystemExit(1)

trusted_stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
launcher_root = trusted_stdlib / "venv" / "scripts" / "nt"
if is_reparse(trusted_stdlib) or is_reparse(launcher_root) or not launcher_root.is_dir():
    raise SystemExit(1)

def locate_launcher(installed_name, packaged_name, fallback_name):
    candidates = (
        launcher_root / installed_name,
        launcher_root / packaged_name,
        trusted_python.parent / fallback_name,
    )
    for candidate in candidates:
        if not candidate.exists():
            continue
        resolved = candidate.resolve(strict=True)
        try:
            if candidate.parent == launcher_root:
                resolved.relative_to(trusted_stdlib)
            else:
                resolved.relative_to(trusted_python.parent.resolve(strict=True))
        except ValueError:
            raise SystemExit(1)
        if is_reparse(candidate) or not candidate.is_file():
            raise SystemExit(1)
        return candidate
    raise SystemExit(1)

console_launcher = locate_launcher("python.exe", "venvlauncher.exe", "venvlauncher.exe")
windowed_launcher = locate_launcher("pythonw.exe", "venvwlauncher.exe", "venvwlauncher.exe")
if sha256_file(target_python) != sha256_file(console_launcher):
    raise SystemExit(1)
if sha256_file(target_pythonw) != sha256_file(windowed_launcher):
    raise SystemExit(1)

configuration_path = runtime_path / "pyvenv.cfg"
if is_reparse(configuration_path) or not configuration_path.is_file():
    raise SystemExit(1)
try:
    configuration_value = configuration_path.read_text(encoding="utf-8")
except (OSError, UnicodeError):
    raise SystemExit(1)
if not 1 <= len(configuration_value) <= 16384 or "\x00" in configuration_value:
    raise SystemExit(1)
configuration = {}
for raw_line in configuration_value.splitlines():
    key, separator, value = raw_line.partition(" = ")
    if not separator or not key or key in configuration or not value:
        raise SystemExit(1)
    configuration[key] = value
if set(configuration) != {
    "home",
    "include-system-site-packages",
    "version",
    "executable",
    "command",
}:
    raise SystemExit(1)
try:
    home_matches = same_path(Path(configuration["home"]), trusted_python.parent)
    executable_matches = same_path(Path(configuration["executable"]), trusted_python)
except OSError:
    raise SystemExit(1)
command = configuration["command"]
if (
    not home_matches
    or not executable_matches
    or configuration["include-system-site-packages"].casefold() != "false"
    or configuration["version"] != platform.python_version()
    or " -m venv --without-pip " not in command
    or os.path.normcase(str(runtime_path)) not in os.path.normcase(command)
):
    raise SystemExit(1)

expected = {}
for raw in requirements_path.read_text(encoding="ascii").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    match = re.fullmatch(
        r"([A-Za-z0-9][A-Za-z0-9._-]*)(\[worker-comfyui\])?"
        r"==([A-Za-z0-9][A-Za-z0-9.!+_-]*) --hash=sha256:[0-9a-f]{64}",
        line,
    )
    if match is None:
        raise SystemExit(1)
    name = canonicalize_name(match.group(1))
    extra = match.group(2)
    if (name == "vgen" and extra != "[worker-comfyui]") or (name != "vgen" and extra):
        raise SystemExit(1)
    if name in expected:
        raise SystemExit(1)
    expected[name] = match.group(3)

installed = {}
distributions = list(metadata.distributions(path=[str(site_root)]))
for distribution in distributions:
    name = canonicalize_name(distribution.metadata.get("Name", ""))
    if not name or name in installed:
        raise SystemExit(1)
    installed[name] = distribution.version
if installed != expected:
    raise SystemExit(1)

tracked = set()
for distribution in distributions:
    record = distribution.read_text("RECORD")
    if record is None:
        raise SystemExit(1)
    distribution_paths = set()
    for relative, encoded_hash, raw_size in csv.reader(io.StringIO(record)):
        try:
            raw_target = Path(distribution.locate_file(relative))
            target = raw_target.resolve()
            target.relative_to(runtime_root)
        except (OSError, ValueError):
            raise SystemExit(1)
        if is_reparse(raw_target) or target in distribution_paths or target in tracked:
            raise SystemExit(1)
        if not encoded_hash:
            if not relative.endswith(".dist-info/RECORD") or raw_size:
                raise SystemExit(1)
            distribution_paths.add(target)
            tracked.add(target)
            continue
        try:
            algorithm, encoded = encoded_hash.split("=", 1)
            value = target.read_bytes()
        except (OSError, ValueError):
            raise SystemExit(1)
        if algorithm != "sha256" or not raw_size.isdecimal() or len(value) != int(raw_size):
            raise SystemExit(1)
        actual = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
        if actual != encoded:
            raise SystemExit(1)
        distribution_paths.add(target)
        tracked.add(target)

baseline_files = {
    configuration_path.resolve(strict=True),
    target_python.resolve(strict=True),
    target_pythonw.resolve(strict=True),
}
for forbidden_activation_name in (
    "activate",
    "activate.bat",
    "activate.fish",
    "Activate.ps1",
    "deactivate.bat",
):
    if (runtime_path / "Scripts" / forbidden_activation_name).exists():
        raise SystemExit(1)

allowed_directories = {
    runtime_root,
    (runtime_path / "Include").resolve(strict=True),
    (runtime_path / "Lib").resolve(strict=True),
    site_root,
    (runtime_path / "Scripts").resolve(strict=True),
}
for target in tracked:
    parent = target.parent
    while parent != runtime_root:
        allowed_directories.add(parent)
        parent = parent.parent

for directory, directory_names, file_names in os.walk(runtime_root, followlinks=False):
    parent = Path(directory)
    for entry in (*directory_names, *file_names):
        if is_reparse(parent / entry):
            raise SystemExit(1)
    for directory_name in directory_names:
        if (parent / directory_name).resolve(strict=True) not in allowed_directories:
            raise SystemExit(1)
    for file_name in file_names:
        resolved_file = (parent / file_name).resolve(strict=True)
        if resolved_file not in tracked and resolved_file not in baseline_files:
            raise SystemExit(1)
'@
    & $TrustedPython -I -B -S -c $verificationCode $Python $Requirements 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Install-LockedWorkerPythonPackages {
    param(
        [string]$Python,
        [string]$BundleRoot,
        [string]$BootstrapPip,
        [string]$Requirements,
        [string]$TrustedPython
    )
    $bootstrapCode = "import sys; sys.path.insert(0, sys.argv.pop(1)); from pip._internal.cli.main import main; raise SystemExit(main())"
    & $Python -I -B -c $bootstrapCode $BootstrapPip install `
        --disable-pip-version-check `
        --no-index `
        --find-links $BundleRoot `
        --require-hashes `
        --only-binary=:all: `
        --no-compile `
        -r $Requirements | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "The reviewed offline Worker Python dependencies could not be installed."
    }
    & $Python -I -B -m pip check | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "The reviewed Worker Python dependency set is inconsistent."
    }
    if (-not (Test-LockedWorkerRuntime $Python $Requirements $TrustedPython)) {
        throw "The installed Worker Python files do not match the reviewed dependency lock."
    }
}

function Remove-ClosedWorkerRuntimeTree {
    param(
        [string]$RuntimeRoot,
        [string]$CandidateRoot
    )
    $runtimeFull = [System.IO.Path]::GetFullPath($RuntimeRoot).TrimEnd("\")
    $candidateFull = [System.IO.Path]::GetFullPath($CandidateRoot).TrimEnd("\")
    $allowed = @(
        "$runtimeFull-invalid",
        "$runtimeFull-staging"
    )
    if ($candidateFull -cnotin $allowed -or
        -not [System.IO.Path]::GetDirectoryName($candidateFull).Equals(
            [System.IO.Path]::GetDirectoryName($runtimeFull),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Worker runtime cleanup refused an unexpected path."
    }
    if (-not (Test-Path -LiteralPath $candidateFull)) {
        return
    }

    $removeEntry = $null
    $removeEntry = {
        param([string]$Path)
        $item = Get-Item -LiteralPath $Path -Force
        $isReparse = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        if ($item.PSIsContainer -and -not $isReparse) {
            foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force)) {
                & $removeEntry $child.FullName
            }
            $item.Attributes = [System.IO.FileAttributes]::Directory
            [System.IO.Directory]::Delete($item.FullName, $false)
            return
        }
        if ($item.PSIsContainer) {
            [System.IO.Directory]::Delete($item.FullName, $false)
            return
        }
        $item.Attributes = [System.IO.FileAttributes]::Normal
        [System.IO.File]::Delete($item.FullName)
    }
    & $removeEntry $candidateFull
}

function Complete-LockedWorkerRuntime {
    param(
        [string]$StagingRoot,
        [string]$RuntimeRoot
    )
    $quarantine = "$RuntimeRoot-invalid"
    $movedExisting = $false
    if (Test-Path -LiteralPath $quarantine) {
        Remove-ClosedWorkerRuntimeTree $RuntimeRoot $quarantine
    }
    if (Test-Path -LiteralPath $RuntimeRoot) {
        $existing = Get-Item -LiteralPath $RuntimeRoot -Force
        if (-not $existing.PSIsContainer -or
            ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The existing Worker Python runtime is not a safe local directory."
        }
        [System.IO.Directory]::Move($RuntimeRoot, $quarantine)
        $movedExisting = $true
    }
    try {
        [System.IO.Directory]::Move($StagingRoot, $RuntimeRoot)
    }
    catch {
        if ($movedExisting -and -not (Test-Path -LiteralPath $RuntimeRoot) -and
            (Test-Path -LiteralPath $quarantine -PathType Container)) {
            [System.IO.Directory]::Move($quarantine, $RuntimeRoot)
        }
        throw
    }
    if ($movedExisting -and (Test-Path -LiteralPath $quarantine)) {
        try {
            Remove-ClosedWorkerRuntimeTree $RuntimeRoot $quarantine
        }
        catch {
            Write-Warning "The replaced Worker runtime remains in its bounded quarantine path: $quarantine"
        }
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for VGen's private Worker enrollment state."
    }
    Assert-ClosedBundleDirectory $PSScriptRoot
    $bundleConfigPath = Assert-RegularLocalFile `
        (Join-Path $PSScriptRoot "vgen-worker-bundle.json") "Worker bundle configuration"
    $checksumsPath = Assert-RegularLocalFile `
        (Join-Path $PSScriptRoot "SHA256SUMS") "Worker bundle checksum list"
    try {
        $config = [System.IO.File]::ReadAllText($bundleConfigPath) | ConvertFrom-Json
    }
    catch {
        throw "Worker bundle configuration is invalid."
    }
    if ($config.format -cne "vgen-windows-worker-bundle" -or $config.version -ne 2) {
        throw "Worker bundle configuration has an unsupported format."
    }
    try {
        $gateway = [Uri]([string]$config.gateway_url)
    }
    catch {
        throw "Worker bundle Gateway URL is invalid."
    }
    $isLoopback = $gateway.Host -in @("127.0.0.1", "::1", "localhost")
    if (($gateway.Scheme -cne "https" -and -not $isLoopback) -or
        -not [string]::IsNullOrEmpty($gateway.UserInfo) -or
        $gateway.AbsolutePath -cne "/" -or
        -not [string]::IsNullOrEmpty($gateway.Query) -or
        -not [string]::IsNullOrEmpty($gateway.Fragment)) {
        throw "Worker bundle Gateway must be an HTTPS origin."
    }
    $gatewayOrigin = ([string]$gateway.AbsoluteUri).TrimEnd("/")

    $checksumRecords = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($checksumsPath)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') {
            throw "Worker bundle checksum list is invalid."
        }
        if ($checksumRecords.ContainsKey($Matches[2])) {
            throw "Worker bundle checksum list contains duplicate names."
        }
        $checksumRecords[$Matches[2]] = $Matches[1]
    }
    $actualBundleNames = @(
        Get-ChildItem -LiteralPath $PSScriptRoot -Force |
            Where-Object { -not $_.PSIsContainer -and $_.Name -cne "SHA256SUMS" } |
            ForEach-Object { $_.Name }
    )
    if ($actualBundleNames.Count -ne $checksumRecords.Count) {
        throw "Worker bundle checksum list does not cover exactly its files."
    }
    foreach ($actualName in $actualBundleNames) {
        if (-not $checksumRecords.ContainsKey($actualName)) {
            throw "Worker bundle checksum list does not cover exactly its files."
        }
    }
    foreach ($entry in $checksumRecords.GetEnumerator()) {
        $path = Assert-RegularLocalFile (Join-Path $PSScriptRoot $entry.Key) $entry.Key
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $entry.Value) {
            throw "Worker installer integrity check failed for $($entry.Key)."
        }
    }

    $wheelName = [string]$config.wheel.name
    if ([System.IO.Path]::GetFileName($wheelName) -cne $wheelName -or
        $wheelName -notmatch '^vgen-[0-9]+\.[0-9]+\.[0-9]+-py3-none-any\.whl$') {
        throw "Worker bundle wheel name is invalid."
    }
    $pythonRuntime = $config.python_runtime
    if ($null -eq $pythonRuntime -or
        $pythonRuntime.implementation -cne "cp" -or
        $pythonRuntime.python_version -cne "3.11" -or
        $pythonRuntime.platform -cne "win_amd64") {
        throw "Worker bundle Python runtime target is invalid."
    }
    $requirementsName = [string]$pythonRuntime.requirements.name
    $requirementsSha256 = [string]$pythonRuntime.requirements.sha256
    $runtimeLockSetSha256 = [string]$pythonRuntime.lock_set_sha256
    $bootstrapPipName = [string]$pythonRuntime.bootstrap_pip.name
    $bootstrapPipSha256 = [string]$pythonRuntime.bootstrap_pip.sha256
    if ($requirementsName -cne "vgen-worker-requirements.txt" -or
        $requirementsSha256 -notmatch '^[0-9a-f]{64}$' -or
        $runtimeLockSetSha256 -notmatch '^[0-9a-f]{64}$' -or
        [IO.Path]::GetFileName($bootstrapPipName) -cne $bootstrapPipName -or
        $bootstrapPipName -notmatch '^pip-[0-9]+\.[0-9]+(?:\.[0-9]+)?-py3-none-any\.whl$' -or
        $bootstrapPipSha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Worker bundle Python runtime lock is invalid."
    }
    $runtimeWheelNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $runtimeWheelRecords = @($pythonRuntime.wheels)
    if ($runtimeWheelRecords.Count -lt 2 -or $runtimeWheelRecords.Count -gt 128) {
        throw "Worker bundle Python runtime wheel list is invalid."
    }
    foreach ($runtimeWheel in $runtimeWheelRecords) {
        $runtimeWheelName = [string]$runtimeWheel.name
        $runtimeWheelSha256 = [string]$runtimeWheel.sha256
        if ([IO.Path]::GetFileName($runtimeWheelName) -cne $runtimeWheelName -or
            $runtimeWheelName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.whl$' -or
            $runtimeWheelSha256 -notmatch '^[0-9a-f]{64}$' -or
            -not $runtimeWheelNames.Add($runtimeWheelName) -or
            -not $checksumRecords.ContainsKey($runtimeWheelName) -or
            $checksumRecords[$runtimeWheelName] -cne $runtimeWheelSha256) {
            throw "Worker bundle Python runtime wheel list is invalid."
        }
    }
    if (-not $runtimeWheelNames.Contains($wheelName) -or
        -not $runtimeWheelNames.Contains($bootstrapPipName) -or
        $checksumRecords[$requirementsName] -cne $requirementsSha256 -or
        $checksumRecords[$bootstrapPipName] -cne $bootstrapPipSha256 -or
        $checksumRecords[$wheelName] -cne [string]$config.wheel.sha256) {
        throw "Worker bundle Python runtime lock does not match its reviewed files."
    }
    $actualWheelNames = @(
        Get-ChildItem -LiteralPath $PSScriptRoot -Force -Filter "*.whl" |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object { $_.Name }
    )
    if ($actualWheelNames.Count -ne $runtimeWheelNames.Count) {
        throw "Worker bundle Python runtime wheel list does not cover exactly its wheels."
    }
    foreach ($actualWheelName in $actualWheelNames) {
        if (-not $runtimeWheelNames.Contains($actualWheelName)) {
            throw "Worker bundle Python runtime wheel list does not cover exactly its wheels."
        }
    }
    $requiredChecksumNames = @(
        "INSTALL.txt",
        "enroll-worker.ps1",
        "start-worker.cmd",
        "setup-worker.ps1",
        "supervise-worker.ps1",
        "vgen-worker-bundle.json",
        "comfyui-minimax-h3-policy.yaml",
        $requirementsName,
        $wheelName
    )
    $requiredChecksumNames += @($runtimeWheelNames | ForEach-Object { $_ })
    foreach ($requiredName in $requiredChecksumNames) {
        if (-not $checksumRecords.ContainsKey($requiredName)) {
            throw "Worker bundle checksum list is incomplete."
        }
    }
    if ($Reenroll -or $Repair) {
        # Always control the fixed task with the supervisor from this
        # checksum-verified bundle. Repair must still work when the previously
        # managed copy is missing or damaged.
        $bundledSupervisor = Assert-RegularLocalFile `
            (Join-Path $PSScriptRoot "supervise-worker.ps1") `
            "Reviewed Worker supervisor"
        $powerShellPath = [IO.Path]::Combine(
            $env:SystemRoot,
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe"
        )
        if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
            throw "Windows PowerShell 5.1 could not be located for Worker repair."
        }
        $supervisorStatus = @(
            & $powerShellPath `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $bundledSupervisor `
                -Mode Status
        )
        $supervisorStatusExit = $LASTEXITCODE
        if ($supervisorStatusExit -eq 0) {
            $supervisorWasRunning = @($supervisorStatus | ForEach-Object {
                ([string]$_).Trim().ToLowerInvariant()
            }) -contains "running"
            $vgenRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "VGen"))
            $supervisorHostConfigPath = Join-Path $vgenRoot "supervisor\worker-host.json"
            $hostConfigItem = Get-Item -LiteralPath $supervisorHostConfigPath -Force
            if ($hostConfigItem.PSIsContainer -or
                ($hostConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $hostConfigItem.Length -le 0 -or $hostConfigItem.Length -gt 65536) {
                throw "The installed Worker supervisor configuration is unsafe; the running task was left untouched."
            }
            try {
                $hostConfig = [IO.File]::ReadAllText($hostConfigItem.FullName) | ConvertFrom-Json
            }
            catch {
                throw "The installed Worker supervisor configuration is invalid; the running task was left untouched."
            }
            $supervisorLaunchConfigPath = [string]$hostConfig.launch_config
            if ([string]::IsNullOrWhiteSpace($supervisorLaunchConfigPath) -or
                -not [IO.Path]::IsPathRooted($supervisorLaunchConfigPath) -or
                -not (Test-PathInside $supervisorLaunchConfigPath $vgenRoot) -or
                -not (Test-Path -LiteralPath $supervisorLaunchConfigPath -PathType Leaf)) {
                throw "The installed Worker launch configuration is invalid; the running task was left untouched."
            }
            $launchConfigItem = Get-Item -LiteralPath $supervisorLaunchConfigPath -Force
            if (($launchConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $launchConfigItem.Length -le 0 -or $launchConfigItem.Length -gt 262144) {
                throw "The installed Worker launch configuration is unsafe; the running task was left untouched."
            }
            $supervisorHostConfigSnapshot = [IO.File]::ReadAllBytes($hostConfigItem.FullName)
            $supervisorLaunchConfigSnapshot = [IO.File]::ReadAllBytes($launchConfigItem.FullName)
            $managedSupervisorForRecovery = $bundledSupervisor
            $powerShellForRecovery = $powerShellPath
            $supervisorStoppedForRepair = $supervisorWasRunning

            Write-Step "Repairing the persistent supervisor controller before stopping its task"
            & $powerShellPath `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $bundledSupervisor `
                -Mode Install `
                -LaunchConfig $supervisorLaunchConfigPath
            if ($LASTEXITCODE -ne 0) {
                throw "The persistent Worker supervisor controller could not be repaired."
            }
            Write-Step "Stopping persistent Worker supervision for reviewed repair"
            & $powerShellPath `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $bundledSupervisor `
                -Mode Stop
            if ($LASTEXITCODE -ne 0) {
                throw "The persistent Worker supervisor could not be stopped for repair."
            }
        }
        elseif ($supervisorStatusExit -ne 3) {
            throw "The persistent Worker supervisor status could not be inspected for repair."
        }
    }
    $wheelPath = Assert-RegularLocalFile (Join-Path $PSScriptRoot $wheelName) "VGen wheel"
    $requirementsPath = Assert-RegularLocalFile `
        (Join-Path $PSScriptRoot $requirementsName) "Worker Python requirements lock"
    $bootstrapPipPath = Assert-RegularLocalFile `
        (Join-Path $PSScriptRoot $bootstrapPipName) "Worker bootstrap pip wheel"
    $setupPath = Assert-RegularLocalFile `
        (Join-Path $PSScriptRoot "setup-worker.ps1") "Worker setup script"
    $credentialRoot = Join-Path $env:LOCALAPPDATA "VGen\credentials"
    $credentialPath = Join-Path $credentialRoot "worker-credentials.json"
    $identityPath = Join-Path $credentialRoot ".worker-enrollment-identity.json"

    if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
        $credentialPath = Assert-RegularLocalFile $credentialPath "Existing Worker credential"
        Protect-CredentialAcl $credentialPath
    }

    $python = Ensure-Python311
    $runtimeLockId = $requirementsSha256.Substring(0, 16)
    $bootstrapRoot = Join-Path $env:LOCALAPPDATA `
        "VGen\enrollment\$([string]$config.wheel.version)-$runtimeLockId"
    $bootstrapPython = Join-Path $bootstrapRoot "Scripts\python.exe"
    if (-not (Test-LockedWorkerRuntime $bootstrapPython $requirementsPath $python)) {
        if (Test-Path -LiteralPath $bootstrapRoot) {
            Write-Step "Preparing a clean replacement for the inconsistent enrollment environment"
        }
        $bootstrapStaging = "$bootstrapRoot-staging"
        $stagingPython = Join-Path $bootstrapStaging "Scripts\python.exe"
        if (Test-Path -LiteralPath $bootstrapStaging) {
            Remove-ClosedWorkerRuntimeTree $bootstrapRoot $bootstrapStaging
        }
        try {
            Write-Step "Creating the local Worker enrollment runtime"
            & $python -I -B -m venv --without-pip $bootstrapStaging | Out-Host
            if ($LASTEXITCODE -ne 0) {
                throw "Python could not create the Worker enrollment runtime."
            }
            Remove-WorkerRuntimeActivationScripts $bootstrapStaging
            Write-Step "Installing the reviewed offline Worker Python dependency set"
            Install-LockedWorkerPythonPackages `
                $stagingPython $PSScriptRoot $bootstrapPipPath $requirementsPath $python
            Complete-LockedWorkerRuntime $bootstrapStaging $bootstrapRoot
        }
        finally {
            if (Test-Path -LiteralPath $bootstrapStaging) {
                try { Remove-ClosedWorkerRuntimeTree $bootstrapRoot $bootstrapStaging }
                catch { Write-Warning "The bounded enrollment runtime staging path could not be removed." }
            }
        }
        $bootstrapPython = Join-Path $bootstrapRoot "Scripts\python.exe"
    }

    $replaceExistingCredential = $false
    if (Test-Path -LiteralPath $credentialPath -PathType Leaf) {
        $credentialCheckMode = if ($Reenroll) { "--reenroll-existing" } else { "--check-existing" }
        Write-Step "Verifying the existing Worker identity with this Gateway"
        & $bootstrapPython -I -B -m vgen.cli.worker_enrollment `
            --gateway-url $gatewayOrigin `
            --credentials-file $credentialPath `
            $credentialCheckMode | Out-Host
        $credentialCheckExit = $LASTEXITCODE
        if ($credentialCheckExit -eq 10) {
            $replaceExistingCredential = $true
            Write-Step "A new Worker identity is required; the current credential remains active until replacement succeeds"
        }
        elseif ($credentialCheckExit -eq 0) {
            Write-Step "Using the verified, locally protected Worker credentials"
        }
        else {
            $reenrollLauncher = Join-Path $PSScriptRoot "start-worker.cmd"
            throw "Existing Worker credentials could not be verified and were kept unchanged. Retry after any Gateway or network issue is fixed. If the Workspace owner has confirmed that this Worker was revoked or belongs to another Gateway, run: `"$reenrollLauncher`" -Reenroll"
        }
    }

    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf) -or
        $replaceExistingCredential) {
        if ([string]::IsNullOrWhiteSpace($WorkerName)) {
            $defaultName = if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
                "Windows GPU Worker"
            }
            else {
                "$($env:COMPUTERNAME) GPU Worker"
            }
            $enteredName = Read-Host "Worker name [$defaultName]"
            $WorkerName = if ([string]::IsNullOrWhiteSpace($enteredName)) {
                $defaultName
            }
            else {
                $enteredName.Trim()
            }
        }
        $enrollmentIdentityPath = $identityPath
        if ($replaceExistingCredential) {
            $enrollmentIdentityPath = Join-Path $credentialRoot `
                ".worker-reenrollment-identity.json"
        }
        Write-Host ""
        Write-Host "[vgen] On the Workspace owner's Mac, run: vgen worker add"
        Write-Host "[vgen] Paste the Invite shown by that still-running command below."
        Write-Step "Creating a local Worker identity and claiming the one-time Invite"
        $enrollmentArguments = @(
            "-I", "-B", "-m", "vgen.cli.worker_enrollment",
            "--gateway-url", $gatewayOrigin,
            "--name", $WorkerName,
            "--identity-file", $enrollmentIdentityPath,
            "--credentials-file", $credentialPath
        )
        if ($replaceExistingCredential) {
            $enrollmentArguments += "--replace-existing"
        }
        & $bootstrapPython @enrollmentArguments
        if ($LASTEXITCODE -ne 0) {
            if ($replaceExistingCredential) {
                throw "Worker re-enrollment did not complete. Existing Worker credentials and the pending replacement identity were kept unchanged so the same Invite can resume."
            }
            throw "Worker enrollment did not complete. No Worker credential was created; the pending enrollment identity was kept so the same Invite can resume."
        }
        if ($replaceExistingCredential -and
            (Test-Path -LiteralPath $enrollmentIdentityPath -PathType Leaf)) {
            Remove-Item -LiteralPath $enrollmentIdentityPath -Force
        }
        if (-not $replaceExistingCredential -and
            (Test-Path -LiteralPath $enrollmentIdentityPath -PathType Leaf)) {
            Remove-Item -LiteralPath $enrollmentIdentityPath -Force
        }
    }

    Write-Step "Enrollment completed; continuing with reviewed Worker setup"
    $setupPowerShellPath = [IO.Path]::Combine(
        $env:SystemRoot,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe"
    )
    if (-not (Test-Path -LiteralPath $setupPowerShellPath -PathType Leaf)) {
        throw "Windows PowerShell 5.1 could not be located for Worker setup."
    }
    # setup-worker.ps1 deliberately uses process exit codes. Run it in a child
    # host so a failed setup returns here and the previous task can be resumed.
    $setupProcessArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $setupPath,
        "-GatewayUrl", $gatewayOrigin,
        "-WorkerCredentials", $credentialPath
    )
    if (-not [string]::IsNullOrWhiteSpace($ComfyUIRoot)) {
        $setupProcessArguments += @("-ComfyUIRoot", $ComfyUIRoot)
    }
    if (-not [string]::IsNullOrWhiteSpace($ComfyUIDataRoot)) {
        $setupProcessArguments += @("-ComfyUIDataRoot", $ComfyUIDataRoot)
    }
    & $setupPowerShellPath @setupProcessArguments
    $setupExitCode = $LASTEXITCODE
    if ($setupExitCode -ne 0) {
        throw "Worker setup stopped with exit code $setupExitCode."
    }
    exit 0
}
catch {
    $failureMessage = [string]$_.Exception.Message
    if ($supervisorStoppedForRepair -and
        $null -ne $managedSupervisorForRecovery -and
        $null -ne $powerShellForRecovery) {
        Write-Warning "Worker repair did not complete; restarting the previously installed supervisor."
        $restoreFailures = [Collections.Generic.List[string]]::new()
        if ($null -ne $supervisorLaunchConfigSnapshot) {
            try {
                Restore-FileSnapshot `
                    $supervisorLaunchConfigPath `
                    $supervisorLaunchConfigSnapshot `
                    "Worker launch configuration"
            }
            catch { $restoreFailures.Add([string]$_.Exception.Message) }
        }
        if ($null -ne $supervisorHostConfigSnapshot) {
            try {
                Restore-FileSnapshot `
                    $supervisorHostConfigPath `
                    $supervisorHostConfigSnapshot `
                    "Worker supervisor configuration"
            }
            catch { $restoreFailures.Add([string]$_.Exception.Message) }
        }
        if ($restoreFailures.Count -gt 0) {
            Write-Warning "The previous Worker configuration could not be fully restored: $($restoreFailures -join '; ')"
        }
        if ($null -ne $supervisorLaunchConfigPath) {
            & $powerShellForRecovery `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -ExecutionPolicy Bypass `
                -File $managedSupervisorForRecovery `
                -Mode Install `
                -LaunchConfig $supervisorLaunchConfigPath
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "The previous Worker supervisor definition could not be restored."
            }
        }
        & $powerShellForRecovery `
            -NoLogo `
            -NoProfile `
            -NonInteractive `
            -ExecutionPolicy Bypass `
            -File $managedSupervisorForRecovery `
            -Mode Start
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "The previously installed Worker supervisor also could not be restarted."
        }
    }
    [Console]::Error.WriteLine("[vgen] ERROR: $failureMessage")
    exit 1
}
