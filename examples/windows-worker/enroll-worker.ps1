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
            [IO.File]::Replace($temporary, $Path, $null)
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
        if ($item.Name -cmatch '^vgen-[0-9]+\.[0-9]+\.[0-9]+-py3-none-any\.whl$') {
            $wheelCount += 1
            continue
        }
        throw "The Worker installer folder contains an unexpected entry: $($item.Name)"
    }
    if ($wheelCount -ne 1) {
        throw "The Worker installer folder must contain exactly one reviewed VGen wheel."
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
    if ($config.format -cne "vgen-windows-worker-bundle" -or $config.version -ne 1) {
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
        $checksumRecords[$Matches[2]] = $Matches[1]
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
    $requiredChecksumNames = @(
        "INSTALL.txt",
        "enroll-worker.ps1",
        "start-worker.cmd",
        "setup-worker.ps1",
        "supervise-worker.ps1",
        "vgen-worker-bundle.json",
        "comfyui-minimax-h3-policy.yaml",
        $wheelName
    )
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
    $bootstrapRoot = Join-Path $env:LOCALAPPDATA "VGen\enrollment\$([string]$config.wheel.version)"
    $bootstrapPython = Join-Path $bootstrapRoot "Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $bootstrapPython -PathType Leaf)) {
        Write-Step "Creating the local Worker enrollment runtime"
        & $python -I -B -m venv $bootstrapRoot | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Python could not create the Worker enrollment runtime."
        }
    }
    Write-Step "Installing the reviewed local VGen wheel"
    & $bootstrapPython -I -B -m pip install --disable-pip-version-check --upgrade $wheelPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "The reviewed VGen wheel could not be installed."
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
    Write-Error $failureMessage
    exit 1
}
