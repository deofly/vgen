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
    [string]$ComfyUIDataRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Step {
    param([string]$Message)
    Write-Host "[vgen] $Message"
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

function Assert-ClosedBundleDirectory {
    param([string]$Root)
    $allowedNames = @(
        "INSTALL.txt",
        "enroll-worker.ps1",
        "start-worker.cmd",
        "setup-worker.ps1",
        "vgen-worker-bundle.json",
        "comfyui-minimax-h3-policy.yaml",
        "SHA256SUMS",
        "worker-credentials.json",
        ".worker-enrollment-identity.json"
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
        "vgen-worker-bundle.json",
        "comfyui-minimax-h3-policy.yaml",
        $wheelName
    )
    foreach ($requiredName in $requiredChecksumNames) {
        if (-not $checksumRecords.ContainsKey($requiredName)) {
            throw "Worker bundle checksum list is incomplete."
        }
    }
    $wheelPath = Assert-RegularLocalFile (Join-Path $PSScriptRoot $wheelName) "VGen wheel"
    $setupPath = Assert-RegularLocalFile `
        (Join-Path $PSScriptRoot "setup-worker.ps1") "Worker setup script"
    $credentialPath = Join-Path $PSScriptRoot "worker-credentials.json"
    $identityPath = Join-Path $PSScriptRoot ".worker-enrollment-identity.json"

    if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
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
        $gatewayOrigin = ([string]$gateway.AbsoluteUri).TrimEnd("/")
        Write-Step "Creating a local Worker identity and claiming the one-time Invite"
        & $bootstrapPython -I -B -m vgen worker claim-invite `
            --gateway-url $gatewayOrigin `
            --name $WorkerName `
            --identity-file $identityPath `
            --credentials-file $credentialPath `
            --wait
        if ($LASTEXITCODE -ne 0) {
            throw "Worker enrollment did not complete. No Invite secret was saved."
        }
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force
        }
    }
    else {
        Write-Step "Using the existing locally protected Worker credentials"
    }

    Write-Step "Enrollment completed; continuing with reviewed Worker setup"
    $setupArguments = @("-WorkerCredentials", $credentialPath)
    if (-not [string]::IsNullOrWhiteSpace($ComfyUIRoot)) {
        $setupArguments += @("-ComfyUIRoot", $ComfyUIRoot)
    }
    if (-not [string]::IsNullOrWhiteSpace($ComfyUIDataRoot)) {
        $setupArguments += @("-ComfyUIDataRoot", $ComfyUIDataRoot)
    }
    & $setupPath @setupArguments
    exit $LASTEXITCODE
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
