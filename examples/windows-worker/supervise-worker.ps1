#requires -Version 5.1

<#
.SYNOPSIS
Installs and runs the persistent VGen Windows Worker supervisor.

.DESCRIPTION
The supervisor is owned by the enrolled Windows user and is registered with
Task Scheduler using that user's interactive token.  It never runs VGen's
user-writable runtime as LocalSystem.  The task keeps Worker control and
ComfyUI in separate owned processes, restarting either one with bounded
backoff without taking the other one down.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Run", "Start", "Stop", "Status")]
    [string]$Mode,

    [string]$LaunchConfig,

    [switch]$Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$env:PYTHONDONTWRITEBYTECODE = "1"

$TaskName = "VGen Worker Supervisor"
$SupervisorFormat = "vgen-windows-worker-supervisor"
$SupervisorVersion = 1
$MaxLogBytes = [Int64](8 * 1024 * 1024)
$MaxChildLogFiles = 12
$HostControlFormat = "vgen-windows-worker-host-control"
$HostControlVersion = 1

function Write-Step {
    param([string]$Message)
    Write-Host "[vgen] $Message"
}

function Resolve-WindowsPowerShell {
    if ([string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        throw "The Windows system directory could not be located."
    }
    $candidate = [IO.Path]::Combine(
        $env:SystemRoot,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe"
    )
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Windows PowerShell 5.1 could not be located."
    }
    return (Get-Item -LiteralPath $candidate -Force).FullName
}

function Resolve-SafeDirectory {
    param([string]$Path, [string]$Description, [switch]$Create)

    if ($Create -and -not (Test-Path -LiteralPath $Path)) {
        [IO.Directory]::CreateDirectory($Path) | Out-Null
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description is missing or is not a directory."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
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

function Read-SupervisorConfig {
    param([string]$Path, [string]$VGenRoot)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "The persistent Worker supervisor configuration is missing."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 65536) {
        throw "The persistent Worker supervisor configuration is unsafe."
    }
    try {
        $config = [IO.File]::ReadAllText($item.FullName) | ConvertFrom-Json
    }
    catch {
        throw "The persistent Worker supervisor configuration is invalid."
    }
    if ($config.format -cne $SupervisorFormat -or $config.version -ne $SupervisorVersion) {
        throw "The persistent Worker supervisor configuration has an unsupported format."
    }
    $launchConfigPath = [string]$config.launch_config
    if ([string]::IsNullOrWhiteSpace($launchConfigPath) -or
        -not [IO.Path]::IsPathRooted($launchConfigPath) -or
        -not (Test-PathInside $launchConfigPath $VGenRoot) -or
        -not (Test-Path -LiteralPath $launchConfigPath -PathType Leaf)) {
        throw "The persistent Worker launch configuration path is invalid."
    }
    $launchConfigItem = Get-Item -LiteralPath $launchConfigPath -Force
    if (($launchConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The persistent Worker launch configuration must not be a reparse point."
    }
    return [PSCustomObject]@{
        LaunchConfig = $launchConfigItem.FullName
    }
}

function Resolve-LaunchExecutable {
    param([string]$Path, [string]$Description)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not [IO.Path]::IsPathRooted($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description executable is missing or is not an absolute path."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description executable must not be a symbolic link or reparse point."
    }
    return $item.FullName
}

function Resolve-LaunchWorkingDirectory {
    param([string]$Path, [string]$Description)

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not [IO.Path]::IsPathRooted($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "$Description working directory is missing or is not an absolute path."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description working directory must not be a reparse point."
    }
    return $item.FullName
}

function Read-LaunchProcess {
    param([object]$Value, [string]$Description, [bool]$Required)

    if ($null -eq $Value) {
        if ($Required) { throw "$Description launch configuration is missing." }
        return $null
    }
    $executable = Resolve-LaunchExecutable ([string]$Value.executable) $Description
    $workingDirectory = Resolve-LaunchWorkingDirectory `
        ([string]$Value.working_directory) $Description
    $arguments = @($Value.arguments)
    if ($arguments.Count -eq 0 -or $arguments.Count -gt 128) {
        throw "$Description launch arguments are invalid."
    }
    $validatedArguments = [Collections.Generic.List[string]]::new()
    foreach ($argumentValue in $arguments) {
        if ($argumentValue -isnot [string]) {
            throw "$Description launch arguments must be strings."
        }
        $argument = [string]$argumentValue
        if ($argument.Length -gt 32767 -or $argument.IndexOf([char]0) -ge 0 -or
            $argument.Contains("`r") -or $argument.Contains("`n")) {
            throw "$Description launch arguments contain an unsafe value."
        }
        $validatedArguments.Add($argument)
    }
    return [PSCustomObject]@{
        Executable = $executable
        WorkingDirectory = $workingDirectory
        Arguments = $validatedArguments.ToArray()
    }
}

function Read-LaunchConfig {
    param([string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 262144) {
        throw "The Worker launch configuration is unsafe."
    }
    try {
        $config = [IO.File]::ReadAllText($item.FullName) | ConvertFrom-Json
    }
    catch {
        throw "The Worker launch configuration is invalid."
    }
    if ($config.format -cne "vgen-windows-worker-launch-config" -or $config.version -ne 1) {
        throw "The Worker launch configuration has an unsupported format."
    }
    $comfy = $null
    if ($null -ne $config.PSObject.Properties["comfyui"] -and $null -ne $config.comfyui) {
        $comfy = Read-LaunchProcess $config.comfyui "ComfyUI" $false
    }
    return [PSCustomObject]@{
        Worker = Read-LaunchProcess $config.worker "Worker" $true
        ComfyUI = $comfy
    }
}

function ConvertTo-NativeArgument {
    param([string]$Value)

    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Start-OwnedProcess {
    param(
        [PSCustomObject]$Definition,
        [string]$Name,
        [string]$LogRoot
    )

    Remove-StaleChildLogs $LogRoot $Name
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
    $stderr = Join-Path $LogRoot "$($Name.ToLowerInvariant())-$timestamp-$suffix.err.log"
    $nativeArguments = @(
        $Definition.Arguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) }
    )
    $process = Start-Process `
        -FilePath $Definition.Executable `
        -ArgumentList $nativeArguments `
        -WorkingDirectory $Definition.WorkingDirectory `
        -NoNewWindow `
        -RedirectStandardOutput "NUL" `
        -RedirectStandardError $stderr `
        -PassThru
    return $process
}

function Remove-StaleChildLogs {
    param([string]$LogRoot, [string]$Name)

    $prefix = "$($Name.ToLowerInvariant())-"
    $files = @(
        Get-ChildItem -LiteralPath $LogRoot -Force |
            Where-Object {
                -not $_.PSIsContainer -and
                $_.Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and
                ($_.Name.EndsWith(".out.log", [StringComparison]::OrdinalIgnoreCase) -or
                    $_.Name.EndsWith(".err.log", [StringComparison]::OrdinalIgnoreCase))
            } |
            Sort-Object LastWriteTimeUtc -Descending
    )
    foreach ($file in @($files | Select-Object -Skip $MaxChildLogFiles)) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A stale $Name log is a reparse point and was not removed."
        }
        Remove-Item -LiteralPath $file.FullName -Force
    }
}

function Stop-OwnedProcessTree {
    param(
        [Diagnostics.Process]$Process,
        [string]$Name
    )

    try {
        if ($Process.HasExited) {
            return
        }
        $ownedProcessId = $Process.Id
        $taskKill = [IO.Path]::Combine($env:SystemRoot, "System32", "taskkill.exe")
        if (-not (Test-Path -LiteralPath $taskKill -PathType Leaf)) {
            throw "Windows taskkill.exe could not be located for owned process cleanup."
        }
        # The PID comes only from Start-Process -PassThru above. /T limits
        # cleanup to that exact owned process tree and avoids name-based scans.
        & $taskKill /PID ([string]$ownedProcessId) /T /F *> $null
        $taskKillExit = $LASTEXITCODE
        try {
            $null = $Process.WaitForExit(10000)
            $Process.Refresh()
        }
        catch {
            # The verification below reports one closed, stable error.
        }
        if (-not $Process.HasExited) {
            throw "$Name process tree $ownedProcessId did not stop cleanly."
        }
        if ($taskKillExit -ne 0) {
            Write-Warning "$Name process tree $ownedProcessId exited while cleanup was in progress."
        }
    }
    finally {
        $Process.Dispose()
    }
}

function Replace-FileAtomically {
    param([string]$Source, [string]$Destination)

    $directory = Split-Path -Parent $Destination
    $backup = Join-Path $directory ".$([IO.Path]::GetFileName($Destination)).$([Guid]::NewGuid().ToString('N')).bak"
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

function Write-AtomicUtf8Json {
    param([string]$Path, [object]$Value)

    $directory = Split-Path -Parent $Path
    $temporary = Join-Path $directory ".$([IO.Path]::GetFileName($Path)).$([Guid]::NewGuid().ToString('N')).tmp"
    $utf8 = [Text.UTF8Encoding]::new($false)
    try {
        $json = ($Value | ConvertTo-Json -Depth 5) + "`n"
        [IO.File]::WriteAllText($temporary, $json, $utf8)
        if (Test-Path -LiteralPath $Path) {
            $existing = Get-Item -LiteralPath $Path -Force
            if ($existing.PSIsContainer -or
                ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The persistent Worker supervisor configuration path is unsafe."
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

function Remove-SafeControlFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The ComfyUI host control path is unsafe."
    }
    Remove-Item -LiteralPath $item.FullName -Force
}

function Read-ComfyPauseRequest {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 4096) {
        throw "The ComfyUI pause request is unsafe."
    }
    try {
        $request = [IO.File]::ReadAllText($item.FullName) | ConvertFrom-Json
    }
    catch {
        throw "The ComfyUI pause request is invalid."
    }
    $propertyNames = @($request.PSObject.Properties.Name | Sort-Object)
    $expectedNames = @("expires_at", "format", "nonce", "requested_at", "version")
    if (($propertyNames -join ",") -cne ($expectedNames -join ",") -or
        $request.format -cne "vgen-comfyui-pause-request" -or
        $request.version -ne 1 -or
        [string]$request.nonce -cnotmatch '^[0-9a-f]{48}$' -or
        (($request.requested_at -isnot [Int32]) -and
            ($request.requested_at -isnot [Int64])) -or
        (($request.expires_at -isnot [Int32]) -and
            ($request.expires_at -isnot [Int64]))) {
        throw "The ComfyUI pause request is invalid."
    }
    $requestedAt = [Int64]$request.requested_at
    $expiresAt = [Int64]$request.expires_at
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($expiresAt -le $requestedAt -or $requestedAt -gt ($now + 300) -or
        $expiresAt -gt ($now + 900)) {
        throw "The ComfyUI pause request lifetime is invalid."
    }
    if ($expiresAt -le $now) {
        Remove-SafeControlFile $item.FullName
        return $null
    }
    return [PSCustomObject]@{
        Nonce = [string]$request.nonce
        ExpiresAt = $expiresAt
    }
}

function Write-ComfyPauseAcknowledgement {
    param([string]$Path, [string]$Nonce)

    Write-AtomicUtf8Json $Path ([ordered]@{
        format = "vgen-comfyui-pause-ack"
        version = 1
        nonce = $Nonce
        paused_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    })
}

function Install-ManagedSupervisorScript {
    param([string]$Source, [string]$Destination)

    $sourceItem = Get-Item -LiteralPath $Source -Force
    if ($sourceItem.PSIsContainer -or
        ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $sourceItem.Length -le 0 -or $sourceItem.Length -gt 2097152) {
        throw "The reviewed Worker supervisor script is unsafe."
    }
    if ($sourceItem.FullName.Equals($Destination, [StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    $value = [IO.File]::ReadAllBytes($sourceItem.FullName)
    if (Test-Path -LiteralPath $Destination -PathType Leaf) {
        $current = [IO.File]::ReadAllBytes($Destination)
        if (([Convert]::ToBase64String($current)) -ceq ([Convert]::ToBase64String($value))) {
            return
        }
    }
    $directory = Split-Path -Parent $Destination
    $temporary = Join-Path $directory ".supervise-worker.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($temporary, $value)
        if (Test-Path -LiteralPath $Destination) {
            $existing = Get-Item -LiteralPath $Destination -Force
            if ($existing.PSIsContainer -or
                ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The managed Worker supervisor script path is unsafe."
            }
            Replace-FileAtomically $temporary $Destination
        }
        else {
            [IO.File]::Move($temporary, $Destination)
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Rotate-SupervisorLog {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The Worker supervisor log path is unsafe."
    }
    if ($item.Length -lt $MaxLogBytes) {
        return
    }
    $archive = "$Path.1"
    if (Test-Path -LiteralPath $archive -PathType Leaf) {
        Remove-Item -LiteralPath $archive -Force
    }
    Move-Item -LiteralPath $Path -Destination $archive
}

function Write-SupervisorLog {
    param([string]$Path, [string]$Message)

    Rotate-SupervisorLog $Path
    $timestamp = [DateTimeOffset]::Now.ToString("o")
    [IO.File]::AppendAllText(
        $Path,
        "$timestamp $Message`r`n",
        [Text.UTF8Encoding]::new($false)
    )
}

if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw "LOCALAPPDATA is required for the persistent VGen Worker supervisor."
}
$vgenRoot = Join-Path $env:LOCALAPPDATA "VGen"
$vgenRoot = Resolve-SafeDirectory $vgenRoot "The VGen application data directory" -Create
$supervisorRoot = Join-Path $vgenRoot "supervisor"
$supervisorRoot = Resolve-SafeDirectory $supervisorRoot "The VGen supervisor directory" -Create
$managedScript = Join-Path $supervisorRoot "supervise-worker.ps1"
$configPath = Join-Path $supervisorRoot "worker-host.json"
$stopRequest = Join-Path $supervisorRoot "stop.request"
$logRoot = Join-Path $vgenRoot "logs"
$logRoot = Resolve-SafeDirectory $logRoot "The VGen log directory" -Create
$logPath = Join-Path $logRoot "worker-supervisor.log"

switch ($Mode) {
    "Install" {
        if ([string]::IsNullOrWhiteSpace($LaunchConfig) -or
            -not [IO.Path]::IsPathRooted($LaunchConfig) -or
            -not (Test-PathInside $LaunchConfig $vgenRoot) -or
            -not (Test-Path -LiteralPath $LaunchConfig -PathType Leaf)) {
            throw "The Worker launch configuration must be an absolute file under LOCALAPPDATA\VGen."
        }
        $launchConfigItem = Get-Item -LiteralPath $LaunchConfig -Force
        if (($launchConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The Worker launch configuration must not be a reparse point."
        }
        $null = Read-LaunchConfig $launchConfigItem.FullName
        Install-ManagedSupervisorScript $PSCommandPath $managedScript
        Write-AtomicUtf8Json $configPath ([ordered]@{
            format = $SupervisorFormat
            version = $SupervisorVersion
            launch_config = $launchConfigItem.FullName
        })

        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($identity.User.Value -eq "S-1-5-18") {
            throw "The VGen Worker supervisor must not run as LocalSystem."
        }
        $powerShell = Resolve-WindowsPowerShell
        $actionArguments = "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$managedScript`" -Mode Run"
        $action = New-ScheduledTaskAction -Execute $powerShell -Argument $actionArguments
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
        $principal = New-ScheduledTaskPrincipal `
            -UserId $identity.Name `
            -LogonType Interactive `
            -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew `
            -RestartCount 999 `
            -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Keeps the enrolled VGen Worker available after stack failures." `
            -Force | Out-Null
        Write-Step "Installed persistent Worker supervision for the current Windows user"
        if ($Start) {
            Start-ScheduledTask -TaskName $TaskName
            Write-Step "Started the persistent Worker supervisor"
        }
        exit 0
    }
    "Start" {
        $null = Read-SupervisorConfig $configPath $vgenRoot
        if (Test-Path -LiteralPath $stopRequest) {
            $stopItem = Get-Item -LiteralPath $stopRequest -Force
            if ($stopItem.PSIsContainer -or
                ($stopItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The Worker supervisor stop request path is unsafe."
            }
            Remove-Item -LiteralPath $stopRequest -Force
        }
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ([string]$task.State -ne "Running") {
            Start-ScheduledTask -TaskName $TaskName
        }
        $deadline = [DateTimeOffset]::Now.AddSeconds(30)
        do {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            if ([string]$task.State -eq "Running") { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTimeOffset]::Now -lt $deadline)
        if ([string]$task.State -ne "Running") {
            throw "Windows Task Scheduler did not start the persistent Worker supervisor."
        }
        Write-Step "Started the persistent Worker supervisor"
        exit 0
    }
    "Stop" {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) { exit 0 }
        if ([string]$task.State -eq "Running") {
            if (Test-Path -LiteralPath $stopRequest) {
                $stopItem = Get-Item -LiteralPath $stopRequest -Force
                if ($stopItem.PSIsContainer -or
                    ($stopItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "The Worker supervisor stop request path is unsafe."
                }
            }
            [IO.File]::WriteAllText(
                $stopRequest,
                "stop`r`n",
                [Text.Encoding]::ASCII
            )
        }
        $deadline = [DateTimeOffset]::Now.AddSeconds(30)
        do {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
            if ([string]$task.State -ne "Running") { break }
            Start-Sleep -Milliseconds 500
        } while ([DateTimeOffset]::Now -lt $deadline)
        if ([string]$task.State -eq "Running") {
            Stop-ScheduledTask -TaskName $TaskName
            $forcedDeadline = [DateTimeOffset]::Now.AddSeconds(10)
            do {
                $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                if ([string]$task.State -ne "Running") { break }
                Start-Sleep -Milliseconds 500
            } while ([DateTimeOffset]::Now -lt $forcedDeadline)
            if ([string]$task.State -eq "Running") {
                throw "Windows Task Scheduler did not stop the persistent Worker supervisor."
            }
        }
        Write-Step "Stopped the persistent Worker supervisor for repair"
        exit 0
    }
    "Run" {
        $mutex = [Threading.Mutex]::new($false, "Local\VGenWorkerHost")
        $waitingLogged = $false
        while (-not $mutex.WaitOne(0)) {
            if (-not $waitingLogged) {
                Write-SupervisorLog $logPath "Waiting for another managed supervisor instance to release ownership."
                $waitingLogged = $true
            }
            Start-Sleep -Seconds 5
        }
        $workerProcess = $null
        $comfyProcess = $null
        $hostControlStatus = $null
        try {
            $config = Read-SupervisorConfig $configPath $vgenRoot
            $launch = Read-LaunchConfig $config.LaunchConfig
            $pauseRequest = Join-Path $launch.Worker.WorkingDirectory "comfyui-pause.request"
            $pauseAcknowledgement = Join-Path $launch.Worker.WorkingDirectory "comfyui-pause.ack"
            $hostControlStatus = Join-Path $launch.Worker.WorkingDirectory "host-control-status.json"
            $supervisorScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
            $hostControlStatusNextWrite = [DateTimeOffset]::MinValue
            $workerFailures = 0
            $comfyFailures = 0
            $workerNextStart = [DateTimeOffset]::Now
            $comfyNextStart = [DateTimeOffset]::Now
            $workerStartedAt = $null
            $comfyStartedAt = $null
            $comfyPausedNonce = $null
            while ($true) {
                $now = [DateTimeOffset]::Now
                if ($now -ge $hostControlStatusNextWrite) {
                    Write-AtomicUtf8Json $hostControlStatus ([ordered]@{
                        format = $HostControlFormat
                        version = $HostControlVersion
                        process_id = [int]$PID
                        script_sha256 = $supervisorScriptSha256
                        heartbeat_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    })
                    $hostControlStatusNextWrite = $now.AddSeconds(2)
                }
                if (Test-Path -LiteralPath $stopRequest -PathType Leaf) {
                    Write-SupervisorLog $logPath "A reviewed repair requested a clean supervisor stop."
                    break
                }
                $pause = $null
                try {
                    $pause = Read-ComfyPauseRequest $pauseRequest
                }
                catch {
                    Write-SupervisorLog $logPath "Rejected an invalid ComfyUI pause request."
                }
                if ($null -ne $pause) {
                    try {
                        if ($null -ne $comfyProcess) {
                            Stop-OwnedProcessTree $comfyProcess "ComfyUI"
                            $comfyProcess.Dispose()
                            $comfyProcess = $null
                        }
                        if ($comfyPausedNonce -cne $pause.Nonce) {
                            Write-ComfyPauseAcknowledgement $pauseAcknowledgement $pause.Nonce
                            $comfyPausedNonce = $pause.Nonce
                            Write-SupervisorLog $logPath "Paused ComfyUI for reviewed Worker maintenance."
                        }
                    }
                    catch {
                        Write-SupervisorLog $logPath "Could not pause ComfyUI for Worker maintenance."
                    }
                    Start-Sleep -Milliseconds 200
                    continue
                }
                if ($null -ne $comfyPausedNonce) {
                    try {
                        Remove-SafeControlFile $pauseAcknowledgement
                    }
                    catch {
                        Write-SupervisorLog $logPath "Could not remove a ComfyUI pause acknowledgement."
                    }
                    $comfyPausedNonce = $null
                    $comfyNextStart = $now
                    Write-SupervisorLog $logPath "Resuming ComfyUI after reviewed Worker maintenance."
                }
                if ($null -ne $workerProcess -and $workerProcess.HasExited) {
                    $exitCode = $workerProcess.ExitCode
                    $runtime = $now - $workerStartedAt
                    $workerProcess.Dispose()
                    $workerProcess = $null
                    if ($runtime.TotalMinutes -ge 5) { $workerFailures = 0 }
                    $workerFailures++
                    $delay = [Math]::Min(60, [Math]::Pow(2, [Math]::Min(5, $workerFailures - 1)) * 2)
                    $workerNextStart = $now.AddSeconds($delay)
                    Write-SupervisorLog $logPath "Worker exited with code $exitCode; retrying in $([int]$delay) second(s)."
                }
                if ($null -eq $workerProcess -and $now -ge $workerNextStart) {
                    try {
                        Write-SupervisorLog $logPath "Starting the authenticated Worker control process."
                        $workerProcess = Start-OwnedProcess $launch.Worker "worker" $logRoot
                        $workerStartedAt = [DateTimeOffset]::Now
                    }
                    catch {
                        $workerFailures++
                        $delay = [Math]::Min(60, [Math]::Pow(2, [Math]::Min(5, $workerFailures - 1)) * 2)
                        $workerNextStart = $now.AddSeconds($delay)
                        Write-SupervisorLog $logPath "Worker launch failed; retrying in $([int]$delay) second(s)."
                    }
                }

                if ($null -ne $launch.ComfyUI -and
                    $null -ne $comfyProcess -and $comfyProcess.HasExited) {
                    $exitCode = $comfyProcess.ExitCode
                    $runtime = $now - $comfyStartedAt
                    $comfyProcess.Dispose()
                    $comfyProcess = $null
                    if ($runtime.TotalMinutes -ge 5) { $comfyFailures = 0 }
                    $comfyFailures++
                    $delay = [Math]::Min(60, [Math]::Pow(2, [Math]::Min(5, $comfyFailures - 1)) * 2)
                    $comfyNextStart = $now.AddSeconds($delay)
                    Write-SupervisorLog $logPath "ComfyUI exited with code $exitCode; retrying in $([int]$delay) second(s) while Worker control stays online."
                }
                if ($null -ne $launch.ComfyUI -and
                    $null -eq $comfyProcess -and $now -ge $comfyNextStart) {
                    try {
                        Write-SupervisorLog $logPath "Starting the isolated ComfyUI process."
                        $comfyProcess = Start-OwnedProcess $launch.ComfyUI "comfyui" $logRoot
                        $comfyStartedAt = [DateTimeOffset]::Now
                    }
                    catch {
                        $comfyFailures++
                        $delay = [Math]::Min(60, [Math]::Pow(2, [Math]::Min(5, $comfyFailures - 1)) * 2)
                        $comfyNextStart = $now.AddSeconds($delay)
                        Write-SupervisorLog $logPath "ComfyUI launch failed; retrying in $([int]$delay) second(s) while Worker control stays online."
                    }
                }
                Start-Sleep -Seconds 2
            }
        }
        finally {
            $cleanupFailures = [Collections.Generic.List[string]]::new()
            foreach ($ownedProcess in @($workerProcess, $comfyProcess)) {
                if ($null -ne $ownedProcess) {
                    $ownedName = if ($ownedProcess -eq $workerProcess) { "Worker" } else { "ComfyUI" }
                    try {
                        Stop-OwnedProcessTree $ownedProcess $ownedName
                    }
                    catch {
                        $cleanupFailures.Add([string]$_.Exception.Message)
                    }
                }
            }
            if ($cleanupFailures.Count -eq 0 -and
                (Test-Path -LiteralPath $stopRequest -PathType Leaf)) {
                Remove-Item -LiteralPath $stopRequest -Force
            }
            if ($null -ne $hostControlStatus) {
                try {
                    Remove-SafeControlFile $hostControlStatus
                }
                catch {
                    $cleanupFailures.Add("The Worker host-control status could not be removed safely.")
                }
            }
            $mutex.ReleaseMutex()
            $mutex.Dispose()
            if ($cleanupFailures.Count -gt 0) {
                throw "Owned process cleanup failed: $($cleanupFailures -join '; ')"
            }
        }
    }
    "Status" {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($null -eq $task) {
            Write-Output "not-installed"
            exit 3
        }
        $taskState = ([string]$task.State).ToLowerInvariant()
        Write-Output $taskState
        exit 0
    }
}
