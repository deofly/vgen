#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($PSVersionTable.PSEdition -ne "Desktop" -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "This test must run under Windows PowerShell 5.1."
}

function Assert-Equal {
    param(
        [object]$Actual,
        [object]$Expected,
        [string]$Description
    )
    if ($Actual -ne $Expected) {
        throw "$Description mismatch. Expected '$Expected', got '$Actual'."
    }
}

function Assert-True {
    param([bool]$Value, [string]$Description)
    if (-not $Value) {
        throw "$Description assertion failed."
    }
}

function Wait-Condition {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSeconds,
        [string]$Description
    )
    $deadline = [DateTimeOffset]::Now.AddSeconds($TimeoutSeconds)
    do {
        if (& $Condition) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::Now -lt $deadline)
    throw "Timed out waiting for $Description."
}

function Invoke-TestPowerShell {
    param(
        [string]$PowerShellPath,
        [string]$ScriptPath,
        [string[]]$ScriptArguments
    )
    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", $ScriptPath
    ) + @($ScriptArguments)
    $output = @(& $PowerShellPath @arguments 2>&1 | ForEach-Object { [string]$_ })
    return [PSCustomObject]@{
        ExitCode = [int]$LASTEXITCODE
        Output = $output
    }
}

function Assert-CommandSucceeded {
    param([PSCustomObject]$Result, [string]$Description)
    if ($Result.ExitCode -ne 0) {
        throw "$Description failed with exit code $($Result.ExitCode): $($Result.Output -join ' | ')"
    }
}

function Get-XmlText {
    param(
        [xml]$Document,
        [System.Xml.XmlNamespaceManager]$Namespaces,
        [string]$XPath,
        [string]$Description
    )
    $node = $Document.SelectSingleNode($XPath, $Namespaces)
    if ($null -eq $node) {
        throw "Scheduled task XML is missing $Description."
    }
    return [string]$node.InnerText
}

function Read-TestPid {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return 0
    }
    $value = 0
    $raw = [IO.File]::ReadAllText($Path).Trim()
    if (-not [int]::TryParse($raw, [ref]$value)) {
        return 0
    }
    return $value
}

function Stop-TestChildren {
    param([string]$StateRoot)
    if (-not (Test-Path -LiteralPath $StateRoot -PathType Container)) {
        return
    }
    foreach ($pidList in @(Get-ChildItem -LiteralPath $StateRoot -Filter "*-pids.txt" -File)) {
        foreach ($line in [IO.File]::ReadAllLines($pidList.FullName)) {
            $processId = 0
            if ([int]::TryParse($line.Trim(), [ref]$processId) -and $processId -gt 0) {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

$resolvedRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$sourceSupervisor = Join-Path $resolvedRepository "examples\windows-worker\supervise-worker.ps1"
$sourceLauncher = Join-Path $resolvedRepository "examples\windows-worker\start-worker.cmd"
foreach ($requiredSource in @($sourceSupervisor, $sourceLauncher)) {
    if (-not (Test-Path -LiteralPath $requiredSource -PathType Leaf)) {
        throw "Required Windows Worker source is missing: $requiredSource"
    }
}

$powerShellPath = [IO.Path]::Combine(
    $env:SystemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
)
if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
    throw "Windows PowerShell 5.1 executable could not be located."
}

$taskName = "VGen Worker Supervisor"
$realLocalAppData = $env:LOCALAPPDATA
if ([string]::IsNullOrWhiteSpace($realLocalAppData)) {
    throw "LOCALAPPDATA is required for this Windows integration test."
}
$vgenRoot = Join-Path $realLocalAppData "VGen"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($null -ne $existingTask -or (Test-Path -LiteralPath $vgenRoot)) {
    throw "Persistent Worker integration requires a clean hosted runner; existing VGen state was not changed."
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) "vgen-supervisor-$([Guid]::NewGuid().ToString('N'))"
$stateRoot = Join-Path $vgenRoot "tests\state"
$launchConfig = Join-Path $vgenRoot "tests\launch-config.json"
$managedSupervisor = Join-Path $vgenRoot "supervisor\supervise-worker.ps1"
$workerScript = Join-Path $testRoot "fake-worker.ps1"
$comfyScript = Join-Path $testRoot "fake-comfyui.ps1"
$grandchildScript = Join-Path $testRoot "fake-grandchild.ps1"
$workerCurrentPid = Join-Path $stateRoot "worker-current-pid.txt"
$workerPidList = Join-Path $stateRoot "worker-pids.txt"
$workerCrashRequest = Join-Path $stateRoot "worker-crash.request"
$comfyCurrentPid = Join-Path $stateRoot "comfyui-current-pid.txt"
$comfyGrandchildPid = Join-Path $stateRoot "comfyui-grandchild-current-pid.txt"
$supervisorLog = Join-Path $vgenRoot "logs\worker-supervisor.log"
$vgenRootCreatedByTest = $false
$supervisorRunProcess = $null

try {
    [IO.Directory]::CreateDirectory($testRoot) | Out-Null
    [IO.Directory]::CreateDirectory($stateRoot) | Out-Null
    $vgenRootCreatedByTest = $true

    $fakeWorker = @'
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$StateRoot)
$ErrorActionPreference = "Stop"
$utf8 = New-Object Text.UTF8Encoding($false)
$pidList = Join-Path $StateRoot "worker-pids.txt"
$currentPid = Join-Path $StateRoot "worker-current-pid.txt"
$crashRequest = Join-Path $StateRoot "worker-crash.request"
[IO.File]::AppendAllText($pidList, "$PID`r`n", $utf8)
[IO.File]::WriteAllText($currentPid, "$PID`r`n", $utf8)
while ($true) {
    if (Test-Path -LiteralPath $crashRequest -PathType Leaf) {
        Remove-Item -LiteralPath $crashRequest -Force
        exit 17
    }
    Start-Sleep -Milliseconds 200
}
'@
    $fakeComfy = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StateRoot,
    [Parameter(Mandatory = $true)][string]$GrandchildScript
)
$ErrorActionPreference = "Stop"
$utf8 = New-Object Text.UTF8Encoding($false)
$pidList = Join-Path $StateRoot "comfyui-pids.txt"
$currentPid = Join-Path $StateRoot "comfyui-current-pid.txt"
$grandchildPidList = Join-Path $StateRoot "comfyui-grandchild-pids.txt"
$grandchildCurrentPid = Join-Path $StateRoot "comfyui-grandchild-current-pid.txt"
[IO.File]::AppendAllText($pidList, "$PID`r`n", $utf8)
[IO.File]::WriteAllText($currentPid, "$PID`r`n", $utf8)
$powerShell = [IO.Path]::Combine(
    $env:SystemRoot,
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
)
$grandchild = Start-Process `
    -FilePath $powerShell `
    -ArgumentList @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-File", $GrandchildScript
    ) `
    -NoNewWindow `
    -PassThru
[IO.File]::AppendAllText($grandchildPidList, "$($grandchild.Id)`r`n", $utf8)
[IO.File]::WriteAllText($grandchildCurrentPid, "$($grandchild.Id)`r`n", $utf8)
while ($true) {
    Start-Sleep -Milliseconds 200
}
'@
    $fakeGrandchild = @'
$ErrorActionPreference = "Stop"
while ($true) {
    Start-Sleep -Milliseconds 200
}
'@
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($workerScript, $fakeWorker, $utf8)
    [IO.File]::WriteAllText($comfyScript, $fakeComfy, $utf8)
    [IO.File]::WriteAllText($grandchildScript, $fakeGrandchild, $utf8)

    $commonArguments = @(
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass"
    )
    $config = [ordered]@{
        format = "vgen-windows-worker-launch-config"
        version = 1
        worker = [ordered]@{
            executable = $powerShellPath
            arguments = @($commonArguments + @("-File", $workerScript, "-StateRoot", $stateRoot))
            working_directory = $testRoot
        }
        comfyui = [ordered]@{
            executable = $powerShellPath
            arguments = @(
                $commonArguments + @(
                    "-File", $comfyScript,
                    "-StateRoot", $stateRoot,
                    "-GrandchildScript", $grandchildScript
                )
            )
            working_directory = $testRoot
        }
    }
    [IO.File]::WriteAllText(
        $launchConfig,
        (($config | ConvertTo-Json -Depth 6) + "`n"),
        $utf8
    )

    $install = Invoke-TestPowerShell `
        $powerShellPath `
        $sourceSupervisor `
        @("-Mode", "Install", "-LaunchConfig", $launchConfig)
    Assert-CommandSucceeded $install "Supervisor Install mode"
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    Assert-Equal $task.TaskPath "\" "Scheduled task path"
    Assert-Equal ([string]$task.State) "Ready" "Scheduled task state after Install"
    Assert-True (Test-Path -LiteralPath $managedSupervisor -PathType Leaf) `
        "Managed supervisor installation"

    [xml]$taskXml = Export-ScheduledTask -TaskName $taskName
    $namespaces = [System.Xml.XmlNamespaceManager]::new($taskXml.NameTable)
    $namespaces.AddNamespace("t", $taskXml.DocumentElement.NamespaceURI)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $triggerUser = Get-XmlText `
        $taskXml $namespaces "//t:Triggers/t:LogonTrigger/t:UserId" "logon trigger user"
    Assert-True ($triggerUser -ieq $identity.Name -or $triggerUser -eq $identity.User.Value) `
        "Scheduled task logon trigger identity"
    $principalUser = Get-XmlText `
        $taskXml $namespaces "//t:Principals/t:Principal/t:UserId" "principal user"
    Assert-True ($principalUser -ieq $identity.Name -or $principalUser -eq $identity.User.Value) `
        "Scheduled task principal identity"
    Assert-Equal `
        (Get-XmlText $taskXml $namespaces "//t:Principals/t:Principal/t:LogonType" "logon type") `
        "InteractiveToken" `
        "Scheduled task logon type"
    Assert-Equal `
        (Get-XmlText $taskXml $namespaces "//t:Principals/t:Principal/t:RunLevel" "run level") `
        "LeastPrivilege" `
        "Scheduled task run level"
    Assert-Equal `
        (Get-XmlText $taskXml $namespaces "//t:Settings/t:MultipleInstancesPolicy" "instance policy") `
        "IgnoreNew" `
        "Scheduled task multiple-instance policy"
    Assert-Equal `
        ([Xml.XmlConvert]::ToTimeSpan((Get-XmlText $taskXml $namespaces "//t:Settings/t:ExecutionTimeLimit" "execution time limit"))) `
        ([TimeSpan]::Zero) `
        "Scheduled task execution time limit"
    Assert-Equal `
        ([Xml.XmlConvert]::ToTimeSpan((Get-XmlText $taskXml $namespaces "//t:Settings/t:RestartOnFailure/t:Interval" "restart interval"))) `
        ([TimeSpan]::FromMinutes(1)) `
        "Scheduled task restart interval"
    Assert-Equal `
        (Get-XmlText $taskXml $namespaces "//t:Settings/t:RestartOnFailure/t:Count" "restart count") `
        "999" `
        "Scheduled task restart count"
    foreach ($booleanContract in @(
        @("//t:Settings/t:StartWhenAvailable", "true", "start-when-available"),
        @("//t:Settings/t:DisallowStartIfOnBatteries", "false", "battery start"),
        @("//t:Settings/t:StopIfGoingOnBatteries", "false", "battery stop")
    )) {
        Assert-Equal `
            ((Get-XmlText $taskXml $namespaces $booleanContract[0] $booleanContract[2]).ToLowerInvariant()) `
            $booleanContract[1] `
            "Scheduled task $($booleanContract[2]) setting"
    }
    $taskCommand = Get-XmlText $taskXml $namespaces "//t:Actions/t:Exec/t:Command" "action command"
    Assert-Equal `
        ([IO.Path]::GetFullPath($taskCommand).ToLowerInvariant()) `
        ([IO.Path]::GetFullPath($powerShellPath).ToLowerInvariant()) `
        "Scheduled task PowerShell action"
    $taskArguments = Get-XmlText $taskXml $namespaces "//t:Actions/t:Exec/t:Arguments" "action arguments"
    Assert-True ($taskArguments.Contains("-NoProfile")) "Scheduled task no-profile argument"
    Assert-True ($taskArguments.Contains("-NonInteractive")) `
        "Scheduled task non-interactive argument"
    Assert-True ($taskArguments.Contains("-WindowStyle Hidden")) `
        "Scheduled task hidden-window argument"
    Assert-True ($taskArguments.Contains("-File `"$managedSupervisor`"")) `
        "Scheduled task managed supervisor argument"
    Assert-True ($taskArguments.EndsWith("-Mode Run")) "Scheduled task Run mode argument"
    foreach ($forbidden in @("private_key", "session_token", "invite", "password")) {
        Assert-True (-not $taskArguments.ToLowerInvariant().Contains($forbidden)) `
            "Scheduled task action excludes $forbidden"
    }

    $statusReady = Invoke-TestPowerShell $powerShellPath $managedSupervisor @("-Mode", "Status")
    Assert-CommandSucceeded $statusReady "Supervisor Status mode before Start"
    Assert-Equal $statusReady.Output[-1] "ready" "Supervisor status before Start"

    # GitHub's hosted Windows runner uses a non-interactive session, so Task
    # Scheduler cannot launch an InteractiveToken task there. Install/export
    # above still exercise the real scheduler. The control modes below run in
    # isolated child PowerShell processes with executable scheduler doubles;
    # dot-sourcing is safe because supervisor `exit` only terminates that child.
    $mockTaskState = Join-Path $stateRoot "mock-task-state.txt"
    $mockStartMarker = Join-Path $stateRoot "mock-task-start.txt"
    $mockStopMarker = Join-Path $stateRoot "mock-task-stop.txt"
    $mockWrapper = Join-Path $testRoot "invoke-supervisor-with-task-mock.ps1"
    $mockWrapperContent = @'
#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SupervisorPath,
    [Parameter(Mandatory = $true)][ValidateSet("Start", "Stop", "Status")][string]$Mode,
    [Parameter(Mandatory = $true)][string]$TaskStatePath,
    [Parameter(Mandatory = $true)][string]$StartMarkerPath,
    [Parameter(Mandatory = $true)][string]$StopMarkerPath
)
$ErrorActionPreference = "Stop"
$utf8 = New-Object Text.UTF8Encoding($false)
$script:MockStopPollCount = 0

function Read-MockTaskState {
    return [IO.File]::ReadAllText($TaskStatePath).Trim()
}

function Write-MockTaskState {
    param([string]$Value)
    [IO.File]::WriteAllText($TaskStatePath, "$Value`r`n", $utf8)
}

function Get-ScheduledTask {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TaskName)
    if ($Mode -eq "Stop") {
        $script:MockStopPollCount++
        if ($script:MockStopPollCount -gt 1) {
            Write-MockTaskState "Ready"
            [IO.File]::WriteAllText($StopMarkerPath, "$TaskName`:graceful", $utf8)
        }
    }
    return [PSCustomObject]@{
        TaskName = $TaskName
        TaskPath = "\"
        State = (Read-MockTaskState)
    }
}

function Start-ScheduledTask {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TaskName)
    [IO.File]::WriteAllText($StartMarkerPath, $TaskName, $utf8)
    Write-MockTaskState "Running"
}

function Stop-ScheduledTask {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$TaskName)
    [IO.File]::WriteAllText($StopMarkerPath, "$TaskName`:forced", $utf8)
    Write-MockTaskState "Ready"
}

. $SupervisorPath -Mode $Mode
throw "The isolated supervisor control mode returned without an explicit exit."
'@
    [IO.File]::WriteAllText($mockWrapper, $mockWrapperContent, $utf8)
    [IO.File]::WriteAllText($mockTaskState, "Ready`r`n", $utf8)
    $mockArguments = @(
        "-SupervisorPath", $managedSupervisor,
        "-TaskStatePath", $mockTaskState,
        "-StartMarkerPath", $mockStartMarker,
        "-StopMarkerPath", $mockStopMarker
    )

    $mockStatusReady = Invoke-TestPowerShell `
        $powerShellPath $mockWrapper (@("-Mode", "Status") + $mockArguments)
    Assert-CommandSucceeded $mockStatusReady "Supervisor mocked Status mode before Start"
    Assert-Equal $mockStatusReady.Output[-1] "ready" "Mocked supervisor status before Start"

    $start = Invoke-TestPowerShell `
        $powerShellPath $mockWrapper (@("-Mode", "Start") + $mockArguments)
    Assert-CommandSucceeded $start "Supervisor Start mode with executable scheduler mock"
    Assert-Equal ([IO.File]::ReadAllText($mockStartMarker)) $taskName `
        "Supervisor Start scheduled-task target"
    Assert-Equal ([IO.File]::ReadAllText($mockTaskState).Trim()) "Running" `
        "Supervisor Start scheduled-task state"

    # Run is launched in another process so its long-lived loop and any `exit`
    # remain isolated from this integration test, just as they are in the task.
    $runArguments = (
        "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden " +
        "-ExecutionPolicy Bypass -File `"$managedSupervisor`" -Mode Run"
    )
    $supervisorRunProcess = Start-Process `
        -FilePath $powerShellPath `
        -ArgumentList $runArguments `
        -WindowStyle Hidden `
        -PassThru
    Wait-Condition `
        {
            (Read-TestPid $workerCurrentPid) -gt 0 -and
                (Read-TestPid $comfyCurrentPid) -gt 0 -and
                (Read-TestPid $comfyGrandchildPid) -gt 0
        } `
        30 `
        "initial Worker, ComfyUI, and ComfyUI grandchild processes"
    $initialWorkerPid = Read-TestPid $workerCurrentPid
    $initialComfyPid = Read-TestPid $comfyCurrentPid
    $initialComfyGrandchildPid = Read-TestPid $comfyGrandchildPid
    Assert-True ($null -ne (Get-Process -Id $initialWorkerPid -ErrorAction SilentlyContinue)) `
        "Initial Worker process is running"
    Assert-True ($null -ne (Get-Process -Id $initialComfyPid -ErrorAction SilentlyContinue)) `
        "Initial ComfyUI process is running"
    Assert-True `
        ($null -ne (Get-Process -Id $initialComfyGrandchildPid -ErrorAction SilentlyContinue)) `
        "Initial ComfyUI grandchild process is running"
    Assert-True (Test-Path -LiteralPath $supervisorLog -PathType Leaf) `
        "Supervisor log uses the managed VGen log path"
    $managedLogRoot = Split-Path -Parent $supervisorLog
    Assert-True (@(Get-ChildItem -LiteralPath $managedLogRoot -Filter "worker-*.err.log").Count -ge 1) `
        "Worker stderr log uses the managed VGen log path"
    Assert-True (@(Get-ChildItem -LiteralPath $managedLogRoot -Filter "comfyui-*.err.log").Count -ge 1) `
        "ComfyUI stderr log uses the managed VGen log path"
    Assert-Equal `
        (@(Get-ChildItem -LiteralPath $managedLogRoot -Filter "*.out.log").Count) `
        0 `
        "Child stdout remains disconnected from managed log storage"

    $statusRunning = Invoke-TestPowerShell `
        $powerShellPath $mockWrapper (@("-Mode", "Status") + $mockArguments)
    Assert-CommandSucceeded $statusRunning "Supervisor mocked Status mode while running"
    Assert-Equal $statusRunning.Output[-1] "running" "Supervisor status while running"

    [IO.File]::WriteAllText($workerCrashRequest, "crash`r`n", [Text.Encoding]::ASCII)
    Wait-Condition `
        {
            $currentWorkerPid = Read-TestPid $workerCurrentPid
            $workerStarts = if (Test-Path -LiteralPath $workerPidList -PathType Leaf) {
                [IO.File]::ReadAllLines($workerPidList).Count
            }
            else { 0 }
            $currentWorkerPid -gt 0 -and
                $currentWorkerPid -ne $initialWorkerPid -and
                $workerStarts -ge 2
        } `
        45 `
        "independent Worker restart"
    $restartedWorkerPid = Read-TestPid $workerCurrentPid
    Assert-True ($null -ne (Get-Process -Id $restartedWorkerPid -ErrorAction SilentlyContinue)) `
        "Restarted Worker process is running"
    Assert-True ($null -eq (Get-Process -Id $initialWorkerPid -ErrorAction SilentlyContinue)) `
        "Crashed Worker process exited before replacement"
    Assert-Equal (Read-TestPid $comfyCurrentPid) $initialComfyPid `
        "ComfyUI PID across Worker restart"
    Assert-True ($null -ne (Get-Process -Id $initialComfyPid -ErrorAction SilentlyContinue)) `
        "ComfyUI remains running across Worker restart"
    Assert-Equal (Read-TestPid $comfyGrandchildPid) $initialComfyGrandchildPid `
        "ComfyUI grandchild PID across Worker restart"
    Assert-True `
        ($null -ne (Get-Process -Id $initialComfyGrandchildPid -ErrorAction SilentlyContinue)) `
        "ComfyUI grandchild remains running across Worker restart"

    $stop = Invoke-TestPowerShell `
        $powerShellPath $mockWrapper (@("-Mode", "Stop") + $mockArguments)
    Assert-CommandSucceeded $stop "Supervisor Stop mode with executable scheduler mock"
    Assert-Equal ([IO.File]::ReadAllText($mockStopMarker)) "$taskName`:graceful" `
        "Supervisor Stop scheduled-task transition"
    Wait-Condition { $supervisorRunProcess.HasExited } 30 "supervisor Run process exit"
    $supervisorRunProcess.WaitForExit()
    Assert-Equal $supervisorRunProcess.ExitCode 0 "Supervisor Run mode exit code"
    $supervisorRunProcess.Dispose()
    $supervisorRunProcess = $null
    Wait-Condition `
        {
            $workerGone = $null -eq (Get-Process -Id $restartedWorkerPid -ErrorAction SilentlyContinue)
            $comfyGone = $null -eq (Get-Process -Id $initialComfyPid -ErrorAction SilentlyContinue)
            $grandchildGone = $null -eq (
                Get-Process -Id $initialComfyGrandchildPid -ErrorAction SilentlyContinue
            )
            $workerGone -and $comfyGone -and $grandchildGone
        } `
        30 `
        "owned process-tree cleanup after Stop"
    $statusStopped = Invoke-TestPowerShell `
        $powerShellPath $mockWrapper (@("-Mode", "Status") + $mockArguments)
    Assert-CommandSucceeded $statusStopped "Supervisor mocked Status mode after Stop"
    Assert-Equal $statusStopped.Output[-1] "ready" "Supervisor status after Stop"
    $realStatusStopped = Invoke-TestPowerShell `
        $powerShellPath $managedSupervisor @("-Mode", "Status")
    Assert-CommandSucceeded $realStatusStopped "Real registered task Status mode after Stop"
    Assert-Equal $realStatusStopped.Output[-1] "ready" "Real registered task status after Stop"

    $launcherContent = [IO.File]::ReadAllText($sourceLauncher)
    Assert-True (-not [regex]::IsMatch($launcherContent, '(?im)^\s*pause\s*$')) `
        "Versioned Worker launcher contains no interactive pause"

    $launcherTestRoot = Join-Path $testRoot "launcher paths"
    $normalLocalAppData = Join-Path $launcherTestRoot "normal local app data"
    $normalPackage = Join-Path $launcherTestRoot "normal package"
    $fakeManaged = Join-Path $normalLocalAppData "VGen\supervisor\supervise-worker.ps1"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $fakeManaged)) | Out-Null
    [IO.Directory]::CreateDirectory($normalPackage) | Out-Null
    Copy-Item -LiteralPath $sourceLauncher -Destination (Join-Path $normalPackage "start-worker.cmd")
    $normalMarker = Join-Path $launcherTestRoot "normal-invocation.txt"
    $fakeManagedContent = @'
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Mode)
[IO.File]::WriteAllText($env:VGEN_TEST_LAUNCHER_MARKER, $Mode, [Text.Encoding]::ASCII)
exit 0
'@
    [IO.File]::WriteAllText($fakeManaged, $fakeManagedContent, $utf8)
    $env:LOCALAPPDATA = $normalLocalAppData
    $env:VGEN_TEST_LAUNCHER_MARKER = $normalMarker
    & $env:ComSpec /d /c "`"$(Join-Path $normalPackage 'start-worker.cmd')`""
    Assert-Equal $LASTEXITCODE 0 "Versioned launcher managed Start exit code"
    Assert-Equal ([IO.File]::ReadAllText($normalMarker)) "Start" `
        "Versioned launcher managed Start arguments"

    $fallbackLocalAppData = Join-Path $launcherTestRoot "fallback local app data"
    $fallbackPackage = Join-Path $launcherTestRoot "fallback package"
    $fallbackManaged = Join-Path `
        $fallbackLocalAppData `
        "VGen\supervisor\supervise-worker.ps1"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $fallbackManaged)) | Out-Null
    [IO.Directory]::CreateDirectory($fallbackPackage) | Out-Null
    Copy-Item `
        -LiteralPath $sourceLauncher `
        -Destination (Join-Path $fallbackPackage "start-worker.cmd")
    $fallbackManagedMarker = Join-Path $launcherTestRoot "fallback-managed-invocation.txt"
    $fallbackEnrollmentMarker = Join-Path `
        $launcherTestRoot `
        "fallback-enrollment-invocation.txt"
    $failingManagedContent = @'
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$Mode)
[IO.File]::WriteAllText($env:VGEN_TEST_MANAGED_MARKER, $Mode, [Text.Encoding]::ASCII)
exit 41
'@
    $fallbackEnrollmentContent = @'
[IO.File]::WriteAllText(
    $env:VGEN_TEST_ENROLLMENT_MARKER,
    ($args -join "`r`n"),
    [Text.Encoding]::ASCII
)
exit 0
'@
    [IO.File]::WriteAllText($fallbackManaged, $failingManagedContent, $utf8)
    [IO.File]::WriteAllText(
        (Join-Path $fallbackPackage "enroll-worker.ps1"),
        $fallbackEnrollmentContent,
        $utf8
    )
    $env:LOCALAPPDATA = $fallbackLocalAppData
    $env:VGEN_TEST_MANAGED_MARKER = $fallbackManagedMarker
    $env:VGEN_TEST_ENROLLMENT_MARKER = $fallbackEnrollmentMarker
    & $env:ComSpec /d /c "`"$(Join-Path $fallbackPackage 'start-worker.cmd')`""
    Assert-Equal $LASTEXITCODE 0 "Versioned launcher automatic Repair exit code"
    Assert-Equal ([IO.File]::ReadAllText($fallbackManagedMarker)) "Start" `
        "Versioned launcher failed managed Start arguments"
    Assert-Equal ([IO.File]::ReadAllText($fallbackEnrollmentMarker)) "-Repair" `
        "Versioned launcher automatic Repair arguments"

    $repairLocalAppData = Join-Path $launcherTestRoot "repair local app data"
    $repairPackage = Join-Path $launcherTestRoot "repair package"
    [IO.Directory]::CreateDirectory($repairLocalAppData) | Out-Null
    [IO.Directory]::CreateDirectory($repairPackage) | Out-Null
    Copy-Item -LiteralPath $sourceLauncher -Destination (Join-Path $repairPackage "start-worker.cmd")
    $repairMarker = Join-Path $launcherTestRoot "repair-invocation.txt"
    $fakeEnrollment = @'
[IO.File]::WriteAllText(
    $env:VGEN_TEST_LAUNCHER_MARKER,
    ($args -join "`r`n"),
    [Text.Encoding]::ASCII
)
exit 0
'@
    [IO.File]::WriteAllText(
        (Join-Path $repairPackage "enroll-worker.ps1"),
        $fakeEnrollment,
        $utf8
    )
    $env:LOCALAPPDATA = $repairLocalAppData
    $env:VGEN_TEST_LAUNCHER_MARKER = $repairMarker
    & $env:ComSpec /d /c "`"$(Join-Path $repairPackage 'start-worker.cmd')`" -Repair"
    Assert-Equal $LASTEXITCODE 0 "Versioned launcher Repair exit code"
    Assert-Equal ([IO.File]::ReadAllText($repairMarker)) "-Repair" `
        "Versioned launcher Repair arguments"

    Write-Host "Windows PowerShell 5.1 persistent Worker supervisor checks passed"
}
finally {
    $env:LOCALAPPDATA = $realLocalAppData
    [Environment]::SetEnvironmentVariable("VGEN_TEST_LAUNCHER_MARKER", $null, "Process")
    [Environment]::SetEnvironmentVariable("VGEN_TEST_MANAGED_MARKER", $null, "Process")
    [Environment]::SetEnvironmentVariable("VGEN_TEST_ENROLLMENT_MARKER", $null, "Process")
    if ($null -ne $supervisorRunProcess) {
        try {
            if (-not $supervisorRunProcess.HasExited) {
                $cleanupStopRequest = Join-Path $vgenRoot "supervisor\stop.request"
                [IO.File]::WriteAllText(
                    $cleanupStopRequest,
                    "stop`r`n",
                    [Text.Encoding]::ASCII
                )
                $null = $supervisorRunProcess.WaitForExit(10000)
            }
            if (-not $supervisorRunProcess.HasExited) {
                Stop-Process -Id $supervisorRunProcess.Id -Force -ErrorAction SilentlyContinue
                $null = $supervisorRunProcess.WaitForExit(5000)
            }
        }
        catch {
            # Exact PID-list cleanup below is the final recovery path.
        }
        finally {
            $supervisorRunProcess.Dispose()
        }
    }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        if (Test-Path -LiteralPath $managedSupervisor -PathType Leaf) {
            try {
                $null = Invoke-TestPowerShell $powerShellPath $managedSupervisor @("-Mode", "Stop")
            }
            catch {
                # Continue to the exact task cleanup below.
            }
        }
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Stop-TestChildren $stateRoot
    if ($vgenRootCreatedByTest -and (Test-Path -LiteralPath $vgenRoot)) {
        Remove-Item -LiteralPath $vgenRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
