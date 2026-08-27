#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Assert-PathEqual {
    param(
        [string]$Actual,
        [string]$Expected,
        [string]$Description
    )
    $actualPath = [IO.Path]::GetFullPath($Actual)
    $expectedPath = [IO.Path]::GetFullPath($Expected)
    if (-not $actualPath.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Description mismatch. Expected '$expectedPath', got '$actualPath'."
    }
}

$setupPath = Join-Path `
    (Resolve-Path -LiteralPath $RepositoryRoot).Path `
    "examples\windows-worker\setup-worker.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $setupPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    $parseErrors | ForEach-Object { Write-Error $_.Message }
    exit 1
}

$requiredFunctions = @(
    "Test-WorkerPathAncestryWithoutReparse",
    "Test-AllowedWorkerPythonPath",
    "Compare-WorkerReleaseVersion",
    "Get-WorkerRuntimeState",
    "Select-InitialWorkerRuntime"
)
$functionAsts = @(
    $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -in $requiredFunctions
        },
        $true
    )
)
foreach ($functionName in $requiredFunctions) {
    $matches = @($functionAsts | Where-Object { $_.Name -eq $functionName })
    Assert-Equal $matches.Count 1 "$functionName function count"
}
$definitions = @(
    $functionAsts |
        Sort-Object { $_.Extent.StartOffset } |
        ForEach-Object { $_.Extent.Text }
)
Invoke-Expression ($definitions -join [Environment]::NewLine)

function Write-TestPointer {
    param(
        [string]$WorkRoot,
        [string]$ActivePython,
        [string]$ActiveVersion,
        [switch]$Pending,
        [switch]$ActivationVerified,
        [switch]$RolledBack,
        [string]$PreviousPython,
        [string]$PreviousVersion = "0.13.8"
    )
    $pointer = [ordered]@{
        format = "vgen-worker-runtime-pointer"
        version = 1
        active_python = $ActivePython
        active_version = $ActiveVersion
    }
    if ($Pending) {
        $pointer["previous_python"] = $PreviousPython
        $pointer["previous_version"] = $PreviousVersion
        $pointer["pending_job_id"] = "mtn_test"
        $pointer["pending_fencing_token"] = 1
        $pointer["artifact_sha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        if ($ActivationVerified) {
            $pointer["activation_verified_at"] = 1
        }
    }
    if ($RolledBack) {
        $pointer["rolled_back_job_id"] = "mtn_rolled_back"
        $pointer["rolled_back_at"] = 1
    }
    $json = ($pointer | ConvertTo-Json -Depth 4 -Compress) + "`n"
    [IO.File]::WriteAllText(
        (Join-Path $WorkRoot "runtime-active.json"),
        $json,
        (New-Object Text.UTF8Encoding($false))
    )
}

$testRoot = Join-Path `
    ([IO.Path]::GetTempPath()) `
    "vgen-runtime-pointer-$([Guid]::NewGuid().ToString('N'))"
$junctionPaths = New-Object System.Collections.Generic.List[string]
try {
    $workRoot = Join-Path $testRoot "work"
    $releaseRoot = Join-Path $workRoot "runtime-releases"
    $basePython = Join-Path $testRoot "worker-runtime-0.13.10\Scripts\python.exe"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $basePython)) | Out-Null
    [IO.Directory]::CreateDirectory($releaseRoot) | Out-Null
    [IO.File]::WriteAllText($basePython, "base")

    $cases = @(
        [PSCustomObject]@{ Version = "0.13.9"; Expected = "base" },
        [PSCustomObject]@{ Version = "0.13.10"; Expected = "active" },
        [PSCustomObject]@{ Version = "0.14.0"; Expected = "active" }
    )
    foreach ($case in $cases) {
        $activePython = Join-Path `
            $releaseRoot `
            "$($case.Version)\Scripts\python.exe"
        [IO.Directory]::CreateDirectory((Split-Path -Parent $activePython)) | Out-Null
        [IO.File]::WriteAllText($activePython, "active")
        Write-TestPointer $workRoot $activePython $case.Version

        $state = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
        $expectedPython = if ($case.Expected -eq "base") { $basePython } else { $activePython }
        Assert-PathEqual `
            $state.ActivePython `
            $expectedPython `
            "Completed pointer selection for $($case.Version)"
        Assert-Equal $state.Pending $false "Completed pointer pending state"
        Assert-Equal `
            -Actual $state.PreviousPython `
            -Expected $null `
            -Description "Completed pointer previous runtime"
    }

    $missingOlderPython = Join-Path $releaseRoot "0.13.8-missing\Scripts\python.exe"
    Write-TestPointer $workRoot $missingOlderPython "0.13.8"
    $missingOlderState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-PathEqual `
        $missingOlderState.ActivePython `
        $basePython `
        "Missing superseded runtime selection"
    Assert-Equal $missingOlderState.Pending $false "Missing superseded runtime pending state"

    $missingEqualPython = Join-Path $releaseRoot "0.13.10-missing\Scripts\python.exe"
    Write-TestPointer $workRoot $missingEqualPython "0.13.10"
    $missingEqualState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-PathEqual `
        $missingEqualState.ActivePython `
        $basePython `
        "Missing same-version runtime selection"
    Assert-Equal $missingEqualState.Pending $false "Missing same-version runtime pending state"

    $partialPointers = @(
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            pending_job_id = 0
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            pending_fencing_token = 1
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            activation_verified_at = 1
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            previous_python = $basePython
            previous_version = "0.13.9"
            pending_job_id = "mtn_missing_artifact"
            pending_fencing_token = 1
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            previous_python = $basePython
            previous_version = "0.13.9"
            pending_job_id = "   "
            pending_fencing_token = 1
            artifact_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            previous_python = $basePython
            previous_version = "0.13.9"
            pending_job_id = "mtn_mixed"
            pending_fencing_token = 1
            artifact_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            rolled_back_job_id = "mtn_old"
            rolled_back_at = 1
        },
        [ordered]@{
            format = "VGEN-WORKER-RUNTIME-POINTER"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = "1"
            active_python = $basePython
            active_version = "0.13.10"
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            previous_python = $basePython
            previous_version = "0.13.9"
            pending_job_id = "mtn_uppercase_digest"
            pending_fencing_token = 1
            artifact_sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        },
        [ordered]@{
            format = "vgen-worker-runtime-pointer"
            version = 1
            active_python = $basePython
            active_version = "0.13.10"
            rolled_back_job_id = "mtn_partial"
        }
    )
    foreach ($partialPointer in $partialPointers) {
        [IO.File]::WriteAllText(
            (Join-Path $workRoot "runtime-active.json"),
            (($partialPointer | ConvertTo-Json -Depth 4 -Compress) + "`n"),
            (New-Object Text.UTF8Encoding($false))
        )
        $partialRejected = $false
        try {
            $null = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
        }
        catch {
            $partialRejected = $true
        }
        Assert-Equal $partialRejected $true "Partial runtime pointer rejection"
    }

    $pendingPython = Join-Path $releaseRoot "pending\Scripts\python.exe"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $pendingPython)) | Out-Null
    [IO.File]::WriteAllText($pendingPython, "pending")
    Write-TestPointer `
        $workRoot `
        $pendingPython `
        "0.13.9" `
        -Pending `
        -PreviousPython $basePython
    $pendingState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-PathEqual $pendingState.ActivePython $pendingPython "Pending active runtime"
    Assert-PathEqual $pendingState.PreviousPython $basePython "Pending rollback runtime"
    Assert-Equal $pendingState.Pending $true "Pending pointer state"
    Assert-Equal $pendingState.ActiveAvailable $true "Pending target availability"
    Assert-Equal $pendingState.ActivationVerified $false "Pending activation verification"
    Assert-Equal $pendingState.SupersededPending $true "Superseded pending state"
    $pendingSelection = Select-InitialWorkerRuntime $pendingState
    Assert-PathEqual `
        $pendingSelection.Python `
        $basePython `
        "Superseded pending launch selection"
    Assert-Equal $pendingSelection.Rollback $true "Superseded pending rollback marker"

    Write-TestPointer `
        $workRoot `
        $pendingPython `
        "0.13.9" `
        -Pending `
        -ActivationVerified `
        -PreviousPython $basePython
    $verifiedPendingState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-Equal `
        $verifiedPendingState.ActivationVerified `
        $true `
        "Verified pending activation state"
    Assert-Equal `
        $verifiedPendingState.SupersededPending `
        $true `
        "Verified superseded pending state"
    $verifiedPendingSelection = Select-InitialWorkerRuntime $verifiedPendingState
    Assert-PathEqual `
        $verifiedPendingSelection.Python `
        $basePython `
        "Verified superseded launch selection"
    Assert-Equal `
        $verifiedPendingSelection.Rollback `
        $true `
        "Verified superseded rollback marker"

    $invalidVerifiedPointer = [IO.File]::ReadAllText(
        (Join-Path $workRoot "runtime-active.json")
    ) | ConvertFrom-Json
    $invalidVerifiedPointer.activation_verified_at = "1"
    $invalidVerifiedJson = ($invalidVerifiedPointer | ConvertTo-Json -Depth 4 -Compress) + "`n"
    [IO.File]::WriteAllText(
        (Join-Path $workRoot "runtime-active.json"),
        $invalidVerifiedJson,
        (New-Object Text.UTF8Encoding($false))
    )
    $invalidVerifiedRejected = $false
    try {
        $null = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    }
    catch {
        $invalidVerifiedRejected = $true
    }
    Assert-Equal $invalidVerifiedRejected $true "Invalid activation verification rejection"

    $missingPendingPython = Join-Path $releaseRoot "0.14.1-missing\Scripts\python.exe"
    Write-TestPointer `
        $workRoot `
        $missingPendingPython `
        "0.14.1" `
        -Pending `
        -PreviousPython $basePython `
        -PreviousVersion "0.13.10"
    $missingPendingState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-Equal $missingPendingState.Pending $true "Missing pending pointer state"
    Assert-Equal $missingPendingState.ActiveAvailable $false "Missing pending availability"
    Assert-PathEqual `
        $missingPendingState.PreviousPython `
        $basePython `
        "Missing pending rollback runtime"

    Write-TestPointer `
        $workRoot `
        $missingPendingPython `
        "0.14.1" `
        -Pending `
        -ActivationVerified `
        -PreviousPython $basePython `
        -PreviousVersion "0.13.10"
    $missingVerifiedState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-Equal $missingVerifiedState.Pending $true "Missing verified pending state"
    Assert-Equal $missingVerifiedState.ActiveAvailable $false "Missing verified availability"
    Assert-Equal `
        $missingVerifiedState.ActivationVerified `
        $true `
        "Missing verified activation state"
    $missingVerifiedRejected = $false
    try {
        $null = Select-InitialWorkerRuntime $missingVerifiedState
    }
    catch {
        $missingVerifiedRejected = $true
    }
    Assert-Equal `
        $missingVerifiedRejected `
        $true `
        "Missing verified target launch rejection"

    $olderReleasePython = Join-Path $releaseRoot "0.13.8\Scripts\python.exe"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $olderReleasePython)) | Out-Null
    [IO.File]::WriteAllText($olderReleasePython, "older release")
    Write-TestPointer `
        $workRoot `
        $pendingPython `
        "0.13.9" `
        -Pending `
        -PreviousPython $olderReleasePython `
        -PreviousVersion "0.13.8"
    $supersededRollback = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-PathEqual `
        $supersededRollback.PreviousPython `
        $basePython `
        "Newer installer rollback runtime"

    $outsideRoot = Join-Path $testRoot "outside"
    $outsidePython = Join-Path $outsideRoot "Scripts\python.exe"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $outsidePython)) | Out-Null
    [IO.File]::WriteAllText($outsidePython, "outside")
    $junctionPath = Join-Path $releaseRoot "junction"
    $junctionResult = & cmd.exe /d /c mklink /J $junctionPath $outsideRoot 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create runtime release junction: $junctionResult"
    }
    $junctionPaths.Add($junctionPath)
    Write-TestPointer `
        $workRoot `
        (Join-Path $junctionPath "Scripts\python.exe") `
        "0.14.0"
    $junctionRejected = $false
    try {
        $null = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    }
    catch {
        $junctionRejected = $true
    }
    Assert-Equal $junctionRejected $true "Runtime release junction rejection"

    $realWorkRoot = Join-Path $testRoot "real-work"
    $workJunction = Join-Path $testRoot "work-junction"
    $realCandidate = Join-Path $realWorkRoot "runtime-releases\0.14.0\Scripts\python.exe"
    [IO.Directory]::CreateDirectory((Split-Path -Parent $realCandidate)) | Out-Null
    [IO.File]::WriteAllText($realCandidate, "outside work root")
    $workJunctionResult = & cmd.exe /d /c mklink /J $workJunction $realWorkRoot 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Could not create Worker root junction: $workJunctionResult"
    }
    $junctionPaths.Add($workJunction)
    Write-TestPointer `
        $workJunction `
        (Join-Path $workJunction "runtime-releases\0.14.0\Scripts\python.exe") `
        "0.14.0"
    $workJunctionRejected = $false
    try {
        $null = Get-WorkerRuntimeState $workJunction $basePython "0.13.10"
    }
    catch {
        $workJunctionRejected = $true
    }
    Assert-Equal $workJunctionRejected $true "Worker root junction rejection"

    Write-TestPointer $workRoot $pendingPython "0.13.9" -RolledBack
    $rolledBackState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-PathEqual $rolledBackState.ActivePython $basePython "Terminal rollback runtime"
    Assert-Equal $rolledBackState.Pending $false "Terminal rollback pending state"

    $newerRecoveredPython = Join-Path $releaseRoot "0.14.0\Scripts\python.exe"
    Write-TestPointer $workRoot $newerRecoveredPython "0.14.0" -RolledBack
    $newerRollbackState = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    Assert-PathEqual `
        $newerRollbackState.ActivePython `
        $newerRecoveredPython `
        "Newer terminal rollback runtime"

    Write-TestPointer $workRoot $outsidePython "0.14.0" -RolledBack
    $outsideRollbackRejected = $false
    try {
        $null = Get-WorkerRuntimeState $workRoot $basePython "0.13.10"
    }
    catch {
        $outsideRollbackRejected = $true
    }
    Assert-Equal $outsideRollbackRejected $true "Outside terminal rollback rejection"

    $unboundedVersionRejected = $false
    try {
        $null = Compare-WorkerReleaseVersion "100000000000000000000.0.0" "9.0.0"
    }
    catch {
        $unboundedVersionRejected = $true
    }
    Assert-Equal $unboundedVersionRejected $true "Unbounded release rejection"

    Write-Host "Windows PowerShell 5.1 runtime pointer checks passed"
}
finally {
    foreach ($junctionPath in $junctionPaths) {
        if (Test-Path -LiteralPath $junctionPath) {
            $null = & cmd.exe /d /c rmdir $junctionPath 2>&1
        }
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}

exit 0
