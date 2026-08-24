#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BootstrapPath
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

$resolvedBootstrap = (Resolve-Path -LiteralPath $BootstrapPath).Path
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $resolvedBootstrap,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    $parseErrors | ForEach-Object { Write-Error $_.Message }
    exit 1
}

$requiredFunctions = @(
    "Get-Sha256",
    "Resolve-SafeVGenDirectory",
    "Install-VGenWorkerLauncher",
    "Install-VGenWorkerDesktopShortcut"
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
    Assert-Equal $matches.Count 1 "Generated $functionName function count"
}
$definitions = @(
    $functionAsts |
        Sort-Object { $_.Extent.StartOffset } |
        ForEach-Object { $_.Extent.Text }
)
Invoke-Expression ($definitions -join [Environment]::NewLine)

$previousLocalAppData = $env:LOCALAPPDATA
$testRoot = Join-Path ([IO.Path]::GetTempPath()) "vgen-launcher-$([Guid]::NewGuid().ToString('N'))"
$desktop = Join-Path $testRoot "Desktop"
$vgenRoot = Join-Path $testRoot "VGen"
$installerRoot = Join-Path $vgenRoot "installer"
$junction = $null

function New-TestInstaller {
    param(
        [string]$Version,
        [string]$DigestCharacter,
        [int]$ExitCode
    )
    $script:ExpectedVersion = $Version
    $script:ExpectedManifestSha256 = ($DigestCharacter * 64) -join ""
    $leaf = "$Version-$($script:ExpectedManifestSha256.Substring(0, 12))"
    $root = Join-Path $installerRoot $leaf
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $target = Join-Path $root "start-worker.cmd"
$content = @"
@echo off
> "%~dp0invocation.txt" echo(%*
exit /b $ExitCode
"@
    [IO.File]::WriteAllText($target, $content, [Text.Encoding]::ASCII)
    return $root
}

function Assert-ShortcutTarget {
    param([string]$ExpectedLauncher)
    $shortcutPath = Join-Path $desktop "VGen Worker.lnk"
    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)) {
        throw "The VGen Worker Desktop shortcut was not created."
    }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    Assert-Equal `
        ([IO.Path]::GetFullPath($shortcut.TargetPath).ToLowerInvariant()) `
        ([IO.Path]::GetFullPath($ExpectedLauncher).ToLowerInvariant()) `
        "Desktop shortcut target"
    Assert-Equal `
        ([IO.Path]::GetFullPath($shortcut.WorkingDirectory).ToLowerInvariant()) `
        ([IO.Path]::GetFullPath($vgenRoot).ToLowerInvariant()) `
        "Desktop shortcut working directory"
}

try {
    $env:LOCALAPPDATA = $testRoot
    $detectedDesktop = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::DesktopDirectory
    )
    if ([string]::IsNullOrWhiteSpace($detectedDesktop)) {
        throw "Windows PowerShell 5.1 could not resolve the current user's Desktop directory."
    }
    [IO.Directory]::CreateDirectory($desktop) | Out-Null
    [IO.Directory]::CreateDirectory($installerRoot) | Out-Null

    $firstRoot = New-TestInstaller "0.9.1" "1" 23
    $stableLauncher = Install-VGenWorkerLauncher $firstRoot
    $expectedStableLauncher = Join-Path $vgenRoot "start-worker.cmd"
    Assert-Equal $stableLauncher $expectedStableLauncher "Stable launcher path"
    $firstLauncherContent = [IO.File]::ReadAllText($stableLauncher)
    if (-not $firstLauncherContent.Contains("installer\0.9.1-111111111111\start-worker.cmd")) {
        throw "The stable launcher did not select the first verified installer."
    }

    Install-VGenWorkerDesktopShortcut $stableLauncher $desktop
    Assert-ShortcutTarget $stableLauncher

    & $env:ComSpec /d /c "`"$stableLauncher`""
    Assert-Equal $LASTEXITCODE 23 "Stable launcher exit code"
    Assert-Equal `
        ([IO.File]::ReadAllText((Join-Path $firstRoot "invocation.txt")).Trim()) `
        "" `
        "Stable launcher normal arguments"

    & $env:ComSpec /d /c "`"$stableLauncher`" -Reenroll"
    Assert-Equal $LASTEXITCODE 23 "Stable launcher reenrollment exit code"
    Assert-Equal `
        ([IO.File]::ReadAllText((Join-Path $firstRoot "invocation.txt")).Trim()) `
        "-Reenroll" `
        "Stable launcher reenrollment arguments"

    & $env:ComSpec /d /c "`"$stableLauncher`" -Unknown"
    Assert-Equal $LASTEXITCODE 2 "Stable launcher rejected-argument exit code"
    Assert-Equal `
        ([IO.File]::ReadAllText((Join-Path $firstRoot "invocation.txt")).Trim()) `
        "-Reenroll" `
        "Rejected arguments did not reach the versioned launcher"

    $secondRoot = New-TestInstaller "0.9.2" "2" 29
    $secondLauncher = Install-VGenWorkerLauncher $secondRoot
    Assert-Equal $secondLauncher $stableLauncher "Stable launcher path after update"
    $secondLauncherContent = [IO.File]::ReadAllText($stableLauncher)
    if (-not $secondLauncherContent.Contains("installer\0.9.2-222222222222\start-worker.cmd") -or
        $secondLauncherContent.Contains("installer\0.9.1-111111111111\start-worker.cmd")) {
        throw "The stable launcher did not switch atomically to the second verified installer."
    }
    Assert-Equal `
        (Install-VGenWorkerLauncher $secondRoot) `
        $stableLauncher `
        "Idempotent stable launcher path"

    Install-VGenWorkerDesktopShortcut $stableLauncher $desktop
    Assert-ShortcutTarget $stableLauncher
    & $env:ComSpec /d /c "`"$stableLauncher`""
    Assert-Equal $LASTEXITCODE 29 "Updated stable launcher exit code"

    $shortcutPath = Join-Path $desktop "VGen Worker.lnk"
    Remove-Item -LiteralPath $shortcutPath -Force
    [IO.Directory]::CreateDirectory($shortcutPath) | Out-Null
    Install-VGenWorkerDesktopShortcut $stableLauncher $desktop
    if (-not (Test-Path -LiteralPath $shortcutPath -PathType Container)) {
        throw "An unsafe shortcut path was unexpectedly replaced."
    }
    & $env:ComSpec /d /c "`"$stableLauncher`""
    Assert-Equal $LASTEXITCODE 29 "Worker launch after shortcut warning"

    $badInstallRoot = Join-Path $installerRoot "0.9.3-333333333333"
    [IO.File]::WriteAllText($badInstallRoot, "not a directory")
    $script:ExpectedVersion = "0.9.3"
    $script:ExpectedManifestSha256 = ("3" * 64) -join ""
    $failedClosed = $false
    try {
        Install-VGenWorkerLauncher $badInstallRoot | Out-Null
    }
    catch {
        $failedClosed = $true
    }
    if (-not $failedClosed) {
        throw "The stable launcher accepted an unsafe installer path."
    }

    $junctionCase = Join-Path $testRoot "junction-case"
    $junctionVGen = Join-Path $junctionCase "VGen"
    $junctionTarget = Join-Path $testRoot "junction-target"
    $junction = Join-Path $junctionVGen "installer"
    [IO.Directory]::CreateDirectory($junctionVGen) | Out-Null
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    & $env:ComSpec /d /c "mklink /J `"$junction`" `"$junctionTarget`""
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $junction -PathType Container)) {
        throw "The reparse-point test fixture could not create an installer junction."
    }
    $script:ExpectedVersion = "0.9.4"
    $script:ExpectedManifestSha256 = ("4" * 64) -join ""
    $junctionInstallRoot = Join-Path $junction "0.9.4-444444444444"
    [IO.Directory]::CreateDirectory($junctionInstallRoot) | Out-Null
    [IO.File]::WriteAllText((Join-Path $junctionInstallRoot "start-worker.cmd"), "@exit /b 0")
    $env:LOCALAPPDATA = $junctionCase
    $reparseFailedClosed = $false
    try {
        Install-VGenWorkerLauncher $junctionInstallRoot | Out-Null
    }
    catch {
        $reparseFailedClosed = $true
    }
    if (-not $reparseFailedClosed) {
        throw "The stable launcher accepted a reparse-point installer directory."
    }

    Write-Host "Windows PowerShell 5.1 stable Worker launcher checks passed"
}
finally {
    $env:LOCALAPPDATA = $previousLocalAppData
    if ($null -ne $junction -and (Test-Path -LiteralPath $junction)) {
        & $env:ComSpec /d /c "rmdir `"$junction`"" | Out-Null
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
