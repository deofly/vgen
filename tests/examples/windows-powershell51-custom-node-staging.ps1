#requires -Version 5.1

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSEdition -ne "Desktop" -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "This compatibility check must run in Windows PowerShell 5.1."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$installer = Join-Path $repositoryRoot "examples\windows-worker\setup-worker.ps1"
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "vgen-custom-node-staging-" + [Guid]::NewGuid().ToString("N")
)
$originalLocalAppData = $env:LOCALAPPDATA
[System.IO.Directory]::CreateDirectory($testRoot) | Out-Null
$env:LOCALAPPDATA = $testRoot

function New-ReadOnlyLegacyStaging {
    param(
        [string]$CustomNodesRoot,
        [string]$DirectoryName,
        [string]$Suffix
    )
    $leaf = ".$DirectoryName.vgen-staging-$Suffix"
    $staging = Join-Path $CustomNodesRoot $leaf
    New-ReadOnlyPackFile $staging
    return $staging
}

function New-ReadOnlyPackFile {
    param([string]$Staging)
    $packRoot = Join-Path $Staging ".git\objects\pack"
    [System.IO.Directory]::CreateDirectory($packRoot) | Out-Null
    $pack = Join-Path $packRoot "pack-test.idx"
    [System.IO.File]::WriteAllText($pack, "readonly pack index")
    [System.IO.File]::SetAttributes($pack, [System.IO.FileAttributes]::ReadOnly)
}

function Clear-TestReadOnlyAttributes {
    param([string]$Path)
    if (-not [System.IO.Directory]::Exists($Path)) {
        return
    }
    foreach ($item in @(
            Get-ChildItem -LiteralPath $Path -Force -Recurse -ErrorAction SilentlyContinue
        )) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
            [System.IO.File]::SetAttributes(
                $item.FullName,
                $item.Attributes -band (-bnot [System.IO.FileAttributes]::ReadOnly)
            )
        }
    }
}

try {
    . $installer

    $pin = [PSCustomObject]@{
        Name = "MiniMax H3 Audio T8"
        Directory = "minimax-h3-audio-T8"
    }
    $workerRoot = Join-Path $env:LOCALAPPDATA (
        "VGen\comfyui\wrk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    $customNodesRoot = Join-Path $workerRoot "custom_nodes"
    [System.IO.Directory]::CreateDirectory($customNodesRoot) | Out-Null

    $unrelated = Join-Path $customNodesRoot (
        ".$($pin.Directory).vgen-staging-not-a-32-character-hex-guid"
    )
    [System.IO.Directory]::CreateDirectory($unrelated) | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $unrelated "keep.txt"), "keep")

    $script:CheckOnly = $false
    $legacy = New-ReadOnlyLegacyStaging `
        $customNodesRoot $pin.Directory "0123456789abcdef0123456789abcdef"
    Remove-OrphanedVGenCustomNodeStaging $pin $customNodesRoot
    if ([System.IO.Directory]::Exists($legacy)) {
        throw "normal setup did not remove the exact legacy staging directory"
    }
    if (-not [System.IO.File]::Exists((Join-Path $unrelated "keep.txt"))) {
        throw "normal setup removed an unrelated hidden directory"
    }

    $shortLeaf = ".v-0123456789abcdef"
    if ($shortLeaf.Length -gt $pin.Directory.Length) {
        throw "the active random staging leaf is longer than the canonical MiniMax directory"
    }
    $shortStaging = Join-Path $customNodesRoot $shortLeaf
    New-ReadOnlyPackFile $shortStaging
    Remove-OrphanedVGenCustomNodeStaging $pin $customNodesRoot
    if ([System.IO.Directory]::Exists($shortStaging)) {
        throw "normal setup did not remove an exact short VGen staging directory"
    }

    $checkOnlyLegacy = New-ReadOnlyLegacyStaging `
        $customNodesRoot $pin.Directory "fedcba9876543210fedcba9876543210"
    $script:CheckOnly = $true
    Remove-OrphanedVGenCustomNodeStaging $pin $customNodesRoot
    if (-not [System.IO.File]::Exists(
            (Join-Path $checkOnlyLegacy ".git\objects\pack\pack-test.idx")
        )) {
        throw "CheckOnly changed an exact legacy staging directory"
    }

    $script:CheckOnly = $false
    Remove-OrphanedVGenCustomNodeStaging $pin $customNodesRoot
    if ([System.IO.Directory]::Exists($checkOnlyLegacy)) {
        throw "normal setup did not remove the staging directory preserved by CheckOnly"
    }
}
finally {
    $script:CheckOnly = $false
    Clear-TestReadOnlyAttributes $testRoot
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
    $env:LOCALAPPDATA = $originalLocalAppData
}
