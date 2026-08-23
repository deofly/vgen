#requires -Version 5.1

<#
.SYNOPSIS
Safely prepares and starts a VGen ComfyUI Worker on Windows without Docker.

.DESCRIPTION
The script installs only reviewable local runtime dependencies. Missing pinned
model weights leave the Worker online in maintenance-only mode; a Broker can
then submit a signed, license-bound model job. Existing files are never replaced.
Existing custom-node directories are changed only when they are clean Git
repositories with the expected origin, and never while an existing ComfyUI
process is reachable.
#>

[CmdletBinding()]
param(
    [Uri]$GatewayUrl,

    [string]$WorkerCredentials,

    [string]$ComfyUIRoot,

    [string]$ComfyUIDataRoot,

    [string]$BundleConfig,

    [switch]$CheckOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$GatewayUrlWasProvided = $PSBoundParameters.ContainsKey("GatewayUrl")
$gitBoundaryVariables = @(
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_INDEX_FILE",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT"
)
foreach ($gitBoundaryVariable in $gitBoundaryVariables) {
    [System.Environment]::SetEnvironmentVariable(
        $gitBoundaryVariable,
        $null,
        [System.EnvironmentVariableTarget]::Process
    )
}
if ($CheckOnly) {
    # Python imports and Git status must remain filesystem-read-only too.
    $env:PYTHONDONTWRITEBYTECODE = "1"
    $env:GIT_OPTIONAL_LOCKS = "0"
}

$PolicyName = "comfyui-minimax-h3-policy.yaml"
$PolicySha256 = "5ae3a0f9fa16dadd2435496bd96584e9206720a613460e06c8ec6ff2f2c97f75"
$MinimumExecutorVersion = "1.1.0"
$MinimumRuntimeVersion = "0.30.0"
$MinimumVramBytes = [Int64]16000000000
$MinimumRamBytes = [Int64]32000000000
$ComfyUrl = "http://127.0.0.1:8188"

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

$ModelPins = @(
    [PSCustomObject]@{
        Folder = "diffusion_models"
        FileName = "minimax_h3_fl2va_pruned_int8_convrot.safetensors"
        Size = [Int64]20970379616
        Sha256 = "e889202c41dafb67b10d67b97f0d8541508036a6090af23425a5c2615d03c47a"
        Source = "https://huggingface.co/Comfy-Org/MiniMax-H3/resolve/3f57e8291d2ef846f9a074b1b76d2767db434abe/diffusion_models/minimax_h3_fl2va_pruned_int8_convrot.safetensors"
        License = "MiniMax H3 Community License"
        LicenseUrl = "https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE"
    },
    [PSCustomObject]@{
        Folder = "loras"
        FileName = "minimax_h3_fl2v_turbo_8step_v1.0_comfyui_bf16.safetensors"
        Size = [Int64]1956193000
        Sha256 = "2339acdf19bfe123f46b971ea35d367a84adb85de43627e1eceafa5a5b2b111e"
        Source = "https://huggingface.co/lightx2v/Minimax-h3-Turbo/resolve/62487ee643501626a71502d679f735a23ee6af45/minimax_h3_fl2v_turbo_8step_v1.0_comfyui_bf16.safetensors"
        License = "Apache-2.0"
        LicenseUrl = "https://www.apache.org/licenses/LICENSE-2.0"
    },
    [PSCustomObject]@{
        Folder = "text_encoders"
        FileName = "qwen3vl_32b_minimax_h3_nvfp4_awq.safetensors"
        Size = [Int64]15687142551
        Sha256 = "35a88d51044231fe332301d7a62aa81e3f2cba62febeb446e2c1e3e0ef76f2c6"
        Source = "https://huggingface.co/Comfy-Org/MiniMax-H3/resolve/3f57e8291d2ef846f9a074b1b76d2767db434abe/text_encoders/qwen3vl_32b_minimax_h3_nvfp4_awq.safetensors"
        License = "MiniMax H3 Community License"
        LicenseUrl = "https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE"
    },
    [PSCustomObject]@{
        Folder = "vae"
        FileName = "minimax_h3_video_vae_fp16.safetensors"
        Size = [Int64]5207808496
        Sha256 = "7c1f131492e7eddacaac9069a61b81bdd39de5cc96561e677c5eab1cdce5e522"
        Source = "https://huggingface.co/Comfy-Org/MiniMax-H3/resolve/64fa20dbeffe251ce32fad3b811c74a6467111bb/vae/minimax_h3_video_vae_fp16.safetensors"
        License = "MiniMax H3 Community License"
        LicenseUrl = "https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE"
    },
    [PSCustomObject]@{
        Folder = "vae"
        FileName = "minimax_h3_audio_vae_fp32.safetensors"
        Size = [Int64]605254808
        Sha256 = "8e505d95dd1561d47abd43d4238fd40d9bb1ae9e147ed0a4cba778d76ae4db48"
        Source = "https://huggingface.co/Comfy-Org/MiniMax-H3/resolve/3f57e8291d2ef846f9a074b1b76d2767db434abe/vae/minimax_h3_audio_vae_fp32.safetensors"
        License = "MiniMax H3 Community License"
        LicenseUrl = "https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE"
    }
)

$CustomNodePins = @(
    [PSCustomObject]@{
        Name = "MiniMax H3 Audio T8"
        Directory = "minimax-h3-audio-T8"
        Aliases = @("comfyui-minimax-h3-audio-T8")
        Source = "https://github.com/T8mars/comfyui-minimax-h3-audio-T8"
        Revision = "1c754fd6688697f9d36545a7d922e485ab92b515"
        Requirements = $null
    },
    [PSCustomObject]@{
        Name = "ComfyUI Video Helper Suite"
        Directory = "ComfyUI-VideoHelperSuite"
        Aliases = @()
        Source = "https://github.com/Kosinkadink/ComfyUI-VideoHelperSuite"
        Revision = "4ee72c065db22c9d96c2427954dc69e7b908444b"
        Requirements = "requirements.txt"
    }
)

$RequiredNodeClasses = @(
    "UNETLoader",
    "CLIPLoader",
    "VAELoader",
    "BasicGuider",
    "RandomNoise",
    "SamplerCustomAdvanced",
    "LoadImage",
    "LoraLoaderBypassModelOnly",
    "MiniMaxH3AudioConditioningT8",
    "MiniMaxH3DualClockSamplerT8",
    "MiniMaxH3AVDecodeT8",
    "VHS_VideoCombine"
)

$script:Findings = [System.Collections.Generic.List[string]]::new()
$script:GitExecutable = $null
$script:ManagedComfyProcess = $null
$script:ManualComfyDesktopSelected = $false

function Write-Step {
    param([string]$Message)
    Write-Host "[vgen] $Message"
}

function Add-Finding {
    param([string]$Message)
    $script:Findings.Add($Message)
    Write-Warning $Message
}

function Resolve-BundledFile {
    param(
        [string]$Description,
        [string[]]$Candidates
    )
    foreach ($candidate in $Candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "$Description was not found beside the script or in the source checkout."
}

function Get-RequiredJsonProperty {
    param(
        [object]$Object,
        [string]$Name,
        [string]$Description
    )
    if ($null -eq $Object -or $null -eq $Object.PSObject.Properties[$Name]) {
        throw "$Description is missing '$Name'."
    }
    return $Object.PSObject.Properties[$Name].Value
}

function Get-JsonArrayRecords {
    param([object]$Value)
    if ($null -eq $Value) {
        return @()
    }
    if ($null -ne $Value.PSObject.Properties["installations"]) {
        return @($Value.installations)
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value)
    }
    return @($Value)
}

function Resolve-SafeBundleFile {
    param(
        [string]$Root,
        [string]$Name,
        [string]$Description
    )
    if ([string]::IsNullOrWhiteSpace($Name) -or
        [System.IO.Path]::IsPathRooted($Name) -or
        [System.IO.Path]::GetFileName($Name) -ne $Name) {
        throw "$Description must be a file name inside the Worker bundle."
    }
    $candidate = Join-Path $Root $Name
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "$Description is missing from the Worker bundle."
    }
    $item = Get-Item -LiteralPath $candidate
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a symbolic link or reparse point."
    }
    return $item.FullName
}

function Get-RecordedComfyDesktopRoots {
    $result = [System.Collections.Generic.List[object]]::new()
    $installationFiles = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        foreach ($relative in @(
                "Comfy Desktop\installations.json",
                "ComfyUI\installations.json",
                "comfyui-desktop-2\installations.json",
                "comfyui-launcher\installations.json"
            )) {
            $installationFiles.Add((Join-Path $env:APPDATA $relative))
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        foreach ($relative in @(
                "Comfy-Desktop\installations.json",
                "Comfy Desktop\installations.json",
                "comfyui-desktop-2\installations.json",
                "comfyui-launcher\installations.json"
            )) {
            $installationFiles.Add((Join-Path $env:LOCALAPPDATA $relative))
        }
    }
    foreach ($installationsPath in @($installationFiles | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $installationsPath -PathType Leaf)) {
            continue
        }
        try {
            $records = @(Get-JsonArrayRecords ([System.IO.File]::ReadAllText($installationsPath) | ConvertFrom-Json))
        }
        catch {
            continue
        }
        foreach ($record in $records) {
            if ($null -eq $record -or
                $null -eq $record.PSObject.Properties["installPath"] -or
                [string]::IsNullOrWhiteSpace([string]$record.installPath)) {
                continue
            }
            $sourceId = if ($null -ne $record.PSObject.Properties["sourceId"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.sourceId)) {
                [string]$record.sourceId
            }
            else {
                $null
            }
            if ($sourceId -in @("cloud", "remote")) {
                continue
            }
            if ($null -ne $record.PSObject.Properties["status"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.status) -and
                [string]$record.status -ne "installed") {
                continue
            }
            $candidate = $null
            foreach ($attempt in @(
                    (Join-Path ([string]$record.installPath) "ComfyUI"),
                    [string]$record.installPath
                )) {
                if (Test-Path -LiteralPath (Join-Path $attempt "main.py") -PathType Leaf) {
                    $candidate = (Resolve-Path -LiteralPath $attempt).Path
                    break
                }
            }
            if ($null -eq $candidate) {
                continue
            }
            $resolvedInstallPath = (Resolve-Path -LiteralPath ([string]$record.installPath)).Path
            $lastLaunchedAt = [Int64]0
            if ($null -ne $record.PSObject.Properties["lastLaunchedAt"]) {
                $parsed = [Int64]0
                if ([Int64]::TryParse([string]$record.lastLaunchedAt, [ref]$parsed)) {
                    $lastLaunchedAt = $parsed
                }
            }
            $adopted = $false
            if ($null -ne $record.PSObject.Properties["adopted"] -and
                $record.PSObject.Properties["adopted"].Value -is [bool]) {
                $adopted = [bool]$record.PSObject.Properties["adopted"].Value
            }
            $adoptedBaseDir = if ($null -ne $record.PSObject.Properties["adoptedBaseDir"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.adoptedBaseDir)) {
                [string]$record.adoptedBaseDir
            }
            else {
                $null
            }
            $adoptedPythonPath = if ($null -ne $record.PSObject.Properties["adoptedPythonPath"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.adoptedPythonPath)) {
                [string]$record.adoptedPythonPath
            }
            else {
                $null
            }
            $venvPath = if ($null -ne $record.PSObject.Properties["venvPath"] -and
                -not [string]::IsNullOrWhiteSpace([string]$record.venvPath)) {
                [string]$record.venvPath
            }
            else {
                $null
            }
            $result.Add([PSCustomObject]@{
                    Root = $candidate
                    InstallPath = $resolvedInstallPath
                    SourceId = $sourceId
                    Adopted = $adopted
                    AdoptedBaseDir = $adoptedBaseDir
                    AdoptedPythonPath = $adoptedPythonPath
                    VenvPath = $venvPath
                    LastLaunchedAt = $lastLaunchedAt
                })
        }
    }
    return @($result | Sort-Object LastLaunchedAt -Descending)
}

function Get-RecordedComfyDesktopRootForPath {
    param([string]$Root)

    if ([string]::IsNullOrWhiteSpace($Root) -or
        -not (Test-Path -LiteralPath $Root -PathType Container)) {
        return $null
    }
    $resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
    foreach ($record in @(Get-RecordedComfyDesktopRoots)) {
        if ([string]$record.Root -ieq $resolvedRoot) {
            return $record
        }
    }
    return $null
}

function Get-DefaultComfyDesktopRoots {
    $result = [System.Collections.Generic.List[string]]::new()
    foreach ($installationsRoot in @(
            $(if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { Join-Path $env:LOCALAPPDATA "Comfy-Desktop\ComfyUI-Installs" }),
            $(if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { Join-Path $env:USERPROFILE "ComfyUI-Installs" })
        )) {
        if ([string]::IsNullOrWhiteSpace($installationsRoot) -or
            -not (Test-Path -LiteralPath $installationsRoot -PathType Container)) {
            continue
        }
        foreach ($installation in @(Get-ChildItem -LiteralPath $installationsRoot -Directory -ErrorAction SilentlyContinue)) {
            foreach ($candidate in @(
                    (Join-Path $installation.FullName "ComfyUI"),
                    $installation.FullName
                )) {
                if (Test-Path -LiteralPath (Join-Path $candidate "main.py") -PathType Leaf) {
                    $result.Add((Resolve-Path -LiteralPath $candidate).Path)
                }
            }
        }
    }
    return @($result | Select-Object -Unique)
}

function Test-ComfyDesktopLauncherInstalled {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($root in @(
            $env:ProgramFiles,
            [Environment]::GetEnvironmentVariable("ProgramW6432"),
            [Environment]::GetEnvironmentVariable("ProgramFiles(x86)"),
            $env:LOCALAPPDATA,
            $env:APPDATA
        )) {
        if ([string]::IsNullOrWhiteSpace($root)) {
            continue
        }
        foreach ($relative in @(
                "Comfy Desktop\Comfy Desktop.exe",
                "Programs\Comfy Desktop\Comfy Desktop.exe",
                "Programs\@comfyorgcomfyui-electron\ComfyUI.exe",
                "Programs\ComfyUI\ComfyUI.exe",
                "@comfyorgcomfyui-electron\ComfyUI.exe",
                "comfyui-electron\ComfyUI.exe",
                "ComfyUI\ComfyUI.exe"
            )) {
            $candidates.Add((Join-Path $root $relative))
        }
    }
    return (@($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0)
}

function Test-InteractiveConsole {
    try {
        return -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected
    }
    catch {
        return $true
    }
}

function Read-ManualComfyDataRoot {
    param([string]$Reason)

    if ($CheckOnly -or -not (Test-InteractiveConsole)) {
        throw "$Reason Rerun normal setup interactively or pass -ComfyUIDataRoot with the Desktop data directory."
    }
    Write-Warning $Reason
    Write-Host "The data directory is the folder configured by ComfyUI Desktop; it normally contains .venv together with models, input, output, or user."
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $enteredPath = Read-Host "Paste the ComfyUI Desktop data directory"
        if ([string]::IsNullOrWhiteSpace($enteredPath)) {
            Write-Warning "The data directory cannot be empty."
            continue
        }
        $expanded = [Environment]::ExpandEnvironmentVariables($enteredPath.Trim().Trim('"'))
        if (-not [System.IO.Path]::IsPathRooted($expanded) -or
            -not (Test-Path -LiteralPath $expanded -PathType Container)) {
            Write-Warning "That data directory is not an existing absolute folder."
            continue
        }
        $resolved = (Resolve-Path -LiteralPath $expanded).Path
        $hasPythonMarker = $false
        foreach ($marker in @(
                ".venv\Scripts\python.exe",
                "venv\Scripts\python.exe"
            )) {
            if (Test-Path -LiteralPath (Join-Path $resolved $marker) -PathType Leaf) {
                $hasPythonMarker = $true
                break
            }
        }
        if (-not $hasPythonMarker) {
            Write-Warning "That folder does not contain the ComfyUI Desktop Python environment (.venv or venv)."
            continue
        }
        return $resolved
    }
    throw "A valid ComfyUI Desktop data directory was not selected after three attempts. No files were changed."
}

function Get-ComfyRootKind {
    param([string]$Root)

    $parent = Split-Path -Parent $Root
    if ((Split-Path -Leaf $parent) -ieq "resources") {
        return "ComfyUI Desktop"
    }
    if ($null -ne (Get-RecordedComfyDesktopRootForPath $Root)) {
        return "ComfyUI Desktop"
    }
    foreach ($desktopRoot in @(
            $(if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) { Join-Path $env:LOCALAPPDATA "Comfy-Desktop\ComfyUI-Installs" }),
            $(if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { Join-Path $env:USERPROFILE "ComfyUI-Installs" })
        )) {
        if (-not [string]::IsNullOrWhiteSpace($desktopRoot) -and
            (Test-PathInside $Root $desktopRoot)) {
            return "ComfyUI Desktop"
        }
    }
    foreach ($candidate in @(
            (Join-Path $parent "python_embeded\python.exe"),
            (Join-Path $Root "python_embeded\python.exe")
        )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return "ComfyUI Portable"
        }
    }
    return "ComfyUI"
}

function Get-ComfyRootsFromInstallPath {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"'))
    if (-not [System.IO.Path]::IsPathRooted($expanded) -or
        -not (Test-Path -LiteralPath $expanded)) {
        return @()
    }
    $item = Get-Item -LiteralPath $expanded -Force
    $base = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }
    if ([string]::IsNullOrWhiteSpace($base)) {
        return @()
    }

    $relativeCandidates = @(
        "",
        "ComfyUI",
        "resources\ComfyUI",
        "Comfy Desktop\resources\ComfyUI",
        "ComfyUI\resources\ComfyUI",
        "@comfyorgcomfyui-electron\resources\ComfyUI",
        "comfyui-electron\resources\ComfyUI",
        "Programs\Comfy Desktop\resources\ComfyUI",
        "Programs\ComfyUI\resources\ComfyUI",
        "Programs\@comfyorgcomfyui-electron\resources\ComfyUI",
        "Programs\comfyui-electron\resources\ComfyUI",
        "ComfyUI_windows_portable\ComfyUI"
    )
    $result = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($relative in $relativeCandidates) {
        $candidate = if ([string]::IsNullOrEmpty($relative)) { $base } else { Join-Path $base $relative }
        if (-not (Test-Path -LiteralPath (Join-Path $candidate "main.py") -PathType Leaf)) {
            continue
        }
        $resolved = (Resolve-Path -LiteralPath $candidate).Path
        if ($seen.Add($resolved)) {
            $result.Add($resolved)
        }
    }
    return @($result)
}

function Read-ManualComfyRoot {
    if ($CheckOnly -or -not (Test-InteractiveConsole)) {
        throw "ComfyUI could not be found automatically. Run normal setup interactively or pass -ComfyUIRoot with the installation directory."
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Write-Host ""
        Write-Host "Choose the installed application:"
        Write-Host "  1. ComfyUI Desktop"
        Write-Host "  2. ComfyUI / Portable"
        $typeChoice = (Read-Host "Enter 1 or 2").Trim()
        if ($typeChoice -notin @("1", "2")) {
            Write-Warning "Please enter 1 for ComfyUI Desktop or 2 for ComfyUI / Portable."
            continue
        }
        Write-Host "Examples:"
        Write-Host "  Desktop launcher: C:\Program Files\Comfy Desktop"
        Write-Host "  Desktop launcher: C:\Users\<you>\AppData\Local\Programs\@comfyorgcomfyui-electron"
        Write-Host "  Desktop instance: C:\Users\<you>\AppData\Local\Comfy-Desktop\ComfyUI-Installs\<instance>"
        Write-Host "  Portable root: D:\ComfyUI_windows_portable\ComfyUI"
        $enteredPath = Read-Host "Paste its installation folder, ComfyUI.exe, or main.py path"
        $matches = @(Get-ComfyRootsFromInstallPath $enteredPath)
        if ($matches.Count -eq 0) {
            Write-Warning "That folder does not contain a ready local ComfyUI installation. Nothing was changed."
            continue
        }
        $preferredLabel = if ($typeChoice -eq "1") { "ComfyUI Desktop" } else { "ComfyUI" }
        $preferred = @(
            $matches |
                Where-Object {
                    $kind = Get-ComfyRootKind $_
                    if ($typeChoice -eq "1") { $kind -eq "ComfyUI Desktop" } else { $kind -ne "ComfyUI Desktop" }
                }
        )
        $choices = if ($preferred.Count -gt 0) { $preferred } else { $matches }
        $script:ManualComfyDesktopSelected = ($typeChoice -eq "1")
        if ($choices.Count -eq 1) {
            Write-Step "Selected $preferredLabel installation: $($choices[0])"
            return $choices[0]
        }
        return Select-ComfyRootInteractively $choices "More than one ComfyUI runtime exists below that folder." $false
    }
    throw "A valid ComfyUI installation was not selected after three attempts. No files were changed."
}

function Select-ComfyRootInteractively {
    param(
        [string[]]$Candidates,
        [string]$Message,
        [bool]$AllowManual = $true
    )
    if ($CheckOnly -or -not (Test-InteractiveConsole)) {
        throw $Message
    }
    Write-Warning $Message
    for ($index = 0; $index -lt $Candidates.Count; $index++) {
        $kind = Get-ComfyRootKind $Candidates[$index]
        Write-Host "  $($index + 1). $kind - $($Candidates[$index])"
    }
    if ($AllowManual) {
        Write-Host "  M. Choose another installation folder"
    }
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        $selection = (Read-Host "Select the ComfyUI installation VGen should use").Trim()
        if ($AllowManual -and $selection -ieq "M") {
            return Read-ManualComfyRoot
        }
        $number = 0
        if ([int]::TryParse($selection, [ref]$number) -and
            $number -ge 1 -and $number -le $Candidates.Count) {
            return $Candidates[$number - 1]
        }
        Write-Warning "Select one of the numbers shown above$(if ($AllowManual) { ' or M' } else { '' })."
    }
    throw "A valid ComfyUI installation was not selected. No files were changed."
}

function Resolve-ConfiguredComfyRoot {
    param([string]$Value)
    $matches = @(Get-ComfyRootsFromInstallPath $Value)
    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    if ($matches.Count -gt 1) {
        return Select-ComfyRootInteractively $matches "The configured path contains more than one ComfyUI runtime."
    }
    throw "The configured ComfyUIRoot is not a ready ComfyUI or ComfyUI Desktop installation directory."
}

function Select-UniqueComfyRoot {
    param(
        [object[]]$Candidates,
        [string]$MultipleMessage
    )
    $matches = @(
        $Candidates |
            ForEach-Object { if ($_ -is [string]) { $_ } else { [string]$_.Root } } |
            Where-Object { Test-Path -LiteralPath (Join-Path $_ "main.py") -PathType Leaf } |
            ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
            Select-Object -Unique
    )
    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    if ($matches.Count -gt 1) {
        return Select-ComfyRootInteractively $matches $MultipleMessage
    }
    return $null
}

function Resolve-AutomaticComfyRoot {
    $recorded = @(Get-RecordedComfyDesktopRoots)
    if ($recorded.Count -gt 0) {
        # Desktop records carry user intent; use the most recently launched valid local instance.
        return [string]$recorded[0].Root
    }

    $managedDesktopRoot = Select-UniqueComfyRoot @(Get-DefaultComfyDesktopRoots) "More than one managed ComfyUI Desktop installation was found. Select the one VGen should use."
    if ($null -ne $managedDesktopRoot) {
        return $managedDesktopRoot
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    $commonRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($root in @(
            $env:ProgramFiles,
            [Environment]::GetEnvironmentVariable("ProgramW6432"),
            [Environment]::GetEnvironmentVariable("ProgramFiles(x86)"),
            $env:LOCALAPPDATA,
            $env:APPDATA
        )) {
        if (-not [string]::IsNullOrWhiteSpace($root)) {
            $commonRoots.Add($root)
        }
    }
    foreach ($root in $commonRoots) {
        foreach ($candidate in @(Get-ComfyRootsFromInstallPath $root)) {
            $candidates.Add($candidate)
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        foreach ($relative in @(
                "Documents\ComfyUI",
                "ComfyUI",
                "Desktop\ComfyUI",
                "Downloads\ComfyUI_windows_portable\ComfyUI",
                "Desktop\ComfyUI_windows_portable\ComfyUI"
            )) {
            $candidates.Add((Join-Path $env:USERPROFILE $relative))
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        foreach ($relative in @(
                "ComfyUI",
                "Programs\ComfyUI_windows_portable\ComfyUI"
            )) {
            $candidates.Add((Join-Path $env:LOCALAPPDATA $relative))
        }
    }
    foreach ($candidate in @("C:\ComfyUI", "C:\AI\ComfyUI")) {
        $candidates.Add($candidate)
    }

    $selectedRoot = Select-UniqueComfyRoot $candidates "More than one ComfyUI installation was found. Select the one VGen should use."
    if ($null -ne $selectedRoot) {
        return $selectedRoot
    }

    if (Test-ComfyDesktopLauncherInstalled) {
        Write-Warning "ComfyUI Desktop was found, but no ready local runtime was detected. If it is installed elsewhere, choose that folder now. Otherwise open Desktop, create and launch one local installation, exit Desktop, then rerun."
    }
    else {
        Write-Warning "ComfyUI was not found in AppData, Program Files, Program Files (x86), or the usual Portable folders."
    }
    return Read-ManualComfyRoot
}

function Test-PathInside {
    param(
        [string]$Path,
        [string]$Root
    )
    $resolvedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd("\") + "\"
    $resolvedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd("\") + "\"
    return $resolvedPath.StartsWith($resolvedRoot, [System.StringComparison]::OrdinalIgnoreCase)
}

function Read-LegacyDesktopDataRoot {
    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        throw "APPDATA is required to locate the ComfyUI Desktop data directory."
    }
    $configPath = Join-Path $env:APPDATA "ComfyUI\config.json"
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "ComfyUI Desktop config.json was not found. Start ComfyUI Desktop once to finish its setup, then rerun this installer."
    }
    try {
        $config = [System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json
    }
    catch {
        throw "ComfyUI Desktop config.json is not valid JSON."
    }
    if ($null -eq $config -or
        $null -eq $config.PSObject.Properties["basePath"] -or
        [string]::IsNullOrWhiteSpace([string]$config.basePath)) {
        throw "ComfyUI Desktop config.json does not contain basePath. Finish Desktop setup, then rerun this installer."
    }
    $basePath = [string]$config.basePath
    if (-not [System.IO.Path]::IsPathRooted($basePath) -or
        -not (Test-Path -LiteralPath $basePath -PathType Container)) {
        throw "ComfyUI Desktop basePath is not an existing absolute directory."
    }
    return (Resolve-Path -LiteralPath $basePath).Path
}

function Get-LegacyDesktopDataRootIfAvailable {
    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        return $null
    }
    $configPath = Join-Path $env:APPDATA "ComfyUI\config.json"
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        return $null
    }
    try {
        $config = [System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json
    }
    catch {
        return $null
    }
    if ($null -eq $config -or
        $null -eq $config.PSObject.Properties["basePath"] -or
        [string]::IsNullOrWhiteSpace([string]$config.basePath)) {
        return $null
    }
    $basePath = [string]$config.basePath
    if (-not [System.IO.Path]::IsPathRooted($basePath) -or
        -not (Test-Path -LiteralPath $basePath -PathType Container)) {
        return $null
    }
    return (Resolve-Path -LiteralPath $basePath).Path
}

function Add-ExistingModelRootCandidate {
    param(
        [System.Collections.Generic.List[string]]$Candidates,
        [System.Collections.Generic.HashSet[string]]$Seen,
        [object]$Value
    )
    if ($null -eq $Value) {
        return
    }
    if ($Value -is [string]) {
        $path = [string]$Value
        if ([string]::IsNullOrWhiteSpace($path) -or
            -not [System.IO.Path]::IsPathRooted($path) -or
            -not (Test-Path -LiteralPath $path -PathType Container)) {
            return
        }
        $resolved = (Resolve-Path -LiteralPath $path).Path
        if ($Seen.Add($resolved)) {
            $Candidates.Add($resolved)
        }
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($entry in $Value.Values) {
            Add-ExistingModelRootCandidate $Candidates $Seen $entry
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($entry in $Value) {
            Add-ExistingModelRootCandidate $Candidates $Seen $entry
        }
        return
    }
    if ($Value -is [PSCustomObject]) {
        foreach ($property in $Value.PSObject.Properties) {
            Add-ExistingModelRootCandidate $Candidates $Seen $property.Value
        }
    }
}

function Add-JsonModelRootProperty {
    param(
        [System.Collections.Generic.List[string]]$Candidates,
        [System.Collections.Generic.HashSet[string]]$Seen,
        [object]$Object,
        [string]$PropertyName
    )
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$PropertyName]) {
        Add-ExistingModelRootCandidate $Candidates $Seen $Object.PSObject.Properties[$PropertyName].Value
    }
}

function Get-ComfyModelRootCandidates {
    param(
        [string]$DataRoot,
        [string]$VGenModelsRoot
    )

    $candidates = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    Add-ExistingModelRootCandidate $candidates $seen (Join-Path $DataRoot "models")

    if (-not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        $settingsPath = Join-Path $env:APPDATA "Comfy Desktop\settings.json"
        if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
            try {
                $settings = [System.IO.File]::ReadAllText($settingsPath) | ConvertFrom-Json
                Add-JsonModelRootProperty $candidates $seen $settings "modelsDirs"
            }
            catch {
                Write-Warning "Comfy Desktop settings.json could not be read; its model directories were ignored."
            }
        }

        $installationsPath = Join-Path $env:APPDATA "Comfy Desktop\installations.json"
        if (Test-Path -LiteralPath $installationsPath -PathType Leaf) {
            try {
                $installationJson = [System.IO.File]::ReadAllText($installationsPath) | ConvertFrom-Json
                $installationRecords = @(Get-JsonArrayRecords $installationJson)
                foreach ($record in $installationRecords) {
                    Add-JsonModelRootProperty $candidates $seen $record "modelDirsPrimary"
                    Add-JsonModelRootProperty $candidates $seen $record "modelDirs"
                }
            }
            catch {
                Write-Warning "Comfy Desktop installations.json could not be read for model directories."
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        Add-ExistingModelRootCandidate $candidates $seen (Join-Path $env:LOCALAPPDATA "Comfy-Desktop\ComfyUI-Shared\models")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        Add-ExistingModelRootCandidate $candidates $seen (Join-Path $env:USERPROFILE "ComfyUI-Shared\models")
    }
    $legacyDataRoot = Get-LegacyDesktopDataRootIfAvailable
    if ($null -ne $legacyDataRoot) {
        Add-ExistingModelRootCandidate $candidates $seen (Join-Path $legacyDataRoot "models")
    }
    Add-ExistingModelRootCandidate $candidates $seen $VGenModelsRoot
    return @($candidates)
}

function Resolve-ComfyLayout {
    param(
        [string]$CodeRoot,
        [string]$DataRootOverride
    )
    if (-not (Test-Path -LiteralPath $CodeRoot -PathType Container)) {
        throw "ComfyUIRoot does not exist."
    }
    $resolvedCodeRoot = (Resolve-Path -LiteralPath $CodeRoot).Path
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedCodeRoot "main.py") -PathType Leaf)) {
        throw "ComfyUIRoot does not contain main.py."
    }
    $desktopRecord = Get-RecordedComfyDesktopRootForPath $resolvedCodeRoot
    $isBundledDesktop = (Split-Path -Leaf (Split-Path -Parent $resolvedCodeRoot)) -ieq "resources"
    $isRecognizedDesktop = $isBundledDesktop -or
        $null -ne $desktopRecord -or
        $script:ManualComfyDesktopSelected -or
        (Get-ComfyRootKind $resolvedCodeRoot) -eq "ComfyUI Desktop"
    if (-not [string]::IsNullOrWhiteSpace($DataRootOverride)) {
        if (-not (Test-Path -LiteralPath $DataRootOverride -PathType Container)) {
            throw "ComfyUIDataRoot does not exist."
        }
        $resolvedDataRoot = (Resolve-Path -LiteralPath $DataRootOverride).Path
    }
    elseif ($null -ne $desktopRecord -and [bool]$desktopRecord.Adopted) {
        $adoptedBaseDir = [string]$desktopRecord.AdoptedBaseDir
        if (-not [string]::IsNullOrWhiteSpace($adoptedBaseDir) -and
            [System.IO.Path]::IsPathRooted($adoptedBaseDir) -and
            (Test-Path -LiteralPath $adoptedBaseDir -PathType Container)) {
            $resolvedDataRoot = (Resolve-Path -LiteralPath $adoptedBaseDir).Path
        }
        else {
            $resolvedDataRoot = Read-ManualComfyDataRoot "ComfyUI Desktop says this is an adopted installation, but its custom data directory could not be read from the installation record."
        }
    }
    elseif ($isBundledDesktop) {
        $legacyDataRoot = Get-LegacyDesktopDataRootIfAvailable
        if ($null -ne $legacyDataRoot) {
            $resolvedDataRoot = $legacyDataRoot
        }
        else {
            $resolvedDataRoot = Read-ManualComfyDataRoot "ComfyUI Desktop's configured data directory could not be read automatically."
        }
    }
    elseif ($isRecognizedDesktop) {
        $rootParent = Split-Path -Parent $resolvedCodeRoot
        $runtimeMarkers = @(
            (Join-Path $resolvedCodeRoot ".venv\Scripts\python.exe"),
            (Join-Path $resolvedCodeRoot "venv\Scripts\python.exe"),
            (Join-Path $rootParent "envs\default\Scripts\python.exe"),
            (Join-Path $rootParent "venv\base\python.exe"),
            (Join-Path $rootParent "venv\python.exe"),
            (Join-Path $rootParent "python_embeded\python.exe"),
            (Join-Path $resolvedCodeRoot "python_embeded\python.exe")
        )
        if ($null -ne $desktopRecord -and
            -not [string]::IsNullOrWhiteSpace([string]$desktopRecord.VenvPath)) {
            $recordedVenvPath = [string]$desktopRecord.VenvPath
            $runtimeMarkers += @(
                $recordedVenvPath,
                (Join-Path $recordedVenvPath "Scripts\python.exe"),
                (Join-Path $recordedVenvPath "python.exe")
            )
        }
        if (@($runtimeMarkers | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }).Count -gt 0) {
            $resolvedDataRoot = $resolvedCodeRoot
        }
        else {
            $resolvedDataRoot = Read-ManualComfyDataRoot "A ComfyUI Desktop instance was found, but its custom data directory was not present in a readable installation record or standard runtime layout."
        }
    }
    else {
        $resolvedDataRoot = $resolvedCodeRoot
    }

    foreach ($programRoot in @(
            $env:ProgramFiles,
            [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
        )) {
        if (-not [string]::IsNullOrWhiteSpace($programRoot) -and
            (Test-PathInside $resolvedDataRoot $programRoot)) {
            throw "ComfyUI data root must be outside Program Files; VGen will not write models, custom nodes, or Python environments there."
        }
    }
    if ($isBundledDesktop) {
        if (Test-PathInside $resolvedDataRoot $resolvedCodeRoot) {
            throw "ComfyUI Desktop data must be outside its managed resources directory."
        }
    }

    $frontEndRoot = $null
    if ($isBundledDesktop -and -not [string]::IsNullOrWhiteSpace($env:APPDATA)) {
        $frontEndCandidate = Join-Path $resolvedCodeRoot "web_custom_versions\desktop_app"
        if (Test-Path -LiteralPath $frontEndCandidate -PathType Container) {
            $frontEndRoot = (Resolve-Path -LiteralPath $frontEndCandidate).Path
        }
    }
    return [PSCustomObject]@{
        CodeRoot = $resolvedCodeRoot
        DataRoot = $resolvedDataRoot
        IsBundledDesktop = $isBundledDesktop
        FrontEndRoot = $frontEndRoot
        DesktopRecord = $desktopRecord
    }
}

function Resolve-WorkerBundleSettings {
    $configPath = $null
    if (-not [string]::IsNullOrWhiteSpace($BundleConfig)) {
        $configPath = (Resolve-Path -LiteralPath $BundleConfig).Path
    }
    else {
        $automaticConfig = Join-Path $PSScriptRoot "vgen-worker-bundle.json"
        if (Test-Path -LiteralPath $automaticConfig -PathType Leaf) {
            $configPath = (Resolve-Path -LiteralPath $automaticConfig).Path
        }
    }

    $config = $null
    if ($null -ne $configPath) {
        $configItem = Get-Item -LiteralPath $configPath
        if (($configItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "BundleConfig must not be a symbolic link or reparse point."
        }
        try {
            $config = [System.IO.File]::ReadAllText($configPath) | ConvertFrom-Json
        }
        catch {
            throw "BundleConfig is not valid JSON."
        }
        if ((Get-RequiredJsonProperty $config "format" "BundleConfig") -ne "vgen-windows-worker-bundle" -or
            (Get-RequiredJsonProperty $config "version" "BundleConfig") -ne 1) {
            throw "BundleConfig has an unsupported format or version."
        }
    }
    else {
        throw "vgen-worker-bundle.json is required. Download and extract the official universal Windows Worker installer again."
    }

    $resolvedGateway = $null
    if ($GatewayUrlWasProvided) {
        $resolvedGateway = $GatewayUrl
    }
    elseif ($null -ne $config) {
        try {
            $resolvedGateway = [Uri](Get-RequiredJsonProperty $config "gateway_url" "BundleConfig")
        }
        catch {
            throw "BundleConfig gateway_url is invalid."
        }
    }
    if ($null -eq $resolvedGateway) {
        throw "GatewayUrl is required when no vgen-worker-bundle.json is beside the script."
    }

    $resolvedCredentials = $WorkerCredentials
    if ([string]::IsNullOrWhiteSpace($resolvedCredentials) -and $null -ne $config) {
        $resolvedCredentials = Resolve-SafeBundleFile $PSScriptRoot ([string](Get-RequiredJsonProperty $config "worker_credentials" "BundleConfig")) "Worker credential"
    }
    if ([string]::IsNullOrWhiteSpace($resolvedCredentials)) {
        $automaticCredential = Join-Path $PSScriptRoot "worker-credentials.json"
        if (Test-Path -LiteralPath $automaticCredential -PathType Leaf) {
            $resolvedCredentials = $automaticCredential
        }
        else {
            throw "WorkerCredentials is required when no credential is beside the script."
        }
    }

    $resolvedComfyRoot = $ComfyUIRoot
    if ([string]::IsNullOrWhiteSpace($resolvedComfyRoot) -and $null -ne $config -and
        $null -ne $config.PSObject.Properties["comfyui_root"] -and
        -not [string]::IsNullOrWhiteSpace([string]$config.comfyui_root)) {
        $resolvedComfyRoot = [string]$config.comfyui_root
    }
    if ([string]::IsNullOrWhiteSpace($resolvedComfyRoot)) {
        $resolvedComfyRoot = Resolve-AutomaticComfyRoot
    }
    else {
        $resolvedComfyRoot = Resolve-ConfiguredComfyRoot $resolvedComfyRoot
    }

    $resolvedComfyDataRoot = $ComfyUIDataRoot
    if ([string]::IsNullOrWhiteSpace($resolvedComfyDataRoot) -and $null -ne $config -and
        $null -ne $config.PSObject.Properties["comfyui_data_root"] -and
        -not [string]::IsNullOrWhiteSpace([string]$config.comfyui_data_root)) {
        $resolvedComfyDataRoot = [string]$config.comfyui_data_root
    }

    $resolvedPolicyName = $PolicyName
    $resolvedPolicySha256 = $PolicySha256
    $wheel = Get-RequiredJsonProperty $config "wheel" "BundleConfig"
    $policy = Get-RequiredJsonProperty $config "policy" "BundleConfig"
    $wheelVersionValue = Get-RequiredJsonProperty $wheel "version" "BundleConfig wheel"
    if ($wheelVersionValue -isnot [string]) {
        throw "BundleConfig wheel version must be a string."
    }
    $resolvedVGenVersion = [string]$wheelVersionValue
    if ($resolvedVGenVersion -notmatch '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$') {
        throw "BundleConfig wheel version is not a supported VGen release version."
    }
    $resolvedWheelName = [string](Get-RequiredJsonProperty $wheel "name" "BundleConfig wheel")
    $resolvedWheelSha256 = [string](Get-RequiredJsonProperty $wheel "sha256" "BundleConfig wheel")
    $resolvedPolicyName = [string](Get-RequiredJsonProperty $policy "name" "BundleConfig policy")
    $resolvedPolicySha256 = [string](Get-RequiredJsonProperty $policy "sha256" "BundleConfig policy")
    foreach ($fileName in @($resolvedWheelName, $resolvedPolicyName)) {
        if ([string]::IsNullOrWhiteSpace($fileName) -or
            [System.IO.Path]::IsPathRooted($fileName) -or
            [System.IO.Path]::GetFileName($fileName) -ne $fileName) {
            throw "BundleConfig asset names must be file names inside the Worker bundle."
        }
    }
    $expectedWheelName = "vgen-$resolvedVGenVersion-py3-none-any.whl"
    if ($resolvedWheelName -cne $expectedWheelName) {
        throw "BundleConfig wheel name does not match its version."
    }
    if ($resolvedWheelSha256 -notmatch "^[0-9a-f]{64}$" -or $resolvedPolicySha256 -notmatch "^[0-9a-f]{64}$") {
        throw "BundleConfig file hashes must be lowercase SHA-256 values."
    }

    return [PSCustomObject]@{
        GatewayUrl = $resolvedGateway
        WorkerCredentials = $resolvedCredentials
        ComfyUIRoot = $resolvedComfyRoot
        ComfyUIDataRoot = $resolvedComfyDataRoot
        VGenVersion = $resolvedVGenVersion
        WheelName = $resolvedWheelName
        WheelSha256 = $resolvedWheelSha256
        PolicyName = $resolvedPolicyName
        PolicySha256 = $resolvedPolicySha256
        HasBundleConfig = ($null -ne $config)
    }
}

function Assert-FileHash {
    param(
        [string]$Path,
        [string]$Expected,
        [string]$Description
    )
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected) {
        throw "$Description failed SHA-256 verification."
    }
}

function Test-PrivateIpAddress {
    param([System.Net.IPAddress]$Address)
    if ([System.Net.IPAddress]::IsLoopback($Address)) {
        return $true
    }
    $bytes = $Address.GetAddressBytes()
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return (
            $bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
            ($bytes[0] -eq 100 -and (($bytes[1] -band 0xC0) -eq 64))
        )
    }
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        return (($bytes[0] -band 0xFE) -eq 0xFC) -or ($bytes[0] -eq 0xFE -and (($bytes[1] -band 0xC0) -eq 0x80))
    }
    return $false
}

function Test-PrivateGatewayHost {
    param([string]$HostName)
    if ($HostName -in @("localhost", "127.0.0.1", "::1")) {
        return $true
    }
    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($HostName, [ref]$parsed)) {
        return (Test-PrivateIpAddress $parsed)
    }
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($HostName)
    }
    catch {
        return $false
    }
    if ($addresses.Count -eq 0) {
        return $false
    }
    foreach ($address in $addresses) {
        if (-not (Test-PrivateIpAddress $address)) {
            return $false
        }
    }
    return $true
}

function Assert-GatewayUrl {
    param([Uri]$Url)
    if ($Url.Scheme -notin @("http", "https") -or -not $Url.IsAbsoluteUri) {
        throw "GatewayUrl must be an absolute HTTP(S) URL."
    }
    if (-not [string]::IsNullOrEmpty($Url.UserInfo) -or -not [string]::IsNullOrEmpty($Url.Query) -or -not [string]::IsNullOrEmpty($Url.Fragment)) {
        throw "GatewayUrl must not contain credentials, a query, or a fragment."
    }
    if ($Url.AbsolutePath -notin @("", "/")) {
        throw "GatewayUrl must not contain a path; use the Gateway origin only."
    }
    if ($Url.Scheme -eq "http" -and -not (Test-PrivateGatewayHost $Url.DnsSafeHost)) {
        throw "Plain HTTP is allowed only for loopback or private-network Gateway addresses."
    }
}

function Test-ComfyHealth {
    try {
        $null = Invoke-RestMethod -Uri "$ComfyUrl/system_stats" -Method Get -TimeoutSec 10
        return $true
    }
    catch {
        return $false
    }
}

function Test-AnyComfyProcess {
    param(
        [string]$CodeRoot,
        [string]$DataRoot
    )
    if (Test-ComfyHealth) {
        return $true
    }
    $mainPath = Join-Path $CodeRoot "main.py"
    try {
        foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
            $name = [string]$process.Name
            if ($name -match "^(ComfyUI|Comfy Desktop|comfyui-electron)\.exe$") {
                return $true
            }
            $commandLine = [string]$process.CommandLine
            if (-not [string]::IsNullOrWhiteSpace($commandLine) -and
                ($commandLine.IndexOf($mainPath, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
                    ($commandLine.IndexOf("main.py", [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
                        $commandLine.IndexOf($DataRoot, [System.StringComparison]::OrdinalIgnoreCase) -ge 0))) {
                return $true
            }
        }
    }
    catch {
        foreach ($name in @("ComfyUI", "Comfy Desktop", "comfyui-electron")) {
            if ($null -ne (Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1)) {
                return $true
            }
        }
    }
    return $false
}

function Stop-VGenManagedComfyUI {
    $process = $script:ManagedComfyProcess
    $script:ManagedComfyProcess = $null
    if ($null -eq $process) {
        return
    }
    try {
        if (-not $process.HasExited) {
            Write-Step "Stopping the ComfyUI process started by this Worker"
            Stop-Process -InputObject $process -Force -ErrorAction Stop
            $null = $process.WaitForExit(10000)
        }
    }
    catch {
        Write-Warning "The VGen-managed ComfyUI process could not be stopped automatically; close it before the next Worker start."
    }
}

function ConvertTo-NativeArgument {
    param([string]$Value)
    if ($Value.Contains('"')) {
        throw "A ComfyUI launch path contains an unsupported quote character."
    }
    if ($Value.Length -eq 0) {
        return '""'
    }
    if ($Value -match "\s") {
        # Paths cannot contain a quote on Windows. Resolve-Path also removes a
        # trailing separator, so simple quoting is safe for Windows PowerShell 5.1.
        return '"' + $Value + '"'
    }
    return $Value
}

function ConvertTo-YamlSingleQuotedScalar {
    param([string]$Value)
    if ($Value.Contains("`r") -or $Value.Contains("`n")) {
        throw "A VGen model path contains an unsupported newline character."
    }
    return "'" + $Value.Replace("'", "''") + "'"
}

function Write-VGenModelPathsConfig {
    param(
        [string]$ModelsRoot,
        [string]$ConfigPath,
        [string]$OwnedRoot
    )
    $configParent = Split-Path -Parent $ConfigPath
    if (-not (Test-PathInside $ConfigPath $OwnedRoot) -or
        -not (Test-Path -LiteralPath $configParent -PathType Container) -or
        -not (Test-ModelPathReparseSafe $configParent $OwnedRoot)) {
        throw "The VGen model path configuration location is unsafe."
    }
    if (Test-Path -LiteralPath $ConfigPath) {
        $existing = Get-Item -LiteralPath $ConfigPath -Force
        if ($existing.PSIsContainer -or
            ($existing.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The VGen model path configuration is not a regular file."
        }
    }

    $quotedRoot = ConvertTo-YamlSingleQuotedScalar $ModelsRoot
    $content = @(
        "vgen_verified_models:",
        "  base_path: $quotedRoot",
        "  diffusion_models: diffusion_models",
        "  text_encoders: text_encoders",
        "  loras: loras",
        "  vae: vae"
    ) -join "`r`n"
    $content += "`r`n"

    if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
        try {
            $existingContent = [System.IO.File]::ReadAllText($ConfigPath)
        }
        catch {
            throw "The existing VGen model path configuration could not be read."
        }
        if ($existingContent -ceq $content) {
            Write-Step "Using the existing VGen-only model path configuration: $ConfigPath"
            return
        }
    }

    $temporaryPath = Join-Path $configParent (".vgen-model-paths-" + [Guid]::NewGuid().ToString("N") + ".tmp")
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $content,
            [System.Text.UTF8Encoding]::new($false)
        )
        if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
            # Windows PowerShell 5.1 requires NullString.Value to pass a real
            # null .NET string; plain $null can bind as an invalid empty backup
            # path. Ignore non-essential ACL metadata merge errors as well.
            [System.IO.File]::Replace(
                $temporaryPath,
                $ConfigPath,
                [System.Management.Automation.Language.NullString]::Value,
                $true
            )
        }
        else {
            [System.IO.File]::Move($temporaryPath, $ConfigPath)
        }
        if ([System.IO.File]::ReadAllText($ConfigPath) -cne $content) {
            throw "written model path configuration did not verify"
        }
    }
    catch {
        $failureType = $_.Exception.GetType().Name
        $failureCode = [int]$_.Exception.HResult
        if (Test-Path -LiteralPath $temporaryPath -PathType Leaf) {
            [System.IO.File]::Delete($temporaryPath)
        }
        throw "The VGen model path configuration could not be written ($failureType, HRESULT $failureCode)."
    }
    Write-Step "Using a VGen-only model path configuration: $ConfigPath"
}

function Write-ComfyStartupLogTail {
    param(
        [string]$Path,
        [string]$Label = "startup error log"
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    Write-Warning "ComfyUI $Label (last 40 lines): $Path"
    foreach ($entry in @(Get-Content -LiteralPath $Path -Tail 40 -ErrorAction SilentlyContinue)) {
        $safe = [string]$entry
        $safe = [regex]::Replace(
            $safe,
            '(?i)((?:token|secret|password|authorization|api[_-]?key)\s*[:=]\s*)\S+',
            '${1}[redacted]'
        )
        $safe = [regex]::Replace($safe, '(?i)(https?://[^\s?]+)\?\S+', '${1}?[redacted]')
        Write-Host "  $safe"
    }
}

function Install-WingetPackage {
    param(
        [string]$PackageId,
        [string]$Description
    )
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        throw "$Description is missing and Windows Package Manager (winget) is unavailable. Install $Description, then rerun setup-worker.ps1."
    }
    Write-Step "Installing $Description for the current user with winget ($PackageId)"
    & $winget.Source install --id $PackageId --exact --scope user --silent --disable-interactivity --accept-package-agreements --accept-source-agreements | Out-Host
    $wingetExitCode = $LASTEXITCODE
    if ($wingetExitCode -ne 0) {
        throw "winget could not install $Description ($PackageId)."
    }
}

function Resolve-SingleExecutableResult {
    param(
        [object[]]$Values,
        [string]$Description,
        [bool]$AllowMissing
    )
    $items = @($Values | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0 -and $AllowMissing) {
        return $null
    }
    if ($items.Count -ne 1 -or $items[0] -isnot [string]) {
        throw "$Description returned unexpected command output instead of one executable path."
    }
    $path = [string]$items[0]
    if ([string]::IsNullOrWhiteSpace($path) -or
        -not [System.IO.Path]::IsPathRooted($path) -or
        -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$Description did not return an existing absolute executable path."
    }
    return (Resolve-Path -LiteralPath $path).Path
}

function Resolve-Python311 {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $launcher) {
        try {
            $resolved = (& $launcher.Source -3.11 -c "import sys; print(sys.executable)" 2>$null | Select-Object -Last 1).Trim()
            if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                return (Resolve-Path -LiteralPath $resolved).Path
            }
        }
        catch {
            # Continue through fixed post-winget locations.
        }
    }
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates.Add((Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates.Add((Join-Path $env:ProgramFiles "Python311\python.exe"))
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Ensure-Python311 {
    $python = Resolve-Python311
    if ($null -ne $python) {
        return $python
    }
    if ($CheckOnly) {
        Add-Finding "Python 3.11 is not installed; normal setup can install Python.Python.3.11 with winget."
        return $null
    }
    Install-WingetPackage "Python.Python.3.11" "Python 3.11"
    $python = Resolve-Python311
    if ($null -eq $python) {
        throw "Python 3.11 was installed but python.exe could not be found in a reviewed location."
    }
    return $python
}

function Resolve-GitExecutable {
    $command = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    $candidates = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates.Add((Join-Path $env:LOCALAPPDATA "Programs\Git\cmd\git.exe"))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates.Add((Join-Path $env:ProgramFiles "Git\cmd\git.exe"))
    }
    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $candidates.Add((Join-Path $programFilesX86 "Git\cmd\git.exe"))
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Ensure-GitExecutable {
    $git = Resolve-GitExecutable
    if ($null -ne $git) {
        return $git
    }
    if ($CheckOnly) {
        Add-Finding "Git is not installed; normal setup can install Git.Git with winget."
        return $null
    }
    Install-WingetPackage "Git.Git" "Git for Windows"
    $git = Resolve-GitExecutable
    if ($null -eq $git) {
        throw "Git was installed but git.exe could not be found in a reviewed location."
    }
    return $git
}

function Normalize-GitRemote {
    param([string]$Value)
    $normalized = $Value.Trim().TrimEnd("/")
    if ($normalized.EndsWith(".git", [System.StringComparison]::OrdinalIgnoreCase)) {
        $normalized = $normalized.Substring(0, $normalized.Length - 4)
    }
    return $normalized.ToLowerInvariant()
}

function Invoke-GitText {
    param(
        [string]$Repository,
        [string[]]$Arguments
    )
    $output = & $script:GitExecutable `
        -c "core.hooksPath=NUL" `
        -c "core.fsmonitor=false" `
        -c "core.longpaths=true" `
        -C $Repository @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Git could not inspect a custom-node repository."
    }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function Test-VGenOwnedPathSafe {
    param(
        [string]$Path,
        [string]$TrustedRoot
    )
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return $false
    }
    $vgenComfyRoot = Join-Path $env:LOCALAPPDATA "VGen\comfyui"
    return (
        (Test-PathInside $Path $TrustedRoot) -and
        (Test-PathInside $TrustedRoot $vgenComfyRoot) -and
        (Test-ModelPathReparseSafe $Path $env:LOCALAPPDATA)
    )
}

function Test-NoReparseDescendant {
    param(
        [string]$Path,
        [string]$TrustedRoot
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Container) -or
        -not (Test-VGenOwnedPathSafe $Path $TrustedRoot)) {
        return $false
    }
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    try {
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
            foreach ($child in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
                if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    return $false
                }
                if ($child.PSIsContainer) {
                    $pending.Push($child.FullName)
                }
            }
        }
    }
    catch {
        return $false
    }
    return $true
}

function Test-SameFullPath {
    param(
        [string]$Left,
        [string]$Right
    )
    $directorySeparators = [char[]]"\/"
    $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd($directorySeparators)
    $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd($directorySeparators)
    return $leftPath.Equals($rightPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-GitReportedPath {
    param(
        [string]$Repository,
        [string]$Value
    )
    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }
    return [System.IO.Path]::GetFullPath((Join-Path $Repository $Value))
}

function Test-ReviewedCustomNodeRepository {
    param(
        [PSCustomObject]$Pin,
        [string]$Repository,
        [string]$TrustedRoot,
        [switch]$AllowDifferentRevision
    )
    if (-not (Test-Path -LiteralPath $Repository -PathType Container) -or
        -not (Test-ModelPathReparseSafe $Repository $TrustedRoot) -or
        -not (Test-VGenOwnedPathSafe $Repository $TrustedRoot) -or
        -not (Test-NoReparseDescendant $Repository $TrustedRoot)) {
        return $false
    }
    $gitDirectory = Join-Path $Repository ".git"
    if (-not (Test-Path -LiteralPath $gitDirectory -PathType Container)) {
        return $false
    }
    $gitItem = Get-Item -LiteralPath $gitDirectory -Force
    if (($gitItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }
    $alternates = Join-Path $gitDirectory "objects\info\alternates"
    if (Test-Path -LiteralPath $alternates) {
        return $false
    }
    try {
        $origin = Invoke-GitText $Repository @("remote", "get-url", "origin")
        $allOrigins = Invoke-GitText $Repository @("remote", "get-url", "--all", "origin")
        $remoteNames = Invoke-GitText $Repository @("remote")
        $status = Invoke-GitText $Repository @("status", "--porcelain", "--untracked-files=all")
        $head = Invoke-GitText $Repository @("rev-parse", "HEAD")
        $topLevel = Invoke-GitText $Repository @("rev-parse", "--show-toplevel")
        $absoluteGitDirectory = Invoke-GitText $Repository @("rev-parse", "--absolute-git-dir")
        $commonGitDirectory = Invoke-GitText $Repository @("rev-parse", "--git-common-dir")
        $null = Invoke-GitText $Repository @("fsck", "--full", "--strict", "--no-dangling")
    }
    catch {
        return $false
    }
    $originValues = @($allOrigins -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $remoteValues = @($remoteNames -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $resolvedCommonGitDirectory = Resolve-GitReportedPath $Repository $commonGitDirectory
    return (
        $originValues.Count -eq 1 -and
        $remoteValues.Count -eq 1 -and
        $remoteValues[0] -ceq "origin" -and
        (Normalize-GitRemote $origin) -eq (Normalize-GitRemote $Pin.Source) -and
        (Normalize-GitRemote $originValues[0]) -eq (Normalize-GitRemote $Pin.Source) -and
        [string]::IsNullOrEmpty($status) -and
        ($AllowDifferentRevision -or $head -eq $Pin.Revision) -and
        (Test-SameFullPath $topLevel $Repository) -and
        (Test-SameFullPath $absoluteGitDirectory $gitDirectory) -and
        (Test-SameFullPath $resolvedCommonGitDirectory $gitDirectory)
    )
}

function Find-ReviewedCustomNodeSeed {
    param(
        [PSCustomObject]$Pin,
        [string]$VGenComfyRoot,
        [string]$Destination
    )
    if (-not (Test-Path -LiteralPath $VGenComfyRoot -PathType Container) -or
        -not (Test-ModelPathReparseSafe $VGenComfyRoot $VGenComfyRoot) -or
        -not (Test-VGenOwnedPathSafe $VGenComfyRoot $VGenComfyRoot)) {
        return $null
    }
    $directoryNames = @($Pin.Directory) + @($Pin.Aliases)
    $workerRoots = @(
        Get-ChildItem -LiteralPath $VGenComfyRoot -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "^wrk_[a-z2-7]{26}$" }
    )
    foreach ($workerRoot in $workerRoots) {
        if (-not (Test-ModelPathReparseSafe $workerRoot.FullName $VGenComfyRoot) -or
            -not (Test-VGenOwnedPathSafe $workerRoot.FullName $VGenComfyRoot)) {
            continue
        }
        $workerCustomNodes = Join-Path $workerRoot.FullName "custom_nodes"
        $presentCandidates = @(
            $directoryNames |
                ForEach-Object { Join-Path $workerCustomNodes $_ } |
                Where-Object { Test-Path -LiteralPath $_ }
        )
        if ($presentCandidates.Count -ne 1) {
            continue
        }
        $candidate = $presentCandidates[0]
        if (Test-SameFullPath $candidate $Destination) {
            continue
        }
        if (Test-ReviewedCustomNodeRepository $Pin $candidate $VGenComfyRoot) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Remove-VGenCustomNodeStaging {
    param(
        [string]$Path,
        [string]$CustomNodesRoot,
        [string]$ExpectedDirectory
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $leaf = Split-Path -Leaf $Path
    $legacyPattern = (
        "^\." + [regex]::Escape($ExpectedDirectory) +
        "\.vgen-staging-[a-f0-9]{32}$"
    )
    $shortPattern = "^\.v-[a-f0-9]{16}$"
    if (($leaf -cnotmatch $legacyPattern -and $leaf -cnotmatch $shortPattern) -or
        -not (Test-SameFullPath (Split-Path -Parent $Path) $CustomNodesRoot) -or
        -not (Test-VGenOwnedPathSafe $Path $CustomNodesRoot)) {
        throw "A custom-node staging directory is outside the VGen-owned path."
    }
    $lastFailure = $null
    for ($attempt = 1; $attempt -le 4; $attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) {
            return
        }
        if (-not (Test-NoReparseDescendant $Path $CustomNodesRoot)) {
            throw "A custom-node staging directory contains an unsafe reparse point."
        }
        $pending = [System.Collections.Generic.Stack[string]]::new()
        $pending.Push($Path)
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A custom-node staging directory contains an unsafe reparse point."
            }
            if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
                $currentItem.Attributes = [System.IO.FileAttributes](
                    [int]$currentItem.Attributes -band
                    (-bnot [int][System.IO.FileAttributes]::ReadOnly)
                )
            }
            if ($currentItem.PSIsContainer) {
                foreach ($child in @(Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop)) {
                    if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                        throw "A custom-node staging directory contains an unsafe reparse point."
                    }
                    $pending.Push($child.FullName)
                }
            }
        }
        try {
            [System.IO.Directory]::Delete($Path, $true)
            return
        }
        catch {
            $lastFailure = $_
            if ($attempt -lt 4) {
                Start-Sleep -Milliseconds 250
            }
        }
    }
    throw "VGen could not clean an incomplete custom-node staging directory: $($lastFailure.Exception.Message)"
}

function Remove-OrphanedVGenCustomNodeStaging {
    param(
        [PSCustomObject]$Pin,
        [string]$CustomNodesRoot
    )
    if ($CheckOnly -or -not (Test-Path -LiteralPath $CustomNodesRoot -PathType Container)) {
        return
    }
    $legacyPattern = (
        "^\." + [regex]::Escape($Pin.Directory) +
        "\.vgen-staging-[a-f0-9]{32}$"
    )
    $shortPattern = "^\.v-[a-f0-9]{16}$"
    foreach ($candidate in @(
            Get-ChildItem -LiteralPath $CustomNodesRoot -Directory -Force -ErrorAction Stop |
                Where-Object {
                    $_.Name -cmatch $legacyPattern -or $_.Name -cmatch $shortPattern
                }
        )) {
        Write-Step "Cleaning an incomplete custom-node staging directory: $($Pin.Name)"
        Remove-VGenCustomNodeStaging $candidate.FullName $CustomNodesRoot $Pin.Directory
    }
}

function New-PinnedCustomNodeRepository {
    param(
        [PSCustomObject]$Pin,
        [string]$Destination,
        [string]$CustomNodesRoot,
        [string]$VGenComfyRoot
    )
    if (-not (Test-VGenOwnedPathSafe $CustomNodesRoot $VGenComfyRoot) -or
        -not (Test-VGenOwnedPathSafe $Destination $CustomNodesRoot) -or
        (Test-Path -LiteralPath $Destination)) {
        throw "The custom-node destination is not a new VGen-owned directory."
    }
    $staging = $null
    for ($stagingAttempt = 1; $stagingAttempt -le 8; $stagingAttempt++) {
        $stagingLeaf = ".v-" + [Guid]::NewGuid().ToString("N").Substring(0, 16)
        $staging = Join-Path $CustomNodesRoot $stagingLeaf
        if (-not (Test-Path -LiteralPath $staging)) {
            break
        }
        $staging = $null
    }
    if ($null -eq $staging) {
        throw "VGen could not allocate a private custom-node staging directory."
    }
    $seed = Find-ReviewedCustomNodeSeed $Pin $VGenComfyRoot $Destination
    $operationFailure = $null
    try {
        if ($null -ne $seed) {
            Write-Step "Reusing locally reviewed custom node: $($Pin.Name)"
            & $script:GitExecutable `
                -c "core.hooksPath=NUL" `
                -c "core.fsmonitor=false" `
                -c "core.longpaths=true" `
                clone --no-checkout --no-hardlinks --dissociate -- $seed $staging
            if ($LASTEXITCODE -ne 0) {
                throw "Git could not copy the locally reviewed $($Pin.Name) repository."
            }
            & $script:GitExecutable `
                -c "core.hooksPath=NUL" `
                -c "core.fsmonitor=false" `
                -c "core.longpaths=true" `
                -C $staging remote set-url origin $Pin.Source
            if ($LASTEXITCODE -ne 0) {
                throw "Git could not restore the reviewed origin for $($Pin.Name)."
            }
        }
        else {
            Write-Step "Installing pinned custom node: $($Pin.Name)"
            & $script:GitExecutable `
                -c "core.hooksPath=NUL" `
                -c "core.fsmonitor=false" `
                -c "core.longpaths=true" `
                init --template= -- $staging 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Git could not initialize $($Pin.Name)."
            }
            & $script:GitExecutable `
                -c "core.hooksPath=NUL" `
                -c "core.fsmonitor=false" `
                -c "core.longpaths=true" `
                -C $staging remote add origin $Pin.Source
            if ($LASTEXITCODE -ne 0) {
                throw "Git could not configure the reviewed origin for $($Pin.Name)."
            }
            & $script:GitExecutable `
                -c "core.hooksPath=NUL" `
                -c "core.fsmonitor=false" `
                -c "core.longpaths=true" `
                -C $staging fetch --depth 1 --no-tags origin $Pin.Revision
            if ($LASTEXITCODE -ne 0) {
                throw "Git could not fetch the pinned revision for $($Pin.Name)."
            }
        }
        & $script:GitExecutable `
            -c "core.hooksPath=NUL" `
            -c "core.fsmonitor=false" `
            -c "core.longpaths=true" `
            -C $staging checkout --detach $Pin.Revision
        if ($LASTEXITCODE -ne 0) {
            throw "Git could not check out the pinned revision for $($Pin.Name)."
        }
        if (-not (Test-ReviewedCustomNodeRepository $Pin $staging $CustomNodesRoot)) {
            throw "Custom-node repository verification failed for $($Pin.Name)."
        }
        [System.IO.Directory]::Move($staging, $Destination)
        if (-not (Test-ReviewedCustomNodeRepository $Pin $Destination $CustomNodesRoot)) {
            throw "Installed custom-node verification failed for $($Pin.Name)."
        }
    }
    catch {
        $operationFailure = $_
    }
    finally {
        try {
            Remove-VGenCustomNodeStaging $staging $CustomNodesRoot $Pin.Directory
        }
        catch {
            if ($null -eq $operationFailure) {
                throw
            }
            Write-Warning "Incomplete custom-node staging cleanup was deferred until the next setup run."
        }
    }
    if ($null -ne $operationFailure) {
        throw $operationFailure
    }
}

function Install-PinnedCustomNode {
    param(
        [PSCustomObject]$Pin,
        [string]$CustomNodesRoot,
        [bool]$ComfyWasRunning,
        [string]$VGenComfyRoot
    )
    Remove-OrphanedVGenCustomNodeStaging $Pin $CustomNodesRoot
    $directoryNames = @($Pin.Directory) + @($Pin.Aliases)
    $existingDestinations = @(
        $directoryNames |
            ForEach-Object { Join-Path $CustomNodesRoot $_ } |
            Where-Object { Test-Path -LiteralPath $_ }
    )
    if ($existingDestinations.Count -gt 1) {
        $message = "Multiple directories exist for the same custom node and were left untouched: $($Pin.Name)"
        if ($CheckOnly) { Add-Finding $message; return $false }
        throw $message
    }
    $destination = if ($existingDestinations.Count -eq 1) {
        $existingDestinations[0]
    }
    else {
        Join-Path $CustomNodesRoot $Pin.Directory
    }
    if (-not (Test-Path -LiteralPath $destination)) {
        if ($CheckOnly) {
            Add-Finding "Custom node is not installed: $($Pin.Name)"
            return $false
        }
        if ($ComfyWasRunning) {
            throw "Stop the existing ComfyUI process before installing $($Pin.Name)."
        }
        New-PinnedCustomNodeRepository $Pin $destination $CustomNodesRoot $VGenComfyRoot
        return $true
    }

    if (-not (Test-Path -LiteralPath (Join-Path $destination ".git") -PathType Container)) {
        $message = "Existing custom-node directory is not a Git repository: $($Pin.Directory)"
        if ($CheckOnly) { Add-Finding $message; return $false }
        throw $message
    }
    if (Test-ReviewedCustomNodeRepository $Pin $destination $CustomNodesRoot) {
        return $false
    }
    if (-not (Test-ReviewedCustomNodeRepository `
            $Pin $destination $CustomNodesRoot -AllowDifferentRevision)) {
        $message = "Existing custom-node repository failed the reviewed integrity checks and was left untouched: $($Pin.Directory)"
        if ($CheckOnly) { Add-Finding $message; return $false }
        throw $message
    }
    $head = Invoke-GitText $destination @("rev-parse", "HEAD")
    if ($head -eq $Pin.Revision) {
        return $false
    }
    if ($CheckOnly) {
        Add-Finding "Custom node is not at its reviewed revision: $($Pin.Name)"
        return $false
    }
    if ($ComfyWasRunning) {
        throw "Stop the existing ComfyUI process before changing $($Pin.Name)."
    }
    Write-Step "Updating clean custom node to reviewed revision: $($Pin.Name)"
    & $script:GitExecutable `
        -c "core.hooksPath=NUL" `
        -c "core.fsmonitor=false" `
        -c "core.longpaths=true" `
        -C $destination fetch --depth 1 --no-tags origin $Pin.Revision
    if ($LASTEXITCODE -ne 0) {
        throw "Git could not fetch the pinned revision for $($Pin.Name)."
    }
    & $script:GitExecutable `
        -c "core.hooksPath=NUL" `
        -c "core.fsmonitor=false" `
        -c "core.longpaths=true" `
        -C $destination checkout --detach $Pin.Revision
    if ($LASTEXITCODE -ne 0) {
        throw "Git could not check out the pinned revision for $($Pin.Name)."
    }
    if (-not (Test-ReviewedCustomNodeRepository $Pin $destination $CustomNodesRoot)) {
        throw "Custom-node revision verification failed for $($Pin.Name)."
    }
    return $true
}

function Resolve-FirstExistingPythonCandidate {
    param([object[]]$Candidates)

    foreach ($candidateValue in @($Candidates)) {
        if ($null -eq $candidateValue) {
            continue
        }
        $candidate = [string]$candidateValue
        if ([string]::IsNullOrWhiteSpace($candidate) -or
            -not [System.IO.Path]::IsPathRooted($candidate)) {
            continue
        }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

function Resolve-ComfyPython {
    param(
        [string]$Root,
        [string]$DataRoot,
        [object]$DesktopRecord
    )
    $rootParent = Split-Path -Parent $Root

    # A Desktop installation record is authoritative. In particular, an
    # adopted installation intentionally keeps its Python and data directory
    # separate from the managed ComfyUI checkout.
    if ($null -ne $DesktopRecord) {
        $sourceId = [string]$DesktopRecord.SourceId
        $installPath = [string]$DesktopRecord.InstallPath
        if ([bool]$DesktopRecord.Adopted) {
            $adoptedPythonPath = [string]$DesktopRecord.AdoptedPythonPath
            if (-not [string]::IsNullOrWhiteSpace($adoptedPythonPath)) {
                if ([System.IO.Path]::IsPathRooted($adoptedPythonPath)) {
                    $resolvedAdoptedPython = Resolve-FirstExistingPythonCandidate @($adoptedPythonPath)
                    if ($null -ne $resolvedAdoptedPython -and
                        (Test-PathInside $resolvedAdoptedPython $DataRoot)) {
                        return $resolvedAdoptedPython
                    }
                }
            }
            return Resolve-FirstExistingPythonCandidate @(
                (Join-Path $DataRoot ".venv\Scripts\python.exe"),
                (Join-Path $DataRoot "venv\Scripts\python.exe")
            )
        }

        switch ($sourceId.ToLowerInvariant()) {
            "standalone" {
                return Resolve-FirstExistingPythonCandidate @(
                    (Join-Path $DataRoot ".venv\Scripts\python.exe"),
                    (Join-Path $Root ".venv\Scripts\python.exe"),
                    (Join-Path $installPath "envs\default\Scripts\python.exe"),
                    (Join-Path $DataRoot "venv\Scripts\python.exe")
                )
            }
            "comfybuilder" {
                return Resolve-FirstExistingPythonCandidate @(
                    (Join-Path $installPath "venv\base\python.exe"),
                    (Join-Path $installPath "venv\python.exe")
                )
            }
            "git" {
                $venvPath = [string]$DesktopRecord.VenvPath
                if ([string]::IsNullOrWhiteSpace($venvPath) -or
                    -not [System.IO.Path]::IsPathRooted($venvPath)) {
                    return $null
                }
                if (Test-Path -LiteralPath $venvPath -PathType Leaf) {
                    return Resolve-FirstExistingPythonCandidate @($venvPath)
                }
                return Resolve-FirstExistingPythonCandidate @(
                    (Join-Path $venvPath "Scripts\python.exe"),
                    (Join-Path $venvPath "python.exe")
                )
            }
            "portable" {
                return Resolve-FirstExistingPythonCandidate @(
                    (Join-Path $installPath "python_embeded\python.exe"),
                    (Join-Path $rootParent "python_embeded\python.exe"),
                    (Join-Path $Root "python_embeded\python.exe")
                )
            }
            "desktop" {
                return Resolve-FirstExistingPythonCandidate @(
                    (Join-Path $DataRoot ".venv\Scripts\python.exe")
                )
            }
        }
    }

    # Current Comfy Desktop Standalone keeps its managed interpreter beside
    # the ComfyUI checkout. The base interpreter is authoritative; the legacy
    # fallback must never make an otherwise valid installation ambiguous when
    # both paths coexist during a Desktop upgrade.
    $managedInstallRoots = [System.Collections.Generic.List[string]]::new()
    if ((Split-Path -Leaf $rootParent) -ieq "resources") {
        $managedInstallRoots.Add((Split-Path -Parent $rootParent))
    }
    $managedInstallRoots.Add($rootParent)
    foreach ($managedInstallRoot in @($managedInstallRoots | Select-Object -Unique)) {
        foreach ($managedCandidate in @(
                (Join-Path $managedInstallRoot "venv\base\python.exe"),
                (Join-Path $managedInstallRoot "venv\python.exe")
            )) {
            if (Test-Path -LiteralPath $managedCandidate -PathType Leaf) {
                return (Resolve-Path -LiteralPath $managedCandidate).Path
            }
        }
    }

    $rawCandidates = [System.Collections.Generic.List[string]]::new()
    foreach ($candidate in @(
            (Join-Path $DataRoot ".venv\Scripts\python.exe"),
            (Join-Path $DataRoot "venv\Scripts\python.exe")
        )) {
        $rawCandidates.Add($candidate)
    }
    if ($DataRoot -eq $Root) {
        foreach ($candidate in @(
                (Join-Path $Root "python_embeded\python.exe"),
                (Join-Path (Split-Path -Parent $Root) "python_embeded\python.exe"),
                (Join-Path (Split-Path -Parent $Root) "envs\default\Scripts\python.exe")
            )) {
            $rawCandidates.Add($candidate)
        }
    }
    $candidates = @(@(
            $rawCandidates |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
                ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
                Select-Object -Unique
        ))
    if ($candidates.Count -ne 1) {
        return $null
    }
    return $candidates[0]
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
        throw "WorkerCredentials access rules could not be verified."
    }

    if (-not $acl.AreAccessRulesProtected) {
        throw "WorkerCredentials must disable inherited access rules."
    }
    if ($ownerSid -notin $allowedSids) {
        throw "WorkerCredentials has an unapproved owner."
    }

    $currentUserAllowed = $false
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $ruleSid = $rule.IdentityReference.Value
        if ($ruleSid -notin $allowedSids) {
            throw "WorkerCredentials grants access to an unapproved principal."
        }
        if ($ruleSid -eq $currentSid -and
            (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
                [System.Security.AccessControl.FileSystemRights]::FullControl)) {
            $currentUserAllowed = $true
        }
    }
    if (-not $currentUserAllowed) {
        throw "WorkerCredentials does not grant full control to the current Windows user."
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
        throw "WorkerCredentials owner could not be secured."
    }
    & $icaclsPath $Path /inheritance:r /grant:r "*$($currentSid):F" "*S-1-5-18:F" "*S-1-5-32-544:F" 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "WorkerCredentials access rules could not be secured."
    }
    Assert-CredentialAcl $Path
}

function Test-ModelPathReparseSafe {
    param(
        [string]$Path,
        [string]$ModelsRoot
    )
    $current = $Path
    $rootPath = [System.IO.Path]::GetFullPath($ModelsRoot).TrimEnd("\")
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return $false
            }
        }
        $currentPath = [System.IO.Path]::GetFullPath($current).TrimEnd("\")
        if ($currentPath.Equals($rootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
        if (-not $currentPath.StartsWith($rootPath + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
        $parent = Split-Path -Parent $currentPath
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $currentPath) {
            return $false
        }
        $current = $parent
    }
    return $false
}

function Test-ModelPins {
    param([string]$ModelsRoot)
    $failures = @()
    foreach ($pin in $ModelPins) {
        $path = Join-Path (Join-Path $ModelsRoot $pin.Folder) $pin.FileName
        $reason = $null
        if (-not (Test-ModelPathReparseSafe $path $ModelsRoot)) {
            $reason = "reparse point"
        }
        elseif (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            if (Test-Path -LiteralPath $path) {
                $reason = "not a regular file"
            }
            else {
                $reason = "missing"
            }
        }
        else {
            $item = Get-Item -LiteralPath $path
            if ($item.Length -ne $pin.Size) {
                $reason = "size mismatch"
            }
        }
        if ($null -ne $reason) {
            $failures += [PSCustomObject]@{ Pin = $pin; Path = $path; Reason = $reason }
        }
    }
    return $failures
}

function Get-ModelRootStatus {
    param(
        [string]$ModelsRoot,
        [int]$Index
    )
    $failures = @(Test-ModelPins $ModelsRoot)
    $failedNames = @($failures | ForEach-Object { [string]$_.Pin.FileName })
    $validNames = @(
        $ModelPins |
            Where-Object { [string]$_.FileName -notin $failedNames } |
            ForEach-Object { [string]$_.FileName }
    )
    return [PSCustomObject]@{
        Root = $ModelsRoot
        Index = $Index
        Failures = $failures
        ValidNames = $validNames
        ValidCount = $validNames.Count
        InvalidCount = @($failures | Where-Object { $_.Reason -ne "missing" }).Count
    }
}

function Test-ModelRootWritable {
    param([string]$ModelsRoot)

    foreach ($programRoot in @(
            $env:ProgramFiles,
            [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
        )) {
        if (-not [string]::IsNullOrWhiteSpace($programRoot) -and
            (Test-PathInside $ModelsRoot $programRoot)) {
            return $false
        }
    }
    try {
        $item = Get-Item -LiteralPath $ModelsRoot
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $applicableSids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $null = $applicableSids.Add($identity.User.Value)
        foreach ($group in $identity.Groups) {
            $null = $applicableSids.Add($group.Value)
        }
        $writeRight = [System.Security.AccessControl.FileSystemRights]::CreateFiles
        $allowed = $false
        foreach ($rule in (Get-Acl -LiteralPath $ModelsRoot).Access) {
            try {
                $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                continue
            }
            if (-not $applicableSids.Contains($sid) -or
                (($rule.FileSystemRights -band $writeRight) -eq 0)) {
                continue
            }
            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                return $false
            }
            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                $allowed = $true
            }
        }
        return $allowed
    }
    catch {
        return $false
    }
}

function Select-ComfyModelRoot {
    param([string[]]$Candidates)

    if ($Candidates.Count -eq 0) {
        throw "No existing absolute ComfyUI model directory was found. Finish the local ComfyUI setup, then rerun this installer."
    }
    $statuses = [System.Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Candidates.Count; $index++) {
        $statuses.Add((Get-ModelRootStatus $Candidates[$index] $index))
    }

    $complete = @($statuses | Where-Object { $_.ValidCount -eq $ModelPins.Count -and $_.InvalidCount -eq 0 })
    if ($complete.Count -gt 0) {
        $selected = $complete[0]
        Write-Step "Using ComfyUI models: $($selected.Root) (all five pinned models found by path and size)"
        return [string]$selected.Root
    }

    $validAcrossRoots = @(
        $statuses |
            ForEach-Object { @($_.ValidNames) } |
            Select-Object -Unique
    )
    if ($validAcrossRoots.Count -eq $ModelPins.Count) {
        throw "The five pinned models are split across multiple model directories. VGen will not download duplicate copies or combine roots; move them into one reviewed model directory, then rerun."
    }

    $eligible = @(
        $statuses |
            Where-Object { $_.InvalidCount -eq 0 -and (Test-ModelRootWritable ([string]$_.Root)) } |
            Sort-Object -Property @(
                @{ Expression = { [int]$_.ValidCount }; Descending = $true },
                @{ Expression = { [int]$_.Index }; Ascending = $true }
            )
    )
    if ($eligible.Count -eq 0) {
        throw "No writable non-Program-Files model directory is safe for the missing pinned models. Existing mismatched or reparse-point files were left untouched."
    }
    $selected = $eligible[0]
    Write-Step "Using ComfyUI models: $($selected.Root) ($($selected.ValidCount) of five pinned models already match by path and size)"
    return [string]$selected.Root
}

function Assert-NoLegacyModelShadows {
    param([string]$ModelsRoot)

    $legacyAliases = @{
        "diffusion_models" = "unet"
        "text_encoders" = "clip"
    }
    foreach ($pin in $ModelPins) {
        if (-not $legacyAliases.ContainsKey([string]$pin.Folder)) {
            continue
        }
        $shadowPath = Join-Path (Join-Path $ModelsRoot $legacyAliases[[string]$pin.Folder]) $pin.FileName
        if (Test-Path -LiteralPath $shadowPath) {
            throw "A legacy model alias shadows a pinned model name: $shadowPath. VGen will not start with ambiguous unet/clip model precedence."
        }
    }
}

function Test-ComfyPythonRequirements {
    param([string]$Python)
    if ([string]::IsNullOrWhiteSpace($Python)) {
        return $false
    }
    & $Python -B -c "import cv2, imageio_ffmpeg, torch, torchaudio" 2>$null | Out-Null
    $requirementsExitCode = $LASTEXITCODE
    return $requirementsExitCode -eq 0
}

function Write-ManualModelList {
    param([System.Collections.IEnumerable]$Failures)
    Write-Warning "One or more model files need attention:"
    foreach ($failure in $Failures) {
        Write-Host ""
        Write-Host "  reason: $($failure.Reason)"
        Write-Host "  target: $($failure.Path)"
        Write-Host "  bytes:  $($failure.Pin.Size)"
        Write-Host "  sha256: $($failure.Pin.Sha256)"
        Write-Host "  source: $($failure.Pin.Source)"
        Write-Host "  license: $($failure.Pin.LicenseUrl)"
    }
}

function Ensure-WorkerRuntime {
    param(
        [string]$RuntimeRoot,
        [string]$WheelPath,
        [string]$BootstrapPython,
        [string]$ExpectedVersion
    )
    $python = Join-Path $RuntimeRoot "Scripts\python.exe"
    if ($CheckOnly) {
        if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
            Add-Finding "The dedicated VGen Worker virtual environment is not installed."
            return $null
        }
        try {
            $version = (& $python -B -c "import vgen; print(vgen.__version__)" 2>$null | Select-Object -Last 1).Trim()
        }
        catch {
            Add-Finding "The VGen package cannot be imported from the Worker virtual environment."
            return $null
        }
        if ($LASTEXITCODE -ne 0 -or $version -cne $ExpectedVersion) {
            Add-Finding "The Worker virtual environment does not contain VGen $ExpectedVersion."
            return $null
        }
        return $python
    }

    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        if ([string]::IsNullOrWhiteSpace($BootstrapPython)) {
            throw "Python 3.11 is required to create the isolated Worker environment."
        }
        Write-Step "Creating dedicated Python 3.11 Worker environment"
        & $BootstrapPython -m venv $RuntimeRoot | Out-Host
        $venvExitCode = $LASTEXITCODE
        if ($venvExitCode -ne 0) {
            throw "Python could not create the Worker virtual environment."
        }
    }
    Write-Step "Installing the reviewed VGen Worker wheel"
    & $python -m pip install --disable-pip-version-check --upgrade pip | Out-Host
    $pipBootstrapExitCode = $LASTEXITCODE
    if ($pipBootstrapExitCode -ne 0) {
        throw "pip could not initialize the Worker virtual environment."
    }
    $wheelRequirement = "$WheelPath`[worker-comfyui`]"
    & $python -m pip install --disable-pip-version-check --upgrade $wheelRequirement | Out-Host
    $pipInstallExitCode = $LASTEXITCODE
    if ($pipInstallExitCode -ne 0) {
        throw "pip could not install the reviewed VGen Worker wheel."
    }
    try {
        $installedVersion = (& $python -B -c "import vgen; print(vgen.__version__)" 2>$null | Select-Object -Last 1).Trim()
    }
    catch {
        throw "The installed VGen Worker package could not be verified."
    }
    if ($LASTEXITCODE -ne 0 -or $installedVersion -cne $ExpectedVersion) {
        throw "The installed VGen Worker package version does not match the reviewed bundle."
    }
    return $python
}

function Convert-ToComparableVersion {
    param([object]$Value)
    if ($null -eq $Value) {
        return $null
    }
    $match = [regex]::Match([string]$Value, "(?<!\d)(\d+\.\d+\.\d+)")
    if (-not $match.Success) {
        return $null
    }
    return [Version]$match.Groups[1].Value
}

function Get-ComfyRuntimeVersion {
    $stats = Invoke-RestMethod -Uri "$ComfyUrl/system_stats" -Method Get -TimeoutSec 60
    if ($null -eq $stats -or
        $null -eq $stats.PSObject.Properties["system"] -or
        $null -eq $stats.system -or
        $null -eq $stats.system.PSObject.Properties["comfyui_version"] -or
        [string]::IsNullOrWhiteSpace([string]$stats.system.comfyui_version)) {
        throw "ComfyUI did not report its runtime version. Update ComfyUI, exit it completely, then rerun start-worker.cmd."
    }
    $raw = [string]$stats.system.comfyui_version
    $parsed = Convert-ToComparableVersion $raw
    if ($null -eq $parsed) {
        throw "ComfyUI reported an unsupported runtime version. Update ComfyUI, exit it completely, then rerun start-worker.cmd."
    }
    return [PSCustomObject]@{
        Raw = $raw
        Parsed = $parsed
    }
}

function Get-ComfyCodeVersion {
    param([string]$Root)
    foreach ($candidate in @(
            [PSCustomObject]@{ Path = (Join-Path $Root "comfyui_version.py"); Pattern = '(?m)^\s*__version__\s*=\s*["'']([^"'']+)' },
            [PSCustomObject]@{ Path = (Join-Path $Root "pyproject.toml"); Pattern = '(?m)^\s*version\s*=\s*["'']([^"'']+)' }
        )) {
        if (-not (Test-Path -LiteralPath $candidate.Path -PathType Leaf)) {
            continue
        }
        $match = [regex]::Match([System.IO.File]::ReadAllText($candidate.Path), $candidate.Pattern)
        if (-not $match.Success) {
            continue
        }
        $raw = $match.Groups[1].Value
        $parsed = Convert-ToComparableVersion $raw
        if ($null -ne $parsed) {
            return [PSCustomObject]@{
                Raw = $raw
                Parsed = $parsed
            }
        }
    }
    return $null
}

function Get-ComfyUpdateInstruction {
    param(
        [string]$Root,
        [string]$DetectedVersion
    )
    $description = if ([string]::IsNullOrWhiteSpace($DetectedVersion)) { "an unknown version" } else { "version $DetectedVersion" }
    if ((Get-ComfyRootKind $Root) -eq "ComfyUI Desktop") {
        return "The selected ComfyUI code reports $description, but H3 requires $MinimumRuntimeVersion or newer. In ComfyUI Desktop choose Menu > Help > Check for Updates (or install the latest Desktop), let the update finish, exit Desktop completely, then rerun start-worker.cmd. VGen did not modify Desktop."
    }
    return "The selected ComfyUI code reports $description, but H3 requires $MinimumRuntimeVersion or newer. Update ComfyUI, exit it completely, then rerun start-worker.cmd."
}

function Assert-DoctorResult {
    param([PSCustomObject]$Doctor)
    if (-not $Doctor.ok) {
        throw "Worker doctor reported that ComfyUI is unavailable."
    }
    $executor = $Doctor.executor
    $executorVersion = Convert-ToComparableVersion $executor.version
    if ($null -eq $executorVersion -or $executorVersion -lt [Version]$MinimumExecutorVersion) {
        throw "VGen ComfyUI Executor is older than the workflow requirement."
    }
    $capabilities = $executor.capabilities
    $runtimeVersion = Convert-ToComparableVersion $capabilities.runtime_version
    if ($null -eq $runtimeVersion -or $runtimeVersion -lt [Version]$MinimumRuntimeVersion) {
        throw "ComfyUI runtime is older than $MinimumRuntimeVersion or did not report a parseable version."
    }
    $policy = $capabilities.execution_policy
    if (-not $policy.configured -or $policy.model_pins -ne 5 -or
        ([int]$policy.models_verified + [int]$policy.models_failed) -ne 5) {
        throw "Worker doctor did not load the complete five-model local policy."
    }
    if ([Int64]$capabilities.vram_bytes -lt $MinimumVramBytes) {
        throw "The Worker reports less than 16,000,000,000 bytes of VRAM."
    }
    if ([Int64]$capabilities.ram_bytes -lt $MinimumRamBytes) {
        throw "The Worker reports less than 32,000,000,000 bytes of system RAM."
    }
}

function Test-AllowedWorkerPythonPath {
    param(
        [string]$Candidate,
        [string]$InitialPython,
        [string]$WorkRoot
    )
    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $false
    }
    try {
        $resolvedCandidate = [System.IO.Path]::GetFullPath($Candidate)
        $resolvedInitial = [System.IO.Path]::GetFullPath($InitialPython)
        $releaseRoot = [System.IO.Path]::GetFullPath((Join-Path $WorkRoot "runtime-releases"))
        $releasePrefix = $releaseRoot.TrimEnd("\") + "\"
        $allowed = $resolvedCandidate.Equals($resolvedInitial, [System.StringComparison]::OrdinalIgnoreCase) -or
            $resolvedCandidate.StartsWith($releasePrefix, [System.StringComparison]::OrdinalIgnoreCase)
        if (-not $allowed -or -not (Test-Path -LiteralPath $resolvedCandidate -PathType Leaf)) {
            return $false
        }
        $item = Get-Item -LiteralPath $resolvedCandidate
        return ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    }
    catch {
        return $false
    }
}

function Get-WorkerRuntimeState {
    param(
        [string]$WorkRoot,
        [string]$InitialPython
    )
    $pointerPath = Join-Path $WorkRoot "runtime-active.json"
    if (-not (Test-Path -LiteralPath $pointerPath)) {
        return [PSCustomObject]@{
            ActivePython = $InitialPython
            PreviousPython = $null
            Pending = $false
        }
    }
    $item = Get-Item -LiteralPath $pointerPath
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The VGen Worker runtime pointer is unsafe."
    }
    try {
        $pointer = [System.IO.File]::ReadAllText($pointerPath) | ConvertFrom-Json
    }
    catch {
        throw "The VGen Worker runtime pointer is invalid."
    }
    if ($pointer.format -ne "vgen-worker-runtime-pointer" -or $pointer.version -ne 1 -or
        -not (Test-AllowedWorkerPythonPath ([string]$pointer.active_python) $InitialPython $WorkRoot)) {
        throw "The VGen Worker runtime pointer is invalid."
    }
    $pending = $null -ne $pointer.PSObject.Properties["pending_job_id"] -and
        -not [string]::IsNullOrWhiteSpace([string]$pointer.pending_job_id)
    $previousPython = $null
    if ($pending) {
        if ($null -eq $pointer.PSObject.Properties["previous_python"] -or
            -not (Test-AllowedWorkerPythonPath ([string]$pointer.previous_python) $InitialPython $WorkRoot)) {
            throw "The VGen Worker rollback runtime pointer is invalid."
        }
        $previousPython = [string]$pointer.previous_python
    }
    return [PSCustomObject]@{
        ActivePython = [string]$pointer.active_python
        PreviousPython = $previousPython
        Pending = $pending
    }
}

# Dot-sourcing is reserved for the Windows PowerShell 5.1 conformance tests;
# normal users and start-worker.cmd execute this file with -File.
if ($MyInvocation.InvocationName -eq ".") {
    return
}

try {
    $bundleSettings = Resolve-WorkerBundleSettings
    $GatewayUrl = [Uri]$bundleSettings.GatewayUrl
    $WorkerCredentials = [string]$bundleSettings.WorkerCredentials
    $ComfyUIRoot = [string]$bundleSettings.ComfyUIRoot
    $ComfyUIDataRoot = [string]$bundleSettings.ComfyUIDataRoot
    Assert-GatewayUrl $GatewayUrl

    $credentialsPath = (Resolve-Path -LiteralPath $WorkerCredentials).Path
    $credentialItem = Get-Item -LiteralPath $credentialsPath
    if ($credentialItem.PSIsContainer) {
        throw "WorkerCredentials must be a regular file."
    }
    if (($credentialItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "WorkerCredentials must not be a symbolic link or reparse point."
    }
    $credentialReady = $true
    if ($CheckOnly) {
        try {
            Assert-CredentialAcl $credentialsPath
        }
        catch {
            Add-Finding "Worker credential access rules are not protected; normal setup will secure them before first use."
            $credentialReady = $false
        }
    }
    else {
        Protect-CredentialAcl $credentialsPath
    }

    $workerId = $null
    if ($credentialReady) {
        try {
            $credentialObject = [System.IO.File]::ReadAllText($credentialsPath) | ConvertFrom-Json
        }
        catch {
            throw "WorkerCredentials is not a valid VGen credential bundle."
        }
        $credentialFields = @($credentialObject.PSObject.Properties.Name)
        if (@("format", "version", "worker_id") | Where-Object { $_ -notin $credentialFields }) {
            throw "WorkerCredentials is not a supported VGen Worker credential bundle."
        }
        if ($credentialObject.format -ne "vgen-worker-credentials" -or $credentialObject.version -ne 1 -or [string]$credentialObject.worker_id -notmatch "^wrk_[a-z2-7]{26}$") {
            throw "WorkerCredentials is not a supported VGen Worker credential bundle."
        }
        $workerId = [string]$credentialObject.worker_id
        $credentialObject = $null
    }

    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw "LOCALAPPDATA is required for the isolated Worker runtime."
    }

    $comfyLayout = Resolve-ComfyLayout $ComfyUIRoot $ComfyUIDataRoot
    $resolvedComfyRoot = [string]$comfyLayout.CodeRoot
    $resolvedComfyDataRoot = [string]$comfyLayout.DataRoot
    Write-Step "Using ComfyUI code: $resolvedComfyRoot"
    Write-Step "Reading existing ComfyUI data: $resolvedComfyDataRoot"
    $workerRuntimeName = if ([string]::IsNullOrWhiteSpace($workerId)) { "uninitialized" } else { $workerId }
    $vgenComfyRoot = Join-Path $env:LOCALAPPDATA "VGen\comfyui"
    $isolatedComfyDataRoot = Join-Path $vgenComfyRoot $workerRuntimeName
    Write-Step "Using isolated VGen ComfyUI data: $isolatedComfyDataRoot"
    $mainPath = Join-Path $resolvedComfyRoot "main.py"
    $vgenModelsRoot = Join-Path $isolatedComfyDataRoot "models"
    $modelPathsConfig = Join-Path $isolatedComfyDataRoot "vgen-model-paths.yaml"
    $inputRoot = Join-Path $isolatedComfyDataRoot "input"
    $outputRoot = Join-Path $isolatedComfyDataRoot "output"
    $tempRoot = Join-Path $isolatedComfyDataRoot "temp"
    $userRoot = Join-Path $isolatedComfyDataRoot "user"
    $customNodesRoot = Join-Path $isolatedComfyDataRoot "custom_nodes"
    $databasePath = Join-Path $userRoot "comfyui.db"
    $databaseUrl = "sqlite:///" + $databasePath.Replace("\", "/")
    foreach ($directory in @($isolatedComfyDataRoot, $vgenModelsRoot, $inputRoot, $outputRoot, $tempRoot, $userRoot, $customNodesRoot)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            if ($CheckOnly) {
                Add-Finding "Isolated VGen ComfyUI data directory does not exist: $directory"
            }
            else {
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
            }
        }
    }
    $modelRootCandidates = @(Get-ComfyModelRootCandidates $resolvedComfyDataRoot $vgenModelsRoot)
    $modelsRoot = Select-ComfyModelRoot $modelRootCandidates
    Assert-NoLegacyModelShadows $modelsRoot

    $wheelPath = Resolve-BundledFile "VGen Worker wheel" @(
        (Join-Path $PSScriptRoot $bundleSettings.WheelName),
        (Join-Path (Join-Path $PSScriptRoot "..\..\dist") $bundleSettings.WheelName)
    )
    $policyPath = Resolve-BundledFile "ComfyUI execution policy" @(
        (Join-Path $PSScriptRoot $bundleSettings.PolicyName),
        (Join-Path (Join-Path $PSScriptRoot "..") $PolicyName)
    )
    Assert-FileHash $wheelPath $bundleSettings.WheelSha256 "VGen Worker wheel"
    Assert-FileHash $policyPath $bundleSettings.PolicySha256 "ComfyUI execution policy"

    Write-Step "Checking Gateway health"
    $gatewayBase = $GatewayUrl.AbsoluteUri.TrimEnd("/")
    try {
        $health = Invoke-RestMethod -Uri "$gatewayBase/healthz" -Method Get -TimeoutSec 20
        if (-not $health.ok) {
            throw "not ready"
        }
    }
    catch {
        if ($CheckOnly) { Add-Finding "Gateway health check failed." } else { throw "Gateway health check failed." }
    }

    $codeVersionInfo = Get-ComfyCodeVersion $resolvedComfyRoot
    if ($null -eq $codeVersionInfo) {
        $compatibilityMessage = Get-ComfyUpdateInstruction $resolvedComfyRoot $null
        if ($CheckOnly) { Add-Finding $compatibilityMessage } else { throw $compatibilityMessage }
    }
    else {
        Write-Step "Detected ComfyUI code version: $($codeVersionInfo.Raw)"
        if ($codeVersionInfo.Parsed -lt [Version]$MinimumRuntimeVersion) {
            $compatibilityMessage = Get-ComfyUpdateInstruction $resolvedComfyRoot $codeVersionInfo.Raw
            if ($CheckOnly) { Add-Finding $compatibilityMessage } else { throw $compatibilityMessage }
        }
    }

    $bootstrapPythonResults = @(Ensure-Python311)
    $bootstrapPython = Resolve-SingleExecutableResult `
        $bootstrapPythonResults "Python 3.11 discovery" ([bool]$CheckOnly)
    $runtimeRoot = Join-Path $env:LOCALAPPDATA "VGen\worker-runtime-$($bundleSettings.VGenVersion)"
    $runtimePythonResults = @(
        Ensure-WorkerRuntime $runtimeRoot $wheelPath $bootstrapPython $bundleSettings.VGenVersion
    )
    $runtimePython = Resolve-SingleExecutableResult `
        $runtimePythonResults "VGen Worker runtime preparation" ([bool]$CheckOnly)
    $comfyPython = Resolve-ComfyPython $resolvedComfyRoot $resolvedComfyDataRoot $comfyLayout.DesktopRecord
    if ($null -eq $comfyPython) {
        if ($CheckOnly) {
            Add-Finding "Could not resolve the Python runtime recorded for the selected ComfyUI installation."
        }
        else {
            throw "The selected ComfyUI Python could not be resolved. For Desktop with custom storage, rerun and enter its data directory when prompted, or pass -ComfyUIDataRoot explicitly."
        }
    }
    else {
        Write-Step "Using ComfyUI Python: $comfyPython"
    }

    $comfyWorkerPortRunning = Test-ComfyHealth
    $comfyWasRunning = Test-AnyComfyProcess $resolvedComfyRoot $isolatedComfyDataRoot
    if ($comfyWasRunning) {
        if ($CheckOnly) {
            Add-Finding "ComfyUI is already running; VGen cannot prove that process uses the selected model directory without Desktop extra model paths."
        }
        else {
            throw "ComfyUI or ComfyUI Desktop is already running. Exit it completely so VGen can start it with the selected model directory and no Desktop extra model paths."
        }
    }
    $gitExecutableResults = @(Ensure-GitExecutable)
    $script:GitExecutable = Resolve-SingleExecutableResult `
        $gitExecutableResults "Git discovery" ([bool]$CheckOnly)
    if ($null -ne $script:GitExecutable -and (Test-Path -LiteralPath $customNodesRoot -PathType Container)) {
        foreach ($pin in $CustomNodePins) {
            $null = Install-PinnedCustomNode $pin $customNodesRoot $comfyWasRunning $vgenComfyRoot
        }
    }

    if ($null -ne $comfyPython -and $CheckOnly) {
        if (-not (Test-ComfyPythonRequirements $comfyPython)) {
            $message = "The selected ComfyUI Python runtime cannot import the required Torch, audio, or Video Helper modules."
            Add-Finding $message
        }
    }
    elseif (-not $CheckOnly -and -not $comfyWasRunning -and $null -ne $comfyPython) {
        $vhsRequirements = Join-Path (Join-Path $customNodesRoot "ComfyUI-VideoHelperSuite") "requirements.txt"
        if (-not (Test-Path -LiteralPath $vhsRequirements -PathType Leaf)) {
            throw "Pinned Video Helper Suite requirements.txt is missing."
        }
        Write-Step "Installing Video Helper Suite Python requirements into the ComfyUI runtime"
        & $comfyPython -m pip install --disable-pip-version-check -r $vhsRequirements
        if ($LASTEXITCODE -ne 0) {
            throw "ComfyUI could not install Video Helper Suite requirements."
        }
        if (-not (Test-ComfyPythonRequirements $comfyPython)) {
            throw "The selected ComfyUI Python runtime cannot import the required Torch, audio, or Video Helper modules."
        }
    }

    $modelFailures = @(Test-ModelPins $modelsRoot)
    if ($modelFailures.Count -gt 0) {
        $invalidModels = @($modelFailures | Where-Object { $_.Reason -ne "missing" })
        $missingModels = @($modelFailures | Where-Object { $_.Reason -eq "missing" })
        if ($invalidModels.Count -gt 0) {
            Write-ManualModelList $invalidModels
            Add-Finding "Existing model paths that are unsafe or have a size mismatch were left untouched."
        }
        if ($missingModels.Count -gt 0) {
            # Missing files are no longer an installation failure.  The Worker
            # starts online without inference capacity and can receive a signed
            # Broker model_install job whose license acceptance, immutable
            # source revision, size, and SHA-256 are rechecked locally.
            Write-Warning "$($missingModels.Count) policy-pinned model file(s) are missing. The Worker will start in maintenance-only mode until a Broker-authorized model download completes."
        }
    }

    if ($script:Findings.Count -gt 0) {
        Write-Warning "Worker setup is not ready ($($script:Findings.Count) finding(s)). No Worker was started."
        exit 5
    }

    $comfyStdoutPath = $null
    $comfyStderrPath = $null
    if (-not $comfyWorkerPortRunning) {
        if ($CheckOnly) {
            Add-Finding "ComfyUI is not running; CheckOnly does not start it."
            exit 5
        }
        if ($comfyWasRunning) {
            throw "ComfyUI or ComfyUI Desktop is already running on another port. Exit it completely, then rerun start-worker.cmd."
        }
        Write-VGenModelPathsConfig $modelsRoot $modelPathsConfig $isolatedComfyDataRoot
        $logRoot = Join-Path $env:LOCALAPPDATA "VGen\logs"
        New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $comfyStdoutPath = Join-Path $logRoot "comfyui-$timestamp.out.log"
        $comfyStderrPath = Join-Path $logRoot "comfyui-$timestamp.err.log"
        Write-Step "Starting local-only ComfyUI"
        $comfyArguments = @(
            $mainPath,
            "--base-directory", $isolatedComfyDataRoot,
            "--extra-model-paths-config", $modelPathsConfig,
            "--user-directory", $userRoot,
            "--input-directory", $inputRoot,
            "--output-directory", $outputRoot,
            "--temp-directory", $tempRoot,
            "--database-url", $databaseUrl,
            "--listen", "127.0.0.1",
            "--port", "8188"
        )
        if ($null -ne $comfyLayout.FrontEndRoot) {
            $comfyArguments += @("--front-end-root", [string]$comfyLayout.FrontEndRoot)
        }
        $nativeComfyArguments = @($comfyArguments | ForEach-Object { ConvertTo-NativeArgument ([string]$_) })
        $comfyProcess = Start-Process -FilePath $comfyPython -ArgumentList @(
            $nativeComfyArguments
        ) -WorkingDirectory $isolatedComfyDataRoot -NoNewWindow -RedirectStandardOutput $comfyStdoutPath -RedirectStandardError $comfyStderrPath -PassThru
        $script:ManagedComfyProcess = $comfyProcess
        $deadline = (Get-Date).AddSeconds(180)
        while ((Get-Date) -lt $deadline -and -not (Test-ComfyHealth)) {
            if ($comfyProcess.HasExited) {
                Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"
                Write-ComfyStartupLogTail $comfyStderrPath
                throw "ComfyUI exited before becoming healthy. The startup error is printed above."
            }
            Start-Sleep -Seconds 2
        }
        if (-not (Test-ComfyHealth)) {
            Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"
            Write-ComfyStartupLogTail $comfyStderrPath
            throw "ComfyUI did not become healthy within 180 seconds. The startup error is printed above."
        }
    }

    Write-Step "Checking ComfyUI runtime compatibility"
    try {
        $runtimeVersionInfo = Get-ComfyRuntimeVersion
    }
    catch {
        $versionFailure = [string]$_.Exception.Message
        Stop-VGenManagedComfyUI
        Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"
        Write-ComfyStartupLogTail $comfyStderrPath
        throw $versionFailure
    }
    Write-Step "Detected ComfyUI runtime: $($runtimeVersionInfo.Raw)"
    if ($runtimeVersionInfo.Parsed -lt [Version]$MinimumRuntimeVersion) {
        Stop-VGenManagedComfyUI
        Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"
        Write-ComfyStartupLogTail $comfyStderrPath
        if ((Get-ComfyRootKind $resolvedComfyRoot) -eq "ComfyUI Desktop") {
            throw (Get-ComfyUpdateInstruction $resolvedComfyRoot $runtimeVersionInfo.Raw)
        }
        throw (Get-ComfyUpdateInstruction $resolvedComfyRoot $runtimeVersionInfo.Raw)
    }

    Write-Step "Checking required ComfyUI node classes"
    try {
        $objectInfo = Invoke-RestMethod -Uri "$ComfyUrl/object_info" -Method Get -TimeoutSec 60
    }
    catch {
        Stop-VGenManagedComfyUI
        Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"
        Write-ComfyStartupLogTail $comfyStderrPath
        throw "ComfyUI did not return its node registry. The startup error is printed above."
    }
    $missingNodes = @($RequiredNodeClasses | Where-Object { $null -eq $objectInfo.PSObject.Properties[$_] })
    if ($missingNodes.Count -gt 0) {
        Stop-VGenManagedComfyUI
        Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"
        Write-ComfyStartupLogTail $comfyStderrPath
        if ("LoraLoaderBypassModelOnly" -in $missingNodes) {
            throw "The selected ComfyUI core is incomplete or incompatible with the H3 workflow. Missing node classes: $($missingNodes -join ', '). Update or repair ComfyUI, exit it completely, then rerun start-worker.cmd. The startup details are printed above."
        }
        throw "ComfyUI did not load the required H3 node classes: $($missingNodes -join ', '). The startup import error is printed above; fix that error, then rerun start-worker.cmd."
    }

    if ($null -eq $runtimePython) {
        throw "The VGen Worker runtime is unavailable."
    }
    $workerExecutable = Join-Path $runtimeRoot "Scripts\vgen-worker.exe"
    if (-not (Test-Path -LiteralPath $workerExecutable -PathType Leaf)) {
        throw "vgen-worker.exe is missing from the isolated runtime."
    }

    Write-Step "Running fail-closed Worker doctor"
    $doctorOutput = & $workerExecutable doctor --comfy-url $ComfyUrl --comfy-output-dir $outputRoot --comfy-model-root $modelsRoot --comfy-policy-file $policyPath --progress --json
    $doctorExit = $LASTEXITCODE
    try {
        $doctor = (($doctorOutput | ForEach-Object { [string]$_ }) -join "`n") | ConvertFrom-Json
    }
    catch {
        throw "Worker doctor returned invalid JSON."
    }
    if ($doctorExit -ne 0) {
        throw "Worker doctor failed."
    }
    Assert-DoctorResult $doctor
    $verifiedModelCount = [int]$doctor.executor.capabilities.execution_policy.models_verified
    if ($verifiedModelCount -eq 5) {
        Write-Step "Worker doctor verified runtime, policy, resources, and all five model pins"
    }
    else {
        Write-Step "Worker doctor verified runtime, policy, and resources; $verifiedModelCount of five model pins are installed"
        Write-Warning "Inference remains unavailable until Broker-authorized model maintenance installs the missing pins."
    }

    if ($CheckOnly) {
        Write-Step "CheckOnly completed successfully; no files or processes were changed"
        exit 0
    }

    $workRoot = Join-Path $env:LOCALAPPDATA "VGen\workers\$workerId"
    $workerArguments = @(
        "serve",
        "--gateway-url", $gatewayBase,
        "--worker-id", $workerId,
        "--credentials-file", $credentialsPath,
        "--comfy-url", $ComfyUrl,
        "--comfy-output-dir", $outputRoot,
        "--comfy-model-root", $modelsRoot,
        "--comfy-policy-file", $policyPath,
        "--work-root", $workRoot,
        "--interval", "2",
        "--json",
        "--announce"
    )
    if ($GatewayUrl.Scheme -eq "http") {
        $workerArguments += "--allow-http"
    }
    Write-Step "Starting authenticated Worker $workerId in the foreground"
    if (-not (Test-Path -LiteralPath $workRoot -PathType Container)) {
        New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
    }
    # Current Workers supervise versioned child runtimes themselves. Keep this
    # outer loop so a pre-supervisor Worker can still complete its first remote
    # upgrade without reinstalling the Windows package.
    $workerExitCode = 1
    $activeWorkerPython = (Get-WorkerRuntimeState $workRoot $runtimePython).ActivePython
    $restartAttempts = 0
    $launchingRollback = $false
    try {
        while ($true) {
            if ($launchingRollback) {
                $env:VGEN_WORKER_UPDATE_ROLLBACK = "1"
            }
            else {
                [Environment]::SetEnvironmentVariable("VGEN_WORKER_UPDATE_ROLLBACK", $null, "Process")
            }
            & $activeWorkerPython -m vgen.worker.main @workerArguments
            $workerExitCode = $LASTEXITCODE
            [Environment]::SetEnvironmentVariable("VGEN_WORKER_UPDATE_ROLLBACK", $null, "Process")

            $runtimeState = Get-WorkerRuntimeState $workRoot $runtimePython
            if ($workerExitCode -eq 75) {
                if ($runtimeState.ActivePython.Equals($activeWorkerPython, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "The VGen Worker update restart pointer did not advance safely."
                }
                # This can be a later, independent update after the current
                # child served for days; start a fresh rollback budget.
                $restartAttempts = 1
                Write-Step "Restarting Worker with the reviewed versioned runtime"
                $activeWorkerPython = $runtimeState.ActivePython
                $launchingRollback = $false
                continue
            }

            # If the target interpreter could not reach its activation
            # heartbeat, restart the previous runtime once.  That old process
            # reports a signed rolled_back result and clears the pending pointer.
            if ($workerExitCode -ne 0 -and $runtimeState.Pending -and
                $runtimeState.ActivePython.Equals($activeWorkerPython, [System.StringComparison]::OrdinalIgnoreCase)) {
                $restartAttempts++
                if ($restartAttempts -gt 3) {
                    throw "The VGen Worker update failed and exceeded the safe rollback limit."
                }
                Write-Warning "The updated Worker did not activate; restarting the previous reviewed runtime."
                $activeWorkerPython = $runtimeState.PreviousPython
                $launchingRollback = $true
                continue
            }
            break
        }
    }
    finally {
        Stop-VGenManagedComfyUI
    }
    exit $workerExitCode
}
catch {
    Stop-VGenManagedComfyUI
    # Never include credential JSON, tokens, upstream response bodies, or command lines.
    [Console]::Error.WriteLine("[vgen] ERROR: $([string]$_.Exception.Message)")
    exit 1
}
