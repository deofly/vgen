from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "examples" / "windows-worker" / "setup-worker.ps1"
ENROLLMENT_SCRIPT = ROOT / "examples" / "windows-worker" / "enroll-worker.ps1"
WORKER_LAUNCHER = ROOT / "examples" / "windows-worker" / "start-worker.cmd"
USER_GUIDE = ROOT / "docs" / "user-guide.md"
DEVELOPER_GUIDE = ROOT / "docs" / "developer-guide.md"
MANIFEST = ROOT / "workflows" / "vgen" / "minimax-h3-8step" / "1.0.0" / "manifest.yaml"
POLICY = ROOT / "examples" / "comfyui-minimax-h3-policy.yaml"


def _blocks(text: str, variable: str, next_variable: str) -> list[str]:
    body = text.split(f"${variable} = @(", 1)[1].split(f"${next_variable} = @(", 1)[0]
    return re.findall(r"\[PSCustomObject\]@\{(.*?)\n\s*\}", body, flags=re.DOTALL)


def _quoted_value(block: str, name: str) -> str:
    match = re.search(rf'^\s*{re.escape(name)}\s*=\s*"([^"]+)"', block, flags=re.MULTILINE)
    assert match, f"missing {name} in PowerShell pin block"
    return match.group(1)


def _integer_value(block: str, name: str) -> int:
    match = re.search(
        rf"^\s*{re.escape(name)}\s*=\s*(?:\[Int64\])?(\d+)", block, flags=re.MULTILINE
    )
    assert match, f"missing {name} in PowerShell pin block"
    return int(match.group(1))


def test_windows_worker_script_auto_loads_bundle_and_keeps_advanced_inputs() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert USER_GUIDE.is_file()
    for parameter in ("GatewayUrl", "WorkerCredentials", "ComfyUIRoot"):
        assert re.search(rf"\${parameter}\b", text)
    assert "[switch]$CheckOnly" in text
    assert "if ($CheckOnly)" in text
    assert "CheckOnly completed successfully" in text
    assert '$env:PYTHONDONTWRITEBYTECODE = "1"' in text
    assert '$env:GIT_OPTIONAL_LOCKS = "0"' in text
    assert '$Url.AbsolutePath -notin @("", "/")' in text
    assert '"vgen-worker-bundle.json"' in text
    assert '"vgen-windows-worker-bundle"' in text
    assert "function Resolve-AutomaticComfyRoot" in text
    assert "[Parameter(Mandatory = $true)]" not in text.split("Set-StrictMode", 1)[0]
    assert not re.search(r"(?im)^\s*(?:&\s*)?docker(?:\.exe)?\b", text)


def test_windows_worker_derives_and_validates_product_version_from_bundle() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    settings = text.split("function Resolve-WorkerBundleSettings", 1)[1].split(
        "function Assert-FileHash", 1
    )[0]
    runtime = text.split("function Ensure-WorkerRuntime", 1)[1].split(
        "function Convert-ToComparableVersion", 1
    )[0]
    main = text.split("try {\n    $bundleSettings", 1)[1]

    assert not re.search(r'^\$VGenVersion\s*=\s*"', text, flags=re.MULTILINE)
    assert not re.search(r'^\$WheelName\s*=\s*"', text, flags=re.MULTILINE)
    assert 'Get-RequiredJsonProperty $wheel "version" "BundleConfig wheel"' in settings
    assert "(?:a|b|rc)" not in settings
    assert "$wheelVersionValue -isnot [string]" in settings
    assert "BundleConfig wheel version is not a supported VGen release version." in settings
    assert '$expectedWheelName = "vgen-$resolvedVGenVersion-py3-none-any.whl"' in settings
    assert "$resolvedWheelName -cne $expectedWheelName" in settings
    assert "VGenVersion = $resolvedVGenVersion" in settings
    assert "[string]$ExpectedVersion" in runtime
    assert "$version -cne $ExpectedVersion" in runtime
    assert "$installedVersion -cne $ExpectedVersion" in runtime
    assert '"VGen\\worker-runtime-$($bundleSettings.VGenVersion)"' in main
    assert (
        "Ensure-WorkerRuntime $runtimeRoot $wheelPath $bootstrapPython $bundleSettings.VGenVersion"
    ) in main


def test_windows_worker_native_installer_output_never_becomes_a_return_value() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    runtime = text.split("function Ensure-WorkerRuntime", 1)[1].split(
        "function Convert-ToComparableVersion", 1
    )[0]
    winget = text.split("function Install-WingetPackage", 1)[1].split(
        "function Resolve-Python311", 1
    )[0]

    assert re.search(r"&\s+\$BootstrapPython\s+-m\s+venv\s+\$RuntimeRoot\s*\|\s*Out-Host", runtime)
    assert len(re.findall(r"&\s+\$python\s+-m\s+pip\s+install[^\r\n]*\|\s*Out-Host", runtime)) == 2
    assert re.search(r"&\s+\$winget\.Source\s+install[^\r\n]*\|\s*Out-Host", winget)
    assert runtime.count("return $python") == 2
    assert "$bootstrapPythonResults = @(Ensure-Python311)" in text
    assert '$bootstrapPythonResults "Python 3.11 discovery" ([bool]$CheckOnly)' in text
    assert "$runtimePythonResults = @(" in text
    assert '$runtimePythonResults "VGen Worker runtime preparation" ([bool]$CheckOnly)' in text
    assert "$gitExecutableResults = @(Ensure-GitExecutable)" in text
    assert '$gitExecutableResults "Git discovery" ([bool]$CheckOnly)' in text


def test_windows_worker_supports_official_portable_and_generic_python_layouts_fail_closed() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    guide = USER_GUIDE.read_text(encoding="utf-8")
    assert '(Join-Path (Split-Path -Parent $Root) "python_embeded\\python.exe")' in text
    assert "$candidates.Count -ne 1" in text
    assert '"portable" {' in text
    assert "ComfyUI Portable" in guide
    assert "找到多套时在当前窗口列出编号供选择" in guide
    assert "不会扫描整个磁盘" in guide


def test_windows_worker_preserves_desktop_record_layout_metadata() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    records = text.split("function Get-RecordedComfyDesktopRoots", 1)[1].split(
        "function Get-DefaultComfyDesktopRoots", 1
    )[0]
    for field in (
        "InstallPath",
        "SourceId",
        "Adopted",
        "AdoptedBaseDir",
        "AdoptedPythonPath",
        "VenvPath",
    ):
        assert re.search(rf"(?m)^\s*{field}\s*=", records)
    for source_field in (
        "installPath",
        "sourceId",
        "adopted",
        "adoptedBaseDir",
        "adoptedPythonPath",
        "venvPath",
    ):
        assert f'$record.PSObject.Properties["{source_field}"]' in records


def test_windows_worker_matches_desktop_records_by_canonical_code_root() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    matcher = text.split("function Get-RecordedComfyDesktopRootForPath", 1)[1].split(
        "function Get-DefaultComfyDesktopRoots", 1
    )[0]
    assert "Get-RecordedComfyDesktopRoots" in matcher
    assert "Resolve-Path" in matcher or "[System.IO.Path]::GetFullPath" in matcher
    assert re.search(r"(?i)\.Root\s+-ieq\s+\$", matcher)
    assert "return $record" in matcher


def test_windows_worker_uses_adopted_desktop_data_root_and_passes_record_to_python() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    layout = text.split("function Resolve-ComfyLayout", 1)[1].split(
        "function Resolve-WorkerBundleSettings", 1
    )[0]
    assert "$desktopRecord = Get-RecordedComfyDesktopRootForPath $resolvedCodeRoot" in layout
    assert "$desktopRecord.Adopted" in layout
    assert "$desktopRecord.AdoptedBaseDir" in layout
    assert "$adoptedBaseDir = [string]$desktopRecord.AdoptedBaseDir" in layout
    assert "Resolve-Path -LiteralPath $adoptedBaseDir" in layout
    assert "DesktopRecord = $desktopRecord" in layout

    main = text.split("$comfyLayout = Resolve-ComfyLayout", 1)[1]
    assert (
        "Resolve-ComfyPython $resolvedComfyRoot $resolvedComfyDataRoot $comfyLayout.DesktopRecord"
    ) in main


def test_windows_worker_requires_a_confirmed_desktop_data_root_or_prompts_safely() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    manual = text.split("function Read-ManualComfyDataRoot", 1)[1].split(
        "function Get-ComfyRootKind", 1
    )[0]
    assert "if ($CheckOnly -or -not (Test-InteractiveConsole))" in manual
    assert "pass -ComfyUIDataRoot" in manual
    assert "[System.IO.Path]::IsPathRooted($expanded)" in manual
    assert "Test-Path -LiteralPath $expanded -PathType Container" in manual
    assert "Resolve-Path -LiteralPath $expanded" in manual

    python_markers = manual.split("foreach ($marker in @(", 1)[1].split(")) {", 1)[0]
    assert '".venv\\Scripts\\python.exe"' in python_markers
    assert '"venv\\Scripts\\python.exe"' in python_markers
    for non_python_marker in ('"models"', '"input"', '"output"', '"user"'):
        assert non_python_marker not in python_markers
    assert "Test-Path -LiteralPath (Join-Path $resolved $marker) -PathType Leaf" in manual
    assert "if (-not $hasPythonMarker)" in manual

    layout = text.split("function Resolve-ComfyLayout", 1)[1].split(
        "function Resolve-WorkerBundleSettings", 1
    )[0]
    override = layout.index("if (-not [string]::IsNullOrWhiteSpace($DataRootOverride))")
    adopted = layout.index("elseif ($null -ne $desktopRecord -and [bool]$desktopRecord.Adopted)")
    legacy = layout.index("elseif ($isBundledDesktop)")
    recognized = layout.index("elseif ($isRecognizedDesktop)")
    assert override < adopted < legacy < recognized
    assert "Get-LegacyDesktopDataRootIfAvailable" in layout
    assert "$runtimeMarkers = @(" in layout
    assert "Read-ManualComfyDataRoot" in layout
    assert "not present in a readable installation record or standard runtime layout" in layout

    settings = text.split("function Resolve-WorkerBundleSettings", 1)[1].split(
        "function Get-InstalledPython311", 1
    )[0]
    assert "$resolvedComfyDataRoot = $ComfyUIDataRoot" in settings
    assert '$config.PSObject.Properties["comfyui_data_root"]' in settings
    assert "$resolvedComfyDataRoot = [string]$config.comfyui_data_root" in settings


def test_windows_worker_resolves_recorded_python_layouts_deterministically() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    resolver = text.split("function Resolve-ComfyPython", 1)[1].split(
        "function Assert-CredentialAcl", 1
    )[0]
    helper = text.split("function Resolve-FirstExistingPythonCandidate", 1)[1].split(
        "function Resolve-ComfyPython", 1
    )[0]

    assert "[object]$DesktopRecord" in resolver
    assert "$DesktopRecord.AdoptedPythonPath" in resolver
    assert "$DesktopRecord.SourceId" in resolver
    assert "$DesktopRecord.VenvPath" in resolver
    assert "Test-Path -LiteralPath $candidate -PathType Leaf" in helper
    assert "return (Resolve-Path -LiteralPath $candidate).Path" in helper

    assert "$rootParent = Split-Path -Parent $Root" in resolver
    standalone = '(Join-Path $Root ".venv\\Scripts\\python.exe")'
    standalone_fallback = '(Join-Path $installPath "envs\\default\\Scripts\\python.exe")'
    comfybuilder = '(Join-Path $installPath "venv\\base\\python.exe")'
    comfybuilder_fallback = '(Join-Path $installPath "venv\\python.exe")'
    portable = '(Join-Path $rootParent "python_embeded\\python.exe")'
    for marker in (
        standalone,
        standalone_fallback,
        comfybuilder,
        comfybuilder_fallback,
        portable,
    ):
        assert marker in resolver

    adopted = resolver.index("$DesktopRecord.AdoptedPythonPath")
    assert adopted < resolver.index(standalone)
    assert resolver.index(standalone) < resolver.index(standalone_fallback)
    assert resolver.index(comfybuilder) < resolver.index(comfybuilder_fallback)
    assert resolver.index("$DesktopRecord.VenvPath") < resolver.index(portable)

    generic = resolver.split("$rawCandidates", 1)[1]
    assert "$candidates.Count -ne 1" in generic


def test_windows_worker_discovers_current_and_legacy_comfy_desktop_layouts() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert '"Comfy Desktop\\installations.json"' in text
    assert "function Get-JsonArrayRecords" in text
    assert '(Join-Path ([string]$record.installPath) "ComfyUI")' in text
    assert "[string]$record.installPath" in text
    assert '"Comfy Desktop\\resources\\ComfyUI"' in text
    assert '"Programs\\@comfyorgcomfyui-electron\\resources\\ComfyUI"' in text
    assert '"@comfyorgcomfyui-electron\\resources\\ComfyUI"' in text
    assert 'Join-Path $env:APPDATA "ComfyUI\\config.json"' in text
    assert "$basePath = [string]$config.basePath" in text
    assert 'Join-Path $env:LOCALAPPDATA "Comfy-Desktop\\ComfyUI-Installs"' in text
    assert 'Join-Path $env:USERPROFILE "ComfyUI-Installs"' in text
    assert "function Test-ComfyDesktopLauncherInstalled" in text
    assert '"Comfy Desktop\\Comfy Desktop.exe"' in text
    assert "function Read-ManualComfyRoot" in text
    assert "Choose the installed application:" in text
    assert (
        "Desktop instance: C:\\Users\\<you>\\AppData\\Local\\Comfy-Desktop\\ComfyUI-Installs\\<instance>"
        in text
    )
    assert '"Programs\\@comfyorgcomfyui-electron\\ComfyUI.exe"' in text
    assert '"ComfyUI_windows_portable\\ComfyUI"' in text
    assert "ComfyUI data root must be outside Program Files" in text
    assert 'Write-Step "Using ComfyUI code: $resolvedComfyRoot"' in text
    assert 'Write-Step "Reading existing ComfyUI data: $resolvedComfyDataRoot"' in text
    assert 'Write-Step "Using isolated VGen ComfyUI data: $isolatedComfyDataRoot"' in text


def test_windows_worker_auto_detects_common_roots_and_prompts_only_as_fallback() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    automatic = text.split("function Resolve-AutomaticComfyRoot", 1)[1].split(
        "function Test-PathInside", 1
    )[0]
    settings = text.split("function Resolve-WorkerBundleSettings", 1)[1].split(
        "function Get-InstalledPython311", 1
    )[0]

    for marker in (
        "$env:LOCALAPPDATA",
        "$env:APPDATA",
        "$env:ProgramFiles",
        'GetEnvironmentVariable("ProgramW6432")',
        'GetEnvironmentVariable("ProgramFiles(x86)")',
    ):
        assert marker in automatic
    assert "Get-RecordedComfyDesktopRoots" in automatic
    assert "Get-DefaultComfyDesktopRoots" in automatic
    assert "Get-ComfyRootsFromInstallPath $root" in automatic
    assert "Select-UniqueComfyRoot $candidates" in automatic
    assert "return Read-ManualComfyRoot" in automatic
    assert "Program Files (x86)" in automatic
    assert "Get-ChildItem -Recurse" not in automatic

    assert "function Test-InteractiveConsole" in text
    assert "[Console]::IsInputRedirected" in text
    assert "function Resolve-ConfiguredComfyRoot" in text
    assert "function Read-ManualComfyRoot" in text
    assert 'Write-Host "  1. ComfyUI Desktop"' in text
    assert 'Write-Host "  2. ComfyUI / Portable"' in text
    assert "Paste its installation folder, ComfyUI.exe, or main.py path" in text
    assert 'Write-Host "  M. Choose another installation folder"' in text
    assert "$CheckOnly -or -not (Test-InteractiveConsole)" in text

    assert "$resolvedComfyRoot = $ComfyUIRoot" in settings
    assert "$resolvedComfyRoot = [string]$config.comfyui_root" in settings
    assert "$resolvedComfyRoot = Resolve-AutomaticComfyRoot" in settings
    assert "$resolvedComfyRoot = Resolve-ConfiguredComfyRoot $resolvedComfyRoot" in settings
    assert (
        "The configured ComfyUIRoot is not a ready ComfyUI or ComfyUI Desktop installation directory."
        in text
    )


def test_windows_worker_accepts_app_folder_executable_or_direct_comfy_root() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    normalizer = text.split("function Get-ComfyRootsFromInstallPath", 1)[1].split(
        "function Read-ManualComfyRoot", 1
    )[0]
    classifier = text.split("function Get-ComfyRootKind", 1)[1].split(
        "function Get-ComfyRootsFromInstallPath", 1
    )[0]

    assert "[Environment]::ExpandEnvironmentVariables" in normalizer
    assert "$item.PSIsContainer" in normalizer
    assert "$item.DirectoryName" in normalizer
    for relative in (
        '""',
        '"ComfyUI"',
        '"resources\\ComfyUI"',
        '"@comfyorgcomfyui-electron\\resources\\ComfyUI"',
        '"Programs\\@comfyorgcomfyui-electron\\resources\\ComfyUI"',
        '"ComfyUI_windows_portable\\ComfyUI"',
    ):
        assert relative in normalizer
    assert 'Join-Path $candidate "main.py"' in normalizer
    assert "$seen.Add($resolved)" in normalizer
    assert 'return "ComfyUI Desktop"' in classifier
    assert 'return "ComfyUI Portable"' in classifier
    assert 'return "ComfyUI"' in classifier
    assert "Get-RecordedComfyDesktopRootForPath $Root" in classifier
    assert '"Comfy-Desktop\\ComfyUI-Installs"' in classifier
    assert '"venv\\base\\python.exe"' not in classifier
    assert '"venv\\python.exe"' not in classifier


def test_windows_worker_keeps_bundled_desktop_code_read_only() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    layout_block = text.split("$comfyLayout = Resolve-ComfyLayout", 1)[1]
    assert '$vgenComfyRoot = Join-Path $env:LOCALAPPDATA "VGen\\comfyui"' in layout_block
    assert "$isolatedComfyDataRoot = Join-Path $vgenComfyRoot $workerRuntimeName" in layout_block
    assert '$vgenModelsRoot = Join-Path $isolatedComfyDataRoot "models"' in layout_block
    assert (
        "$modelRootCandidates = @(Get-ComfyModelRootCandidates "
        "$resolvedComfyDataRoot $vgenModelsRoot)"
    ) in layout_block
    assert "$modelsRoot = Select-ComfyModelRoot $modelRootCandidates" in layout_block
    assert '$customNodesRoot = Join-Path $isolatedComfyDataRoot "custom_nodes"' in layout_block
    assert '$outputRoot = Join-Path $isolatedComfyDataRoot "output"' in layout_block
    assert '$userRoot = Join-Path $isolatedComfyDataRoot "user"' in layout_block
    assert "Resolve-ComfyPython $resolvedComfyRoot $resolvedComfyDataRoot" in layout_block
    assert "New-Item -ItemType Directory -Force -Path $directory" in layout_block
    assert 'Join-Path $resolvedComfyRoot "models"' not in layout_block
    assert 'Join-Path $resolvedComfyRoot "custom_nodes"' not in layout_block
    assert '$customNodesRoot = Join-Path $resolvedComfyDataRoot "custom_nodes"' not in layout_block


def test_windows_worker_reuses_only_strictly_reviewed_sibling_worker_custom_nodes() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    reviewer = text.split("function Test-ReviewedCustomNodeRepository", 1)[1].split(
        "function Find-ReviewedCustomNodeSeed", 1
    )[0]
    same_path = text.split("function Test-SameFullPath", 1)[1].split(
        "function Resolve-GitReportedPath", 1
    )[0]
    finder = text.split("function Find-ReviewedCustomNodeSeed", 1)[1].split(
        "function Remove-VGenCustomNodeStaging", 1
    )[0]

    assert 'Where-Object { $_.Name -match "^wrk_[a-z2-7]{26}$" }' in finder
    assert "Get-ChildItem -LiteralPath $VGenComfyRoot -Directory" in finder
    assert "Test-ModelPathReparseSafe $workerRoot.FullName $VGenComfyRoot" in finder
    assert 'Join-Path $workerRoot.FullName "custom_nodes"' in finder
    assert "$Pin.Directory" in finder
    assert "$Pin.Aliases" in finder
    assert "Test-ReviewedCustomNodeRepository $Pin $candidate $VGenComfyRoot" in finder
    assert "$resolvedComfyRoot" not in finder
    assert "$resolvedComfyDataRoot" not in finder
    assert "Get-ChildItem -Path" not in finder
    assert "-Recurse" not in finder

    for command in (
        '@("remote", "get-url", "origin")',
        '@("status", "--porcelain", "--untracked-files=all")',
        '@("rev-parse", "HEAD")',
        '@("rev-parse", "--show-toplevel")',
        '@("fsck", "--full", "--strict", "--no-dangling")',
    ):
        assert command in reviewer
    assert 'Join-Path $gitDirectory "objects\\info\\alternates"' in reviewer
    assert "Normalize-GitRemote $origin" in reviewer
    assert "Normalize-GitRemote $Pin.Source" in reviewer
    assert "[string]::IsNullOrEmpty($status)" in reviewer
    assert "$head -eq $Pin.Revision" in reviewer
    assert "Test-ModelPathReparseSafe $Repository $TrustedRoot" in reviewer
    assert "Test-SameFullPath $topLevel $Repository" in reviewer
    assert "[System.IO.Path]::GetFullPath" in same_path
    assert "[System.StringComparison]::OrdinalIgnoreCase" in same_path


def test_windows_worker_prefers_independent_local_clone_then_verified_staged_remote_fallback() -> (
    None
):
    text = SCRIPT.read_text(encoding="utf-8")
    creator = text.split("function New-PinnedCustomNodeRepository", 1)[1].split(
        "function Install-PinnedCustomNode", 1
    )[0]

    seed = creator.index("$seed = Find-ReviewedCustomNodeSeed")
    local = creator.index("if ($null -ne $seed)", seed)
    local_clone = creator.index("clone --no-checkout", local)
    remote = creator.index("else {", local)
    remote_fetch = creator.index("fetch --depth 1 --no-tags origin $Pin.Revision", remote)
    assert seed < local < local_clone < remote < remote_fetch
    assert "--no-hardlinks" in creator
    assert "--dissociate" in creator
    assert "remote set-url origin $Pin.Source" in creator

    checkout = creator.index("checkout --detach $Pin.Revision")
    staged_verify = creator.index(
        "Test-ReviewedCustomNodeRepository $Pin $staging $CustomNodesRoot", checkout
    )
    move = creator.index("[System.IO.Directory]::Move($staging, $Destination)", staged_verify)
    destination_verify = creator.index(
        "Test-ReviewedCustomNodeRepository $Pin $Destination $CustomNodesRoot", move
    )
    assert remote_fetch < checkout < staged_verify < move < destination_verify
    assert "Remove-VGenCustomNodeStaging $staging $CustomNodesRoot $Pin.Directory" in creator


def test_windows_worker_enables_long_paths_for_every_custom_node_git_command() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    custom_node_git = text.split("function Invoke-GitText", 1)[1].split(
        "function Resolve-FirstExistingPythonCandidate", 1
    )[0]

    git_invocations = custom_node_git.count("& $script:GitExecutable")
    assert git_invocations >= 8
    assert custom_node_git.count('-c "core.longpaths=true"') == git_invocations


def test_windows_worker_uses_a_random_short_custom_node_staging_leaf() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    creator = text.split("function New-PinnedCustomNodeRepository", 1)[1].split(
        "function Install-PinnedCustomNode", 1
    )[0]

    match = re.search(
        r'^\s*\$stagingLeaf\s*=\s*"([^"]*)"\s*\+\s*'
        r'\[Guid\]::NewGuid\(\)\.ToString\("N"\)\.Substring\(0,\s*(\d+)\)',
        creator,
        flags=re.MULTILINE,
    )
    assert match, "custom-node staging must use a fresh, shortened GUID leaf"
    prefix, random_length_text = match.groups()
    random_length = int(random_length_text)
    assert random_length >= 12
    assert len(prefix) + random_length <= len("minimax-h3-audio-T8")
    assert "$staging = Join-Path $CustomNodesRoot $stagingLeaf" in creator
    assert ".$($Pin.Directory).vgen-staging-" not in creator


def test_windows_worker_staging_cleanup_is_owned_safe_readonly_tolerant_and_retried() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    cleanup = text.split("function Remove-VGenCustomNodeStaging", 1)[1].split(
        "function Remove-OrphanedVGenCustomNodeStaging", 1
    )[0]

    owned = cleanup.index("Test-VGenOwnedPathSafe")
    no_reparse = cleanup.index("Test-NoReparseDescendant", owned)
    clear_readonly = cleanup.index("$currentItem.Attributes =", no_reparse)
    delete = cleanup.index("[System.IO.Directory]::Delete", clear_readonly)
    assert owned < no_reparse < clear_readonly < delete
    assert "[System.IO.FileAttributes]::ReadOnly" in cleanup
    assert re.search(r"for\s*\([^)]*attempt[^)]*-[il]e\s*[3-9]", cleanup, flags=re.IGNORECASE)
    assert "Start-Sleep -Milliseconds" in cleanup
    assert "throw" in cleanup[delete:]


def test_windows_worker_normal_setup_only_removes_exact_legacy_staging_leaves() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    legacy_cleanup = text.split("function Remove-OrphanedVGenCustomNodeStaging", 1)[1].split(
        "function New-PinnedCustomNodeRepository", 1
    )[0]

    check_only = legacy_cleanup.index("$CheckOnly")
    early_return = legacy_cleanup.index("return", check_only)
    enumeration = legacy_cleanup.index("Get-ChildItem -LiteralPath $CustomNodesRoot", early_return)
    removal = legacy_cleanup.index("Remove-VGenCustomNodeStaging", enumeration)
    assert check_only < early_return < enumeration < removal
    assert re.search(r"\[regex\]::Escape", legacy_cleanup, flags=re.IGNORECASE)
    assert re.search(r"\\\.vgen-staging-\[(?:a-f0-9|0-9a-f)\]\{32\}\$", legacy_cleanup)
    assert "-Directory" in legacy_cleanup
    assert "-Force" in legacy_cleanup
    assert "-Recurse" not in legacy_cleanup
    assert "Remove-OrphanedVGenCustomNodeStaging $Pin $CustomNodesRoot" in text


def test_windows_worker_check_only_never_copies_a_reusable_custom_node() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    installer = text.split("function Install-PinnedCustomNode", 1)[1].split(
        "function Resolve-FirstExistingPythonCandidate", 1
    )[0]
    missing = installer.split("if (-not (Test-Path -LiteralPath $destination))", 1)[1].split(
        'if (-not (Test-Path -LiteralPath (Join-Path $destination ".git")', 1
    )[0]

    check_only = missing.index("if ($CheckOnly)")
    return_without_copy = missing.index("return $false", check_only)
    copy = missing.index("New-PinnedCustomNodeRepository", return_without_copy)
    assert check_only < return_without_copy < copy
    assert "Find-ReviewedCustomNodeSeed" not in missing[:return_without_copy]
    assert "clone" not in missing[:return_without_copy]
    assert "fetch" not in missing[:return_without_copy]


def test_windows_worker_desktop_launch_reuses_worker_console_and_quotes_space_paths() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    launch = text.split("$comfyArguments = @(", 1)[1].split("$deadline =", 1)[0]
    for argument in (
        "--base-directory",
        "--extra-model-paths-config",
        "--user-directory",
        "--input-directory",
        "--output-directory",
        "--temp-directory",
        "--database-url",
        "--front-end-root",
    ):
        assert f'"{argument}"' in launch
    assert "$mainPath" in launch
    assert '"--temp-directory", $tempRoot' in launch
    assert '"--temp-directory", $resolvedComfyDataRoot' not in launch
    assert '$databasePath.Replace("\\", "/")' in text
    assert '$databaseUrl = "sqlite:///" +' in text
    assert "ConvertTo-NativeArgument" in launch
    assert '"--base-directory", $isolatedComfyDataRoot' in launch
    assert "-WorkingDirectory $isolatedComfyDataRoot" in launch
    assert "-NoNewWindow" in launch
    assert "-RedirectStandardOutput $comfyStdoutPath" in launch
    assert "-RedirectStandardError $comfyStderrPath" in launch
    assert "-PassThru" in launch
    assert "-WindowStyle" not in launch
    assert "function Test-AnyComfyProcess" in text
    assert "Get-CimInstance Win32_Process" in text
    assert "already running on another port" in text
    assert '"--models-directory"' not in launch
    assert '"--extra-model-paths-config", $modelPathsConfig' in launch
    assert "VGen cannot prove that process uses the selected model directory" in text
    assert "so VGen can start it with the selected model directory" in text


def test_windows_worker_stops_only_the_comfy_process_it_started() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "$script:ManagedComfyProcess = $null" in text
    assert "$script:ManagedComfyProcess = $comfyProcess" in text
    assert "function Stop-VGenManagedComfyUI" in text
    assert "$comfyProcess.HasExited" in text
    assert "Stop-Process -InputObject $process" in text
    assert "$null = $process.WaitForExit(10000)" in text
    assert "finally {\n        Stop-VGenManagedComfyUI\n    }" in text
    catch_block = text.rsplit("catch {", 1)[1]
    assert "Stop-VGenManagedComfyUI" in catch_block


def test_windows_worker_discovers_and_deduplicates_existing_absolute_model_roots() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    discovery = text.split("function Get-ComfyModelRootCandidates", 1)[1].split(
        "function Resolve-ComfyLayout", 1
    )[0]
    assert '"Comfy Desktop\\settings.json"' in discovery
    assert 'Add-JsonModelRootProperty $candidates $seen $settings "modelsDirs"' in discovery
    assert '"Comfy Desktop\\installations.json"' in discovery
    assert 'Add-JsonModelRootProperty $candidates $seen $record "modelDirsPrimary"' in discovery
    assert 'Add-JsonModelRootProperty $candidates $seen $record "modelDirs"' in discovery
    assert '"Comfy-Desktop\\ComfyUI-Shared\\models"' in discovery
    assert '"ComfyUI-Shared\\models"' in discovery
    assert 'Join-Path $legacyDataRoot "models"' in discovery
    assert "Add-ExistingModelRootCandidate $candidates $seen $VGenModelsRoot" in discovery
    candidate_helper = text.split("function Add-ExistingModelRootCandidate", 1)[1].split(
        "function Add-JsonModelRootProperty", 1
    )[0]
    assert "[System.IO.Path]::IsPathRooted($path)" in candidate_helper
    assert "Test-Path -LiteralPath $path -PathType Container" in candidate_helper
    assert "$Seen.Add($resolved)" in candidate_helper


def test_windows_worker_selects_one_model_root_and_fails_closed_on_split_or_shadowed_pins() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    selection = text.split("function Select-ComfyModelRoot", 1)[1].split(
        "function Assert-NoLegacyModelShadows", 1
    )[0]
    assert "ValidCount -eq $ModelPins.Count" in selection
    assert "The five pinned models are split across multiple model directories" in selection
    assert "will not download duplicate copies or combine roots" in selection
    assert "Test-ModelRootWritable" in selection
    assert "InvalidCount -eq 0" in selection
    assert "Descending = $true" in selection
    assert 'Write-Step "Using ComfyUI models:' in selection
    shadow = text.split("function Assert-NoLegacyModelShadows", 1)[1].split(
        "function Write-ModelLicenseNotice", 1
    )[0]
    assert '"diffusion_models" = "unet"' in shadow
    assert '"text_encoders" = "clip"' in shadow
    assert "legacy model alias shadows a pinned model name" in shadow

    main = text.split("$modelRootCandidates = @(", 1)[1]
    assert "$modelsRoot = Select-ComfyModelRoot $modelRootCandidates" in main
    assert "Assert-NoLegacyModelShadows $modelsRoot" in main
    for required in (
        '"--extra-model-paths-config", $modelPathsConfig',
        "Write-VGenModelPathsConfig $modelsRoot $modelPathsConfig $isolatedComfyDataRoot",
        "Test-ModelPins $modelsRoot",
        "doctor --comfy-url $ComfyUrl --comfy-output-dir $outputRoot --comfy-model-root $modelsRoot",
        '"--comfy-model-root", $modelsRoot',
    ):
        assert required in main


def test_windows_worker_generates_only_a_controlled_model_path_map() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    writer = text.split("function Write-VGenModelPathsConfig", 1)[1].split(
        "function Write-ComfyStartupLogTail", 1
    )[0]
    assert '"vgen_verified_models:"' in writer
    assert '"  base_path: $quotedRoot"' in writer
    for category in ("diffusion_models", "text_encoders", "loras", "vae"):
        assert f'"  {category}: {category}"' in writer
    assert "custom_nodes" not in writer
    assert "is_default" not in writer
    assert "ConvertTo-YamlSingleQuotedScalar" in writer
    assert "Test-ModelPathReparseSafe $configParent $OwnedRoot" in writer
    assert "$existingContent -ceq $content" in writer
    assert "Using the existing VGen-only model path configuration" in writer
    assert "[System.Management.Automation.Language.NullString]::Value" in writer
    assert "$ConfigPath, $null" not in writer
    assert "ReadAllText($ConfigPath) -cne $content" in writer
    assert "could not be written ($failureType, HRESULT $failureCode)" in writer
    assert 'Join-Path $isolatedComfyDataRoot "vgen-model-paths.yaml"' in text


def test_windows_worker_surfaces_sanitized_comfy_startup_log() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    diagnostics = text.split("function Write-ComfyStartupLogTail", 1)[1].split(
        "function Install-WingetPackage", 1
    )[0]
    assert "Get-Content -LiteralPath $Path -Tail 40" in diagnostics
    assert "token|secret|password|authorization|api[_-]?key" in diagnostics
    assert "?[redacted]" in diagnostics
    assert 'Write-ComfyStartupLogTail $comfyStdoutPath "startup output log"' in text
    assert "Write-ComfyStartupLogTail $comfyStderrPath" in text
    assert "$null = $process.WaitForExit(10000)" in text


def test_windows_worker_rejects_old_comfy_before_checking_h3_nodes() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    setup = text.split("try {\n    $bundleSettings", 1)[1]
    main = text.split("$comfyStdoutPath = $null", 1)[1]
    runtime_check = main.index('Write-Step "Checking ComfyUI runtime compatibility"')
    node_check = main.index('Write-Step "Checking required ComfyUI node classes"')
    doctor_check = main.index('Write-Step "Running fail-closed Worker doctor"')

    assert "function Get-ComfyRuntimeVersion" in text
    assert "function Get-ComfyCodeVersion" in text
    assert 'Join-Path $Root "comfyui_version.py"' in text
    assert 'Join-Path $Root "pyproject.toml"' in text
    assert "function Get-ComfyUpdateInstruction" in text
    assert '$stats.system.PSObject.Properties["comfyui_version"]' in text
    assert "$codeVersionInfo.Parsed -lt [Version]$MinimumRuntimeVersion" in setup
    assert setup.index("$codeVersionInfo = Get-ComfyCodeVersion") < setup.index(
        "$bootstrapPythonResults = @(Ensure-Python311)"
    )
    assert "$runtimeVersionInfo.Parsed -lt [Version]$MinimumRuntimeVersion" in main
    assert "Menu > Help > Check for Updates" in text
    assert runtime_check < node_check < doctor_check
    assert '"LoraLoaderBypassModelOnly" -in $missingNodes' in main
    assert "incomplete or incompatible with the H3 workflow" in main
    assert "Restart an existing ComfyUI process" not in text


def test_windows_worker_model_selection_checks_path_size_and_safety_without_rehashing() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    preflight = text.split("function Test-ModelPins", 1)[1].split(
        "function Get-ModelRootStatus", 1
    )[0]
    reparse_check = text.split("function Test-ModelPathReparseSafe", 1)[1].split(
        "function Test-ModelPins", 1
    )[0]
    assert "PathType Leaf" in preflight
    assert "Test-ModelPathReparseSafe" in preflight
    assert "FileAttributes]::ReparsePoint" in reparse_check
    assert "$item.Length -ne $pin.Size" in preflight
    assert "Get-FileHash" not in preflight
    assert "Hashing model" not in text
    assert "function Download-PinnedModel" not in text
    assert "Broker-authorized model download" in text
    assert "Worker doctor verified runtime, policy, resources, and all five model pins" in text


def test_windows_worker_rejects_broad_credential_acl() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    guide = USER_GUIDE.read_text(encoding="utf-8")
    assert "function Assert-CredentialAcl" in text
    assert "$acl.AreAccessRulesProtected" in text
    assert "$acl.GetAccessRules(" in text
    assert '"S-1-5-18"' in text
    assert '"S-1-5-32-544"' in text
    assert "grants access to an unapproved principal" in text
    assert text.index("Assert-CredentialAcl $credentialsPath") < text.index(
        "[System.IO.File]::ReadAllText($credentialsPath)"
    )
    assert "function Protect-CredentialAcl" in text
    assert (
        '& icacls.exe $Path /inheritance:r /grant:r "*$($currentSid):F" '
        '"*S-1-5-18:F" "*S-1-5-32-544:F"'
    ) in text
    assert text.index("Protect-CredentialAcl $credentialsPath") < text.index(
        "[System.IO.File]::ReadAllText($credentialsPath)"
    )
    assert "不需要用户先运行 `icacls`" in guide


def test_windows_worker_reinstall_verifies_identity_and_stages_safe_reenrollment() -> None:
    enrollment = ENROLLMENT_SCRIPT.read_text(encoding="utf-8")
    launcher = WORKER_LAUNCHER.read_text(encoding="utf-8")

    assert "[switch]$Reenroll" in enrollment
    assert "--check-existing" in enrollment
    assert "--reenroll-existing" in enrollment
    assert "$credentialCheckExit -eq 10" in enrollment
    assert "--replace-existing" in enrollment
    assert '".worker-reenrollment-identity.json"' in enrollment
    assert ".worker-reenrollment-$([Guid]" not in enrollment
    assert "current credential remains active until replacement succeeds" in enrollment
    assert "pending replacement identity were kept unchanged" in enrollment
    assert 'Join-Path $PSScriptRoot "start-worker.cmd"' in enrollment
    assert '" -Reenroll' in enrollment
    assert "Remove-Item -LiteralPath $credentialPath" not in enrollment
    assert "Move-Item -LiteralPath $credentialPath" not in enrollment
    assert enrollment.index("--check-existing") < enrollment.index("$setupArguments")
    assert 'if /I not "%~1"=="-Reenroll"' in launcher
    assert 'if not "%~2"==""' in launcher
    assert "%*" not in launcher
    assert '"%~dp0enroll-worker.ps1" %VGEN_WORKER_REENROLL_ARG%' in launcher


def test_windows_worker_enrollment_secures_acl_before_any_gateway_identity_request() -> None:
    enrollment = ENROLLMENT_SCRIPT.read_text(encoding="utf-8")
    acl = enrollment.split("function Assert-CredentialAcl", 1)[1].split(
        "function Assert-ClosedBundleDirectory", 1
    )[0]

    assert "$acl.AreAccessRulesProtected" in acl
    assert "$acl.GetAccessRules(" in acl
    assert '"S-1-5-18"' in acl
    assert '"S-1-5-32-544"' in acl
    assert "FileSystemRights]::FullControl" in acl
    assert "grants access to an unapproved principal" in acl
    assert '& icacls.exe $Path /setowner "*$currentSid"' in acl
    assert '& icacls.exe $Path /inheritance:r /grant:r "*$($currentSid):F"' in acl
    assert enrollment.index(
        '$credentialPath = Assert-RegularLocalFile $credentialPath "Existing Worker credential"'
    ) < enrollment.index("Protect-CredentialAcl $credentialPath")
    assert enrollment.index("Protect-CredentialAcl $credentialPath") < enrollment.index(
        "--check-existing"
    )


def test_windows_worker_check_only_never_changes_acl_or_installs_prerequisites() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    credential_branch = text.split("$credentialReady = $true", 1)[1].split("$workerId = $null", 1)[
        0
    ]
    assert "if ($CheckOnly)" in credential_branch
    check_branch, normal_branch = credential_branch.split("else {", 1)
    assert "Assert-CredentialAcl $credentialsPath" in check_branch
    assert "Protect-CredentialAcl $credentialsPath" not in check_branch
    assert "Protect-CredentialAcl $credentialsPath" in normal_branch
    assert text.index("if ($credentialReady)") < text.index(
        "[System.IO.File]::ReadAllText($credentialsPath)"
    )
    assert 'if ($CheckOnly) {\n        Add-Finding "Python 3.11 is not installed' in text
    assert 'if ($CheckOnly) {\n        Add-Finding "Git is not installed' in text


def test_windows_worker_normal_setup_uses_fixed_winget_packages_and_absolute_discovery() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'Install-WingetPackage "Python.Python.3.11" "Python 3.11"' in text
    assert 'Install-WingetPackage "Git.Git" "Git for Windows"' in text
    assert '"Programs\\Python\\Python311\\python.exe"' in text
    assert '"Programs\\Git\\cmd\\git.exe"' in text
    assert "& $BootstrapPython -m venv $RuntimeRoot" in text
    assert "& $script:GitExecutable" in text


def test_two_handbooks_are_the_only_documentation_sources_for_operations_and_release() -> None:
    user = USER_GUIDE.read_text(encoding="utf-8")
    developer = DEVELOPER_GUIDE.read_text(encoding="utf-8")

    assert "面向部署者和使用者的唯一操作手册" in user
    assert "面向开发者、贡献者和发布者的唯一权威手册" in developer
    assert "python tools/build_gateway_bundle.py" in developer
    assert "./examples/macos/build-bundle.sh" in developer
    assert "sha256sum -c SHA256SUMS" in user
    assert "sudo ./setup-gateway.sh install \\" in user
    assert "--artifact-store oss" in user
    assert "./setup-gateway.sh upgrade --domain <Gateway域名>" in user
    assert "健康检查失败时自动恢复旧版本" in user
    assert "sudo cat /var/lib/vgen/bootstrap-code" in user
    assert "sudo rm -f /var/lib/vgen/bootstrap-code" in user
    assert "start-worker.cmd" in user
    assert "%LOCALAPPDATA%\\VGen" in user
    assert "vgen broker model-install" in user
    assert "vgen broker worker-update" in user
    assert "--wait --output-dir" in user

    for duplicate in (
        ROOT / "docs" / "deploy-ecs-windows-quickstart.md",
        ROOT / "docs" / "development-and-deployment.md",
        ROOT / "examples" / "ecs" / "README.md",
        ROOT / "examples" / "macos" / "README.md",
        ROOT / "examples" / "windows-worker" / "README.md",
    ):
        assert not duplicate.exists()


def test_windows_worker_missing_models_start_maintenance_only_without_direct_download() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "invoke-webrequest" not in lowered
    assert "start-bitstransfer" not in lowered
    assert "Get-Command curl.exe" not in text
    assert "Download-PinnedModel" not in text
    assert "Confirm-ModelDownload" not in text
    assert (
        "Existing model paths that are unsafe or have a size mismatch were left untouched." in text
    )
    model_branch = text.split("$modelFailures = @(Test-ModelPins $modelsRoot)", 1)[1].split(
        "if ($script:Findings.Count", 1
    )[0]
    assert "maintenance-only mode" in model_branch
    assert "Add-Finding" not in model_branch.split("if ($missingModels.Count -gt 0)", 1)[1]
    assert "([int]$policy.models_verified + [int]$policy.models_failed) -ne 5" in text
    assert "git.exe reset" not in lowered
    assert "git.exe clean" not in lowered
    assert "remove-item" not in lowered
    assert "write-host $credential" not in lowered
    assert "write-output $credential" not in lowered
    assert 'status", "--porcelain"' in text
    assert 'remote", "get-url", "origin"' in text
    assert "checkout --detach" in text
    assert "elseif (-not $CheckOnly -and -not $comfyWasRunning" in text
    assert 'Directory = "minimax-h3-audio-T8"' in text
    assert 'Aliases = @("comfyui-minimax-h3-audio-T8")' in text
    assert "Multiple directories exist for the same custom node" in text


def test_windows_worker_foreground_supervisor_switches_and_rolls_back_updates() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'Join-Path $WorkRoot "runtime-active.json"' in text
    assert "$workerExitCode -eq 75" in text
    assert "Restarting Worker with the reviewed versioned runtime" in text
    assert '$env:VGEN_WORKER_UPDATE_ROLLBACK = "1"' in text
    assert "restarting the previous reviewed runtime" in text
    assert "runtime-releases" in text
    assert "-m vgen.worker.main @workerArguments" in text


def test_windows_worker_model_pins_match_reference_manifest() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    models = manifest["variants"][0]["models"]
    script_models = []
    for block in _blocks(text, "ModelPins", "CustomNodePins"):
        script_models.append(
            {
                "folder": _quoted_value(block, "Folder"),
                "filename": _quoted_value(block, "FileName"),
                "size": _integer_value(block, "Size"),
                "sha256": _quoted_value(block, "Sha256"),
                "source": _quoted_value(block, "Source"),
                "license": _quoted_value(block, "License"),
                "license_url": _quoted_value(block, "LicenseUrl"),
            }
        )
    expected = [
        {
            "folder": item["folder"],
            "filename": item["filename"],
            "size": item["size"],
            "sha256": item["sha256"].removeprefix("sha256:"),
            "source": item["source"],
            "license": (
                "MiniMax H3 Community License"
                if item["license"] == "LicenseRef-MiniMax-H3-Community"
                else item["license"]
            ),
            "license_url": (
                "https://huggingface.co/MiniMaxAI/MiniMax-H3/blob/main/LICENSE"
                if item["license"] == "LicenseRef-MiniMax-H3-Community"
                else "https://www.apache.org/licenses/LICENSE-2.0"
            ),
        }
        for item in models
    ]
    assert script_models == expected
    assert all(item["manual_download"] is True for item in models)


def test_windows_worker_custom_node_pins_match_reference_manifest() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    expected = [
        (item["source"], item["revision"]) for item in manifest["variants"][0]["custom_nodes"]
    ]
    actual = [
        (_quoted_value(block, "Source"), _quoted_value(block, "Revision"))
        for block in _blocks(text, "CustomNodePins", "RequiredNodeClasses")
    ]
    assert actual == expected


def test_windows_worker_required_nodes_match_machine_policy() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    body = text.split("$RequiredNodeClasses = @(", 1)[1].split(")", 1)[0]
    actual = set(re.findall(r'"([A-Za-z0-9_]+)"', body))
    expected = set(policy["allowed_node_classes"]) | set(policy["allowed_custom_node_classes"])
    assert actual == expected


def test_windows_worker_resource_contract_matches_manifest() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))["variants"][0]
    assert f'$MinimumExecutorVersion = "{manifest["executor_min_version"]}"' in text
    assert f'$MinimumRuntimeVersion = "{manifest["runtime_min_version"]}"' in text
    assert f"$MinimumVramBytes = [Int64]{manifest['min_vram_bytes']}" in text
    assert f"$MinimumRamBytes = [Int64]{manifest['min_ram_bytes']}" in text


def test_windows_worker_bundled_file_hashes_are_current() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "$WheelSha256 = $null" not in text
    assert "BundleConfig file hashes must be lowercase SHA-256 values." in text
    policy_digest = hashlib.sha256(POLICY.read_bytes()).hexdigest()
    assert f'$PolicySha256 = "{policy_digest}"' in text


def test_worker_assets_are_force_included_at_stable_importlib_resource_paths() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert pyproject.count("[tool.hatch.build.targets.wheel.force-include]") == 1
    assert (
        '"examples/windows-worker/enroll-worker.ps1" = '
        '"vgen/assets/worker/enroll-worker.ps1"'
    ) in pyproject
    assert (
        '"examples/windows-worker/setup-worker.ps1" = "vgen/assets/worker/setup-worker.ps1"'
    ) in pyproject
    assert (
        '"examples/windows-worker/start-worker.cmd" = "vgen/assets/worker/start-worker.cmd"'
    ) in pyproject
    assert (
        '"examples/comfyui-minimax-h3-policy.yaml" = '
        '"vgen/assets/worker/comfyui-minimax-h3-policy.yaml"'
    ) in pyproject
