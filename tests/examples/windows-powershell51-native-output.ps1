#requires -Version 5.1

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSEdition -ne "Desktop" -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "This compatibility check must run in Windows PowerShell 5.1."
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$installer = Join-Path $repositoryRoot "examples\windows-worker\setup-worker.ps1"
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "vgen-native-output-" + [Guid]::NewGuid().ToString("N")
)
$originalLocalAppData = $env:LOCALAPPDATA
$originalPath = $env:PATH
[System.IO.Directory]::CreateDirectory($testRoot) | Out-Null
$env:LOCALAPPDATA = $testRoot

try {
    . $installer

    $fakeNative = Join-Path $testRoot "fake-python.exe"
    $fakeSource = @'
using System;
using System.IO;
using System.Reflection;

public static class VGenFakeNative
{
    public static int Main(string[] args)
    {
        string executable = Assembly.GetExecutingAssembly().Location;
        string name = Path.GetFileName(executable).ToLowerInvariant();
        if (name == "winget.exe")
        {
            Console.WriteLine("winget-native-noise-must-not-be-returned");
            string joined = String.Join(" ", args);
            string localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA");
            string target = null;
            if (joined.IndexOf("Python.Python.3.11", StringComparison.Ordinal) >= 0)
            {
                target = Path.Combine(localAppData, "Programs", "Python", "Python311", "python.exe");
            }
            else if (joined.IndexOf("Git.Git", StringComparison.Ordinal) >= 0)
            {
                target = Path.Combine(localAppData, "Programs", "Git", "cmd", "git.exe");
            }
            if (target != null)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                File.WriteAllText(target, "installed by fake winget");
            }
            return 0;
        }

        Console.WriteLine("python-native-noise-must-not-be-returned");
        int venvIndex = -1;
        for (int index = 0; index + 1 < args.Length; index++)
        {
            if (args[index] == "-m" && args[index + 1] == "venv")
            {
                venvIndex = index + 1;
                break;
            }
        }
        if (venvIndex >= 0 && args.Length > venvIndex + 1)
        {
            string scripts = Path.Combine(args[args.Length - 1], "Scripts");
            Directory.CreateDirectory(scripts);
            File.Copy(executable, Path.Combine(scripts, "python.exe"), true);
            File.Copy(executable, Path.Combine(scripts, "pythonw.exe"), true);
            foreach (string activationName in new string[] {
                    "activate", "activate.bat", "Activate.ps1", "deactivate.bat"
                })
            {
                File.WriteAllText(Path.Combine(scripts, activationName), "test activation script");
            }
            return 0;
        }
        for (int index = 0; index < args.Length; index++)
        {
            if (args[index] == "-c")
            {
                Console.WriteLine("0.2.2");
                break;
            }
        }
        return 0;
    }
}
'@
    Add-Type `
        -TypeDefinition $fakeSource `
        -Language CSharp `
        -OutputAssembly $fakeNative `
        -OutputType ConsoleApplication

    $multipleOutputRejected = $false
    try {
        $null = Resolve-SingleExecutableResult `
            @("native noise", $fakeNative) "test executable" $false
    }
    catch {
        $multipleOutputRejected = $true
    }
    if (-not $multipleOutputRejected) {
        throw "The executable result guard accepted native stdout together with a path."
    }

    # Keep this test focused on PowerShell's native-output boundary. The locked
    # dependency installer and verifier have dedicated end-to-end coverage; the
    # two stubs let the real Ensure-WorkerRuntime function reach its native venv
    # and version checks without constructing an unrelated wheelhouse here.
    function Test-LockedWorkerRuntime {
        param(
            [string]$Python,
            [string]$Requirements,
            [string]$TrustedPython
        )
        return $false
    }
    function Install-LockedWorkerPythonPackages {
        param(
            [string]$Python,
            [string]$BundleRoot,
            [string]$BootstrapPip,
            [string]$Requirements,
            [string]$TrustedPython
        )
    }

    $script:CheckOnly = $false
    $runtimeRoot = Join-Path $testRoot "worker-runtime"
    $runtimeResult = @(
        Ensure-WorkerRuntime `
            -RuntimeRoot $runtimeRoot `
            -BootstrapPython $fakeNative `
            -ExpectedVersion "0.2.2" `
            -BundleRoot $testRoot `
            -BootstrapPip (Join-Path $testRoot "bootstrap-pip") `
            -Requirements (Join-Path $testRoot "requirements.lock")
    )
    $expectedRuntimePython = Join-Path $runtimeRoot "Scripts\python.exe"
    if ($runtimeResult.Count -ne 1 -or
        [string]$runtimeResult[0] -cne $expectedRuntimePython) {
        throw "Ensure-WorkerRuntime returned native stdout together with the Python path."
    }

    $fakeBin = Join-Path $testRoot "bin"
    [System.IO.Directory]::CreateDirectory($fakeBin) | Out-Null
    [System.IO.File]::Copy($fakeNative, (Join-Path $fakeBin "winget.exe"), $true)
    $env:PATH = "$fakeBin;$originalPath"

    function Resolve-Python311 {
        $candidate = Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
        return $null
    }
    function Resolve-GitExecutable {
        $candidate = Join-Path $env:LOCALAPPDATA "Programs\Git\cmd\git.exe"
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
        return $null
    }

    $pythonResult = @(Ensure-Python311)
    $expectedPython = Join-Path $env:LOCALAPPDATA "Programs\Python\Python311\python.exe"
    if ($pythonResult.Count -ne 1 -or [string]$pythonResult[0] -cne $expectedPython) {
        throw "Ensure-Python311 returned winget stdout together with the Python path."
    }

    $gitResult = @(Ensure-GitExecutable)
    $expectedGit = Join-Path $env:LOCALAPPDATA "Programs\Git\cmd\git.exe"
    if ($gitResult.Count -ne 1 -or [string]$gitResult[0] -cne $expectedGit) {
        throw "Ensure-GitExecutable returned winget stdout together with the Git path."
    }
}
finally {
    $script:CheckOnly = $false
    $env:PATH = $originalPath
    $env:LOCALAPPDATA = $originalLocalAppData
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}

exit 0
