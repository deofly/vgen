#requires -Version 5.1

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSEdition -ne "Desktop" -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "This compatibility check must run in Windows PowerShell 5.1."
}

$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "vgen-no-new-window-" + [Guid]::NewGuid().ToString("N")
)
[System.IO.Directory]::CreateDirectory($testRoot) | Out-Null

try {
    $fakeNative = Join-Path $testRoot "vgen-console-fixture.exe"
    $fakeSource = @'
using System;

public static class VGenConsoleFixture
{
    public static int Main()
    {
        Console.Out.WriteLine("vgen-console-stdout");
        Console.Error.WriteLine("vgen-console-stderr");
        return 23;
    }
}
'@
    Add-Type `
        -TypeDefinition $fakeSource `
        -Language CSharp `
        -OutputAssembly $fakeNative `
        -OutputType ConsoleApplication

    $stdoutPath = Join-Path $testRoot "stdout.log"
    $stderrPath = Join-Path $testRoot "stderr.log"
    $process = Start-Process `
        -FilePath $fakeNative `
        -WorkingDirectory $testRoot `
        -NoNewWindow `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -PassThru `
        -Wait

    if ($process.ExitCode -ne 23) {
        throw "The console fixture exit code was not preserved."
    }
    if ([System.IO.File]::ReadAllText($stdoutPath).Trim() -cne "vgen-console-stdout") {
        throw "Standard output was not redirected."
    }
    if ([System.IO.File]::ReadAllText($stderrPath).Trim() -cne "vgen-console-stderr") {
        throw "Standard error was not redirected."
    }
}
finally {
    if ([System.IO.Directory]::Exists($testRoot)) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}
