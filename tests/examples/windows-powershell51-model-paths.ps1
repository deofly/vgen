#requires -Version 5.1

$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSEdition -ne "Desktop" -or $PSVersionTable.PSVersion.Major -ne 5) {
    throw "This compatibility check must run in Windows PowerShell 5.1."
}

$root = Join-Path ([System.IO.Path]::GetTempPath()) (
    "vgen-model-path-replace-" + [Guid]::NewGuid().ToString("N")
)
[System.IO.Directory]::CreateDirectory($root) | Out-Null

try {
    $target = Join-Path $root "vgen-model-paths.yaml"
    $encoding = New-Object System.Text.UTF8Encoding($false)
    foreach ($value in @("first", "second", "third")) {
        $temporary = Join-Path $root (
            ".vgen-model-paths-" + [Guid]::NewGuid().ToString("N") + ".tmp"
        )
        [System.IO.File]::WriteAllText($temporary, $value, $encoding)
        if ([System.IO.File]::Exists($target)) {
            [System.IO.File]::Replace(
                $temporary,
                $target,
                [System.Management.Automation.Language.NullString]::Value,
                $true
            )
        }
        else {
            [System.IO.File]::Move($temporary, $target)
        }
        if ([System.IO.File]::ReadAllText($target) -cne $value) {
            throw "replacement verification failed"
        }
        if ([System.IO.File]::Exists($temporary)) {
            throw "temporary file was not consumed"
        }
    }
}
finally {
    if ([System.IO.Directory]::Exists($root)) {
        [System.IO.Directory]::Delete($root, $true)
    }
}

exit 0
