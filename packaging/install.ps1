[CmdletBinding()]
# Invocation supports: install.ps1 [-BinDir DIR] [-Yes] [-NoPath]
param(
    [string]$BinDir = (Join-Path $env:LOCALAPPDATA 'OpenBOLA\bin'),
    [switch]$Yes,
    [switch]$NoPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Install([string]$Message) {
    [Console]::Error.WriteLine("OpenBOLA install failed: $Message")
    exit 1
}

try {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        Stop-Install 'Windows x64 is required'
    }
    $scriptDir = (Resolve-Path -LiteralPath $PSScriptRoot).Path
    $source = Join-Path $scriptDir 'openbola.exe'
    $manifest = Join-Path $scriptDir 'openbola.sha256'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
        (Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Stop-Install 'executable is missing or invalid'
    }
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf) -or
        (Get-Item -LiteralPath $manifest).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Stop-Install 'checksum manifest is missing or invalid'
    }
    $line = @(Get-Content -LiteralPath $manifest | Where-Object { $_ -match '^([0-9a-fA-F]{64})  openbola\.exe$' })
    if ($line.Count -ne 1) { Stop-Install 'checksum manifest is invalid' }
    $expected = ([regex]::Match($line[0], '^([0-9a-fA-F]{64})')).Groups[1].Value.ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { Stop-Install 'checksum mismatch' }

    if (Test-Path -LiteralPath $BinDir) {
        $destinationInfo = Get-Item -LiteralPath $BinDir -Force
        if ($destinationInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Install 'destination is a reparse point' }
        if (-not $destinationInfo.PSIsContainer) { Stop-Install 'destination is not a directory' }
    } else {
        New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    }
    $destination = Join-Path $BinDir 'openbola.exe'
    if (Test-Path -LiteralPath $destination) {
        $existing = Get-Item -LiteralPath $destination -Force
        if ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint) { Stop-Install 'destination executable is a reparse point' }
        if (-not $Yes) {
            $answer = Read-Host "Replace $destination? [y/N]"
            if ($answer -notmatch '^(?i:y|yes)$') { Stop-Install 'replacement declined' }
        }
    }
    $temporary = Join-Path $BinDir ('.openbola-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    try {
        Copy-Item -LiteralPath $source -Destination $temporary -Force
        Move-Item -LiteralPath $temporary -Destination $destination -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
    [Console]::WriteLine("Installed $destination")

    if (-not $NoPath) {
        $answer = Read-Host "Add $BinDir to the user PATH? [y/N]"
        if ($answer -match '^(?i:y|yes)$') {
            $parts = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ })
            if ($parts -notcontains $BinDir) {
                [Environment]::SetEnvironmentVariable('Path', (($parts + $BinDir) -join ';'), 'User')
            }
        }
    }
} catch {
    Stop-Install 'filesystem operation failed'
}
