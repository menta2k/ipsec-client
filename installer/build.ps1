<#
.SYNOPSIS
  Builds the release binaries and packages them into an MSI.

.EXAMPLE
  .\installer\build.ps1 -Wintun C:\Downloads\wintun\bin\amd64\wintun.dll

.NOTES
  Needs the .NET SDK (WiX 5 is restored as a repo-local dotnet tool) and the
  amd64 wintun.dll from https://www.wintun.net. Without -Wintun, the script
  looks in target\release, then target\debug.
  Output: target\installer\IpsecClient-<version>-x64.msi
#>
param(
    [string]$Wintun,
    [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $manifest = Get-Content Cargo.toml -Raw
    if ($manifest -notmatch '(?ms)^\[workspace\.package\].*?^version\s*=\s*"([^"]+)"') {
        throw 'workspace version not found in Cargo.toml'
    }
    $version = $Matches[1]

    if (-not $NoBuild) {
        cargo build --release -p ipsec-service -p ipsec-gui
        if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
    }

    if (-not $Wintun) {
        $Wintun = @('target\release\wintun.dll', 'target\debug\wintun.dll') |
            Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    if (-not $Wintun -or -not (Test-Path $Wintun)) {
        throw 'wintun.dll not found: download it from https://www.wintun.net and pass -Wintun <path to bin\amd64\wintun.dll>'
    }

    dotnet tool restore | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'dotnet tool restore failed' }
    dotnet tool run wix extension add -g WixToolset.Util.wixext/5.0.2 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'could not fetch WixToolset.Util.wixext' }

    $out = "target\installer\IpsecClient-$version-x64.msi"
    dotnet tool run wix build installer\IpsecClient.wxs -arch x64 `
        -ext WixToolset.Util.wixext `
        -d "Version=$version" -d "BinDir=target\release" -d "Wintun=$((Resolve-Path $Wintun).Path)" `
        -o $out
    if ($LASTEXITCODE -ne 0) { throw 'wix build failed' }
    Write-Host "Built $out"
}
finally {
    Pop-Location
}
