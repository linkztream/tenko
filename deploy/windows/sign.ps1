<#
.SYNOPSIS
Signs a file with Authenticode when a signing certificate is configured, and does nothing,
with a notice, when it is not.

.DESCRIPTION
The release workflow runs it for the Windows binary and for the MSI. It reads the
certificate from the environment, never from the command line:

  SIGNING_CERT_PFX        the PFX file, base64 (secret WINDOWS_SIGNING_CERT_PFX)
  SIGNING_PASSWORD        its password (secret WINDOWS_SIGNING_PASSWORD)
  SIGNING_TIMESTAMP_URL   an RFC 3161 time-stamp server (default http://timestamp.digicert.com)

Without the first two it prints a GitHub Actions notice and exits with status 0, so a
release without a certificate ships unsigned files (deploy/windows/README.md, "Signing").
With them it signs with SHA-256, time-stamps the signature and verifies it; any failure
exits with status 1. signtool.exe comes from the newest Windows 10/11 SDK on the machine.

  pwsh -File deploy\windows\sign.ps1 -File dist\tenko-0.2.0-windows-x86_64.msi
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $File
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { throw "$File does not exist" }
if (-not $env:SIGNING_CERT_PFX -or -not $env:SIGNING_PASSWORD) {
    Write-Output "::notice title=Unsigned::$File is not signed: the secrets WINDOWS_SIGNING_CERT_PFX and WINDOWS_SIGNING_PASSWORD are not set (deploy/windows/README.md, Signing)."
    exit 0
}
$timestamp = if ($env:SIGNING_TIMESTAMP_URL) { $env:SIGNING_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }

$signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.*\x64\signtool.exe" -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Directory.Parent.Name } | Select-Object -Last 1
if (-not $signtool) { throw 'signtool.exe was not found in a Windows SDK' }

$pfx = Join-Path ([System.IO.Path]::GetTempPath()) ("signing-" + [guid]::NewGuid().ToString('N') + '.pfx')
[System.IO.File]::WriteAllBytes($pfx, [Convert]::FromBase64String($env:SIGNING_CERT_PFX))
try {
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr $timestamp /f $pfx /p $env:SIGNING_PASSWORD /d 'Tenko DDI' $File
    if ($LASTEXITCODE -ne 0) { throw "signtool sign exited with status $LASTEXITCODE" }
    & $signtool.FullName verify /pa /v $File
    if ($LASTEXITCODE -ne 0) { throw "signtool verify exited with status $LASTEXITCODE" }
}
finally {
    Remove-Item -LiteralPath $pfx -Force -ErrorAction SilentlyContinue
}
Write-Output "signed $File"
