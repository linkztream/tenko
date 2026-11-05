<#
.SYNOPSIS
Signs a file with Authenticode when a signing certificate is configured, and does nothing,
with a notice, when it is not.

.DESCRIPTION
The release workflow runs it in the jobs `sign-binary` and `sign-msi`, the only jobs that
hold the signing secrets; they download the built file, run this script and upload the
result, and nothing else runs in them (no build, no package restore, no third-party action).
The script reads the certificate from the environment, never from the command line:

  SIGNING_CERT_PFX        the PFX file, base64 (secret WINDOWS_SIGNING_CERT_PFX)
  SIGNING_PASSWORD        its password (secret WINDOWS_SIGNING_PASSWORD)
  SIGNING_TIMESTAMP_URL   an RFC 3161 time-stamp server (default http://timestamp.digicert.com)

Without the first two it prints a GitHub Actions notice and exits with status 0, so a
release without a certificate ships unsigned files (deploy/windows/README.md, "Signing").
With them it loads the certificate into the current user's certificate store straight from
memory (the PFX is never written to disk, the password is a SecureString, the private key is
not exportable), signs with SHA-256 by the certificate's thumbprint, time-stamps the
signature, verifies it, and removes the certificate and its key from the store. signtool
takes a PFX password only on its command line, which every process of the machine can read;
signing from the store is how the password never reaches a command line. signtool.exe comes
from the newest Windows 10/11 SDK on the machine.

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

# The certificate goes into the current user's personal store (CurrentUser\My), where
# signtool finds it by thumbprint. The key is persisted for signtool and deleted below.
$password = ConvertTo-SecureString -String $env:SIGNING_PASSWORD -AsPlainText -Force
$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags] 'UserKeySet, PersistKeySet'
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    [byte[]] [Convert]::FromBase64String($env:SIGNING_CERT_PFX), $password, $flags)
if (-not $cert.HasPrivateKey) { throw 'the signing certificate has no private key' }
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$store.Open('ReadWrite')
try {
    $store.Add($cert)
    & $signtool.FullName sign /fd SHA256 /td SHA256 /tr $timestamp /s My /sha1 $cert.Thumbprint /d 'Tenko DDI' $File
    if ($LASTEXITCODE -ne 0) { throw "signtool sign exited with status $LASTEXITCODE" }
    & $signtool.FullName verify /pa /v $File
    if ($LASTEXITCODE -ne 0) { throw "signtool verify exited with status $LASTEXITCODE" }
}
finally {
    # The certificate provider deletes the key container with the certificate.
    Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey -Force -ErrorAction SilentlyContinue
    if ($store.Certificates.Contains($cert)) { $store.Remove($cert) }
    $store.Close()
    $cert.Dispose()
}
Write-Output "signed $File"
