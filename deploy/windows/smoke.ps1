<#
.SYNOPSIS
  Windows service smoke test of Tenko DDI (OPS-10, exit criterion E10).

.DESCRIPTION
  Installs the given tenko.exe as a Windows service under a separate name, starts it,
  checks the Event Log and the file log, installs the same binary as version 0.0.2
  through the update API (the service exits with status 12 and the Service Control
  Manager starts it again), stops it and removes it. Everything it creates is removed
  at the end unless -Keep is given.

  It needs PowerShell 7 in an elevated prompt (Run as administrator) and a DEBUG build:
  only debug builds honour TENKO_TEST_VERSION_FROM_LAYOUT, which lets one binary install
  as two versions. Build with `cargo build -p tenko`, then run

    pwsh -File deploy\windows\smoke.ps1 -Binary .\target\debug\tenko.exe

  It talks to 127.0.0.1 only. The service name and the directory are separate from an
  installed `tenko` service, which the script never touches.

.PARAMETER Binary
  Path of the tenko.exe to test (a debug build).

.PARAMETER Name
  Service name and Event Log source of the smoke service. Default: tenko-smoke.

.PARAMETER Root
  Directory for the configuration, the data directory and the release files. It is created
  and removed by the script. Default: %ProgramData%\TenkoSmoke.

.PARAMETER Keep
  Do not stop, uninstall or delete anything at the end, so that a failure can be examined.
#>
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$Name = 'tenko-smoke',
    [string]$Root = "$env:ProgramData\TenkoSmoke",
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

# Test data: documentation values and a throwaway administrator of a throwaway installation.
$AdminUser = 'admin'
$AdminPassword = '739153'
$NewVersion = '0.0.2'
$MarkerName = '.tenko-smoke'

# ---------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------

function Write-Step([string]$Text) {
    Write-Host "==> $Text"
}

function Stop-Smoke([string]$Message) {
    [Console]::Error.WriteLine("smoke: $Message")
    exit 1
}

function Get-Prop($Object, [string]$PropertyName) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$PropertyName]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-That($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

# Calls $Test every second until it returns something true; returns that value.
function Wait-Until([scriptblock]$Test, [int]$TimeoutSec, [string]$What) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ($true) {
        $result = & $Test
        if ($result) { return $result }
        if ([DateTime]::UtcNow -gt $deadline) {
            throw "timed out after $TimeoutSec s waiting for: $What"
        }
        Start-Sleep -Seconds 1
    }
}

# Runs the binary under test; never throws on a non-zero status.
function Invoke-Tenko([string[]]$Arguments) {
    $output = & $script:Binary @Arguments 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Output = $output.TrimEnd() }
}

# Runs the binary and requires status 0; echoes its output.
function Invoke-TenkoOk([string[]]$Arguments) {
    $result = Invoke-Tenko $Arguments
    if ($result.Output) { Write-Host $result.Output }
    Assert-That ($result.Code -eq 0) "tenko $($Arguments -join ' ') exited with status $($result.Code)"
}

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
}

function Get-ServiceRecord {
    Get-CimInstance -ClassName Win32_Service -Filter "Name='$($script:Name)'" -ErrorAction SilentlyContinue
}

function Get-ServiceState {
    $service = Get-Service -Name $script:Name -ErrorAction SilentlyContinue
    if ($null -eq $service) { return $null }
    return [string]$service.Status
}

# The events of the smoke source in the Application log, newest first.
function Get-SmokeEvents([Nullable[datetime]]$Since = $null) {
    $filter = @{ LogName = 'Application'; ProviderName = $script:Name }
    if ($null -ne $Since) { $filter.StartTime = $Since }
    return @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue)
}

# True when the message, or any insertion string, contains $Text. A source without a message
# file cannot render its message text, so the first property is the fallback.
function Test-EventText($Entry, [string]$Text) {
    $message = ''
    try { $message = [string]$Entry.Message } catch { $message = '' }
    if ($message.Contains($Text)) { return $true }
    foreach ($property in $Entry.Properties) {
        if (([string]$property.Value).Contains($Text)) { return $true }
    }
    return $false
}

function Find-SmokeEvent([string]$Text, [Nullable[datetime]]$Since = $null) {
    return @(Get-SmokeEvents $Since | Where-Object { Test-EventText $_ $Text })
}

function Show-Diagnostics {
    Write-Host ''
    Write-Host "---- service state ($Name) ----"
    try { sc.exe query $Name | Out-Host } catch { Write-Host "cannot query: $($_.Exception.Message)" }
    $logPath = Join-Path $DataDir 'logs\tenko.log'
    Write-Host "---- last 200 lines of $logPath ----"
    if (Test-Path -LiteralPath $logPath) {
        try { Get-Content -LiteralPath $logPath -Tail 200 | Out-Host } catch { Write-Host "cannot read: $($_.Exception.Message)" }
    } else {
        Write-Host '(the file does not exist)'
    }
    Write-Host "---- last 50 Event Log entries of source $Name ----"
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $Name } -MaxEvents 50 -ErrorAction SilentlyContinue)
        if ($events.Count -eq 0) { Write-Host '(no entries)' }
        foreach ($entry in $events) {
            $text = ''
            try { $text = [string]$entry.Message } catch { $text = '' }
            if (-not $text -and $entry.Properties.Count -gt 0) { $text = [string]$entry.Properties[0].Value }
            Write-Host ("{0:u} {1,-11} {2}" -f $entry.TimeCreated, $entry.LevelDisplayName, ($text -replace '\s+', ' '))
        }
    } catch {
        Write-Host "cannot read the Event Log: $($_.Exception.Message)"
    }
    Write-Host '----'
}

# ---------------------------------------------------------------------------------------
# HTTPS client that trusts the internal CA of the smoke installation and nothing else
# ---------------------------------------------------------------------------------------

Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class TenkoSmokeTrust
{
    // A client with a cookie jar whose only trust anchor is the CA root in `caPem`. The host
    // name is still checked, and a certificate that does not chain to that root is refused.
    public static HttpClient Create(string caPem)
    {
        X509Certificate2 root = X509Certificate2.CreateFromPem(caPem);
        HttpClientHandler handler = new HttpClientHandler();
        handler.UseProxy = false;
        handler.AllowAutoRedirect = false;
        handler.UseCookies = true;
        handler.CookieContainer = new CookieContainer();
        handler.ServerCertificateCustomValidationCallback =
            (request, certificate, chain, errors) =>
            {
                if (certificate == null) { return false; }
                if ((errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) { return false; }
                using (X509Chain own = new X509Chain())
                {
                    own.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                    own.ChainPolicy.CustomTrustStore.Add(root);
                    own.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    return own.Build(certificate);
                }
            };
        HttpClient client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(60);
        return client;
    }
}
'@

# One API call: Method, path below /api/v1, optional JSON body. Mutations carry the origin of
# the server in `Origin`, as a browser does (the CSRF guard needs it). With -Keyed the call
# carries a fresh Idempotency-Key; setup and login send none.
function Invoke-Api([string]$Method, [string]$Path, $Body = $null, [switch]$Keyed) {
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), "$script:BaseUrl/api/v1$Path")
    if ($Method -ne 'GET') {
        [void]$request.Headers.TryAddWithoutValidation('Origin', $script:BaseUrl)
    }
    if ($Keyed) {
        [void]$request.Headers.TryAddWithoutValidation('Idempotency-Key', [guid]::NewGuid().ToString())
    }
    if ($null -ne $Body) {
        $json = ConvertTo-Json -InputObject $Body -Depth 8 -Compress
        $request.Content = [System.Net.Http.StringContent]::new($json, [System.Text.Encoding]::UTF8, 'application/json')
    }
    $response = $script:Http.SendAsync($request).GetAwaiter().GetResult()
    $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    $parsed = $null
    if ($text) {
        try { $parsed = $text | ConvertFrom-Json -Depth 20 } catch { $parsed = $null }
    }
    return [pscustomobject]@{ Status = [int]$response.StatusCode; Text = $text; Json = $parsed }
}

function Assert-Api($Reply, [int]$Expected, [string]$What) {
    Assert-That ($Reply.Status -eq $Expected) "$What answered HTTP $($Reply.Status), expected ${Expected}: $($Reply.Text)"
}

# ---------------------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------------------

if (-not $IsWindows) { Stop-Smoke 'this script tests the Windows service and runs on Windows only.' }

$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Smoke 'this script needs an elevated prompt. Start PowerShell with "Run as administrator" and run it again.'
}

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) { Stop-Smoke "binary not found: $Binary" }
$Binary = (Resolve-Path -LiteralPath $Binary).ProviderPath
if ($Binary -match '\\release\\') {
    Write-Warning 'the path looks like a release build. Only debug builds honour TENKO_TEST_VERSION_FROM_LAYOUT; step 7 fails with a release build. Build with `cargo build -p tenko`.'
}
if ($Name -ieq 'tenko') { Stop-Smoke "the name `tenko` is the name of the real service. Choose another -Name." }
if ($Name -notmatch '^[A-Za-z0-9._-]+$') { Stop-Smoke "the service name may contain letters, digits, '.', '_' and '-' only." }

$Root = [System.IO.Path]::GetFullPath($Root)
$DataDir = Join-Path $Root 'data'
$ConfigPath = Join-Path $Root 'tenko.toml'
$ReleaseDir = Join-Path $Root 'release'
$Marker = Join-Path $Root $MarkerName
$LogPath = Join-Path $DataDir 'logs\tenko.log'
$CaFile = Join-Path $DataDir 'tls\ca-root.pem'
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"

# Removes the smoke service, its Event Log source and the root directory. Used for a leftover
# of a previous run and at the end of this run.
function Remove-SmokeInstallation {
    if ($null -ne (Get-ServiceRecord)) {
        [void](Invoke-Tenko @('service', 'stop', '--name', $script:Name))
        $result = Invoke-Tenko @('service', 'uninstall', '--name', $script:Name)
        if ($result.Code -ne 0) {
            Write-Host "service uninstall failed ($($result.Output)); using sc.exe delete"
            sc.exe delete $script:Name | Out-Host
        }
    }
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($script:Name)) {
            [System.Diagnostics.EventLog]::DeleteEventSource($script:Name)
        }
    } catch {
        Write-Host "cannot remove the Event Log source: $($_.Exception.Message)"
    }
    if (Test-Path -LiteralPath $script:Root) {
        # A junction is removed on its own; a recursive delete must not follow it.
        $updates = Join-Path $script:DataDir 'updates'
        if (Test-Path -LiteralPath $updates) {
            foreach ($item in Get-ChildItem -LiteralPath $updates -Force -ErrorAction SilentlyContinue) {
                if ($item.LinkType) { try { [System.IO.Directory]::Delete($item.FullName, $false) } catch { } }
            }
        }
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            try { Remove-Item -LiteralPath $script:Root -Recurse -Force -ErrorAction Stop; break } catch {
                if ($attempt -eq 5) { Write-Host "cannot remove $($script:Root): $($_.Exception.Message)" }
                Start-Sleep -Seconds 2
            }
        }
    }
}

# The root directory may be removed by this script, so it must be new, empty or the root of
# a previous smoke run.
if ((Test-Path -LiteralPath $Root) -and -not (Test-Path -LiteralPath $Marker)) {
    if (@(Get-ChildItem -LiteralPath $Root -Force).Count -gt 0) {
        Stop-Smoke "$Root exists and was not created by this script (no $MarkerName file). Choose another -Root or remove it."
    }
}

$existing = Get-ServiceRecord
if ($null -ne $existing) {
    $pathName = [string]$existing.PathName
    $ours = (Test-Path -LiteralPath $Marker) -and ($pathName.IndexOf($DataDir, [StringComparison]::OrdinalIgnoreCase) -ge 0)
    if (-not $ours) {
        Stop-Smoke ("a service named `"$Name`" exists and was not created by a smoke run (image path: $pathName). " +
            "Choose another -Name, or remove it yourself with: tenko service uninstall --name $Name")
    }
    Write-Host "A service `"$Name`" from a previous smoke run exists; removing it."
    Remove-SmokeInstallation
} elseif ([System.Diagnostics.EventLog]::SourceExists($Name) -or (Test-Path -LiteralPath $Marker)) {
    Write-Host 'Leftovers of a previous smoke run found; removing them.'
    Remove-SmokeInstallation
}

# ---------------------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------------------

$failed = $false
$releaseJob = $null
$ApiPort = Get-FreePort
$ReleasePort = Get-FreePort
$BaseUrl = "https://127.0.0.1:$ApiPort"
$Http = $null

try {
    # 1 ----------------------------------------------------------------------------------
    Write-Step "1/9 prepare $Root"
    [void](New-Item -ItemType Directory -Path $Root -Force)
    Set-Content -LiteralPath $Marker -Value 'Created by deploy/windows/smoke.ps1. The script removes this directory.' -Encoding ascii
    [void](New-Item -ItemType Directory -Path $ReleaseDir -Force)
    # The configuration stays outside the data directory, which `service install` restricts
    # to the service account, Administrators and SYSTEM. ProgramData is readable by the account.
    $config = @"
data_dir = '$DataDir'
roles = "controller"

[profile]
name = "home"

[server]
listen = ["127.0.0.1:$ApiPort"]
workers = 1

[tls]
mode = "internal_ca"
addresses = ["127.0.0.1"]

[hibp]
online = false

[log]
level = "info"
event_log = "info"

[updates]
source_url = "http://127.0.0.1:$ReleasePort/releases.json"
ready_timeout_secs = 60
"@
    Set-Content -LiteralPath $ConfigPath -Value $config -Encoding utf8NoBOM
    Write-Host "configuration: $ConfigPath (API on $BaseUrl, release source on port $ReleasePort)"
    Invoke-TenkoOk @('config', 'check', '--config', $ConfigPath)

    # 2 ----------------------------------------------------------------------------------
    Write-Step "2/9 service install --name $Name"
    Invoke-TenkoOk @('service', 'install', '--name', $Name, '--config', $ConfigPath)
    $record = Get-ServiceRecord
    Assert-That ($null -ne $record) "service $Name does not exist after install"
    Assert-That ([System.Diagnostics.EventLog]::SourceExists($Name)) "Event Log source $Name is not registered after install"
    $expectedImage = Join-Path $DataDir 'updates\current\tenko.exe'
    $imageOk = ([string]$record.PathName).IndexOf($expectedImage, [StringComparison]::OrdinalIgnoreCase) -ge 0
    Assert-That $imageOk "the image path does not run $expectedImage : $($record.PathName)"
    Write-Host "image path: $($record.PathName)"

    # 3 ----------------------------------------------------------------------------------
    Write-Step '3/9 set TENKO_TEST_VERSION_FROM_LAYOUT=1 in the service environment'
    Set-ItemProperty -Path $ServiceKey -Name 'Environment' -Type MultiString -Value @('TENKO_TEST_VERSION_FROM_LAYOUT=1')

    # 4 ----------------------------------------------------------------------------------
    Write-Step '4/9 service start, wait for tenko health'
    $stamp = Get-Date
    Invoke-TenkoOk @('service', 'start', '--name', $Name)
    $healthOut = Wait-Until -TimeoutSec 120 -What "tenko health against $BaseUrl" -Test {
        if ((Get-ServiceState) -eq 'Stopped') {
            throw "the service stopped while it started:`n$(sc.exe query $Name | Out-String)"
        }
        if (-not (Test-Path -LiteralPath $CaFile)) { return $false }
        $health = Invoke-Tenko @('health', '--url', $BaseUrl, '--ca-file', $CaFile)
        if ($health.Code -eq 0) { return $health.Output }
        return $false
    }
    Write-Host $healthOut
    $firstPid = [int](Get-ServiceRecord).ProcessId
    Assert-That ($firstPid -gt 0) 'the service has no process id'

    # 5 ----------------------------------------------------------------------------------
    Write-Step '5/9 Event Log: "tenko service starting"'
    $starting = Wait-Until -TimeoutSec 30 -What 'the Information event "tenko service starting"' -Test {
        $found = @(Find-SmokeEvent 'tenko service starting' $stamp | Where-Object { $_.Level -eq 4 })
        if ($found.Count -gt 0) { return $found }
        return $false
    }
    Write-Host ("found {0} event(s), first at {1:u}" -f @($starting).Count, @($starting)[-1].TimeCreated)

    # 6 ----------------------------------------------------------------------------------
    Write-Step '6/9 file log'
    $logItem = Wait-Until -TimeoutSec 30 -What "$LogPath written" -Test {
        if (Test-Path -LiteralPath $LogPath) {
            $item = Get-Item -LiteralPath $LogPath
            if ($item.Length -gt 0) { return $item }
        }
        return $false
    }
    Write-Host "$LogPath has $($logItem.Length) bytes"
    Get-Content -LiteralPath $LogPath -Tail 3 | Out-Host

    # 7 ----------------------------------------------------------------------------------
    Write-Step "7/9 upgrade to $NewVersion through the update API (exit status 12, restart by the SCM)"
    $Http = [TenkoSmokeTrust]::Create((Get-Content -LiteralPath $CaFile -Raw))

    $tokenFile = Join-Path $DataDir 'setup-token'
    $token = (Wait-Until -TimeoutSec 30 -What "the setup token file $tokenFile" -Test {
            if (Test-Path -LiteralPath $tokenFile) {
                $text = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
                if ($text) { return $text }
            }
            return $false
        })
    $setup = Invoke-Api 'POST' '/setup' @{
        setup_token = $token
        profile     = 'home'
        admin       = @{ name = $AdminUser; display_name = 'Smoke Admin'; password = $AdminPassword }
        host_name   = 'localhost'
        language    = 'en'
    }
    Assert-Api $setup 200 'POST /setup'
    Write-Host 'first-run setup done, signed in as the administrator'

    $status = Invoke-Api 'GET' '/system/updates'
    Assert-Api $status 200 'GET /system/updates'
    $platform = [string]$status.Json.platform
    Assert-That ($platform -match '^[a-z]+-[a-z0-9_]+$') "unexpected platform: $platform"
    Assert-That ([string]$status.Json.running -ne $NewVersion) "the server already runs $NewVersion"
    $oldVersion = [string]$status.Json.running
    Write-Host "running $oldVersion on $platform"

    # The release is this same binary, offered as the next version.
    $assetName = "tenko-$NewVersion-$platform.exe"
    $assetPath = Join-Path $ReleaseDir $assetName
    Copy-Item -LiteralPath $Binary -Destination $assetPath
    $sha256 = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = @{
        schema   = 1
        project  = 'tenko'
        releases = @(@{
                version  = $NewVersion
                date     = '2026-10-10'
                notes    = "### Fixed`n`n- A release for the service smoke test."
                security = $true
                assets   = @(@{
                        platform = $platform
                        name     = $assetName
                        url      = $assetName
                        sha256   = $sha256
                        size     = (Get-Item -LiteralPath $assetPath).Length
                    })
            })
    }
    $manifestPath = Join-Path $ReleaseDir 'releases.json'
    ConvertTo-Json -InputObject $manifest -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM

    $releaseJob = Start-Job -ArgumentList $ReleasePort, $manifestPath, $assetPath, $assetName -ScriptBlock {
        param($Port, $ManifestPath, $AssetPath, $AssetName)
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$Port/")
        $listener.Start()
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            try {
                $path = $context.Request.Url.AbsolutePath
                $file = $null
                $type = 'application/octet-stream'
                if ($path -eq '/releases.json') { $file = $ManifestPath; $type = 'application/json' }
                elseif ($path -eq "/$AssetName") { $file = $AssetPath }
                if ($null -eq $file) {
                    $context.Response.StatusCode = 404
                } else {
                    $context.Response.StatusCode = 200
                    $context.Response.ContentType = $type
                    $context.Response.ContentLength64 = (Get-Item -LiteralPath $file).Length
                    $stream = [System.IO.File]::OpenRead($file)
                    try { $stream.CopyTo($context.Response.OutputStream) } finally { $stream.Dispose() }
                }
            } catch {
            } finally {
                $context.Response.Close()
            }
        }
    }
    [void](Wait-Until -TimeoutSec 30 -What "the release server on port $ReleasePort" -Test {
            if ($releaseJob.State -in 'Failed', 'Stopped', 'Completed') {
                throw "the release server job ended: $(Receive-Job $releaseJob -ErrorAction SilentlyContinue | Out-String)"
            }
            try {
                $probe = Invoke-WebRequest -Uri "http://127.0.0.1:$ReleasePort/releases.json" -UseBasicParsing -NoProxy -TimeoutSec 5
                return $probe.StatusCode -eq 200
            } catch { return $false }
        })

    $check = Invoke-Api 'POST' '/system/updates/check' @{} -Keyed
    Assert-Api $check 200 'POST /system/updates/check'
    Assert-That ([string]$check.Json.latest -eq $NewVersion) "the check found latest = $(Get-Prop $check.Json 'latest'), expected $NewVersion"
    Assert-That ($check.Json.update_available -eq $true) 'the check reports no update available'
    $install = Get-Prop $check.Json 'install'
    Write-Host "install ability: $($install | ConvertTo-Json -Compress -Depth 5)"
    Assert-That ((Get-Prop $install 'policy') -eq 'ui') 'the install policy is not "ui"'
    Assert-That ((Get-Prop $install 'from_source') -eq $true) 'the install from the release source is not possible (see the line above)'

    $installStart = Get-Date
    $started = Invoke-Api 'POST' '/system/updates/install' @{ version = $NewVersion } -Keyed
    Assert-Api $started 202 'POST /system/updates/install'
    Write-Host "install job $($started.Json.job_id) started"

    # The server exits with status 12; the failure actions start it again after 10 s.
    $runningVersion = Wait-Until -TimeoutSec 240 -What "the service restarted by the SCM and running $NewVersion" -Test {
        $record = Get-ServiceRecord
        if ($null -eq $record -or [string]$record.State -ne 'Running') { return $false }
        if ([int]$record.ProcessId -eq $firstPid) { return $false }
        $health = Invoke-Tenko @('health', '--live', '--url', $BaseUrl, '--ca-file', $CaFile)
        if ($health.Code -ne 0) { return $false }
        if ($health.Output -match 'version (\S+)\)') { return $Matches[1] }
        return $false
    }
    Assert-That ($runningVersion -eq $NewVersion) "the running version is $runningVersion, expected $NewVersion"
    Write-Host "the service runs $runningVersion in a new process (was process $firstPid)"

    $stops = @(Find-SmokeEvent 'tenko service stopped' $installStart)
    Assert-That ($stops.Count -ge 1) 'no "tenko service stopped" event for the stop before the restart'
    $starts = @(Find-SmokeEvent 'tenko service starting' $installStart)
    Assert-That ($starts.Count -ge 1) 'no "tenko service starting" event for the start after the restart'
    $scm = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7024, 7031; StartTime = $installStart } -ErrorAction SilentlyContinue |
            Where-Object { try { ([string]$_.Message).Contains('Tenko DDI') -or ([string]$_.Message).Contains($Name) } catch { $false } })
    if ($scm.Count -gt 0) {
        Write-Host ("Service Control Manager: {0}" -f (([string]$scm[0].Message) -replace '\s+', ' '))
    } else {
        Write-Host 'note: no Service Control Manager entry about the stop was found (the check above does not depend on it)'
    }

    $current = Get-Item -LiteralPath (Join-Path $DataDir 'updates\current') -Force
    Assert-That ($current.LinkType -eq 'Junction') "updates\current is not a junction (LinkType: $($current.LinkType))"
    $target = [string]@($current.Target)[0]
    Assert-That ((Split-Path -Leaf $target) -eq $NewVersion) "updates\current points at $target, expected updates\$NewVersion"
    Write-Host "updates\current -> $target"

    # Sign in again (the session may not survive the restart) and wait for the probation.
    $login = Invoke-Api 'POST' '/auth/login/password' @{ user_name = $AdminUser; password = $AdminPassword }
    Assert-Api $login 200 'POST /auth/login/password'
    $attempt = Wait-Until -TimeoutSec 120 -What 'the update attempt to be confirmed (probation)' -Test {
        $reply = Invoke-Api 'GET' '/system/updates'
        if ($reply.Status -ne 200) { return $false }
        $state = Get-Prop (Get-Prop $reply.Json 'attempt') 'state'
        if ($state -eq 'rolled_back' -or $state -eq 'failed') {
            throw "the update attempt ended as `"$state`": $($reply.Text)"
        }
        if ($state -eq 'confirmed') { return $reply.Json }
        return $false
    }
    Assert-That ([string]$attempt.running -eq $NewVersion) "GET /system/updates reports running $($attempt.running)"
    Write-Host "attempt confirmed: $($attempt.attempt.from) -> $($attempt.attempt.to)"

    # 8 ----------------------------------------------------------------------------------
    Write-Step '8/9 service stop'
    $stopStamp = Get-Date
    Invoke-TenkoOk @('service', 'stop', '--name', $Name)
    Assert-That ((Get-ServiceState) -eq 'Stopped') "the service is $(Get-ServiceState), expected Stopped"
    [void](Wait-Until -TimeoutSec 30 -What 'the Information event "tenko service stopped"' -Test {
            @(Find-SmokeEvent 'tenko service stopped' $stopStamp | Where-Object { $_.Level -eq 4 }).Count -gt 0
        })
    Write-Host 'stopped, "tenko service stopped" is in the Event Log'

    # 9 ----------------------------------------------------------------------------------
    Write-Step '9/9 service uninstall'
    Invoke-TenkoOk @('service', 'uninstall', '--name', $Name)
    [void](Wait-Until -TimeoutSec 30 -What "service $Name to be gone" -Test { $null -eq (Get-ServiceRecord) })
    Assert-That (-not [System.Diagnostics.EventLog]::SourceExists($Name)) "the Event Log source $Name is still registered after uninstall"
    Write-Host 'the service and the Event Log source are gone'
} catch {
    $failed = $true
    Write-Host ''
    Write-Host "FAILED: $($_.Exception.Message)"
    if ($_.InvocationInfo) { Write-Host $_.InvocationInfo.PositionMessage }
    Show-Diagnostics
} finally {
    if ($null -ne $Http) { $Http.Dispose() }
    if ($null -ne $releaseJob) {
        Stop-Job -Job $releaseJob -ErrorAction SilentlyContinue
        Remove-Job -Job $releaseJob -Force -ErrorAction SilentlyContinue
    }
    if ($Keep) {
        Write-Host ''
        Write-Host "-Keep: left everything in place. Remove it with:"
        Write-Host "  & `"$Binary`" service uninstall --name $Name"
        Write-Host "  Remove-Item -Recurse -Force `"$Root`""
    } else {
        Write-Host ''
        Write-Host '==> clean up'
        Remove-SmokeInstallation
    }
}

if ($failed) { exit 1 }
Write-Host ''
Write-Host 'smoke: all steps passed'
exit 0
