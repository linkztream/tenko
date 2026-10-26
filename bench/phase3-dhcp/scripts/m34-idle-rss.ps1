<#
.SYNOPSIS
  M34 (OPS-15, E32) on Windows: idle memory of `tenko serve` with every role, the dhcp
  role serving three scopes with 200 leases.

.DESCRIPTION
  The M9 procedure of bench/phase1-server/m9-idle-rss.ps1 with the roles
  controller, dns, dhcp and probe. A fresh single node starts with a DNS listener and a
  relay-mode DHCP listener on loopback ports; first-run setup goes through the API under
  the Home profile; three IPAM networks on the documentation ranges (192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24) get a `dhcp_pool` range, a scope with one-hour leases
  and the options 3, 6 and 42; the example's load client (`dhcp_server load`, a relay
  agent that selects the scope with option 118) gives 200 clients a lease across the
  three scopes. With -Prefixes N the M9 data set of N prefixes (one /8 and four /16
  supernets, the rest /24 networks, as m9-idle-rss.ps1 creates them) is added first. The
  server is then left idle and sampled, and stopped gracefully.

  Memory is read with Get-Process: WorkingSet64 (the resident set), PrivateMemorySize64
  (private bytes) and the peak counters. The verdict is against 100 MB read as
  100,000,000 bytes (95.37 MiB), as in M9. The criterion names the static musl binary;
  a Windows figure is the release build's and is labelled so.

  Nothing secret is written out: the setup token is read from the data directory, the
  administrator PIN is generated for the run and never printed, and the server log is
  redacted before it is copied to the output directory.

.PARAMETER Binary
  Path of tenko.exe (release build, with the web UI embedded).

.PARAMETER LoadClient
  Path of the example dhcp_server.exe (release build of crates/tenko-dhcp/examples).

.PARAMETER Roles
  The roles (default controller,dns,dhcp,probe). Without dhcp no scopes and no leases are
  made: the baselines of the results file.

.PARAMETER DhcpWorkers
  `[dhcp] workers` (default 0: one per CPU, at most 8).

.PARAMETER Port
  The API's loopback port (default 18443); -DnsPort, -DhcpPort and -RelayPort move the
  others, so that several runs can go at once.

.PARAMETER Prefixes
  The M9 data set's prefixes to add (default 0: the three home scopes only; M9 uses 200).

.PARAMETER Leases
  The leases to fill (default 200), spread over the three scopes.

.PARAMETER IdleSeconds
  Length of the idle phase (default 600).

.PARAMETER IntervalSeconds
  Seconds between idle samples (default 30).

.EXAMPLE
  pwsh -File bench\phase3-dhcp\scripts\m34-idle-rss.ps1 -Binary F:\t\release\tenko.exe -LoadClient F:\t\release\examples\dhcp_server.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$LoadClient,
    [int]$Port = 18443,
    [int]$DnsPort = 15353,
    [int]$DhcpPort = 6767,
    [int]$RelayPort = 6868,
    [string]$Roles = 'controller,dns,dhcp,probe',
    [int]$Prefixes = 0,
    [int]$Leases = 200,
    [int]$DhcpWorkers = 0,
    [int]$IdleSeconds = 600,
    [int]$IntervalSeconds = 30,
    [string]$WorkDir = '',
    [string]$OutDir = '',
    [switch]$KeepData
)

$ErrorActionPreference = 'Stop'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
$MiB = 1MB

if ($Prefixes -ne 0 -and $Prefixes -lt 6) { throw 'Prefixes must be 0 or at least 6' }
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$LoadClient = (Resolve-Path -LiteralPath $LoadClient).Path
if (-not $OutDir) { $OutDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'results\raw' }
if (-not $WorkDir) { $WorkDir = Join-Path $env:TEMP ('tenko-m34-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force -Path $WorkDir, $OutDir | Out-Null
$tag = 'm34-windows-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + "-p$Port"

$dataDir = Join-Path $WorkDir 'data'
$cfgFile = Join-Path $WorkDir 'tenko.toml'
$outLog = Join-Path $WorkDir 'server.out.log'
$errLog = Join-Path $WorkDir 'server.err.log'
$base = "https://localhost:$Port"
$api = "$base/api/v1"
$roles = $Roles
$withDhcp = (",$roles," -like '*,dhcp,*')

# Throwaway administrator PIN for this run (Home profile: digits). Never printed.
$pin = -join ((0..9) | Get-Random -Count 6)

$config = @"
data_dir = '$dataDir'
roles = "$roles"

[server]
listen = ["127.0.0.1:$Port"]

[hibp]
online = false

[dns]
listen = ["127.0.0.1:$DnsPort"]

[dhcp]
listen = [{ address = "127.0.0.1", mode = "relay" }]
port = $DhcpPort
relay_port = $RelayPort
workers = $DhcpWorkers
"@
Set-Content -LiteralPath $cfgFile -Value $config -Encoding ascii

$samples = New-Object System.Collections.Generic.List[object]
$clock = [System.Diagnostics.Stopwatch]::StartNew()
function Read-Mem([int]$ProcId, [string]$Phase) {
    $p = Get-Process -Id $ProcId -ErrorAction Stop
    $row = [pscustomobject]@{
        t_s           = [math]::Round($clock.Elapsed.TotalSeconds, 1)
        phase         = $Phase
        ws_mib        = [math]::Round($p.WorkingSet64 / $MiB, 2)
        private_mib   = [math]::Round($p.PrivateMemorySize64 / $MiB, 2)
        peak_ws_mib   = [math]::Round($p.PeakWorkingSet64 / $MiB, 2)
        peak_priv_mib = [math]::Round($p.PeakPagedMemorySize64 / $MiB, 2)
        threads       = $p.Threads.Count
        handles       = $p.HandleCount
    }
    $samples.Add($row)
    return $row
}
function Write-Log([string]$Message) { Write-Host ('[{0,7:N1}s] {1}' -f $clock.Elapsed.TotalSeconds, $Message) }
$summary = New-Object System.Collections.Generic.List[string]
function Add-Summary([string]$Line) { $summary.Add($Line); Write-Log $Line }

$session = $null
# One API call; retries a 429 (the API's rate limit after many writes) and a 503 (a role
# not yet ready) like a client would.
function Invoke-Api([string]$Method, [string]$Path, $Body = $null, [hashtable]$Headers = @{}) {
    $h = @{ Origin = $base } + $Headers
    for ($try = 1; $try -le 30; $try++) {
        try {
            $req = @{ Method = $Method; Uri = "$api$Path"; Headers = $h; SkipCertificateCheck = $true; SkipHeaderValidation = $true; WebSession = $script:session }
            if ($null -ne $Body) { $req.Body = ($Body | ConvertTo-Json -Depth 8 -Compress); $req.ContentType = 'application/json' }
            return Invoke-RestMethod @req
        } catch {
            $code = 0
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if (($code -eq 429 -or $code -eq 503) -and $try -lt 30) { Start-Sleep -Seconds 2; continue }
            throw "$Method $Path failed ($code): $($_.ErrorDetails.Message) $($_.Exception.Message)"
        }
    }
}
function Hex([byte[]]$Bytes) { ($Bytes | ForEach-Object { $_.ToString('x2') }) -join '' }

$cmd = $null
$serverPid = 0
$token = $null
try {
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    Add-Summary ("machine: {0}, {1} logical CPUs, {2:N1} GiB RAM, {3} build {4}" -f $cpu.Name.Trim(), `
        $cs.NumberOfLogicalProcessors, ($cs.TotalPhysicalMemory / 1GB), $os.Caption, $os.BuildNumber)
    Add-Summary ("binary: {0} ({1:N1} MiB), {2}" -f $Binary, ((Get-Item $Binary).Length / $MiB), (& $Binary --version))
    Add-Summary "work dir: $WorkDir (data dir on the same volume)"
    Add-Summary "roles: $roles; DNS on 127.0.0.1:$DnsPort; DHCP relay listener on 127.0.0.1:$DhcpPort, replies to relays on $RelayPort"

    # ---- start ---------------------------------------------------------------------------
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/s /c ""{0}" serve --roles {1} --config "{2}" --stop-on-eof >"{3}" 2>"{4}""' -f $Binary, $roles, $cfgFile, $outLog, $errLog
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    $startedAt = $clock.Elapsed
    $cmd = [System.Diagnostics.Process]::Start($psi)
    $exeName = [System.IO.Path]::GetFileName($Binary)
    $deadline = $clock.Elapsed.TotalSeconds + 120
    while ($serverPid -eq 0) {
        $child = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($cmd.Id)" | Where-Object { $_.Name -ieq $exeName } | Select-Object -First 1
        if ($child) { $serverPid = [int]$child.ProcessId } else { Start-Sleep -Milliseconds 50 }
        if ($cmd.HasExited) { throw "the server exited at start with status $($cmd.ExitCode)" }
        if ($clock.Elapsed.TotalSeconds -gt $deadline) { throw 'server process not found' }
    }
    $ready = $false
    while (-not $ready) {
        if ($cmd.HasExited) { throw "the server exited at start with status $($cmd.ExitCode)" }
        $null = Read-Mem $serverPid 'start'
        if (Test-Path -LiteralPath $outLog) {
            $text = Get-Content -LiteralPath $outLog -Raw -ErrorAction SilentlyContinue
            if ($text -match ' ready at ' -and $text -match '={20,}\s*$') { $ready = $true }
        }
        if (-not $ready) { Start-Sleep -Milliseconds 100 }
        if ($clock.Elapsed.TotalSeconds -gt $deadline) { throw 'server did not become ready in 120 s' }
    }
    $r = Read-Mem $serverPid 'ready'
    Add-Summary ("ready after {0:N1} s; working set {1} MiB, private {2} MiB" -f ($clock.Elapsed - $startedAt).TotalSeconds, $r.ws_mib, $r.private_mib)
    $token = (Get-Content -LiteralPath (Join-Path $dataDir 'setup-token') -Raw).Trim()

    # ---- setup ---------------------------------------------------------------------------
    $setup = @{ setup_token = $token; profile = 'home'; host_name = 'localhost'; language = 'en'
        admin = @{ name = 'admin'; display_name = 'Bench'; password = $pin } }
    $null = Invoke-RestMethod -Method Post -Uri "$api/setup" -Headers @{ Origin = $base } -SkipCertificateCheck `
        -ContentType 'application/json' -Body ($setup | ConvertTo-Json -Compress) -SessionVariable session
    $script:session = $session
    Add-Summary 'setup complete (Home profile), session open'
    $null = Read-Mem $serverPid 'setup'

    # ---- the M9 data set (optional) ------------------------------------------------------
    if ($Prefixes -gt 0) {
        $cidrs = New-Object System.Collections.Generic.List[object]
        $cidrs.Add(@('10.0.0.0/8', 'supernet'))
        1..4 | ForEach-Object { $cidrs.Add(@("10.$_.0.0/16", 'supernet')) }
        for ($n = 0; $cidrs.Count -lt $Prefixes; $n++) {
            $cidrs.Add(@("10.$(1 + ($n % 4)).$([math]::Floor($n / 4)).0/24", 'network'))
        }
        foreach ($c in $cidrs) { $null = Invoke-Api Post '/prefixes' @{ cidr = $c[0]; role = $c[1] } }
        Add-Summary "the M9 data set: $($cidrs.Count) prefixes"
    }

    # ---- the three home scopes -----------------------------------------------------------
    $homes = @(
        @{ net = '192.0.2.0/24'; first = '192.0.2.100'; last = '192.0.2.199'; o = @(192, 0, 2) },
        @{ net = '198.51.100.0/24'; first = '198.51.100.100'; last = '198.51.100.199'; o = @(198, 51, 100) },
        @{ net = '203.0.113.0/24'; first = '203.0.113.100'; last = '203.0.113.199'; o = @(203, 0, 113) }
    )
    if (-not $withDhcp) { $homes = @(); Add-Summary 'no dhcp role: no scopes and no leases (the baseline)' }
    foreach ($h in $homes) {
        $prefix = (Invoke-Api Post '/prefixes' @{ cidr = $h.net; role = 'network' }).item.id
        $null = Invoke-Api Post "/prefixes/$prefix/ranges" @{ first = $h.first; last = $h.last; role = 'dhcp_pool' }
        $null = Invoke-Api Post '/dhcp/scopes' @{ prefix = $prefix; lease = @{ default_secs = 3600; min_secs = 600; max_secs = 7200 } }
        $o = $h.o
        $values = @(
            @{ code = 3; data = (Hex ([byte[]]($o + 1))) },
            @{ code = 6; data = (Hex ([byte[]]($o + 53))) },
            @{ code = 42; data = (Hex ([byte[]]($o + 123))) }
        )
        $null = Invoke-Api Put "/dhcp/option-sets/scope:$prefix" @{ values = $values } @{ 'If-Match' = '0' }
        $h.prefix = $prefix
    }
    if ($withDhcp) { Add-Summary 'three scopes with pools of 100 addresses and the options 3, 6 and 42' }
    Start-Sleep -Seconds 3

    # ---- the leases ----------------------------------------------------------------------
    $per = [math]::Ceiling($Leases / 3)
    $left = $Leases
    foreach ($h in $homes) {
        $n = [math]::Min($per, $left)
        $left -= $n
        if ($n -le 0) { continue }
        $subnet = ($h.net -split '/')[0]
        $out = & $LoadClient load --server "127.0.0.1:$DhcpPort" --bind "127.0.0.1:$RelayPort" --mode dora `
            --clients $n --window 8 --seconds 60 --subnet $subnet 2>&1
        Add-Summary ("load client on {0}: {1}" -f $h.net, (($out | ForEach-Object { "$_" }) -join ' '))
    }
    $listed = 0
    $cursor = $null
    if ($withDhcp) { do {
        $q = '/dhcp/leases?limit=500' + $(if ($cursor) { "&cursor=$cursor" } else { '' })
        $page = Invoke-Api Get $q
        $listed += @($page.items).Count
        $cursor = $page.next_cursor
    } while ($cursor) }
    $r = Read-Mem $serverPid 'load-end'
    Add-Summary ("leases listed by GET /dhcp/leases: {0}" -f $listed)
    Add-Summary ("peak during start-up, setup and the fill: working set {0} MiB, private {1} MiB (now {2} / {3} MiB)" -f $r.peak_ws_mib, $r.peak_priv_mib, $r.ws_mib, $r.private_mib)
    $loadPeakWs = $r.peak_ws_mib

    # ---- idle ----------------------------------------------------------------------------
    Add-Summary "idle phase: $IdleSeconds s, one sample every $IntervalSeconds s"
    $idleClock = [System.Diagnostics.Stopwatch]::StartNew()
    $count = [math]::Floor($IdleSeconds / $IntervalSeconds)
    $idle = New-Object System.Collections.Generic.List[object]
    for ($k = 0; $k -le $count; $k++) {
        $wait = $k * $IntervalSeconds - $idleClock.Elapsed.TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
        if ($cmd.HasExited) { throw "the server exited during the idle phase with status $($cmd.ExitCode)" }
        $row = Read-Mem $serverPid 'idle'
        $idle.Add($row)
        Write-Log ("idle {0,4} s: working set {1} MiB, private {2} MiB, threads {3}, handles {4}" -f ($k * $IntervalSeconds), $row.ws_mib, $row.private_mib, $row.threads, $row.handles)
    }
    function Get-Stats($values) {
        $sorted = @($values | Sort-Object)
        $n = $sorted.Count
        $median = if ($n % 2) { $sorted[($n - 1) / 2] } else { ($sorted[$n / 2 - 1] + $sorted[$n / 2]) / 2 }
        [pscustomobject]@{ Min = $sorted[0]; Median = $median; Max = $sorted[$n - 1] }
    }
    $ws = Get-Stats ($idle | ForEach-Object { $_.ws_mib })
    $pr = Get-Stats ($idle | ForEach-Object { $_.private_mib })
    $final = $idle[$idle.Count - 1]
    Add-Summary ("idle working set MiB: min {0} median {1} max {2} final {3}" -f $ws.Min, $ws.Median, $ws.Max, $final.ws_mib)
    Add-Summary ("idle private bytes MiB: min {0} median {1} max {2} final {3}" -f $pr.Min, $pr.Median, $pr.Max, $final.private_mib)
    Add-Summary ("start-up and fill peak: working set {0} MiB" -f $loadPeakWs)
    $limitMiB = 100000000 / $MiB
    $verdict = if ($ws.Max -lt $limitMiB) { 'PASS' } else { 'FAIL' }
    Add-Summary ("verdict against 100 MB = 100,000,000 bytes = {0:N2} MiB (largest idle working set {1} MiB = {2:N1} MB): {3}" -f $limitMiB, $ws.Max, ($ws.Max * $MiB / 1e6), $verdict)

    # ---- stop ----------------------------------------------------------------------------
    $stopAt = $clock.Elapsed
    $cmd.StandardInput.Close()
    if (-not $cmd.WaitForExit(60000)) { throw 'the server did not stop within 60 s after standard input closed' }
    Add-Summary ("graceful stop (standard input closed): exit status {0} after {1:N1} s" -f $cmd.ExitCode, ($clock.Elapsed - $stopAt).TotalSeconds)
}
finally {
    if ($cmd -and -not $cmd.HasExited) {
        try { Stop-Process -Id $serverPid -Force -ErrorAction SilentlyContinue } catch {}
        try { $cmd.Kill() } catch {}
    }
    $samples | Export-Csv -LiteralPath (Join-Path $OutDir "$tag.csv") -NoTypeInformation
    $summary | Set-Content -LiteralPath (Join-Path $OutDir "$tag-summary.txt") -Encoding utf8
    foreach ($pair in @(@($outLog, 'server.out.log'), @($errLog, 'server.err.log'))) {
        if (Test-Path -LiteralPath $pair[0]) {
            $text = Get-Content -LiteralPath $pair[0] -Raw
            if ($token) { $text = $text.Replace($token, '<redacted>') }
            Set-Content -LiteralPath (Join-Path $OutDir "$tag-$($pair[1])") -Value $text -Encoding utf8
        }
    }
    if (-not $KeepData) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "raw output: $OutDir ($tag*)"
}
