<#
.SYNOPSIS
  M9 (OPS-15) on Windows: idle memory of `tenko serve --roles controller`.

.DESCRIPTION
  Starts a fresh single-node controller, completes first-run setup and logs in with the
  CLI, creates a small IPAM data set with `tenko prefix create`, leaves the server idle,
  samples the process memory, stops the server gracefully and checks its exit status.

  Memory is read with Get-Process: WorkingSet64 (resident set), PrivateMemorySize64
  (private bytes, the committed private memory) and the peak counters PeakWorkingSet64
  and PeakPagedMemorySize64 (peak private bytes).

  Nothing secret is written out: the setup token is passed to the CLI through the
  environment, the administrator password is generated for the run and goes through
  standard input, and the server log is redacted before it is copied to the output
  directory.

.PARAMETER Binary
  Path of tenko.exe (release build).

.PARAMETER Port
  Loopback port of the API (default 18443).

.PARAMETER Prefixes
  Number of prefixes to create (default 200): one /8 and four /16 supernets, the rest /24
  networks.

.PARAMETER IdleSeconds
  Length of the idle phase (default 600).

.PARAMETER IntervalSeconds
  Seconds between idle samples (default 30).

.PARAMETER WorkDir
  Scratch directory for data directory, configuration, credentials and raw logs. Default:
  a new directory under $env:TEMP. Keep it off slow disks.

.PARAMETER OutDir
  Where the CSV, the summary and the redacted server log go (default results\raw next to
  this script, which git ignores).

.PARAMETER KekProvider
  `platform` (DPAPI, the default) or `file`.

.PARAMETER KeepData
  Do not delete the scratch directory at the end.

.EXAMPLE
  pwsh -File .\m9-idle-rss.ps1 -Binary F:\cargo-target\release\tenko.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [int]$Port = 18443,
    [int]$Prefixes = 200,
    [int]$IdleSeconds = 600,
    [int]$IntervalSeconds = 30,
    [string]$WorkDir = '',
    [string]$OutDir = '',
    [ValidateSet('platform', 'file')][string]$KekProvider = 'platform',
    [switch]$KeepData
)

$ErrorActionPreference = 'Stop'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
$MiB = 1MB

if ($Prefixes -lt 6) { throw 'Prefixes must be at least 6' }
$Binary = (Resolve-Path -LiteralPath $Binary).Path
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot 'results\raw' }
if (-not $WorkDir) { $WorkDir = Join-Path $env:TEMP ('tenko-m9-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
New-Item -ItemType Directory -Force -Path $WorkDir, $OutDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$tag = "windows-$stamp"

$dataDir = Join-Path $WorkDir 'data'
$cfgFile = Join-Path $WorkDir 'tenko.toml'
$credFile = Join-Path $WorkDir 'credentials.json'
$outLog = Join-Path $WorkDir 'server.out.log'
$errLog = Join-Path $WorkDir 'server.err.log'
$caRoot = Join-Path $dataDir 'tls\ca-root.pem'
$url = "https://localhost:$Port"

# Throwaway administrator PIN for this run (Home profile: digits only). Never printed.
$digits = (0..9) | Get-Random -Count 6
$pin = -join $digits

$kekBlock = ''
if ($KekProvider -eq 'file') {
    $kekBlock = "[kek]`nprovider = `"file`"`npath = '$(Join-Path $WorkDir 'kek.key')'`n"
}
$config = @"
data_dir = '$dataDir'
roles = "controller"

[server]
listen = ["127.0.0.1:$Port"]

[hibp]
online = false

$kekBlock
"@
Set-Content -LiteralPath $cfgFile -Value $config -Encoding ascii

$samples = New-Object System.Collections.Generic.List[object]
$clock = [System.Diagnostics.Stopwatch]::StartNew()

function Read-Mem([int]$ProcId, [string]$Phase) {
    $p = Get-Process -Id $ProcId -ErrorAction Stop
    $row = [pscustomobject]@{
        t_s             = [math]::Round($clock.Elapsed.TotalSeconds, 1)
        phase           = $Phase
        ws_mib          = [math]::Round($p.WorkingSet64 / $MiB, 2)
        private_mib     = [math]::Round($p.PrivateMemorySize64 / $MiB, 2)
        peak_ws_mib     = [math]::Round($p.PeakWorkingSet64 / $MiB, 2)
        peak_priv_mib   = [math]::Round($p.PeakPagedMemorySize64 / $MiB, 2)
        threads         = $p.Threads.Count
        handles         = $p.HandleCount
    }
    $samples.Add($row)
    return $row
}

function Invoke-Tenko([string[]]$CliArgs, [string]$StdIn = $null) {
    if ($null -ne $StdIn) {
        $out = $StdIn | & $Binary @CliArgs 2>&1
    } else {
        $out = & $Binary @CliArgs 2>&1
    }
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = (($out | ForEach-Object { "$_" }) -join "`n") }
}

function Write-Log([string]$Message) {
    Write-Host ('[{0,7:N1}s] {1}' -f $clock.Elapsed.TotalSeconds, $Message)
}

$summary = New-Object System.Collections.Generic.List[string]
function Add-Summary([string]$Line) { $summary.Add($Line); Write-Log $Line }

$cmd = $null
$serverPid = 0
$token = $null
try {
    # ---- machine -------------------------------------------------------------------------
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    Add-Summary ("machine: {0}, {1} logical CPUs, {2:N1} GiB RAM, {3} build {4}" -f $cpu.Name.Trim(), `
        $cs.NumberOfLogicalProcessors, ($cs.TotalPhysicalMemory / 1GB), $os.Caption, $os.BuildNumber)
    Add-Summary ("binary: {0} ({1:N1} MiB), {2}" -f $Binary, ((Get-Item $Binary).Length / $MiB), (& $Binary --version))
    Add-Summary "work dir: $WorkDir (data dir on the same volume)"
    Add-Summary "kek provider: $KekProvider"

    # ---- start ---------------------------------------------------------------------------
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = '/s /c ""{0}" serve --roles controller --config "{1}" --stop-on-eof >"{2}" 2>"{3}""' -f $Binary, $cfgFile, $outLog, $errLog
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
    Add-Summary "server pid $serverPid"

    $ready = $false
    while (-not $ready) {
        if ($cmd.HasExited) { throw "the server exited at start with status $($cmd.ExitCode)" }
        $null = Read-Mem $serverPid 'start'
        if (Test-Path -LiteralPath $outLog) {
            $text = Get-Content -LiteralPath $outLog -Raw -ErrorAction SilentlyContinue
            # The console shows the token itself only to a terminal; otherwise it names the
            # file (`Setup token: in <data_dir>\setup-token; ...`), read below.
            if ($text -match 'Setup token:\s+(?!in\s)(\S+)') { $token = $Matches[1] }
            if ($text -match ' ready at ' -and $text -match '={20,}\s*$') { $ready = $true }
        }
        if (-not $ready) { Start-Sleep -Milliseconds 100 }
        if ($clock.Elapsed.TotalSeconds -gt $deadline) { throw 'server did not become ready in 120 s' }
    }
    $readyAfter = ($clock.Elapsed - $startedAt).TotalSeconds
    $r = Read-Mem $serverPid 'ready'
    Add-Summary ("ready after {0:N1} s; working set {1} MiB, private {2} MiB, peak working set {3} MiB" -f $readyAfter, $r.ws_mib, $r.private_mib, $r.peak_ws_mib)
    $tokenFile = Join-Path $dataDir 'setup-token'
    if (Test-Path -LiteralPath $tokenFile) { $token = (Get-Content -LiteralPath $tokenFile -Raw).Trim() }
    if (-not $token) { throw 'no setup token in the token file or on the server console' }

    # ---- setup and login -----------------------------------------------------------------
    $env:TENKO_CREDENTIALS = $credFile
    $env:TENKO_SETUP_TOKEN = $token
    $res = $null
    for ($try = 1; $try -le 5; $try++) {
        $res = Invoke-Tenko @('setup', '--url', $url, '--ca-file', $caRoot, '--admin', 'admin', '--host-name', 'localhost', '--password-stdin') $pin
        if ($res.Code -eq 0) { break }
        if ($res.Text -match 'trivial|policy|password') {
            $pin = -join ((0..9) | Get-Random -Count 6)
            continue
        }
        break
    }
    Remove-Item Env:TENKO_SETUP_TOKEN -ErrorAction SilentlyContinue
    if ($res.Code -ne 0) { throw "tenko setup failed (status $($res.Code)): $($res.Text -replace [regex]::Escape($token), '<token>')" }
    Add-Summary 'setup complete'
    $res = Invoke-Tenko @('login', '--url', $url, '--ca-file', $caRoot, '--user', 'admin', '--password-stdin') $pin
    if ($res.Code -ne 0) { throw "tenko login failed (status $($res.Code)): $($res.Text)" }
    Add-Summary 'login ok'
    $null = Read-Mem $serverPid 'setup'

    # ---- data set ------------------------------------------------------------------------
    $cidrs = New-Object System.Collections.Generic.List[object]
    $cidrs.Add(@('10.0.0.0/8', 'supernet'))
    1..4 | ForEach-Object { $cidrs.Add(@("10.$_.0.0/16", 'supernet')) }
    for ($n = 0; $cidrs.Count -lt $Prefixes; $n++) {
        $a = 1 + ($n % 4)
        $b = [math]::Floor($n / 4)
        $cidrs.Add(@("10.$a.$b.0/24", 'network'))
    }
    $loadStart = $clock.Elapsed
    $failures = 0
    $i = 0
    foreach ($c in $cidrs) {
        $i++
        $res = Invoke-Tenko @('prefix', 'create', $c[0], '--role', $c[1])
        if ($res.Code -ne 0) {
            Start-Sleep -Seconds 1
            $res = Invoke-Tenko @('prefix', 'create', $c[0], '--role', $c[1])
        }
        if ($res.Code -ne 0) {
            $failures++
            Write-Log "prefix $($c[0]) failed (status $($res.Code)): $($res.Text)"
        }
        if ($i % 10 -eq 0 -or $i -eq $cidrs.Count) { $null = Read-Mem $serverPid 'load' }
    }
    $loadSecs = ($clock.Elapsed - $loadStart).TotalSeconds
    $check = Invoke-Tenko @('prefix', 'list', '--all', '--json')
    $listed = 0
    if ($check.Code -eq 0) {
        try { $listed = @((($check.Text | ConvertFrom-Json).items)).Count } catch { $listed = -1 }
    }
    $r = Read-Mem $serverPid 'load-end'
    Add-Summary ("created {0} of {1} prefixes in {2:N1} s ({3} failures); server lists {4}" -f ($cidrs.Count - $failures), $cidrs.Count, $loadSecs, $failures, $listed)
    Add-Summary ("peak during start-up and data creation: working set {0} MiB, private {1} MiB (now {2} / {3} MiB)" -f $r.peak_ws_mib, $r.peak_priv_mib, $r.ws_mib, $r.private_mib)
    $loadPeakWs = $r.peak_ws_mib
    $loadPeakPriv = $r.peak_priv_mib

    # ---- idle ----------------------------------------------------------------------------
    Add-Summary "idle phase: $IdleSeconds s, one sample every $IntervalSeconds s"
    $idleClock = [System.Diagnostics.Stopwatch]::StartNew()
    $count = [math]::Floor($IdleSeconds / $IntervalSeconds)
    $idle = New-Object System.Collections.Generic.List[object]
    for ($k = 0; $k -le $count; $k++) {
        $due = $k * $IntervalSeconds
        $wait = $due - $idleClock.Elapsed.TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
        if ($cmd.HasExited) { throw "the server exited during the idle phase with status $($cmd.ExitCode) (0x$($cmd.ExitCode.ToString('X')))" }
        $row = Read-Mem $serverPid 'idle'
        $idle.Add($row)
        Write-Log ("idle {0,4} s: working set {1} MiB, private {2} MiB, threads {3}, handles {4}" -f $due, $row.ws_mib, $row.private_mib, $row.threads, $row.handles)
    }
    $final = $idle[$idle.Count - 1]
    $r = Read-Mem $serverPid 'idle-end'
    $peakWsEnd = $r.peak_ws_mib
    $peakPrivEnd = $r.peak_priv_mib

    function Get-Stats($values) {
        $sorted = @($values | Sort-Object)
        $n = $sorted.Count
        $median = if ($n % 2) { $sorted[($n - 1) / 2] } else { ($sorted[$n / 2 - 1] + $sorted[$n / 2]) / 2 }
        [pscustomobject]@{ Min = $sorted[0]; Median = $median; Max = $sorted[$n - 1] }
    }
    $wsStats = Get-Stats ($idle | ForEach-Object { $_.ws_mib })
    $prStats = Get-Stats ($idle | ForEach-Object { $_.private_mib })
    Add-Summary ("idle working set MiB: min {0} median {1} max {2} final {3}" -f $wsStats.Min, $wsStats.Median, $wsStats.Max, $final.ws_mib)
    Add-Summary ("idle private bytes MiB: min {0} median {1} max {2} final {3}" -f $prStats.Min, $prStats.Median, $prStats.Max, $final.private_mib)
    Add-Summary ("peak at the end of the run: working set {0} MiB, private {1} MiB" -f $peakWsEnd, $peakPrivEnd)
    Add-Summary ("start-up and data creation peak: working set {0} MiB, private {1} MiB" -f $loadPeakWs, $loadPeakPriv)
    # OPS-15 says 100 MB; read as 100,000,000 bytes (95.37 MiB), the stricter reading.
    $limitMiB = 100000000 / $MiB
    $verdict = if ($wsStats.Max -lt $limitMiB) { 'PASS' } else { 'FAIL' }
    Add-Summary ("verdict against 100 MB = 100,000,000 bytes = {0:N2} MiB (largest idle working set {1} MiB = {2:N1} MB): {3}" -f $limitMiB, $wsStats.Max, ($wsStats.Max * $MiB / 1e6), $verdict)

    # ---- stop ----------------------------------------------------------------------------
    $stopAt = $clock.Elapsed
    $cmd.StandardInput.Close()
    if (-not $cmd.WaitForExit(60000)) { throw 'the server did not stop within 60 s after standard input closed' }
    $exitCode = $cmd.ExitCode
    Add-Summary ("graceful stop (standard input closed): exit status {0} after {1:N1} s" -f $exitCode, ($clock.Elapsed - $stopAt).TotalSeconds)
}
finally {
    if ($cmd -and -not $cmd.HasExited) {
        try { Stop-Process -Id $serverPid -Force -ErrorAction SilentlyContinue } catch {}
        try { $cmd.Kill() } catch {}
    }
    Remove-Item Env:TENKO_SETUP_TOKEN -ErrorAction SilentlyContinue

    $samples | Export-Csv -LiteralPath (Join-Path $OutDir "m9-$tag.csv") -NoTypeInformation
    $summary | Set-Content -LiteralPath (Join-Path $OutDir "m9-$tag-summary.txt") -Encoding utf8
    foreach ($pair in @(@($outLog, 'server.out.log'), @($errLog, 'server.err.log'))) {
        if (Test-Path -LiteralPath $pair[0]) {
            $text = Get-Content -LiteralPath $pair[0] -Raw
            if ($token) { $text = $text.Replace($token, '<redacted>') }
            Set-Content -LiteralPath (Join-Path $OutDir "m9-$tag-$($pair[1])") -Value $text -Encoding utf8
        }
    }
    Remove-Item Env:TENKO_CREDENTIALS -ErrorAction SilentlyContinue
    if (-not $KeepData) { Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "raw output: $OutDir (m9-$tag*)"
}

