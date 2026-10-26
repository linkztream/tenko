<#
.SYNOPSIS
  M30 (OPS-15) on Windows: the memory of 100,000 leases, stage by stage.

.DESCRIPTION
  Runs the ignored test `e32_ops_15_the_memory_of_100000_leases_by_stage` of
  crates/tenko-dhcp/tests/lease_rebuild.rs from its release test binary. The test writes
  100,000 lease rows and their client index rows to a new Raft store, closes and reopens
  the store, rebuilds the dhcp role's lease table from it (`rebuild_from_view`) and drops
  the table again; at each stage it prints `MEMORY stage=<name>` and waits
  TENKO_MEMORY_PAUSE_SECS seconds. This script reads the test process's memory with
  Get-Process during each wait: WorkingSet64 (the resident set) and PrivateMemorySize64
  (private bytes). It takes three samples a second apart from the middle of the pause and
  keeps their median.

  Build the test binary first:
    cargo test --release --locked -p tenko-dhcp --test lease_rebuild --no-run
  and pass the path cargo prints (target\release\deps\lease_rebuild-<hash>.exe).

.PARAMETER TestBinary
  Path of the release test binary of lease_rebuild.rs.

.PARAMETER Leases
  The number of leases (default 100000).

.PARAMETER PauseSeconds
  The test's pause at each stage (default 10).

.PARAMETER OutDir
  Where the CSV and the summary go (default results\raw next to this script's parent,
  which git ignores).

.EXAMPLE
  pwsh -File bench\phase3-dhcp\scripts\m30-lease-memory.ps1 -TestBinary F:\cargo-target\release\deps\lease_rebuild-0123abcd.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TestBinary,
    [int]$Leases = 100000,
    [int]$PauseSeconds = 10,
    [string]$OutDir = ''
)

$ErrorActionPreference = 'Stop'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
$MiB = 1MB
if ($PauseSeconds -lt 6) { throw 'PauseSeconds must be at least 6 (three samples from the middle of the pause)' }
$TestBinary = (Resolve-Path -LiteralPath $TestBinary).Path
if (-not $OutDir) { $OutDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'results\raw' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$tag = 'm30-windows-' + (Get-Date -Format 'yyyyMMdd-HHmmss')

$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$summary = New-Object System.Collections.Generic.List[string]
function Add-Summary([string]$Line) { $summary.Add($Line); Write-Host $Line }
Add-Summary ("machine: {0}, {1} logical CPUs, {2:N1} GiB RAM, {3} build {4}" -f $cpu.Name.Trim(), `
    $cs.NumberOfLogicalProcessors, ($cs.TotalPhysicalMemory / 1GB), $os.Caption, $os.BuildNumber)
Add-Summary "test binary: $TestBinary"
Add-Summary "leases: $Leases, pause per stage: $PauseSeconds s"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $TestBinary
$psi.Arguments = 'e32_ops_15_the_memory_of_100000_leases_by_stage --exact --ignored --nocapture --test-threads 1'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$psi.Environment['TENKO_REBUILD_LEASES'] = "$Leases"
$psi.Environment['TENKO_MEMORY_PAUSE_SECS'] = "$PauseSeconds"
$proc = [System.Diagnostics.Process]::Start($psi)
$errTask = $proc.StandardError.ReadToEndAsync()

$rows = New-Object System.Collections.Generic.List[object]
try {
    while ($true) {
        $line = $proc.StandardOutput.ReadLine()
        if ($null -eq $line) { break }
        # libtest prints the test's name and its first output on one line.
        if ($line -notmatch 'MEMORY stage=(\S+)\s*(.*)$') { continue }
        $name = $Matches[1]
        $detail = $Matches[2]
        if ($name -eq 'end') { break }
        Start-Sleep -Milliseconds ([int](($PauseSeconds / 2 - 1) * 1000))
        $ws = @(); $pr = @()
        for ($k = 0; $k -lt 3; $k++) {
            $p = Get-Process -Id $proc.Id
            $ws += $p.WorkingSet64 / $MiB
            $pr += $p.PrivateMemorySize64 / $MiB
            if ($k -lt 2) { Start-Sleep -Seconds 1 }
        }
        $row = [pscustomobject]@{
            stage       = $name
            ws_mib      = [math]::Round((@($ws | Sort-Object))[1], 2)
            private_mib = [math]::Round((@($pr | Sort-Object))[1], 2)
            detail      = $detail
        }
        $rows.Add($row)
        Add-Summary ("stage {0,-15} working set {1,9:N2} MiB, private {2,9:N2} MiB {3}" -f $row.stage, $row.ws_mib, $row.private_mib, $row.detail)
    }
    if (-not $proc.WaitForExit(120000)) { throw 'the test did not end within 120 s after its last stage' }
    $out = $proc.StandardOutput.ReadToEnd()
    if ($proc.ExitCode -ne 0) { throw "the test failed with status $($proc.ExitCode): $out $($errTask.Result)" }

    $by = @{}
    foreach ($r in $rows) { $by[$r.stage] = $r }
    function Get-StageDiff([string]$a, [string]$b, [string]$field) { [math]::Round($by[$a].$field - $by[$b].$field, 2) }
    if ($by.ContainsKey('table') -and $by.ContainsKey('table-dropped') -and $by.ContainsKey('store-empty')) {
        Add-Summary ("the table and its client index (table - table-dropped): working set {0} MiB, private {1} MiB" -f (Get-StageDiff 'table' 'table-dropped' 'ws_mib'), (Get-StageDiff 'table' 'table-dropped' 'private_mib'))
        Add-Summary ("the table against the reopened store (table - store-reopened): working set {0} MiB, private {1} MiB" -f (Get-StageDiff 'table' 'store-reopened' 'ws_mib'), (Get-StageDiff 'table' 'store-reopened' 'private_mib'))
        Add-Summary ("the store after the fill (store-filled - store-empty): working set {0} MiB, private {1} MiB" -f (Get-StageDiff 'store-filled' 'store-empty' 'ws_mib'), (Get-StageDiff 'store-filled' 'store-empty' 'private_mib'))
        Add-Summary ("the store after a restart and a full scan (table-dropped - store-empty): working set {0} MiB, private {1} MiB" -f (Get-StageDiff 'table-dropped' 'store-empty' 'ws_mib'), (Get-StageDiff 'table-dropped' 'store-empty' 'private_mib'))
    }
}
finally {
    if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }
    $rows | Export-Csv -LiteralPath (Join-Path $OutDir "$tag.csv") -NoTypeInformation
    $summary | Set-Content -LiteralPath (Join-Path $OutDir "$tag-summary.txt") -Encoding utf8
    Write-Host "raw output: $OutDir ($tag*)"
}
