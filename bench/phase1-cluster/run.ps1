<#
.SYNOPSIS
  Runs the measurements of the cluster lab (WP3.1c) on this machine and summarizes them.

.DESCRIPTION
  The measurements M1, M3, M4, M6 and M12 are ignored integration tests of the `tenko`
  package (`crates/tenko/tests/cluster_measure.rs`, and the M6 scenario in
  `crates/tenko/tests/cluster_membership.rs`). This script builds the test binaries once,
  runs the selected tests one after another (never in parallel), then runs the summary test,
  which reads every JSON file in the results directory and writes `summary.md` next to them.

  The script sets TENKO_LAB_RESULTS to the absolute path of the output directory, and
  TENKO_UI_STUB=1 unless it is already set (the tests do not need the built web UI). It
  restores the environment variables it changed when it finishes.

  The first failing test stops the run. The summary is still written for the results that
  exist, and the script then exits with the status of the failed test.

  The script runs from anywhere: it finds the repository root from its own location. `cargo`
  must be on the PATH.

.PARAMETER OutDir
  Where the raw JSON files, environment.txt and summary.md go. Default: a new directory
  `results\raw\<yyyy-MM-dd-HHmm>` next to this script (git ignores `results/raw/`).

.PARAMETER Only
  The measurements to run, among M1, M3, M4, M6 and M12, as a comma-separated list. Default:
  all of them.

.PARAMETER Seconds
  Shortens the timed phases to this many seconds (sets TENKO_LAB_SECONDS). For a quick check;
  the numbers are not results.

.PARAMETER M3Runs
  Number of failover runs of M3 (sets TENKO_LAB_M3_RUNS). The tests default to 20.

.EXAMPLE
  pwsh -File .\run.ps1

.EXAMPLE
  pwsh -File .\run.ps1 -Seconds 10 -M3Runs 2

.EXAMPLE
  pwsh -File .\run.ps1 -Only M12,M4 -OutDir F:\lab\run1
#>
[CmdletBinding()]
param(
    [string]$OutDir = '',
    [string]$Only = '',
    [Nullable[int]]$Seconds = $null,
    [Nullable[int]]$M3Runs = $null
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture

# The measurements in the order they run: the short ones first, M3 (about 20 minutes) last.
$catalog = @(
    @{ Name = 'M12'; Binary = 'cluster_measure';    Test = 'm12_forwarded_write_latency' },
    @{ Name = 'M4';  Binary = 'cluster_measure';    Test = 'm4_steady_writes_and_the_catch_up_of_an_empty_controller' },
    @{ Name = 'M1';  Binary = 'cluster_measure';    Test = 'm1_reads_on_a_follower_during_a_snapshot_install' },
    @{ Name = 'M6';  Binary = 'cluster_membership'; Test = 'a_member_rejoins_with_an_empty_data_directory' },
    @{ Name = 'M3';  Binary = 'cluster_measure';    Test = 'm3_failover_under_load' }
)

# `pwsh -File` passes -Only M1,M3 as one string, so the list is split here.
$selected = $catalog
if ($Only.Trim()) {
    $wanted = @($Only -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToUpperInvariant() })
    $known = @($catalog | ForEach-Object { $_.Name })
    foreach ($name in $wanted) {
        if ($known -notcontains $name) { throw "unknown measurement '$name'; choose among M1, M3, M4, M6, M12" }
    }
    $selected = @($catalog | Where-Object { $wanted -contains $_.Name })
}
if ($null -ne $Seconds -and $Seconds -lt 1) { throw 'Seconds must be at least 1' }
if ($null -ne $M3Runs -and $M3Runs -lt 1) { throw 'M3Runs must be at least 1' }

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (-not $OutDir) { $OutDir = Join-Path $PSScriptRoot ('results\raw\' + (Get-Date -Format 'yyyy-MM-dd-HHmm')) }
elseif (-not [System.IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path (Get-Location).Path $OutDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'cargo is not on the PATH' }

# ---- environment record -------------------------------------------------------------------
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$system = Get-CimInstance Win32_ComputerSystem
$memGiB = [math]::Round($system.TotalPhysicalMemory / 1GB, 1)
$os = Get-CimInstance Win32_OperatingSystem
$rustc = (& rustc --version 2>&1 | Out-String).Trim()
Push-Location $repo
try {
    $commit = (& git rev-parse --short HEAD 2>&1 | Out-String).Trim()
    $dirty = (& git status --porcelain 2>&1 | Out-String).Trim()
} finally {
    Pop-Location
}
if ($dirty) { $commit += ' (uncommitted changes in the working tree)' }

$secondsText = if ($null -ne $Seconds) { [string]$Seconds } else { 'default' }
$runsText = if ($null -ne $M3Runs) { [string]$M3Runs } else { 'default' }
$envLines = @(
    "machine: $($cpu.Name.Trim()), $($system.NumberOfLogicalProcessors) logical CPUs, $memGiB GiB RAM",
    "os: $($os.Caption) (build $($os.BuildNumber))",
    "rustc: $rustc",
    "commit: $commit",
    "date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')",
    "measurements: $(($selected | ForEach-Object { $_.Name }) -join ', ')",
    "seconds: $secondsText",
    "m3 runs: $runsText",
    'profile: test (debug)'
)
$envLines | ForEach-Object { Write-Host $_ }
Set-Content -LiteralPath (Join-Path $OutDir 'environment.txt') -Value $envLines -Encoding utf8

# ---- run ----------------------------------------------------------------------------------
$changed = 'TENKO_LAB_RESULTS', 'TENKO_LAB_SECONDS', 'TENKO_LAB_M3_RUNS', 'TENKO_UI_STUB'
$saved = @{}
foreach ($name in $changed) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }

$failure = 0
Push-Location $repo
try {
    $env:TENKO_LAB_RESULTS = $OutDir
    if (-not $env:TENKO_UI_STUB) { $env:TENKO_UI_STUB = '1' }
    if ($null -ne $Seconds) { $env:TENKO_LAB_SECONDS = [string]$Seconds }
    if ($null -ne $M3Runs) { $env:TENKO_LAB_M3_RUNS = [string]$M3Runs }

    Write-Host "`n== build"
    & cargo test -p tenko --locked --test cluster_measure --test cluster_membership --no-run
    if ($LASTEXITCODE -ne 0) { throw "the build failed with status $LASTEXITCODE" }

    foreach ($m in $selected) {
        Write-Host "`n== $($m.Name) ($($m.Binary): $($m.Test))"
        $started = Get-Date
        & cargo test -p tenko --locked --test $m.Binary -- --ignored --exact --nocapture $m.Test
        $status = $LASTEXITCODE
        $took = [math]::Round(((Get-Date) - $started).TotalMinutes, 1)
        if ($status -ne 0) {
            Write-Host "$($m.Name) FAILED with status $status after $took min"
            $failure = $status
            break
        }
        Write-Host "$($m.Name) finished in $took min"
    }

    if (Get-ChildItem -LiteralPath $OutDir -Filter '*.json' -ErrorAction SilentlyContinue) {
        Write-Host "`n== summary"
        & cargo test -p tenko --locked --test cluster_measure -- --ignored --exact --nocapture summary_of_the_results
        $status = $LASTEXITCODE
        if ($status -ne 0 -and $failure -eq 0) { $failure = $status }
        $summaryFile = Join-Path $OutDir 'summary.md'
        if (Test-Path -LiteralPath $summaryFile) { Write-Host "`nsummary: $summaryFile" }
    } else {
        Write-Host "`nno result files in $OutDir; no summary"
        if ($failure -eq 0) { $failure = 1 }
    }
} finally {
    Pop-Location
    foreach ($name in $changed) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
exit $failure
