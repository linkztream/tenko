# Proofs that the named tests fail without the line they guard: each mutation is one literal
# change to a copy of deploy/windows/takeover (and the mirror beside it) in a folder under
# the system's temporary folder; the named test file runs against the copy, and at least one
# of the named tests must fail. Not run by CI (each pass costs a Phases suite); run it once
# per review round:
#   pwsh -NoProfile -File deploy/windows/takeover/tests/Invoke-Mutation.ps1
# Exit 0 when every mutation is caught, 1 otherwise. The repository is never changed.
[CmdletBinding()]
param([string[]]$Only = @())

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 5.7.1
# -Only a,b from a command line arrives as one string.
$Only = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$windows = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script = [System.IO.File]::ReadAllText((Join-Path $windows 'takeover\Tenko-Takeover.ps1'))
$nl = "`r`n"
$apartBody = [regex]::Match($script, "(?s)    if \(\`$Name -match '\(\^\|\\\.\)\(_msdcs\|_tcp.*?\.Count -gt 0\r\n").Value
$apartBefore = "    if (`$Name -match '(^|\.)_msdcs\.' -or `$Name -match '^_msdcs\.' -or `$Name -match '(^|\.)(_kerberos|_kpasswd|_ldap|_gc)\.') { return `$true }$nl    return (`$Controllers -contains `$Name -and ('A', 'AAAA' -contains `$Type))$nl"
$mutations = @(
    @{ Name = 'pin-after-collect'; File = 'Tenko-Takeover.ps1'; Old = @("        `$script:TkConn.Pinned = `$tls.RootSha256$nl"); New = @(''); Tests = 'Http.Tests.ps1'; Filter = @("*The approval's pin*") }
    @{ Name = 'no-rehash-before-dot-source'; File = 'Tenko-Takeover.ps1'; Old = @("    Assert-TkPayloadFile -Name 'Tenko-DhcpMirror.ps1' -Path `$ExporterPath$nl"); New = @(''); Tests = 'Guard.Tests.ps1'; Filter = @('*hashes the written copy again*') }
    @{ Name = 'start-after-write-back'; File = 'Tenko-Takeover.ps1'; Old = @("$nl                Write-TkLeaseBack -State `$State$nl                if (`$down.Count", '                # Each server starts unauthorized'); New = @("$nl                if (`$down.Count", "                Write-TkLeaseBack -State `$State$nl                # Each server starts unauthorized"); Tests = 'Phases.Tests.ps1'; Filter = @('*is reversed with Windows ready before Tenko is silent*') }
    @{ Name = 'leases-read-again'; File = 'Tenko-Takeover.ps1'; Old = @("if (-not `$State.Data.values.Contains('leases')) {"); New = @('if ($true) {'); Tests = 'Phases.Tests.ps1'; Filter = @('*keeps the lease pairs read before the stop*') }
    @{ Name = 'apart-rule-before'; File = 'Tenko-Takeover.ps1'; Old = @($apartBody); New = @($apartBefore); Tests = 'Guard.Tests.ps1'; Filter = @('*The names listed apart*') }
    @{ Name = 'no-staged-digest-check'; File = 'Tenko-Takeover.ps1'; Old = @("        if ((Get-FileHash -LiteralPath `$target -Algorithm SHA256).Hash -ne `$Digest) { throw `"`$target is not the export of phase 2 (its SHA-256 differs from the copy this run holds)`" }$nl"); New = @(''); Tests = 'Guard.Tests.ps1'; Filter = @('*The restore block*') }
    @{ Name = 'contract-without-ComputerName'; File = 'tests\fixtures\Install-TenkoDhcpMirror.contract.ps1'; Old = @('    [string]$ComputerName,'); New = @(''); Tests = 'Phases.Tests.ps1'; Filter = @('*A whole run*') }
    @{ Name = 'no-read-first'; File = 'Tenko-Takeover.ps1'; Old = @('if ($Authorized -and -not $listed) {', 'elseif (-not $Authorized -and $listed) {'); New = @('if ($Authorized) {', 'else {'); Tests = 'Guard.Tests.ps1'; Filter = @('*The authorization block*') }
    @{ Name = 'no-windows-restart-after-tenko-fails'; File = 'Tenko-Takeover.ps1'; Old = @('Restore-TkWindowsSide -State $State -Why "Tenko did not complete the takeover'); New = @('throw "Tenko did not complete the takeover'); Tests = 'Phases.Tests.ps1'; Filter = @('*when Tenko never completes its task*') }
    @{ Name = 'no-read-again-on-resume'; File = 'Tenko-Takeover.ps1'; Old = @("if ((Get-TkField `$State.Data.values 'silenced') -eq `$true -and `$waits.Count -gt 0) {"); New = @('if ($false) {'); Tests = 'Phases.Tests.ps1'; Filter = @('*reads each service again on a resume*') }
    @{ Name = 'succeeded-job-not-completed'; File = 'Tenko-Takeover.ps1'; Old = @("if (`$waits[`$key].Step -lt 0 -and `$waits[`$key].State -eq 'succeeded' -and"); New = @('if ($false -and'); Tests = 'Phases.Tests.ps1'; Filter = @('*already made as made*') }
    @{ Name = 'dns-confirmation-not-held'; File = 'Tenko-Takeover.ps1'; Old = @('if ($null -ne $script:TkWindowWatch -and $script:TkWindowWatch.Elapsed.TotalSeconds -le $script:TkWindowHoldSec) {'); New = @('if ($false) {'); Tests = 'Phases.Tests.ps1'; Filter = @('*no second question in one sitting*') }
    @{ Name = 'quiet-network-fails'; File = 'Tenko-Takeover.ps1'; Old = @('Write-Warning "$($script:TkQuietText) Not answered yet'); New = @('throw "$($script:TkQuietText) Not answered yet'); Tests = 'Phases.Tests.ps1'; Filter = @('*finishes the check in a quiet network*') }
    @{ Name = 'zero-acks-count-as-answered'; File = 'Tenko-Takeover.ps1'; Old = @('-or $acks -le 0) { $cidr }'); New = @(') { $cidr }'); Tests = 'Phases.Tests.ps1'; Filter = @('*proves each scope on its own*') }
    @{ Name = 'nrpt-servers-ignored'; File = 'Tenko-Takeover.ps1'; Old = @('        if ($servers.Count -eq 0) { continue }'); New = @('        continue'); Tests = 'Guard.Tests.ps1'; Filter = @('*The name resolution policy*') }
    @{ Name = 'any-item-of-the-list'; File = 'Tenko-Takeover.ps1'; Old = @("| Where-Object { [string](Get-TkField `$_ 'job') -ceq `$job })"); New = @(')'); Tests = 'Phases.Tests.ps1'; Filter = @("*reads only the item of the scope's own job*") }
    @{ Name = 'missing-counter-as-quiet'; File = 'Tenko-Takeover.ps1'; Old = @('if ($null -eq $value) { throw'); New = @('if ($false) { throw'); Tests = 'Phases.Tests.ps1'; Filter = @('*tells a node that reports no ACK counter apart*') }
    @{ Name = 'later-sitting-stops-on-missing-counter'; File = 'Tenko-Takeover.ps1'; Old = @("catch { if (`$_.Exception.Data.Contains('tk.exit')) { throw }; Write-Warning"); New = @('catch { throw; Write-Warning'); Tests = 'Phases.Tests.ps1'; Filter = @('*tells a node that reports no ACK counter apart*') }
    @{ Name = 'two-items-of-one-job'; File = 'Tenko-Takeover.ps1'; Old = @('if ($items.Count -gt 1) {'); New = @('if ($false) {'); Tests = 'Phases.Tests.ps1'; Filter = @('*tells a node that reports no ACK counter apart*') }
    @{ Name = 'one-job-two-scopes'; File = 'Tenko-Takeover.ps1'; Old = @('if ($same.Count -gt 0) {'); New = @('if ($false) {'); Tests = 'Phases.Tests.ps1'; Filter = @('*names one job for two scopes*') }
    @{ Name = 'rule-name-not-named'; File = 'Tenko-Takeover.ps1'; Old = @('catch { Exit-TkTakeover $code "the Name Resolution Policy Table rule for'); New = @('catch { throw }; if ($false) { Exit-TkTakeover $code "the Name Resolution Policy Table rule for'); Tests = 'Guard.Tests.ps1'; Filter = @('*whose name is no DNS name*') }
    @{ Name = 'resolver-order'; File = 'Tenko-Takeover.ps1'; Old = @('$candidates = @(@($all | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }) + @($all | Where-Object { $_.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork }))'); New = @('$candidates = $all'); Tests = 'Http.Tests.ps1'; Filter = @('*tried IPv4 first*') }
)

$missed = 0
foreach ($mutation in $mutations | Where-Object { $Only.Count -eq 0 -or $Only -contains $_.Name }) {
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('tenko-mutation-' + [guid]::NewGuid().ToString())
    try {
        [void](New-Item -ItemType Directory -Path $root)
        Copy-Item -LiteralPath (Join-Path $windows 'takeover') -Destination (Join-Path $root 'takeover') -Recurse
        Copy-Item -LiteralPath (Join-Path $windows 'mirror') -Destination (Join-Path $root 'mirror') -Recurse
        $target = Join-Path (Join-Path $root 'takeover') $mutation.File
        $text = [System.IO.File]::ReadAllText($target)
        $applied = $true
        for ($i = 0; $i -lt $mutation.Old.Count; $i++) {
            if (-not $mutation.Old[$i] -or ([regex]::Matches($text, [regex]::Escape($mutation.Old[$i]))).Count -ne 1) { $applied = $false; break }
            $text = $text.Replace($mutation.Old[$i], $mutation.New[$i])
        }
        if (-not $applied) { Write-Output "$($mutation.Name): NOT APPLIED (the line it changes is not found exactly once)"; $missed++; continue }
        [System.IO.File]::WriteAllText($target, $text)
        $configuration = New-PesterConfiguration
        $configuration.Run.Path = Join-Path (Join-Path $root 'takeover') "tests\$($mutation.Tests)"
        $configuration.Run.PassThru = $true
        $configuration.Output.Verbosity = 'None'
        $configuration.Filter.FullName = $mutation.Filter
        # The script's notes go to the information stream: only the verdicts are printed.
        $result = Invoke-Pester -Configuration $configuration 6>$null
        $ran = @($result.Tests | Where-Object { $_.Result -ne 'NotRun' })
        $failed = @($ran | Where-Object { $_.Result -eq 'Failed' })
        if ($failed.Count -eq 0) { $missed++ }
        Write-Output ("{0}: {1} of {2} failed{3}" -f $mutation.Name, $failed.Count, $ran.Count, $(if ($failed.Count -eq 0) { ' (NOT CAUGHT)' } else { ": $($failed[0].ExpandedPath)" }))
    } finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
exit $(if ($missed -eq 0) { 0 } else { 1 })
