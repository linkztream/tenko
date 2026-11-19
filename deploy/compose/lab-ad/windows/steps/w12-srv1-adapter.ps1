# W12, on srv1 before and after pc1's attempt: srv1 leaves the network and comes back
# (README.md section W12), as SYSTEM. One script for two entries: an id ending in "-off"
# disables the lab adapter, one ending in "-on" enables it and waits for 192.0.2.20.
#
# Expects: srv1 owns its names on Tenko (W11).
# Leaves: "-off": the lab adapter disabled; "-on": it enabled with 192.0.2.20 usable.
# Keeps: adapter.txt.
# Departs from the runbook: Stop-Computer is replaced by disabling the adapter. A job that can
# restart a machine cannot start one that was shut down, and what W12 needs is only that
# 192.0.2.20 is free on the network; the job's agent does not use the network. The "-on"
# entry skips the clock check, which needs the network it turns back on.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

$off = $Id.EndsWith('-off')
Invoke-Step -NoClock:(-not $off) -Pass "the lab adapter of srv1 is $(if ($off) { 'disabled' } else { 'back with 192.0.2.20' })" {
    if ($off) {
        Disable-NetAdapter -Name (Get-NetIPAddress -IPAddress 192.0.2.20).InterfaceAlias -Confirm:$false
    } elseif ($Id.EndsWith('-on')) {
        $disabled = @(Get-NetAdapter | Where-Object Status -eq 'Disabled')
        if ($disabled.Count -ne 1) { Fail "srv1 has $($disabled.Count) disabled adapters, not one" }
        Enable-NetAdapter -Name $disabled[0].Name -Confirm:$false
        Wait-Until { (Get-NetIPAddress -IPAddress 192.0.2.20).AddressState -eq 'Preferred' } 120 '192.0.2.20 usable on srv1'
    } else {
        Fail 'the entry id must end in -off or -on'
    }
    Get-NetAdapter | Format-Table Name, Status, MacAddress -AutoSize |
        Out-File -Encoding utf8 (Join-Path $StepDir 'adapter.txt')
}
