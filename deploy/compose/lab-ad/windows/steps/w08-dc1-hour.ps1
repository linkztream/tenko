# W8, the hourly registration (README.md section W8), on dc1 as SYSTEM.
#
# Expects: the ns1 entry before it kept the zones' serials.
# Leaves: nothing changed.
# Keeps: dc1.pcapng (to captures/w8-dc1.pcapng; keep the first ten minutes after the refresh
# if it is large), pktmon.txt.
# Time: the runbook's own way, no shortcut: Netlogon registers again within the hour, so the
# capture runs 4,200 s (70 minutes) and stops; the manifest gives the entry 90 minutes. What
# it shows is read by a person and by the ns1 entry after it (serials and audit).
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'a 70-minute capture of DNS on dc1 is kept' {
    Start-Capture $Computer 53
    Start-Sleep -Seconds 4200
    Stop-Capture $Computer
}
