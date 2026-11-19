# W11: the member server registers and refreshes its records (README.md section W11), on
# srv1 as SYSTEM. It runs right after W5, before W6 (README.md, "Running the steps
# unattended"): from W6 on, the DNS server srv1 was handed over with (192.0.2.5) no longer
# serves DNS, and W7 and W9 need srv1 to find a controller.
#
# Expects: the zones on Tenko with srv1's imported records claimable by SRV1$ (W4).
# Leaves: srv1's DNS client at 192.0.2.53 only; srv1's names claimed by SRV1$.
# Keeps: register.txt.
# Checks: the claim and the refresh are read on Tenko by the ns1 entry that follows.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'srv1 points at Tenko and registered twice' {
    Set-DnsServerOfLab $Tenko
    Invoke-Native 'register.txt' { ipconfig /registerdns }
    Start-Sleep -Seconds 30
    Invoke-Native 'register.txt' { ipconfig /registerdns }
    Start-Sleep -Seconds 30
}
