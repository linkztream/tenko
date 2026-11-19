# W10, second part: pc1 registers with GSS-TSIG as PC1$ (README.md section W10), on pc1 as
# SYSTEM.
#
# Expects: pc1 joined and restarted (checks\member-ready.ps1 passed).
# Leaves: pc1's A and PTR records registered again.
# Keeps: after.pcapng (to captures/w10-pc1-after.pcapng), pktmon.txt, w10.txt (ipconfig /all,
# nltest, the two answers).
# Checks: nltest finds a controller; pc1.corp.example.test answers 192.0.2.30 and 192.0.2.30
# answers pc1.corp.example.test on Tenko (within a minute). The owners are the ns1 entry that
# follows.
# Departs from the runbook: the client registers at start-up, before a script can run, so the
# capture holds the registration that `ipconfig /registerdns` forces after the restart (the
# runbook's optional second capture), then waits the runbook's two minutes.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'pc1 registered its A and PTR records on Tenko and finds a controller' {
    Start-Capture 'after' 53, 88
    Invoke-Native 'w10.txt' { ipconfig /registerdns }
    Start-Sleep -Seconds 120
    Stop-Capture 'after'
    Invoke-Native 'w10.txt' { ipconfig /all }
    Invoke-Native 'w10.txt' { nltest /dsgetdc:corp.example.test /force }
    Wait-Until {
        @(Resolve-DnsName pc1.corp.example.test -Server $Tenko -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'A' -and $_.IPAddress -eq '192.0.2.30' }).Count -gt 0
    } 60 'pc1.corp.example.test answering 192.0.2.30 on Tenko'
    Wait-Until {
        @(Resolve-DnsName 192.0.2.30 -Server $Tenko -DnsOnly -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' -and $_.NameHost -eq 'pc1.corp.example.test' }).Count -gt 0
    } 60 '192.0.2.30 answering pc1.corp.example.test on Tenko'
    Resolve-DnsName pc1.corp.example.test -Server $Tenko -DnsOnly | Format-Table -AutoSize | Out-File -Append -Encoding utf8 (Join-Path $StepDir 'w10.txt')
    Resolve-DnsName 192.0.2.30 -Server $Tenko -DnsOnly | Format-Table -AutoSize | Out-File -Append -Encoding utf8 (Join-Path $StepDir 'w10.txt')
}
