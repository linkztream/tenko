# W1, last part: srv1 registers with the Windows DNS server (README.md section W1), on srv1 as
# SYSTEM.
#
# Expects: srv1 joined and restarted (checks\member-ready.ps1 passed), its DNS client at
# 192.0.2.5.
# Leaves: srv1's records registered on dc1.
# Keeps: register.txt, resolve.txt.
# Checks: Resolve-DnsName srv1.corp.example.test -Server 192.0.2.5 answers 192.0.2.20
# (within three minutes).
# Departs from the runbook: the registration runs as SYSTEM, not in a session of
# CORP\Administrator; the DNS client service registers either way.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'srv1.corp.example.test answers 192.0.2.20 on dc1' {
    Invoke-Native 'register.txt' { ipconfig /registerdns }
    Wait-Until {
        $answer = Resolve-DnsName srv1.corp.example.test -Server 192.0.2.5 -DnsOnly -ErrorAction Stop
        $answer | Format-Table -AutoSize | Out-File -Encoding utf8 (Join-Path $StepDir 'resolve.txt')
        @($answer | Where-Object { $_.Type -eq 'A' -and $_.IPAddress -eq '192.0.2.20' }).Count -gt 0
    } 180 'srv1.corp.example.test answering 192.0.2.20 on dc1'
}
