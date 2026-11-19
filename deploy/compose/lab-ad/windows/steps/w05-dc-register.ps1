# W5 on dc1 and W7 on dc2: a controller registers with GSS-TSIG (README.md sections W5 and
# W7), as SYSTEM. One script for both entries; the machine decides the names.
#
# Expects: the controller is promoted and ready; the zones are on Tenko with the secure-only
# policy (W4).
# Leaves: the controller's DNS client pointing at 192.0.2.53 only; its records registered
# again; Netlogon restarted.
# Keeps: <machine>.pcapng (to captures/w5-dc1.pcapng or captures/w7-dc2.pcapng), pktmon.txt,
# nltest.txt (/dsregdns, /dsquerydns, /dsgetdc), events.txt (NETLOGON and DNS client events),
# netlogon-check.txt.
# Checks: `records not in Tenko: 0`; nltest /dsquerydns and /dsgetdc succeed; no NETLOGON
# event 5774 or 5781 after the restart of Netlogon. The audit and the owners are the ns1
# entry that follows.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass "$Computer registered every record of its Netlogon.dns with Tenko" {
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { Fail "$Computer is not a domain controller" }
    Set-DnsServerOfLab $Tenko
    Start-Capture $Computer 53, 88
    Invoke-Native 'nltest.txt' { ipconfig /registerdns }
    Invoke-Native 'nltest.txt' { nltest /dsregdns }
    Restart-Service Netlogon
    $restarted = Get-Date
    Start-Sleep -Seconds 120
    Stop-Capture $Computer
    Invoke-Native 'nltest.txt' { nltest /dsquerydns }
    Invoke-Native 'nltest.txt' { nltest /dsgetdc:corp.example.test /force }
    Get-WinEvent -LogName System -MaxEvents 200 |
        Where-Object { $_.ProviderName -in 'NETLOGON', 'Microsoft-Windows-DNS-Client' } |
        Format-List TimeCreated, Id, Message | Out-File -Encoding utf8 (Join-Path $StepDir 'events.txt')
    $bad = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'NETLOGON'; Id = 5774, 5781; StartTime = $restarted } -ErrorAction SilentlyContinue)
    if ($bad.Count -gt 0) { Fail "NETLOGON logged $($bad.Count) events 5774 or 5781 after the restart (events.txt)" }
    Test-NetlogonRecords
}
