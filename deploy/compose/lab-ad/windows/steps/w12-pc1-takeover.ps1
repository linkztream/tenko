# W12: another computer cannot overwrite srv1's names (README.md section W12), on pc1 as
# SYSTEM.
#
# Expects: srv1's adapter disabled (the "-off" entry before this one); pc1 joined.
# Leaves: pc1 as it was: 192.0.2.20 added, registered and removed again.
# Keeps: register.txt, w12-events.txt (the DNS client's events of the attempt).
# Checks: the DNS client logs a registration failure since the attempt: event 8012 for the
# refused PTR record (8018 and 8020 are the same failure of a host record).
# The refusal and the unchanged PTR record are read on Tenko by the ns1 entry that follows.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass "pc1's update of srv1's PTR name failed on its side (event 8012, 8018 or 8020)" {
    $adapter = (Get-NetIPAddress -IPAddress 192.0.2.30).InterfaceAlias
    $begun = Get-Date
    New-NetIPAddress -InterfaceAlias $adapter -IPAddress 192.0.2.20 -PrefixLength 24 | Out-Null
    try {
        Wait-Until { (Get-NetIPAddress -IPAddress 192.0.2.20).AddressState -eq 'Preferred' } 60 '192.0.2.20 usable on pc1'
        Invoke-Native 'register.txt' { ipconfig /registerdns }
        Start-Sleep -Seconds 30
        Get-WinEvent -LogName System -MaxEvents 50 |
            Where-Object { $_.ProviderName -eq 'Microsoft-Windows-DNS-Client' } |
            Format-List TimeCreated, Id, Message | Out-File -Encoding utf8 (Join-Path $StepDir 'w12-events.txt')
    } finally {
        Remove-NetIPAddress -IPAddress 192.0.2.20 -Confirm:$false
    }
    $failed = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-DNS-Client'; Id = 8012, 8018, 8020; StartTime = $begun } -ErrorAction SilentlyContinue)
    if ($failed.Count -eq 0) { Fail 'the DNS client logged no event 8012, 8018 or 8020 for the attempt (w12-events.txt)' }
}
