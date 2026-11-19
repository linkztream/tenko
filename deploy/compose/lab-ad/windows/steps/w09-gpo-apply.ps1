# W9, on each of dc1, dc2 and srv1: the policy applies and the machine registers (README.md
# section W9), as SYSTEM. One script for the three entries.
#
# Expects: the GPO of the dc1 policy entry; the profile moved to Hardened (the ns1 entry).
# Leaves: the policy applied; the records registered again.
# Keeps: w9.txt (gpupdate, gpresult, the registry value, the registration).
# Checks: gpresult names the GPO; UpdateSecurityLevel is 256; on a controller nltest
# /dsregdns and /dsquerydns succeed. On srv1, /dsregdns and /dsquerydns are not run: they are
# commands of a controller's Netlogon, and srv1's registration is the DNS client's.
# Departs from the runbook: `gpupdate /force` on the machine itself replaces
# Invoke-GPUpdate -Computer from dc1 (see w09-dc1-policy.ps1).
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass "the policy Lab DNS secure only applies on $Computer and its registration succeeds" {
    Invoke-Native 'w9.txt' { gpupdate /force }
    Invoke-Native 'w9.txt' { gpresult /r /scope computer }
    if (-not (Select-String -Path (Join-Path $StepDir 'w9.txt') -Pattern 'Lab DNS secure only' -SimpleMatch -Quiet)) {
        Fail 'gpresult does not name the GPO Lab DNS secure only (w9.txt)'
    }
    $level = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient').UpdateSecurityLevel
    "UpdateSecurityLevel: $level" | Out-File -Append -Encoding utf8 (Join-Path $StepDir 'w9.txt')
    if ($level -ne 256) { Fail "UpdateSecurityLevel is $level, not 256" }
    Invoke-Native 'w9.txt' { ipconfig /registerdns }
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
        Invoke-Native 'w9.txt' { nltest /dsregdns }
        Invoke-Native 'w9.txt' { nltest /dsquerydns }
    }
}
