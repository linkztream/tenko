# W9, first part: the group policy "Lab DNS secure only" (README.md section W9), on dc1 as
# CORP\Administrator.
#
# Expects: both controllers and srv1 members of the domain.
# Leaves: the GPO linked to the domain with UpdateSecurityLevel = 256.
# Keeps: gpo.txt.
# Departs from the runbook: Invoke-GPUpdate -Computer is not run; it starts a scheduled task
# on each remote machine, which the default firewall refuses. Each machine runs
# `gpupdate /force` itself in the W9 entry on it (w09-gpo-apply.ps1).
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass 'the GPO Lab DNS secure only is linked to the domain' {
    New-GPO -Name 'Lab DNS secure only' | New-GPLink -Target 'DC=corp,DC=example,DC=test' |
        Format-List * | Out-File -Encoding utf8 (Join-Path $StepDir 'gpo.txt')
    Set-GPRegistryValue -Name 'Lab DNS secure only' -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' `
        -ValueName UpdateSecurityLevel -Type DWord -Value 256 | Format-List * | Out-File -Append -Encoding utf8 (Join-Path $StepDir 'gpo.txt')
}
