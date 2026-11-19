# W10, first part: the Windows 11 client joins the domain through Tenko (README.md section
# W10), on pc1 as SYSTEM.
#
# Expects: Windows 11 named pc1 with the static address 192.0.2.30, not joined; the secret
# domain_admin_password.
# Leaves: pc1's DNS client at 192.0.2.53 only; pc1 joined without a restart; the job restarts
# it and waits for checks\member-ready.ps1.
# Keeps: join.pcapng (to captures/w10-pc1.pcapng), pktmon.txt, join.txt.
# Departs from the runbook: no Rename-Computer (handed over as pc1); the credential comes
# from the secret file; the capture stops before the restart, which the job does, instead of
# at it, so it holds the join and not the shutdown.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Secrets domain_admin_password -Pass 'pc1 joined corp.example.test through Tenko; the job restarts it' {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { Fail 'pc1 is a domain member already: restore the snapshot before this step' }
    Set-DnsServerOfLab $Tenko
    Start-Capture 'join' 53, 88
    try {
        Add-Computer -DomainName corp.example.test -Credential (Get-DomainAdminCredential) -Force -PassThru |
            Format-List * | Out-File -Encoding utf8 (Join-Path $StepDir 'join.txt')
        Start-Sleep -Seconds 10
    } finally {
        Stop-Capture 'join'
    }
}
