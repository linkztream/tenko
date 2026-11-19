# W1, third part: srv1 joins the domain (README.md section W1), on srv1 as SYSTEM.
#
# Expects: a Windows Server named srv1 with the static address 192.0.2.20 and its DNS client
# at 192.0.2.5, not joined; dc1 a controller; the secret domain_admin_password.
# Leaves: srv1 joined to corp.example.test without a restart; the job restarts it and waits
# for checks\member-ready.ps1.
# Keeps: join.txt.
# Departs from the runbook: no Rename-Computer (handed over as srv1); the credential is built
# from the secret file instead of a prompt; no -Restart, since the job restarts the machine.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Secrets domain_admin_password -Pass 'srv1 joined corp.example.test; the job restarts it' {
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { Fail 'srv1 is a domain member already: restore the snapshot before this step' }
    Add-Computer -DomainName corp.example.test -Credential (Get-DomainAdminCredential) -Force -PassThru |
        Format-List * | Out-File -Encoding utf8 (Join-Path $StepDir 'join.txt')
}
