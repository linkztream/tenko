# W7, first part: dc2 becomes a controller without the DNS Server role (README.md section
# W7), on dc2 as SYSTEM.
#
# Expects: a Windows Server named dc2 with the static address 192.0.2.6, not promoted; the
# secrets domain_admin_password and dsrm_password.
# Leaves: dc2's DNS client at 192.0.2.53 only; the AD DS role; dc2 promoted into
# corp.example.test without DNS and without a restart; the job restarts it and waits for
# checks\dc-ready.ps1.
# Keeps: install.txt.
# Departs from the runbook: no Rename-Computer (handed over as dc2); the credential and the
# restore password come from their secret files instead of prompts; -NoRebootOnCompletion.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Secrets domain_admin_password, dsrm_password -Pass 'dc2 is promoted without the DNS Server role, through Tenko; the job restarts it' {
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { Fail 'dc2 is a domain controller already: restore the snapshot before this step' }
    Set-DnsServerOfLab $Tenko
    $out = Join-Path $StepDir 'install.txt'
    $feature = Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    $feature | Format-List * | Out-File -Encoding utf8 $out
    if (-not $feature.Success) { Fail 'Install-WindowsFeature AD-Domain-Services failed (install.txt)' }
    $result = Install-ADDSDomainController -DomainName corp.example.test -InstallDns:$false `
        -Credential (Get-DomainAdminCredential) -SafeModeAdministratorPassword (Get-SecureSecret 'dsrm_password') `
        -NoRebootOnCompletion:$true -Force:$true
    $result | Format-List * | Out-File -Append -Encoding utf8 $out
    if ($result.Status -ne 'Success') { Fail "Install-ADDSDomainController: $($result.Status) $($result.Message) (install.txt)" }
}
