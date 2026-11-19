# W1, first part: the forest with the DNS Server role (README.md section W1), on dc1 as
# SYSTEM.
#
# Expects: a Windows Server named dc1 with the static address 192.0.2.5 and its DNS client
# pointing at itself, not promoted; the secrets dsrm_password and domain_admin_password.
# Leaves: the built-in Administrator account (RID 500) enabled, named Administrator, with the
# password of domain_admin_password: the promotion makes it CORP\Administrator. Then the AD DS
# and DNS Server roles and the forest corp.example.test (NetBIOS CORP) with DNS, promoted
# without a restart; the job restarts dc1 and waits for checks\dc-ready.ps1.
# Keeps: install.txt (the role installation and the promotion's result).
# Departs from the runbook: no Rename-Computer (the machine is handed over as dc1); the
# restore password comes from its secret file instead of Read-Host; -NoRebootOnCompletion,
# since the job restarts the machine.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Secrets dsrm_password, domain_admin_password -Pass 'dc1 is promoted to the forest corp.example.test with the DNS Server role; the job restarts it' {
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { Fail 'dc1 is a domain controller already: restore the baseline snapshot' }
    if (-not (Get-NetIPAddress -IPAddress 192.0.2.5 -ErrorAction SilentlyContinue)) { Fail 'this machine does not have the address 192.0.2.5' }

    $builtin = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' }
    if ($builtin.Name -ne 'Administrator') { Rename-LocalUser -SID $builtin.SID -NewName 'Administrator' }
    Set-LocalUser -SID $builtin.SID -Password (Get-SecureSecret 'domain_admin_password') -PasswordNeverExpires $true
    Enable-LocalUser -SID $builtin.SID

    $out = Join-Path $StepDir 'install.txt'
    $features = Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
    $features | Format-List * | Out-File -Encoding utf8 $out
    if (-not $features.Success) { Fail 'Install-WindowsFeature AD-Domain-Services, DNS failed (install.txt)' }

    $result = Install-ADDSForest -DomainName corp.example.test -DomainNetbiosName CORP -InstallDns:$true `
        -SafeModeAdministratorPassword (Get-SecureSecret 'dsrm_password') -NoRebootOnCompletion:$true -Force:$true
    $result | Format-List * | Out-File -Append -Encoding utf8 $out
    if ($result.Status -ne 'Success') { Fail "Install-ADDSForest: $($result.Status) $($result.Message) (install.txt)" }
}
