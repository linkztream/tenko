# W3, first part: Tenko's Kerberos account by the block of section 4.1 (README.md section W3,
# items 1 and 2), on dc1 as CORP\Administrator.
#
# Expects: dc1 a controller; C:\lab\in\active-directory.md, the docs/active-directory.md of
# the commit under test; the secrets domain_admin_password and kerberos_onetime_password.
# Leaves: the OU "Service Accounts" and the computer account TENKO-DNS$ with the SPN
# DNS/ns1.corp.example.test and the one-time password.
# Keeps: New-TenkoAccount.ps1 (the block as saved), w3-block-sha256.txt, w3-block-output.txt.
# Checks: the block reports the encryption types 24.
# Departs from the runbook: the block is taken from section 4.1 of the documentation file by
# this script instead of by hand, and it is run unchanged in this session, where its
# Read-Host prompts are answered by a function of the same name that gives the runbook's
# values (TENKO-DNS, the OU, DNS/ns1.corp.example.test, an empty line, and the one-time
# password from its secret file twice, as a SecureString). An unattended session has no
# console to type into; the function refuses any prompt it does not expect, so a changed
# block stops here instead of receiving a wrong value. The block's input flushing then has
# no console to flush, which it already tolerates.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Secrets kerberos_onetime_password -Pass 'the block of section 4.1 created TENKO-DNS$ with AES only' {
    $doc = Join-Path $In 'active-directory.md'
    Assert-File $doc 'the job copies docs/active-directory.md of the commit under test'
    if ([IO.File]::ReadAllText($doc) -notmatch '(?ms)^### 4\.1 .*?^```powershell\r?\n(.*?)^```') {
        Fail 'section 4.1 of active-directory.md has no PowerShell block'
    }
    $block = Join-Path $StepDir 'New-TenkoAccount.ps1'
    [IO.File]::WriteAllText($block, $Matches[1])
    (Get-FileHash $block -Algorithm SHA256).Hash | Save-Output 'w3-block-sha256.txt'

    New-ADOrganizationalUnit -Name 'Service Accounts' -Path 'DC=corp,DC=example,DC=test'

    $password = Get-SecureSecret 'kerberos_onetime_password'
    $global:LabAnswers = [System.Collections.Queue]::new()
    foreach ($answer in @(
            @('Account name', 'TENKO-DNS'),
            @('Organizational unit', 'OU=Service Accounts,DC=corp,DC=example,DC=test'),
            @('SPN', 'DNS/ns1.corp.example.test'),
            @('SPN', ''),
            @('One-time password', $password),
            @('The same password again', $password))) { $global:LabAnswers.Enqueue($answer) }
    function global:Read-Host {
        param([Parameter(Position = 0)][string]$Prompt, [switch]$AsSecureString)
        if ($global:LabAnswers.Count -eq 0) { throw "the block asked more than the lab answers: $Prompt" }
        $expected, $value = $global:LabAnswers.Dequeue()
        if (-not $Prompt.StartsWith($expected) -or $AsSecureString -ne ($value -is [securestring])) {
            throw "the block asked '$Prompt' where the lab expects '$expected'"
        }
        "${Prompt}: $(if ($AsSecureString) { '(secret)' } else { $value })" | Out-Host
        $value
    }
    try {
        & $block *>&1 | ForEach-Object { "$_" } | Save-Output 'w3-block-output.txt'
        if ($global:LabAnswers.Count -gt 0) { Fail 'the block asked fewer questions than the lab answers: it changed' }
    } finally {
        Remove-Item function:global:Read-Host
        $global:LabAnswers = $null
    }
    if (-not (Select-String -Path (Join-Path $StepDir 'w3-block-output.txt') -Pattern '^Encryption:\s+24\b' -Quiet)) {
        Fail 'the block did not report the encryption types 24 (w3-block-output.txt)'
    }
}
