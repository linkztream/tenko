# W3, last part: the one-time password no longer works (README.md section W3, item 4), on dc1
# as CORP\Administrator.
#
# Expects: Tenko adopted TENKO-DNS$ (the ns1 part of W3); C:\lab\in\kerberos-status.json, the
# `tenko dns kerberos status --json` that the ns1 part kept.
# Leaves: nothing changed.
# Keeps: w3-account.txt (the account's attributes).
# Checks: Tenko's current key version equals msDS-KeyVersionNumber, the encryption types are
# 24, the SPN is DNS/ns1.corp.example.test, and PasswordLastSet is within the last half hour
# (the adoption changed the password).
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass "Tenko's key version equals msDS-KeyVersionNumber; the password was changed by the adoption" {
    $status = Join-Path $In 'kerberos-status.json'
    Assert-File $status "the job copies the ns1 part's kerberos-status.json"
    $account = Get-ADComputer TENKO-DNS -Properties msDS-KeyVersionNumber, msDS-SupportedEncryptionTypes, servicePrincipalName, PasswordLastSet
    $account | Format-List Name, msDS-KeyVersionNumber, msDS-SupportedEncryptionTypes, servicePrincipalName, PasswordLastSet |
        Out-File -Encoding utf8 (Join-Path $StepDir 'w3-account.txt')
    $current = @((Get-Content $status -Raw | ConvertFrom-Json).account.versions | Where-Object { $_.state -eq 'current' })
    if ($current.Count -ne 1) { Fail "Tenko's status lists $($current.Count) current key versions, not one" }
    if ($current[0].kvno -ne $account.'msDS-KeyVersionNumber') {
        Fail "Tenko's key version $($current[0].kvno) differs from msDS-KeyVersionNumber $($account.'msDS-KeyVersionNumber')"
    }
    if ($account.'msDS-SupportedEncryptionTypes' -ne 24) { Fail 'msDS-SupportedEncryptionTypes is not 24' }
    if (@($account.servicePrincipalName) -notcontains 'DNS/ns1.corp.example.test') { Fail 'the account does not hold DNS/ns1.corp.example.test' }
    if ($account.PasswordLastSet -lt (Get-Date).AddMinutes(-30)) { Fail 'PasswordLastSet is older than half an hour: the adoption did not change the password' }
}
