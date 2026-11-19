# W14: the health of the domain (README.md section W14), on dc1 and on dc2 as
# CORP\Administrator. One script for both entries.
#
# Expects: every earlier step passed.
# Leaves: nothing changed.
# Keeps: w14-dcdiag.txt, w14-dcdiag-all.txt, w14-repl.txt (to results/w14/<machine>/).
# Checks: the default dcdiag tests report no failed test, and repadmin /replsummary shows no
# error. The dcdiag DNS tests that need the DNS Server role are listed by a person in
# RESULTS.md.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -AdminMinutes 45 -Pass "dcdiag and repadmin on $Computer show no error" {
    Invoke-Native 'w14-dcdiag.txt' { dcdiag /test:dns /v } -AnyStatus
    Invoke-Native 'w14-dcdiag-all.txt' { dcdiag } -AnyStatus
    $failed = @(Select-String -Path (Join-Path $StepDir 'w14-dcdiag-all.txt') -Pattern 'failed test')
    if ($failed.Count -gt 0) { Fail "dcdiag: $(($failed | ForEach-Object { $_.Line.Trim() }) -join '; ')" }
    Test-Replication 'w14-repl.txt'
}
