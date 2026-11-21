# W14: the health of the domain (README.md section W14), on dc1 and on dc2 as
# CORP\Administrator. One script for both entries.
#
# Expects: every earlier step passed.
# Leaves: nothing changed.
# Keeps: w14-dcdiag.txt, w14-dcdiag-all.txt, w14-sysvol.txt, w14-repl.txt (to
# results/w14/<machine>/).
# Checks: the default dcdiag tests report no failed test, SystemLog and DFSREvent apart;
# the SYSVOL replicated folder is in the normal state; repadmin /replsummary shows no
# error. The dcdiag DNS tests that need the DNS Server role, and what SystemLog and
# DFSREvent flag, are listed by a person in RESULTS.md.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -AdminMinutes 45 -Pass "dcdiag and repadmin on $Computer show no error" {
    Invoke-Native 'w14-dcdiag.txt' { dcdiag /test:dns /v } -AnyStatus
    Invoke-Native 'w14-dcdiag-all.txt' { dcdiag } -AnyStatus
    # SystemLog and DFSREvent judge the event logs of the last day, not the state: every start
    # of a controller during the run (its powered-off snapshots, the promotion) leaves errors
    # there. Their output is kept for a person, and the state of SYSVOL is read instead.
    # A dcdiag that did not run prints no failed test either: require that some test passed.
    if (-not (Select-String -Path (Join-Path $StepDir 'w14-dcdiag-all.txt') -Pattern 'passed test' -Quiet)) {
        Fail 'dcdiag ran no test: w14-dcdiag-all.txt has no passed test'
    }
    $failed = @(Select-String -Path (Join-Path $StepDir 'w14-dcdiag-all.txt') -Pattern 'failed test' |
            Where-Object { $_.Line -notmatch 'failed test (SystemLog|DFSREvent)\s*$' })
    if ($failed.Count -gt 0) { Fail "dcdiag: $(($failed | ForEach-Object { $_.Line.Trim() }) -join '; ')" }
    $sysvol = @(Get-CimInstance -Namespace 'root\microsoftdfs' -ClassName DfsrReplicatedFolderInfo -Filter "ReplicatedFolderName='SYSVOL Share'")
    "SYSVOL replicated folder state: $(($sysvol | ForEach-Object { $_.State }) -join ', ') (4 is normal)" | Save-Output 'w14-sysvol.txt'
    if ($sysvol.Count -ne 1 -or $sysvol[0].State -ne 4) { Fail 'the SYSVOL replicated folder is not in the normal state (w14-sysvol.txt)' }
    Test-Replication 'w14-repl.txt'
}
