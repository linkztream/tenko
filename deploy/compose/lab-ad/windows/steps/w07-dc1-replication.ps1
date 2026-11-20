# W7, check on dc1: replication between the two controllers (README.md section W7), on dc1 as
# CORP\Administrator.
#
# Expects: dc2 promoted.
# Leaves: the two controllers replicated in both directions.
# Keeps: kcc-dc1.txt, kcc-dc2.txt, syncall-Ade.txt, syncall-AdeP.txt, replication.txt
# (repadmin /replsummary).
# Checks: both synchronizations end without errors; no failed replication and no
# operational error in the summary.
# Departs from the runbook: it rebuilds the links and replicates before it reads the
# summary, where the runbook's operator would wait for Windows to try again.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass 'dc1 and dc2 replicate in both directions; repadmin /replsummary on dc1 shows no error' {
    # A controller's first attempts right after its promotion fail while its records are not
    # yet registered, and the next attempt can be a quarter of an hour away: rebuild the
    # links and replicate now, so the verdict is of the lab and not of that schedule.
    foreach ($dc in 'dc1', 'dc2') { Invoke-Native "kcc-$dc.txt" { repadmin /kcc "$dc.corp.example.test" } }
    foreach ($way in '/Ade', '/AdeP') {
        $file = "syncall$($way.Replace('/', '-')).txt"
        Invoke-Native $file { repadmin /syncall $way }
        if (-not ((Get-Content (Join-Path $StepDir $file)) -match 'terminated with no errors')) { Fail "repadmin /syncall $way reported errors ($file)" }
    }
    Test-Replication
}
