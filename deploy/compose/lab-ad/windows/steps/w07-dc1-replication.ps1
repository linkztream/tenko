# W7, check on dc1: replication between the two controllers (README.md section W7), on dc1 as
# CORP\Administrator.
#
# Expects: dc2 promoted.
# Leaves: nothing changed.
# Keeps: replication.txt (repadmin /replsummary).
# Checks: no failed replication and no operational error.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass 'repadmin /replsummary on dc1 shows no error' {
    Test-Replication
}
