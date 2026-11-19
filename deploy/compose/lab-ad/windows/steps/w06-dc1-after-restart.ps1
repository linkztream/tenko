# W6, second part: dc1 without the DNS Server role (README.md section W6), on dc1 as
# CORP\Administrator (dcdiag).
#
# Expects: dc1 restarted after the role's removal (checks\dc-ready.ps1 passed).
# Leaves: dc1's records registered again.
# Keeps: nltest.txt, w6-dcdiag.txt.
# Checks: no DNS service; nltest /dsregdns and /dsquerydns succeed against Tenko. Which
# dcdiag tests fail without the role is read by a person (RESULTS.md).
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass 'no DNS service on dc1; its registration and the check succeed against Tenko' {
    if (Get-Service DNS -ErrorAction SilentlyContinue) { Fail 'the DNS service is still there' }
    Invoke-Native 'nltest.txt' { nltest /dsregdns }
    Invoke-Native 'nltest.txt' { nltest /dsquerydns }
    Invoke-Native 'w6-dcdiag.txt' { dcdiag /test:dns /v } -AnyStatus
}
