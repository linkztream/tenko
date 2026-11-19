# W6, first part: the DNS Server role leaves dc1 (README.md section W6), on dc1 as SYSTEM.
#
# Expects: W5 passed (dc1 registers with Tenko); srv1 already points at Tenko (W11 runs
# before this step, see README.md, "Running the steps unattended").
# Leaves: the DNS Server role removed without a restart; the job restarts dc1 and waits for
# checks\dc-ready.ps1.
# Keeps: uninstall.txt.
# Departs from the runbook: no -Restart, since the job restarts the machine.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'the DNS Server role is removed from dc1; the job restarts it' {
    $result = Uninstall-WindowsFeature -Name DNS
    $result | Format-List * | Out-File -Encoding utf8 (Join-Path $StepDir 'uninstall.txt')
    if (-not $result.Success) { Fail 'Uninstall-WindowsFeature DNS failed (uninstall.txt)' }
}
