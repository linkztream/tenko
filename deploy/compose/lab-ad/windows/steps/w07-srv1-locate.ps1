# W7, check on srv1: the member finds a controller through Tenko (README.md section W7), on
# srv1 as SYSTEM.
#
# Expects: dc2 promoted and registered; srv1's DNS client at 192.0.2.53 (W11 ran before W6).
# Leaves: nothing changed.
# Keeps: nltest.txt.
# Checks: nltest /dsgetdc:corp.example.test /force succeeds.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'srv1 finds a controller of corp.example.test through Tenko' {
    Invoke-Native 'nltest.txt' { nltest /dsgetdc:corp.example.test /force }
}
