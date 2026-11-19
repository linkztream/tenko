# W4, first part: the SIDs of the secure-only policy (README.md section W4), on dc1 as SYSTEM
# (the controller's own account reads them).
#
# Expects: dc1 a controller with the DNS Server role (DnsAdmins and DnsUpdateProxy exist).
# Leaves: nothing changed.
# Keeps: sids.json (domain, dnsadmins, dnsupdateproxy), which the ns1 part of W4 reads.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass 'the domain, DnsAdmins and DnsUpdateProxy SIDs are in sids.json' {
    [ordered]@{
        domain         = (Get-ADDomain).DomainSID.Value
        dnsadmins      = (Get-ADGroup DnsAdmins).SID.Value
        dnsupdateproxy = (Get-ADGroup DnsUpdateProxy).SID.Value
    } | ConvertTo-Json | Save-Output 'sids.json'
}
