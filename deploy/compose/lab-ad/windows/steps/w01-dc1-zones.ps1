# W1, second part: the reverse zone, aging, the static record and the registration (README.md
# section W1), on dc1 as CORP\Administrator.
#
# Expects: dc1 promoted and restarted (checks\dc-ready.ps1 passed); the secret
# domain_admin_password.
# Leaves: the zone 2.0.192.in-addr.arpa (secure only, domain scope), aging on for the three
# zones, printer1 A 192.0.2.40 with its PTR, the controller's records registered again; and
# dc1 announcing itself as a reliable time source, so that ns1's systemd-timesyncd takes it
# (the runbook's names section: every machine's clock follows the first controller).
# Keeps: zones.txt, register.txt, time.txt.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass 'the reverse zone, aging and printer1 are in place; dc1 registered again' {
    if ((Get-ADDomain).DNSRoot -ne 'corp.example.test') { Fail 'dc1 is not a controller of corp.example.test' }
    Add-DnsServerPrimaryZone -NetworkId 192.0.2.0/24 -ReplicationScope Domain -DynamicUpdate Secure
    foreach ($zone in 'corp.example.test', '_msdcs.corp.example.test', '2.0.192.in-addr.arpa') {
        Set-DnsServerZoneAging -Name $zone -Aging $true
    }
    Add-DnsServerResourceRecordA -ZoneName corp.example.test -Name printer1 -IPv4Address 192.0.2.40 -CreatePtr
    Invoke-Native 'register.txt' { ipconfig /registerdns }
    Invoke-Native 'register.txt' { nltest /dsregdns }
    Invoke-Native 'time.txt' { w32tm /config /reliable:yes /update }
    Restart-Service w32time
    Start-Sleep -Seconds 60
    Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate, IsAgingEnabled -AutoSize |
        Out-File -Encoding utf8 (Join-Path $StepDir 'zones.txt')
}
