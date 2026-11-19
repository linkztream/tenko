# W2, the starting state (README.md section W2), on dc1 as CORP\Administrator.
#
# Expects: W1 done (the zones with aging on, printer1, srv1 joined and registered).
# Leaves: nothing changed but the zone export files under %SystemRoot%\System32\dns\.
# Keeps (the step directory, the runbook's C:\lab): w2-zones.txt, w2-records-<zone>.csv,
# <zone>.dns (the three exports, which W4 imports on ns1), w2-ds.txt, w2-netlogon-dc1.dns,
# w2-age-count.txt, w2-dcdiag-before.txt.
# Checks: the exports hold lines with [AGE:n]; printer1 has no timestamp and srv1 has one.
# When no record has a timestamp, the script does what the runbook says (register again, wait
# a minute, collect again) once, and fails if there is still none.
param([switch]$Inner)
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

$zones = 'corp.example.test', '_msdcs.corp.example.test', '2.0.192.in-addr.arpa'

function Save-StartingState {
    Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated, ReplicationScope, DynamicUpdate -AutoSize |
        Out-File -Encoding utf8 (Join-Path $StepDir 'w2-zones.txt')
    foreach ($zone in $zones) {
        Get-DnsServerResourceRecord -ZoneName $zone |
            Select-Object HostName, RecordType, Timestamp, TimeToLive, @{ n = 'Data'; e = { $_.RecordData | Out-String } } |
            Export-Csv -NoTypeInformation (Join-Path $StepDir "w2-records-$zone.csv")
        $export = "$env:SystemRoot\System32\dns\$zone.dns"
        if (Test-Path $export) { Remove-Item $export }
        Invoke-Native 'w2-export.txt' { dnscmd /ZoneExport $zone "$zone.dns" }
        Copy-Item $export $StepDir
    }
    $count = @(Select-String -Path (Join-Path $StepDir '*.dns') -Pattern '\[AGE:').Count
    "lines with [AGE:n]: $count" | Save-Output 'w2-age-count.txt'
    $count
}

Invoke-Step -AsDomainAdmin -Inner:$Inner -Pass 'the exports hold aging timestamps; printer1 is static, srv1 dynamic' {
    if ((Save-StartingState) -eq 0) {
        Invoke-Native 'w2-register.txt' { ipconfig /registerdns }
        Invoke-Native 'w2-register.txt' { nltest /dsregdns }
        Start-Sleep -Seconds 60
        if ((Save-StartingState) -eq 0) { Fail 'no record of the exports has an aging timestamp, also after registering again' }
    }
    Get-DnsServerDsSetting | Format-List TombstoneInterval, DirectoryPartitionAutoEnlistInterval |
        Out-File -Encoding utf8 (Join-Path $StepDir 'w2-ds.txt')
    Copy-Item "$env:SystemRoot\System32\config\netlogon.dns" (Join-Path $StepDir 'w2-netlogon-dc1.dns')
    Invoke-Native 'w2-dcdiag-before.txt' { dcdiag /test:dns /v } -AnyStatus

    $records = Import-Csv (Join-Path $StepDir 'w2-records-corp.example.test.csv')
    $printer = @($records | Where-Object { $_.HostName -eq 'printer1' -and $_.RecordType -eq 'A' })
    $member = @($records | Where-Object { $_.HostName -eq 'srv1' -and $_.RecordType -eq 'A' })
    if ($printer.Count -ne 1 -or $printer[0].Timestamp) { Fail 'printer1 is missing or has a timestamp (w2-records-corp.example.test.csv)' }
    if ($member.Count -ne 1 -or -not $member[0].Timestamp) { Fail 'srv1 is missing or has no timestamp (w2-records-corp.example.test.csv)' }
}
