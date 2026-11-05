# The mapping of the recorded cmdlet output of corp.example.test (fixtures/, plan section
# 3.4) onto the MirrorSnapshot envelope of section 3.1, held to fixtures/expected-snapshot.json
# (exit check E72). The cmdlets of the DhcpServer module are replaced by mocks that return
# the recorded output, so the suite runs on any host.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-DhcpMirror.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    Install-DhcpServerMock
}

Describe 'The snapshot of corp.example.test' {
    BeforeAll {
        $raw = Read-DhcpServer
        $snapshot = ConvertTo-MirrorSnapshot -Raw $raw -Sequence 42 -TakenAt '2026-11-06T09:30:00Z' -ServerName 'dc1.corp.example.test'
        $expected = Get-Content -LiteralPath (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'fixtures') -ChildPath 'expected-snapshot.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    It 'equals the expected snapshot byte for byte in canonical form' {
        $produced = ConvertTo-CanonicalJson $snapshot
        $wanted = ConvertTo-CanonicalJson $expected
        $at = 0
        while ($at -lt $produced.Length -and $at -lt $wanted.Length -and $produced[$at] -eq $wanted[$at]) { $at++ }
        $from = [math]::Max(0, $at - 120)
        $near = "at offset $at, produced: " + $produced.Substring($from, [math]::Min(300, $produced.Length - $from)) + " / expected: " + $wanted.Substring($from, [math]::Min(300, $wanted.Length - $from))
        $produced | Should -Be $wanted -Because $near
    }

    It 'carries the envelope of section 3.1' {
        $snapshot.format | Should -Be 1
        $snapshot.sequence | Should -Be 42
        $snapshot.taken_at | Should -Be '2026-11-06T09:30:00Z'
        $snapshot.source.kind | Should -Be 'windows-dhcp'
        $snapshot.source.server | Should -Be 'dc1.corp.example.test'
        $snapshot.source.adapter | Should -Be 'Tenko-DhcpMirror.ps1'
        $snapshot.source.adapter_version | Should -Match '^\d+\.\d+\.\d+$'
        @($snapshot.Keys) | Should -Be @('format', 'sequence', 'taken_at', 'source', 'dhcp', 'losses')
        @($snapshot.dhcp.Keys) | Should -Be @('server_options', 'option_defs', 'classes', 'scopes', 'superscopes', 'policies', 'filters', 'failover', 'leases')
    }

    It 'has one scope with thirty reservations and sixty leases' {
        $snapshot.dhcp.scopes.Count | Should -Be 1
        $snapshot.dhcp.scopes[0].cidr | Should -Be '192.0.2.0/24'
        $snapshot.dhcp.scopes[0].reservations.Count | Should -Be 30
        $snapshot.dhcp.leases.Count | Should -Be 60
    }

    It 'carries leases of each identity kind and leaves out expired and inactive ones' {
        $byState = @{}
        foreach ($lease in $snapshot.dhcp.leases) { $byState[$lease.state] = 1 + $(if ($byState.ContainsKey($lease.state)) { $byState[$lease.state] } else { 0 }) }
        $byState['active'] | Should -Be 52
        $byState['active_reservation'] | Should -Be 6
        $byState['declined'] | Should -Be 2
        @($snapshot.dhcp.leases | Where-Object { $_.client.Contains('mac') }).Count | Should -Be 46
        @($snapshot.dhcp.leases | Where-Object { $_.client.Contains('client_id') }).Count | Should -Be 14
        @($snapshot.dhcp.leases | Where-Object { $_.ip -in '192.0.2.180', '192.0.2.181', '192.0.2.14', '192.0.2.182' }).Count | Should -Be 0
        @($snapshot.dhcp.leases | Where-Object { $_.state -eq 'active_reservation' -and $_.Contains('expires') }).Count | Should -Be 0
    }

    It 'puts the policy, the filter, the superscope and the other losses in the report with their source location' {
        $codes = @($snapshot.losses.entries | ForEach-Object { $_.code })
        $codes | Should -Contain 'mirror.policy'
        $codes | Should -Contain 'mirror.filter'
        $codes | Should -Contain 'mirror.superscope'
        $codes | Should -Contain 'mirror.option.policy'
        $codes | Should -Contain 'mirror.option.managed'
        $codes | Should -Contain 'mirror.reservation.name'
        $codes | Should -Contain 'mirror.reservation.bootp'
        $codes | Should -Contain 'mirror.lease.state'
        $codes | Should -Contain 'mirror.option_def.default'
        foreach ($entry in $snapshot.losses.entries) {
            $entry.location.sheet | Should -Match '^Get-DhcpServerv4'
            $entry.location.column | Should -Not -BeNullOrEmpty
            $entry.detail | Should -Not -BeNullOrEmpty
        }
        $snapshot.dhcp.policies.Count | Should -Be 0
        $snapshot.dhcp.filters.Count | Should -Be 0
        $snapshot.dhcp.superscopes.Count | Should -Be 0
    }

    It 'keeps the names of section 2.9 as they are, lowercased, and reports the ones that are not host names' {
        $names = @{}
        foreach ($reservation in $snapshot.dhcp.scopes[0].reservations) { if ($reservation.Contains('name')) { $names[$reservation.ip] = $reservation.name } }
        $names['192.0.2.10'] | Should -Be 'printer01'
        $names['192.0.2.11'] | Should -Be 'nas01'
        $names['192.0.2.13'] | Should -Be 'printer02.corp.example.test'
        $names['192.0.2.14'] | Should -Be 'nas02.corp.example.test'
        $names['192.0.2.15'] | Should -Be 'esp_3a1f2b'
        $names['192.0.2.19'] | Should -Be 'backup.other.example'
        $names.ContainsKey('192.0.2.17') | Should -BeFalse
        $names.ContainsKey('192.0.2.20') | Should -BeFalse
        $reported = @($snapshot.losses.entries | Where-Object { $_.code -eq 'mirror.reservation.name' } | ForEach-Object { $_.location.column })
        $reported | Should -Be @('192.0.2.17', '192.0.2.18', '192.0.2.21', '192.0.2.38', '192.0.2.39')
    }

    It 'maps the DNS settings by the table of the runbook' {
        $ddns = $snapshot.dhcp.scopes[0].ddns
        $ddns.enabled | Should -BeTrue
        $ddns.client_may_update_a | Should -BeTrue
        $ddns.conflict | Should -Be 'protect'
        $ddns.reverse | Should -BeTrue
        $ddns.legacy_clients | Should -BeTrue
    }

    It 'produces the same bytes and hash on a second run' {
        $again = ConvertTo-MirrorSnapshot -Raw (Read-DhcpServer) -Sequence 42 -TakenAt '2026-11-06T09:30:00Z' -ServerName 'dc1.corp.example.test'
        $first = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson $snapshot))
        $second = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalJson $again))
        (Get-Sha256Hex $first) | Should -Be (Get-Sha256Hex $second)
    }

    It 'reads nothing but the listed cmdlets, and never the DNS credential' {
        $code = @(Get-Content -LiteralPath (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-DhcpMirror.ps1') | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $cmdlets = [regex]::Matches($code, '\b[A-Z][a-z]+-DhcpServer(?!Module\b)[A-Za-z0-9]+') | ForEach-Object { $_.Value } | Sort-Object -Unique
        $cmdlets | Should -Not -Contain 'Get-DhcpServerDnsCredential'
        foreach ($cmdlet in $cmdlets) { $cmdlet | Should -Match '^Get-DhcpServerv4' }
        $cmdlets | Should -Be @(
            'Get-DhcpServerv4Class', 'Get-DhcpServerv4DnsSetting', 'Get-DhcpServerv4ExclusionRange', 'Get-DhcpServerv4Failover',
            'Get-DhcpServerv4Filter', 'Get-DhcpServerv4Lease', 'Get-DhcpServerv4OptionDefinition', 'Get-DhcpServerv4OptionValue',
            'Get-DhcpServerv4Policy', 'Get-DhcpServerv4Reservation', 'Get-DhcpServerv4Scope', 'Get-DhcpServerv4Superscope'
        )
    }
}

Describe 'The dry run' {
    It '-Once prints the snapshot as JSON and pushes nothing' {
        Mock Invoke-MirrorPush { throw 'must not push' }
        Mock Read-MirrorToken { throw 'must not read the token' }
        $output = Invoke-MirrorRun -Once -ServerName 'dc1.corp.example.test' -StateDir (Join-Path $TestDrive 'state') -ConfigPath (Join-Path $TestDrive 'none.json') 3>$null
        $snapshot = ($output -join "`n") | ConvertFrom-Json
        $snapshot.format | Should -Be 1
        $snapshot.dhcp.leases.Count | Should -Be 60
        $snapshot.losses.entries.Count | Should -Be 13
        $snapshot.sequence | Should -BeGreaterThan 1700000000
        Should -Invoke Invoke-MirrorPush -Times 0
        Should -Invoke Read-MirrorToken -Times 0
    }
}

Describe 'The mapping rules' {
    Context 'values as the cmdlets and the recordings give them' {
        It 'reads an address as IPAddress, text or recorded object' {
            ConvertTo-IpText ([System.Net.IPAddress]::Parse('192.0.2.5')) | Should -Be '192.0.2.5'
            ConvertTo-IpText ' 192.0.2.5 ' | Should -Be '192.0.2.5'
            ConvertTo-IpText ([pscustomobject]@{ Address = 84017344; AddressFamily = 2; IPAddressToString = '192.0.2.5' }) | Should -Be '192.0.2.5'
            ConvertTo-IpText ([pscustomobject]@{ Address = 84017344; AddressFamily = 2 }) | Should -Be '192.0.2.5'
            ConvertTo-IpText $null | Should -BeNullOrEmpty
        }

        It 'reads a duration as TimeSpan, text or recorded object' {
            ConvertTo-SecondCount ([timespan]::FromDays(8)) | Should -Be 691200
            ConvertTo-SecondCount '8.00:00:00' | Should -Be 691200
            ConvertTo-SecondCount '01:00:00' | Should -Be 3600
            ConvertTo-SecondCount ([pscustomobject]@{ TotalSeconds = 691200.0 }) | Should -Be 691200
            ConvertTo-SecondCount $null | Should -BeNullOrEmpty
        }

        It 'converts a lease expiry to UTC in RFC 3339' {
            ConvertTo-UtcText ([datetime]::new(2026, 11, 13, 9, 30, 0, [System.DateTimeKind]::Utc)) | Should -Be '2026-11-13T09:30:00Z'
            ConvertTo-UtcText '2026-11-13T10:30:00+01:00' | Should -Be '2026-11-13T09:30:00Z'
            ConvertTo-UtcText '2026-11-13T09:30:00Z' | Should -Be '2026-11-13T09:30:00Z'
            ConvertTo-UtcText '/Date(1794562200000)/' | Should -Be '2026-11-13T09:30:00Z'
            ConvertTo-UtcText $null | Should -BeNullOrEmpty
            ConvertTo-UtcText '' | Should -BeNullOrEmpty
        }

        It 'reads the client identifier as a MAC address or as option 61 octets' {
            (ConvertFrom-ClientId '00-00-5E-00-53-10').mac | Should -Be '00:00:5e:00:53:10'
            (ConvertFrom-ClientId '00:00:5e:00:53:10').mac | Should -Be '00:00:5e:00:53:10'
            (ConvertFrom-ClientId 'ff-00-00-5e-00-53-24-00-01-00-01-2a-3b-4c-5d-00-00-5e-00-53-24').client_id | Should -Be ('ff00005e00532400010001' + '2a3b4c5d00005e005324')
            (ConvertFrom-ClientId 'c0-00-02-aa').client_id | Should -Be 'c00002aa'
            (ConvertFrom-ClientId '').Count | Should -Be 0
            (ConvertFrom-ClientId 'not hex').Count | Should -Be 0
        }

        It 'computes the prefix length from the subnet mask' {
            ConvertTo-PrefixLength '255.255.255.0' | Should -Be 24
            ConvertTo-PrefixLength '255.255.252.0' | Should -Be 22
            ConvertTo-PrefixLength '255.255.255.255' | Should -Be 32
            { ConvertTo-PrefixLength '255.0.255.0' } | Should -Throw
        }
    }

    Context 'the name rule of section 2.9 (HostName of tenko-core)' {
        It 'keeps a fully qualified name, lowercased, without the trailing dot' {
            ConvertTo-HostNameOrNull 'PRINTER02.CORP.EXAMPLE.TEST' | Should -Be 'printer02.corp.example.test'
            ConvertTo-HostNameOrNull 'nas02.corp.example.test.' | Should -Be 'nas02.corp.example.test'
        }
        It 'keeps a bare name and a factory name that is a valid label' {
            ConvertTo-HostNameOrNull 'NAS01' | Should -Be 'nas01'
            ConvertTo-HostNameOrNull 'ESP_3A1F2B' | Should -Be 'esp_3a1f2b'
            ConvertTo-HostNameOrNull 'android-5f2c9e01d4a6b7c8' | Should -Be 'android-5f2c9e01d4a6b7c8'
        }
        It 'refuses what is not a host name instead of tidying it' {
            ConvertTo-HostNameOrNull 'living room tv' | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull "Anna's iPad" | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull '-switch01' | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull 'switch01-' | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull ('K' + [char]0xFC + 'che-TV') | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull ('a' * 64) | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull ('a.' * 127 + 'a') | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull 'a..b' | Should -BeNullOrEmpty
            ConvertTo-HostNameOrNull '' | Should -BeNullOrEmpty
        }
    }

    Context 'the losses the fixture domain does not have' {
        BeforeAll {
            $losses = [System.Collections.ArrayList]::new()
        }

        It 'reports a failover relationship without reading its secret' {
            $failover = [pscustomobject]@{ Name = 'pair'; PartnerServer = 'dc2.corp.example.test'; Mode = 'LoadBalance'; ScopeId = @('192.0.2.0'); SharedSecret = 'swordfish' }
            Add-FailoverLoss -Failover $failover -Losses $losses
            $losses[0].code | Should -Be 'mirror.failover'
            $losses[0].location.sheet | Should -Be 'Get-DhcpServerv4Failover'
            $losses[0].location.column | Should -Be 'pair'
            $losses[0].detail | Should -Match 'dc2\.corp\.example\.test'
            $losses[0].detail | Should -Not -Match 'swordfish'
        }

        It 'reports an offer delay and a BOOTP-only scope' {
            $raw = @{ exclusions = @{ '192.0.2.0' = @() }; reservations = @{ '192.0.2.0' = @() }; reservation_options = @{}; scope_options = @{ '192.0.2.0' = @() }; dns = @{ '192.0.2.0' = @() } }
            $scope = [pscustomobject]@{ ScopeId = '192.0.2.0'; SubnetMask = '255.255.255.0'; Name = 'x'; State = 'InActive'; LeaseDuration = '1.00:00:00'; StartRange = '192.0.2.10'; EndRange = '192.0.2.20'; Delay = 500; Type = 'Bootp' }
            $ir = ConvertTo-IrScope -Scope $scope -Raw $raw -Losses $losses
            $ir.active | Should -BeFalse
            $ir.delay_ms | Should -Be 500
            $ir.lease_secs | Should -Be 86400
            $ir.Contains('ddns') | Should -BeFalse
            @($losses | Where-Object { $_.code -eq 'mirror.scope.delay' }).Count | Should -Be 1
            @($losses | Where-Object { $_.code -eq 'mirror.scope.bootp' }).Count | Should -Be 1
        }

        It 'reports a lease state the mirror does not carry, and leaves expired ones out silently' {
            $before = $losses.Count
            ConvertTo-IrLease -Lease ([pscustomobject]@{ IPAddress = '192.0.2.50'; AddressState = 'Expired'; ClientId = '00-00-5e-00-53-50' }) -Cidr '192.0.2.0/24' -Losses $losses | Should -BeNullOrEmpty
            $losses.Count | Should -Be $before
            ConvertTo-IrLease -Lease ([pscustomobject]@{ IPAddress = '192.0.2.51'; AddressState = 'ActivePending'; ClientId = '00-00-5e-00-53-51' }) -Cidr '192.0.2.0/24' -Losses $losses | Should -BeNullOrEmpty
            $losses[$losses.Count - 1].code | Should -Be 'mirror.lease.state'
            $losses[$losses.Count - 1].location.column | Should -Be '192.0.2.51'
        }

        It 'maps every DynamicUpdates value and reports the settings it cannot carry' {
            $never = ConvertTo-DdnsPolicy -Setting ([pscustomobject]@{ DynamicUpdates = 'Never'; NameProtection = $false; DisableDnsPtrRRUpdate = $true; UpdateDnsRRForOlderClients = $false; DeleteDnsRROnLeaseExpiry = $false; DnsSuffix = 'lab.example.test' }) -Scope '192.0.2.0' -Losses $losses
            $never.enabled | Should -BeFalse
            $never.conflict | Should -Be 'replace'
            $never.reverse | Should -BeFalse
            $never.legacy_clients | Should -BeFalse
            @($never.Keys) | Should -Be @('enabled', 'reverse', 'conflict', 'client_may_update_a', 'legacy_clients', 'refuse_foreign')
            @($losses | Where-Object { $_.code -eq 'mirror.ddns.keep_on_expiry' }).Count | Should -Be 1
            @($losses | Where-Object { $_.code -eq 'mirror.ddns.suffix' }).Count | Should -Be 1
            $always = ConvertTo-DdnsPolicy -Setting ([pscustomobject]@{ DynamicUpdates = 'Always'; NameProtection = $true; DisableDnsPtrRRUpdate = $false; UpdateDnsRRForOlderClients = $true; DeleteDnsRROnLeaseExpiry = $true }) -Scope '192.0.2.0' -Losses $losses
            $always.enabled | Should -BeTrue
            $always.client_may_update_a | Should -BeFalse
        }

        It 'maps the option definition types of the export and reports an unknown one' {
            $def = ConvertTo-IrOptionDef -Definition ([pscustomobject]@{ OptionId = 130; Name = 'x'; Type = 'Word'; MultiValued = $true; VendorClass = ''; Description = ''; DefaultValue = $null }) -Losses $losses
            $def.kind | Should -Be 'u16'
            $def.array | Should -BeTrue
            $def.Contains('description') | Should -BeFalse
            ConvertTo-IrOptionDef -Definition ([pscustomobject]@{ OptionId = 131; Name = 'y'; Type = 'Mystery'; MultiValued = $false; VendorClass = ''; Description = ''; DefaultValue = $null }) -Losses $losses | Should -BeNullOrEmpty
            $losses[$losses.Count - 1].code | Should -Be 'mirror.option_def.type'
            Test-CustomOptionDefinition ([pscustomobject]@{ OptionId = 6; VendorClass = '' }) | Should -BeFalse
            Test-CustomOptionDefinition ([pscustomobject]@{ OptionId = 1; VendorClass = 'Microsoft Windows 2000 Options' }) | Should -BeFalse
            Test-CustomOptionDefinition ([pscustomobject]@{ OptionId = 1; VendorClass = 'Example Phones' }) | Should -BeTrue
            Test-CustomOptionDefinition ([pscustomobject]@{ OptionId = 128; VendorClass = '' }) | Should -BeTrue
        }
    }

    Context 'the canonical JSON' {
        It 'writes the same bytes for a dictionary and for the parsed form' {
            $value = [ordered]@{ a = 1; b = @('x', $true, $null, 2.5); c = [ordered]@{ d = "q`"<>&`n" }; e = @(); f = [uint64]::MaxValue }
            $text = ConvertTo-CanonicalJson $value
            $text | Should -Be '{"a":1,"b":["x",true,null,2.5],"c":{"d":"q\"<>&\n"},"e":[],"f":18446744073709551615}'
            ConvertTo-CanonicalJson ($text | ConvertFrom-Json) | Should -Be $text
        }
    }
}
