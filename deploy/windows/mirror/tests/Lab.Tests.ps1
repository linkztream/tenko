# The records of a Windows Server 2025 lab server (fixtures/lab-dc1: the shapes the cmdlets
# return there, documentation addresses only), held to fixtures/lab-dc1/expected-snapshot.json,
# which the server's tests decode, validate, store and diff as well
# (crates/tenko-migrate/tests/mirror_service.rs). What these records showed: option 81 at
# the server and scope level, an allow list that is on and empty, one superscope row without
# a name, one object where many are possible, and no object at all where there is none.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-DhcpMirror.ps1')
    . (Join-Path $PSScriptRoot 'Fixtures.ps1')
    Install-DhcpServerMock -Set (Join-Path -Path 'fixtures' -ChildPath 'lab-dc1')
}

Describe 'The snapshot of the lab server' {
    BeforeAll {
        $raw = Read-DhcpServer
        $snapshot = ConvertTo-MirrorSnapshot -Raw $raw -Sequence 1795204515 -TakenAt '2026-11-20T19:55:15Z' -ServerName 'dc1.corp.example.test'
        $expected = Get-Content -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath (Join-Path -Path 'fixtures' -ChildPath (Join-Path -Path 'lab-dc1' -ChildPath 'expected-snapshot.json'))) -Raw -Encoding UTF8 | ConvertFrom-Json
        $codes = @($snapshot.losses.entries | ForEach-Object { $_.code })
    }

    It 'equals the expected snapshot in canonical form' {
        ConvertTo-CanonicalJson $snapshot | Should -Be (ConvertTo-CanonicalJson $expected)
    }

    It 'keeps only the named properties of every record' {
        @($raw.scopes[0].PSObject.Properties.Name) | Should -Be $script:ReadProperties.Scope
        @($raw.superscopes[0].PSObject.Properties.Name) | Should -Be $script:ReadProperties.Superscope
    }

    It 'never carries option 81, whose settings are the scope''s ddns' {
        $snapshot.dhcp.server_options.Count | Should -Be 0
        @($snapshot.dhcp.scopes[0].options | ForEach-Object { $_.code }) | Should -Be @(3, 6, 15)
        $snapshot.dhcp.scopes[0].ddns.enabled | Should -BeFalse
        $policyOption = [pscustomobject]@{ OptionId = 81; PolicyName = 'guests'; Value = @('21'); VendorClass = ''; UserClass = '' }
        $losses = [System.Collections.ArrayList]::new()
        ConvertTo-IrOption -Value $policyOption -Sheet 'Get-DhcpServerv4OptionValue' -Scope '192.0.2.10' -Losses $losses | Should -BeNullOrEmpty
        $losses.Count | Should -Be 0
    }

    It 'restricts every scope to an allow list that is on and empty, and reports each reservation it does not list' {
        $snapshot.dhcp.scopes[0].restricted | Should -BeTrue
        $snapshot.dhcp.filters.Count | Should -Be 0
        @($snapshot.losses.entries | Where-Object { $_.code -eq 'migrate.loss.filter_reservation' } | ForEach-Object { $_.location.column }) | Should -Be @('192.0.2.102', '192.0.2.100', '192.0.2.101')
    }

    It 'reports no superscope for the row of the scopes in none' {
        $codes | Should -Not -Contain 'migrate.loss.superscope'
    }

    It 'reads the leases with -AllLeases and leaves the expired one out' {
        Should -Invoke Get-DhcpServerv4Lease -ParameterFilter { $AllLeases } -Times 1 -Exactly -Scope Describe
        @($snapshot.dhcp.leases | ForEach-Object { "$($_.ip) $($_.state)" }) | Should -Be @('192.0.2.110 active', '192.0.2.111 declined')
    }

    It 'writes every loss code the server knows' {
        foreach ($code in $codes) { $code | Should -Match '^migrate\.loss\.[a-z_]+$' }
    }
}

Describe 'The filter lists' {
    BeforeAll {
        # The entries as the lab recorded them, in upper case.
        $entries = @(
            [pscustomobject]@{ Description = 'lab allow test'; List = 'Allow'; MacAddress = '00-00-5E-00-53-20' },
            [pscustomobject]@{ Description = 'lab deny test'; List = 'Deny'; MacAddress = '00-00-5E-00-53-21' }
        )
        $reservations = @(
            [ordered]@{ ip = '192.0.2.100'; client = [ordered]@{ mac = '00:00:5e:00:53:01' } },
            [ordered]@{ ip = '192.0.2.120'; client = [ordered]@{ mac = '00:00:5e:00:53:20' } }
        )
        function Get-Raw { param([bool]$Allow, [bool]$Deny, [object[]]$Filters) @{ filter_lists = @([pscustomobject]@{ Allow = $Allow; Deny = $Deny }); filters = $Filters } }
    }

    It 'carries the entries of both lists when both are on, lowercase with colons' {
        $losses = [System.Collections.ArrayList]::new()
        $filters = ConvertTo-IrFilterList -Raw (Get-Raw -Allow $true -Deny $true -Filters $entries) -Losses $losses
        @($filters | ForEach-Object { "$($_.kind) $($_.mac)" }) | Should -Be @('allow 00:00:5e:00:53:20', 'deny 00:00:5e:00:53:21')
        $filters[0].origin.column | Should -Be '00-00-5E-00-53-20'
        $losses.Count | Should -Be 0
    }

    It 'carries nothing of a list that is off, and restricts nothing then' {
        $losses = [System.Collections.ArrayList]::new()
        @(ConvertTo-IrFilterList -Raw (Get-Raw -Allow $false -Deny $true -Filters $entries) -Losses $losses | ForEach-Object { $_.kind }) | Should -Be @('deny')
        Get-AllowPattern (Get-Raw -Allow $false -Deny $true -Filters $entries) | Should -BeNullOrEmpty
        (ConvertTo-IrFilterList -Raw (Get-Raw -Allow $false -Deny $false -Filters $null) -Losses $losses).Count | Should -Be 0
    }

    It 'reports the reservations the allow list does not list, wildcards included' {
        $losses = [System.Collections.ArrayList]::new()
        Add-AllowListLoss -Reservations $reservations -Allowed (Get-AllowPattern (Get-Raw -Allow $true -Deny $false -Filters $entries)) -Losses $losses
        @($losses | ForEach-Object { $_.location.column }) | Should -Be @('192.0.2.100')
        $losses.Clear()
        Add-AllowListLoss -Reservations $reservations -Allowed @('00:00:5e:00:53:*') -Losses $losses
        $losses.Count | Should -Be 0
    }

    It 'reports an entry Tenko cannot match, saying which way the restriction is lost' {
        $losses = [System.Collections.ArrayList]::new()
        $odd = @([pscustomobject]@{ Description = ''; List = 'Deny'; MacAddress = '00-00-5E-00-53' })
        (ConvertTo-IrFilterList -Raw (Get-Raw -Allow $false -Deny $true -Filters $odd) -Losses $losses).Count | Should -Be 0
        $losses[0].code | Should -Be 'migrate.loss.filter'
        $losses[0].detail | Should -Match 'Tenko would serve the client the server refuses'
    }

    It 'reads a MAC address pattern by the rule of the server' {
        ConvertTo-MacPattern '00-00-5E-00-53-20' | Should -Be '00:00:5e:00:53:20'
        ConvertTo-MacPattern '00-00-5E-*' | Should -Be '00:00:5e:*:*:*'
        ConvertTo-MacPattern '00-00-5E' | Should -BeNullOrEmpty
        ConvertTo-MacPattern '00-00-5E-00-53-20-01' | Should -BeNullOrEmpty
        ConvertTo-MacPattern 'zz-00-5E-00-53-20' | Should -BeNullOrEmpty
    }
}
