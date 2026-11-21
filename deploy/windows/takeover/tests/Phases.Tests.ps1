# The phases against the fake domain and the fake Tenko of Fake.ps1 (MIG-17, MIG-08): every
# phase forward, again with nothing changed, and back with -Reverse; a failure at each step
# stops with exit 2 and resumes; a value that Windows contradicts stops with exit 4; the
# refusals of the discovery and of the DHCP window; the DHCP window's order both ways.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    . (Join-Path $PSScriptRoot 'Fake.ps1')
    $savedProgramData = $env:ProgramData
    function Get-WindowsChange {
        # The calls that change Windows, from the world's log.
        $reads = 'ReadDomain', 'ReadZones', 'ReadDirectoryZones', 'ReadDhcpInDirectory', 'ReadDhcpServer', 'ReadComputers', 'ReadHardening', 'ReadLocalAdmins', 'ReadFeature', 'ReadMarker', 'ReadDhcpConfiguration', 'ReadRecords', 'ReadZone', 'ReadLeases', 'ReadAuthorization', 'ReadPwdLastSet', 'ReadGroups'
        return @($script:world.calls | Where-Object { $reads -notcontains $_.Split('|')[1] })
    }
    function Get-WindowsShape {
        # What the reverse must bring back.
        $w = $script:world
        $zones = foreach ($zone in $w.zones.Keys) { foreach ($dc in 'dc1', 'dc2') { $z = $w.zones[$zone][$dc]; "$zone|$dc|$($z.Type)|$($z.Ds)|$($z.Update)|$($z.Transfer)|$($z.Notify)|$(@($z.Secondaries) -join ',')|$(@($z.NotifyServers) -join ',')" } }
        return (@($zones) + "services $($w.services.dc1.Status)/$($w.services.dc1.Start)/$($w.services.dc1.Role) $($w.services.dc2.Status)/$($w.services.dc2.Start)/$($w.services.dc2.Role)" +
            "authorized $(@($w.authorized | Sort-Object) -join ',')" + "accounts $(@($w.accounts) -join ',')" + "gpo $($w.gpo)" + "tasks $(@($w.tasks) -join ',')" + "batch $($w.batchRight)" + "marker $($null -ne $w.marker)") -join "`n"
    }
}

AfterAll { $env:ProgramData = $savedProgramData }

Describe 'A whole run' {
    BeforeAll { Install-FakeWorld }

    It 'takes the domain through phases 2 to 5 in the first sitting and waits for the parallel period' {
        $script:start = Get-WindowsShape
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $w = $script:world
        $w.services.dc1.Status | Should -Be 'Stopped'
        $w.services.dc2.Start | Should -Be 'Disabled'
        @($w.authorized).Count | Should -Be 0
        $w.zones['corp.example.test'].dc1.Type | Should -Be 'Secondary'
        $w.zones['corp.example.test'].dc2.Type | Should -Be 'Secondary'
        @($w.tasks).Count | Should -Be 2
        @($w.tzones.Values | Where-Object { $_.kind -eq 'primary' }).Count | Should -Be 3
        @($w.gpoMembers) | Should -Be @('pc1')
    }

    It 'finishes in the second sitting after the confirmation, without starting the DHCP Server service' {
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 0
        $script:world.services.dc1.Role | Should -BeFalse
        $script:world.calls | Should -Not -Contain 'dc1|StartDhcp'
        $script:world.marker | Should -BeNullOrEmpty
        @($script:world.mirrors.Keys).Count | Should -Be 0
    }

    It 'changes nothing when run again' {
        $script:world.calls.Clear()
        $script:world.tenkoCalls.Clear()
        Invoke-FakeRun -Answers @('c') | Should -Be 0
        Get-WindowsChange | Where-Object { $_ -notmatch '\|WriteMarker$' } | Should -BeNullOrEmpty
        @($script:world.tenkoCalls | Where-Object { $_ -notmatch '^GET ' }) | Should -BeNullOrEmpty
    }

    It 'walks every phase back with -Reverse to the starting state' {
        foreach ($phase in 6, 5, 4, 3, 2) {
            Invoke-FakeRun -Reverse | Should -Be 5 -Because "phase $phase is reversed ($script:lastError)"
        }
        Get-WindowsShape | Should -Be $script:start
        @($script:world.mirrors.Keys).Count | Should -Be 0
        @($script:world.tzones.Keys).Count | Should -Be 0
    }
}

Describe 'A failure at a step' {
    It 'stops at <step> with exit 2, records it, and resumes there' -ForEach @(
        @{ step = '2.mirrors'; route = '^POST /migrate/mirrors$' }
        @{ step = '2.backups'; block = 'ExportDhcp' }
        @{ step = '2.mirror-account'; block = 'NewMirrorAccount' }
        @{ step = '2.exporter'; block = 'InstallExporter' }
        @{ step = '2.zone-lists'; block = 'SetZoneLists' }
        @{ step = '2.gpo'; block = 'NewGpo' }
        @{ step = '2.tenko-zones'; route = '^POST /dns/zones$' }
        @{ step = '2.tenko-pair'; route = 'prepare$' }
        @{ step = '3.review'; route = '^GET /migrate/runs/' }
        @{ step = '4.configuration'; block = 'ReadDhcpConfiguration' }
        @{ step = '4.replicate'; block = 'Replicate' }
        @{ step = '4.tenko-flip'; route = 'flip$' }
        @{ step = '4.windows-secondaries'; block = 'ConvertToSecondary' }
        @{ step = '4.register'; block = 'RegisterDns' }
        @{ step = '5.takeover'; route = 'takeover$' }
        @{ step = '5.silence'; block = 'StopDhcp' }
        @{ step = '5.check'; route = '^GET /migrate/takeovers' }
    ) {
        Install-FakeWorld
        if ($_.ContainsKey("block")) { $script:world.failAt = $_.block } else { $script:world.failRoute = $_.route }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $state = ConvertFrom-TkJson -Chars ([System.IO.File]::ReadAllText((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json')).ToCharArray())
        $state.steps[$step].state | Should -Be 'failed'
        $state.steps[$step].error | Should -Match 'injected'
        # The token of a mirror lives only in the process: a new sitting makes the mirrors anew.
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 3 -Because $script:lastError
        $state = ConvertFrom-TkJson -Chars ([System.IO.File]::ReadAllText((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json')).ToCharArray())
        $state.steps[$step].state | Should -Be 'done'
        @($script:world.tasks).Count | Should -Be 2
    }

    It 'stops at the finish''s <step> with exit 2 and resumes there' -ForEach @(
        @{ step = '6.tenko'; route = 'release$' }
        @{ step = '6.dhcp-role'; block = 'RemoveDhcpRole' }
        @{ step = '6.exporter'; block = 'RemoveExporter' }
        @{ step = '6.mirror-account'; block = 'RemoveMirrorAccount' }
        @{ step = '6.zone-objects'; block = 'RemoveZoneObject'; pre = { $script:world.directory += 'corp.example.test' } }
        @{ step = '6.mirrors'; route = '^DELETE /migrate/mirrors' }
    ) {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        if ($_.ContainsKey("pre")) { & $_.pre }
        if ($_.ContainsKey("block")) { $script:world.failAt = $_.block } else { $script:world.failRoute = $_.route }
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 2
        Invoke-FakeRun -Answers @('c') | Should -Be 0 -Because $script:lastError
    }
}

Describe 'A value from Tenko that Windows contradicts' {
    BeforeEach { Install-FakeWorld }

    It 'a mirror id that is not of the exact form stops with exit 4' {
        $script:world.badMirror = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 4
        $script:world.tasks | Should -BeNullOrEmpty
    }

    It 'a token that is not of the exact form stops with exit 4' {
        $script:world.badToken = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 4
        $script:world.calls | Should -Not -Contain 'dc1|ExportDhcp'
    }

    It 'a mirror''s fingerprint that is not the pinned root stops with exit 4' {
        $script:world.fingerprint = 'cd' * 32
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 4
    }

    It 'a copy of a zone that differs from a controller''s records refuses the flip with exit 4' {
        $script:world.tenkoRecordsDiffer = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 4
        $script:lastError | Should -Match 'differs from dc1'
        @($script:world.tenkoCalls | Where-Object { $_ -match 'flip$' }) | Should -BeNullOrEmpty
        $script:world.zones['corp.example.test'].dc1.Type | Should -Be 'Primary'
    }

    It 'a configuration that differs from the bound one stops the window before any change' {
        $script:world.configChanged = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 4
        $script:world.calls | Should -Not -Contain 'dc1|Replicate'
        @($script:world.tenkoCalls | Where-Object { $_ -match 'flip$' }) | Should -BeNullOrEmpty
    }

    It 'different leases do not stop the window' {
        $script:world.raw.leases = @{ '192.0.2.0' = @([pscustomobject]@{ IPAddress = [pscustomobject]@{ IPAddressToString = '192.0.2.101' }; ClientId = '00-00-5e-00-53-11'; HostName = 'pc9'; AddressState = 'Active'; LeaseExpiryTime = '2026-11-21T12:00:00Z' }) }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
    }

    It 'a later sitting whose locator answer differs from the discovery''s stops before any session' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.locator = @{ name = 'dc9.corp.example.test'; address = '203.0.113.9' }
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 4
        $script:world.calls | Should -BeNullOrEmpty
    }

    It 'a controller that resolves to an address the discovery did not record stops before any session' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.addresses['dc2.corp.example.test'] = @('203.0.113.12')
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 4
        $script:world.calls | Should -BeNullOrEmpty
    }

    It 'a value to restore outside the discovery''s classes stops the reverse with exit 4' {
        $readings = [ordered]@{ controllers = @([ordered]@{ addresses = @('192.0.2.11') }); values = @('NoTransfer') }
        { Assert-TkRestoreValue -Readings $readings -Value '203.0.113.9' -Class address } | Should -Throw '*not one the discovery recorded*'
        { Assert-TkRestoreValue -Readings $readings -Value 'TransferAnyServer' -Class discovered } | Should -Throw '*not one the discovery recorded*'
        { Assert-TkRestoreValue -Readings $readings -Value '192.0.2.11' -Class address } | Should -Not -Throw
    }
}

Describe 'The refusals' {
    BeforeEach { Install-FakeWorld }

    It 'a zone that takes secure updates only is refused in phase 0 with the release''s sentence, nothing changed, no Tenko' {
        $script:world.zones['corp.example.test'].dc1.Update = 'Secure'
        Invoke-FakeRun -Answers @('corp.example.test', '1') | Should -Be 1
        (Get-WindowsChange) | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        Should -Invoke Connect-TkNode -Times 0
        $readings = Get-TkDiscovery -Domain 'corp.example.test'
        $readings.refusals | Should -Contain 'The zone corp.example.test takes secure updates only. This release of Tenko cannot yet take over a zone that takes secure updates only without weakening it, because its secure updates (the Kerberos line of the identity plan) are not complete. Nothing was changed. Take over this domain with a release whose notes say the Kerberos line is complete.'
    }

    It 'the DHCP window is refused while <case>' -ForEach @(
        @{ case = 'a DHCPv6 scope exists'; setup = { $script:world.v6 = @('2001:db8::') } }
        @{ case = 'a group policy sets the start of DHCPServer'; setup = { $script:world.startPolicy = @('\\corp.example.test\SYSVOL\corp.example.test\Policies\{X}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf') } }
        @{ case = 'a lease time is under an hour'; setup = { $script:world.leaseSeconds = 1800 } }
    ) {
        & $setup
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'DHCP window is refused'
        $script:world.services.dc1.Status | Should -Be 'Running'
        @($script:world.authorized).Count | Should -Be 2
    }

    It 'a second run recorded on the PDC emulator stops with exit 1' {
        $script:world.marker = @{ Run = 'another-run'; Host = 'ADM2'; Time = '2026-11-21T09:00:00Z' }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'another run'
    }

    It 'a second process on the same state stops with exit 1' {
        $held = Open-TkState -Domain 'corp.example.test'
        try { { Open-TkState -Domain 'corp.example.test' } | Should -Throw '*another run of the script*' } finally { Close-TkState $held }
    }

    It 'a declined change list changes nothing' {
        Invoke-FakeRun -Answers @('corp.example.test', '1', 'tenko.corp.example.test', 'no') | Should -Be 1
        (Get-WindowsChange) | Should -BeNullOrEmpty
    }

    It 'a window not confirmed at the console waits with exit 3 and changes nothing of phase 4' {
        Invoke-FakeRun -Answers @('corp.example.test', '1', 'tenko.corp.example.test', 'corp.example.test', 'no') | Should -Be 3
        $script:world.calls | Should -Not -Contain 'dc1|ConvertToSecondary'
    }
}

Describe 'The DHCP window' {
    BeforeAll {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $calls = @($script:world.calls)
        $tenko = @($script:world.tenkoCalls)
    }

    It 'stops DHCPServer on both servers, reads the silence back, removes both authorizations and reads them back on each controller, and only then completes the job''s task' {
        $stop1 = [array]::IndexOf($calls, 'dc1|StopDhcp'); $stop2 = [array]::IndexOf($calls, 'dc2|StopDhcp')
        $auth = [array]::IndexOf($calls, 'dc1|SetAuthorization')
        $read1 = [array]::LastIndexOf($calls, 'dc1|ReadAuthorization'); $read2 = [array]::LastIndexOf($calls, 'dc2|ReadAuthorization')
        $stop1 | Should -BeGreaterThan -1
        $stop2 | Should -BeGreaterThan $stop1
        $auth | Should -BeGreaterThan $stop2
        $read1 | Should -BeGreaterThan $auth
        $read2 | Should -BeGreaterThan $auth
        @($tenko | Where-Object { $_ -match '/steps/1/complete$' }).Count | Should -Be 1
    }

    It 'names the DHCP Server service exactly, never the DHCP client' {
        $text = $script:TkRemote.StopDhcp.ToString()
        $text | Should -Match '-Name DHCPServer'
        $text | Should -Not -Match '-Name Dhcp\b'
    }

    It 'is reversed with Tenko silent first, the narrow write-back, the authorization and then the service' {
        $script:world.calls.Clear(); $script:world.tenkoCalls.Clear()
        $script:world.tenkoLeases = @(
            [ordered]@{ ip = '192.0.2.102'; client_id = '00-00-5e-00-53-12'; remaining_secs = 99999; host_name = 'planted' }
            [ordered]@{ ip = '192.0.2.155'; client_id = '00-00-5e-00-53-13'; remaining_secs = 60 }
            [ordered]@{ ip = '192.0.2.120'; client_id = '00-00-5e-00-53-14'; remaining_secs = 60 }
            [ordered]@{ ip = '198.51.100.7'; client_id = '00-00-5e-00-53-15'; remaining_secs = 60 }
            [ordered]@{ ip = '192.0.2.103'; client_id = 'evil"; Remove-Item'; remaining_secs = 60 }
        )
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $written = @($script:world.written | Where-Object { $_ -like 'dc1|*' })
        $written | Should -Contain 'dc1|192.0.2.101|00-00-5e-00-53-11|28800'
        $written | Should -Contain 'dc1|192.0.2.102|00-00-5e-00-53-12|28800'
        $written.Count | Should -Be 2 -Because 'the excluded, reserved, foreign and malformed leases are left out'
        $revert = [array]::IndexOf(@($script:world.tenkoCalls), ($script:world.tenkoCalls | Where-Object { $_ -match 'revert$' } | Select-Object -First 1))
        $revert | Should -Be 0 -Because 'Tenko is made silent before anything on Windows'
        $calls = @($script:world.calls)
        [array]::IndexOf($calls, 'dc1|WriteLeases') | Should -BeLessThan ([array]::IndexOf($calls, 'dc1|SetAuthorization'))
        [array]::IndexOf($calls, 'dc1|SetAuthorization') | Should -BeLessThan ([array]::IndexOf($calls, 'dc1|StartDhcp'))
        $script:world.services.dc1.Status | Should -Be 'Running'
        $script:world.services.dc1.Start | Should -Be 'Automatic'
    }
}

Describe 'Tenko''s computer account' {
    BeforeEach {
        Install-FakeWorld
        $script:TkKerberosLineComplete = $true
        $script:world.zones['corp.example.test'].dc1.Update = 'Secure'
        $script:world.zones['corp.example.test'].dc2.Update = 'Secure'
    }
    AfterEach { $script:TkKerberosLineComplete = $false }

    It 'is created with one DNS name, AES only, no group and no delegation, and its rights are warned about' {
        $script:world.pwdLastSet = '100'
        Mock Invoke-FakeTenko -ParameterFilter { $Path -eq '/dns/kerberos/adopt' } { $script:world.pwdLastSet = '200'; [void]$script:world.tenkoCalls.Add('POST /dns/kerberos/adopt'); [ordered]@{} }
        $warnings = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1)
        $warnings[-1] | Should -Be 3
        $script:world.accounts | Should -Contain 'tenko$'
        ($warnings | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'CORP\\helpdesk holds ExtendedRight'
        $script:TkRemote.NewTenkoAccount.ToString() | Should -Not -Match 'HTTP/'
    }

    It 'is disabled when Tenko has not changed its password in time, by the stopwatch and pwdLastSet' {
        $script:TkPasswordChangeSec = 0
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:world.disabled | Should -Be 'tenko$'
        $script:lastError | Should -Match 'disabled'
    }

    It 'is removed by the reverse only after every zone is back on its update setting' {
        Mock Invoke-FakeTenko -ParameterFilter { $Path -eq '/dns/kerberos/adopt' } { $script:world.pwdLastSet = '200'; [ordered]@{} }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        foreach ($phase in 5, 4, 3, 2) { Invoke-FakeRun -Reverse | Should -Be 5 -Because $script:lastError }
        $script:world.accounts | Should -Not -Contain 'tenko$'
        $script:world.zones['corp.example.test'].dc1.Update | Should -Be 'Secure'
    }

    It 'fails the reverse when a zone is left open to unsigned updates' {
        Mock Invoke-FakeTenko -ParameterFilter { $Path -eq '/dns/kerberos/adopt' } { $script:world.pwdLastSet = '200'; [ordered]@{} }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        Invoke-FakeRun -Reverse | Should -Be 5
        $script:world.leaveOpen = $true
        Invoke-FakeRun -Reverse | Should -Be 2
        $script:lastError | Should -Match 'open to unsigned updates'
    }
}

Describe 'Without Tenko' {
    It 'reverses the Windows half after the confirmation and records Tenko''s half as pending' {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.unreachable = $true
        $script:world.tenkoCalls.Clear()
        $out = @(Invoke-FakeRun -Reverse -Answers @('corp.example.test') 3>&1)
        $out[-1] | Should -Be 5
        ($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Message | Should -Match 'may still serve DHCP'
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        $script:world.services.dc1.Status | Should -Be 'Running'
        $state = ConvertFrom-TkJson -Chars ([System.IO.File]::ReadAllText((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json')).ToCharArray())
        @($state.values['pending.5']).Count | Should -BeGreaterThan 0
    }
}

Describe 'The dry run' {
    It 'prints the change list, changes nothing on Windows and contacts no Tenko' {
        Install-FakeWorld
        $out = @(Invoke-FakeRun -DryRun -Answers @('corp.example.test', '1') 6>&1)
        $out[-1] | Should -Be 0
        ($out -join "`n") | Should -Match 'Changes on Windows'
        Get-WindowsChange | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        Should -Invoke Connect-TkNode -Times 0
        Should -Invoke Request-TkApproval -Times 0
        Test-Path -LiteralPath (Get-TkStateDir 'corp.example.test') | Should -BeFalse
    }
}

Describe 'The state file' {
    It 'holds no password, token, session or code after every phase' {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $text = [System.IO.File]::ReadAllText((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json'))
        $text | Should -Not -Match 'tnk[abc]?_'
        $text | Should -Not -Match 'Tk1-'
        $text | Should -Not -CMatch '(?<![0-9a-f-])[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}(?![0-9a-f-])' -Because 'an approval code has the form of four groups of four, a UUID has none'
    }
}
