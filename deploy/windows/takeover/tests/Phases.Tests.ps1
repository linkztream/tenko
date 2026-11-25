# The phases against the fake domain and the fake Tenko of Fake.ps1 (MIG-17, MIG-08): every
# phase forward, again with nothing changed, and back with -Reverse; a failure at each step
# stops with exit 2 and resumes; a value that Windows contradicts stops with exit 4; the
# refusals of the discovery and of the DHCP window; the DHCP window's order both ways, with
# servers that answer only while their service runs; what the DNS reverse writes back.

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    . (Join-Path $PSScriptRoot 'Fake.ps1')
    $savedRoot = $script:TkDataRoot
    function Get-WindowsChange {
        # The calls that change Windows, from the world's log.
        $reads = 'ReadDomain', 'ReadZones', 'ReadDirectoryZones', 'ReadDhcpInDirectory', 'ReadDhcpServer', 'ReadComputers', 'ReadNameUse', 'ReadHardening', 'ReadLocalAdmins', 'ReadFeature', 'ReadMarker', 'ReadDhcpConfiguration', 'ReadRecords', 'ReadZone', 'ReadLeases', 'ReadAuthorization', 'ReadPwdLastSet', 'ReadSoa', 'ReadProgramFiles'
        return @($script:world.calls | Where-Object { $reads -notcontains $_.Split('|')[1] })
    }
    function Get-WindowsShape {
        # What the reverse must bring back.
        $w = $script:world
        $zones = foreach ($zone in $w.zones.Keys) { foreach ($dc in 'dc1', 'dc2') { $z = $w.zones[$zone][$dc]; "$zone|$dc|$($z.Type)|$($z.Ds)|$($z.Update)|$($z.Transfer)|$($z.Notify)|$(@($z.Secondaries) -join ',')|$(@($z.NotifyServers) -join ',')" } }
        return (@($zones) + "services $($w.services.dc1.Status)/$($w.services.dc1.Start) $($w.services.dc2.Status)/$($w.services.dc2.Start)" +
            "authorized $(@($w.authorized | Sort-Object) -join ',')" + "accounts $(@($w.accounts.Keys) -join ',')" + "gpo $($w.gpo)" + "tasks $(@($w.tasks) -join ',')" + "batch $($w.batchRight)" + "marker $($null -ne $w.marker)") -join "`n"
    }
    function Read-State { ConvertFrom-TkJson -Chars ([System.IO.File]::ReadAllText((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json')).ToCharArray()) }
}

AfterAll { $script:TkDataRoot = $savedRoot }

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
        $script:beforeFinish = [System.IO.File]::ReadAllBytes((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json'))
    }

    It 'finishes in the second sitting after the confirmation, without starting the DHCP Server service or reading a stopped server' {
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 0 -Because $script:lastError
        $script:finishCalls = @($script:world.calls)
        foreach ($dc in 'dc1', 'dc2') { "$($script:world.services[$dc].Status)/$($script:world.services[$dc].Start)" | Should -Be 'Stopped/Disabled' -Because $dc }
        @($script:world.authorized).Count | Should -Be 0
        $script:world.calls | Should -Not -Contain 'dc1|StartDhcp'
        $script:world.calls | Should -Not -Contain 'dc1|ReadDhcpServer'
        $script:world.marker | Should -BeNullOrEmpty
        $script:world.finished | Should -Be (Read-State).id -Because 'the domain names the finished run'
        @($script:world.mirrors.Keys).Count | Should -Be 0
    }

    It 'says before the finish that there is no scripted way back, what stays on the servers and where the export is' {
        $prompt = @($script:world.prompts | Where-Object { $_ -match 'finish \(phase 6\)' })[-1]
        $prompt | Should -Match 'After it there is no scripted way back: -Reverse is refused and going back is manual work\.'
        $prompt | Should -Match 'The finish \(phase 6\) releases the frozen names in Tenko''s zones and removes'
        $prompt | Should -Match 'Each DHCP server keeps the DHCP Server role and its database; the finish neither starts nor authorizes its service\. The DHCP Server service and authorization read now: dc1\.corp\.example\.test Stopped and Disabled, not authorized; dc2\.corp\.example\.test Stopped and Disabled, not authorized\.'
        $prompt | Should -Match ([regex]::Escape("The export of phase 2 stays in Program Files\Tenko\takeover\backup on each DHCP server and in $(Join-Path (Get-TkStateDir 'corp.example.test') 'backup') here."))
        $prompt | Should -Not -Match 'Set-DhcpServerDnsCredential' -Because 'the servers keep the DNS credential they had'
    }

    It 'calls on Windows exactly the blocks the finish is known to call, none that installs, removes, starts or restarts' {
        # A new remote call in the finish fails here until someone has decided that it belongs.
        @($script:finishCalls | ForEach-Object { $_.Split('|')[1] } | Sort-Object -Unique) | Should -Be @('ProtectDirectory', 'ReadComputers', 'ReadDhcpInDirectory', 'ReadDhcpService', 'ReadDirectoryZones', 'ReadDomain', 'ReadFeature', 'ReadHardening', 'ReadLocalAdmins', 'ReadMarker', 'ReadProgramFiles', 'ReadZones', 'RemoveAccount', 'RemoveBatchRight', 'RemoveExporter', 'WriteMarker')
        foreach ($name in @($script:finishCalls | ForEach-Object { $_.Split('|')[1] } | Sort-Object -Unique)) { $script:TkRemote[$name].ToString() | Should -Not -Match '\b(Install|Uninstall|Add|Remove)-WindowsFeature\b|\b(Enable|Disable)-WindowsOptionalFeature\b|\b(Restart|Stop)-Computer\b|\bshutdown\b|\bdism\b|\b(Start|Set|Restart)-Service\b|\bAdd-DhcpServerInDC\b' -Because $name }
    }

    It 'refuses -Reverse after the finish with exit 1 and changes nothing' {
        $script:world.calls.Clear()
        $script:world.tenkoCalls.Clear()
        Invoke-FakeRun -Reverse | Should -Be 1
        $script:lastError | Should -Match 'the finish \(phase 6\) has started: there is no scripted way back'
        $script:world.calls | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        (Read-State).phases['6'] | Should -Be 'done'
    }

    It 'changes nothing when run again' {
        $script:world.calls.Clear()
        $script:world.tenkoCalls.Clear()
        Invoke-FakeRun | Should -Be 0 -Because $script:lastError
        $script:world.calls | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
    }

    It 'refuses -Reverse from a copy of the state file made before the finish, by the mark the domain keeps' {
        $script:world.calls.Clear()
        $script:world.tenkoCalls.Clear()
        [System.IO.File]::WriteAllBytes((Join-Path (Get-TkStateDir 'corp.example.test') 'state.json'), $script:beforeFinish)
        Invoke-FakeRun -Reverse | Should -Be 1
        $script:lastError | Should -Match 'the finish \(phase 6\) has started: there is no scripted way back'
        Get-WindowsChange | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
    }

    It 'walks every phase before the finish back with -Reverse to the starting state' {
        Install-FakeWorld
        $start = Get-WindowsShape
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        foreach ($phase in 5, 4, 3, 2) {
            Invoke-FakeRun -Reverse | Should -Be 5 -Because "phase $phase is reversed ($script:lastError)"
        }
        Get-WindowsShape | Should -Be $start
        @($script:world.mirrors.Keys).Count | Should -Be 0
        @($script:world.tzones.Keys).Count | Should -Be 0
    }

    It 'resumes a finish cut short, with a step done and one running and no phase recorded, and refuses -Reverse meanwhile' {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $path = Join-Path (Get-TkStateDir 'corp.example.test') 'state.json'
        $text = [System.IO.File]::ReadAllText($path)
        $text = $text -replace '"steps":\{', '"steps":{"6.tenko":{"state":"done","at":"2026-11-24T10:00:00Z"},"6.exporter":{"state":"running","at":"2026-11-24T10:00:01Z"},'
        [System.IO.File]::WriteAllText($path, $text)
        $script:world.calls.Clear()
        $script:world.tenkoCalls.Clear()
        Invoke-FakeRun -Reverse | Should -Be 1
        $script:world.calls | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        Invoke-FakeRun | Should -Be 0 -Because $script:lastError
        (Read-State).phases['6'] | Should -Be 'done'
        @($script:world.mirrors.Keys).Count | Should -Be 0
    }

    It 'does not start the finish when Tenko refuses its dry run: nothing of the finish is recorded and -Reverse still works' {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.failRoute = 'release$'
        Invoke-FakeRun -Answers @('c') | Should -Be 1
        $script:lastError | Should -Match '^finish not started, nothing changed, -Reverse works: release of [^:]+: Tenko refused POST /dns/zones/[^/]+/release'
        @((Read-State).steps.Keys | Where-Object { $_ -like '6.*' }) | Should -BeNullOrEmpty
        (Read-State).phases.Contains('6') | Should -BeFalse
        Invoke-FakeRun -Reverse | Should -Be 5 -Because $script:lastError
    }

    It 'does not start the finish when Tenko answers its first real release after the confirmation with <status> <code>: nothing is recorded and -Reverse still works' -ForEach @(
        @{ status = 403; code = 'auth.delegation.refused'; shown = '403 auth\.delegation\.refused, not opened to a takeover''s session by this node' }
        @{ status = 429; code = 'dns.zone.flip.busy'; shown = '429 dns\.zone\.flip\.busy' }
    ) {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:refused = $_
        Mock Invoke-FakeTenko -ParameterFilter { $Path -like '*/release' -and -not $Body.dry_run } {
            $refusal = [System.Exception]::new("Tenko refused POST $Path with $($script:refused.status) $($script:refused.code): refused")
            $refusal.Data['tk.status'] = $script:refused.status
            $refusal.Data['tk.code'] = $script:refused.code
            throw $refusal
        }
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 1
        $script:lastError | Should -Match "^finish not started, nothing changed, -Reverse works: release of [^:]+: $shown$"
        @((Read-State).steps.Keys | Where-Object { $_ -like '6.*' }) | Should -BeNullOrEmpty
        Invoke-FakeRun -Reverse | Should -Be 5 -Because $script:lastError
    }

    It 'counts the finish as started when its first real release ends with <case>, and resumes it' -ForEach @(
        @{ case = 'no answer'; status = 0 }
        @{ case = '503, an unknown outcome'; status = 503 }
    ) {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:timedOut = $false
        $script:unknown = $status
        Mock Invoke-FakeTenko -ParameterFilter { $Path -like '*/release' -and -not $Body.dry_run -and -not $script:timedOut } {
            $script:timedOut = $true
            if (-not $script:unknown) { throw 'the request to Tenko timed out' }
            $failure = [System.Exception]::new("Tenko refused POST $Path with $($script:unknown) sys.store.timeout: no answer from the store")
            $failure.Data['tk.status'] = $script:unknown
            $failure.Data['tk.code'] = 'sys.store.timeout'
            throw $failure
        }
        $out = @(Invoke-FakeRun -Answers @('c', 'corp.example.test') 6>&1)
        $out[-1] | Should -Be 2
        ($out -join "`n") | Should -Match 'The release of [^:]+ may have happened: the finish counts as started, -Reverse is refused\. Run the script again to resume the finish\.'
        (Read-State).steps['6.tenko'].state | Should -Be 'failed'
        Invoke-FakeRun -Reverse | Should -Be 1
        Invoke-FakeRun | Should -Be 0 -Because $script:lastError
    }

    It 'records a refusal of a later zone''s release, after the first succeeded, as a failed step' {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:realReleases = 0
        Mock Invoke-FakeTenko -ParameterFilter { $Path -like '*/release' -and -not $Body.dry_run } {
            $script:realReleases++
            if ($script:realReleases -ne 3) { return [ordered]@{ names = @(); rrsets = 0 } }
            $refusal = [System.Exception]::new("Tenko refused POST $Path with 403 auth.step_up_required: refused")
            $refusal.Data['tk.status'] = 403
            $refusal.Data['tk.code'] = 'auth.step_up_required'
            throw $refusal
        }
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 2
        (Read-State).steps['6.tenko'].state | Should -Be 'failed'
        Invoke-FakeRun -Reverse | Should -Be 1
    }

    It 'deletes the DNS update account it made and says that the servers need another credential before a start' {
        Install-FakeWorld
        $script:world.dnsUser = ''
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.accounts.Contains('tenko-dhcp-dns') | Should -BeTrue
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 0 -Because $script:lastError
        $script:world.accounts.Contains('tenko-dhcp-dns') | Should -BeFalse
        @($script:world.prompts | Where-Object { $_ -match 'finish \(phase 6\)' })[-1] | Should -Match 'names tenko-dhcp-dns, an account the finish deletes: to serve again, a server needs another, set with Set-DhcpServerDnsCredential after its service is started unauthorized and before it is authorized\.'
    }
}

Describe 'A failure at a step' {
    It 'stops at <step> with exit 2, records it, and resumes there in a new process' -ForEach @(
        @{ step = '2.mirrors'; route = '^POST /migrate/mirrors$' }
        @{ step = '2.backups'; block = 'ExportDhcp' }
        @{ step = '2.mirror-account'; block = 'NewAccount' }
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
        @{ step = '5.silence'; block = 'ReadAuthorization' }
        @{ step = '5.check'; route = '^GET /migrate/takeovers\?job=' }
    ) {
        Install-FakeWorld
        if ($_.ContainsKey('block')) { $script:world.failAt = $_.block } else { $script:world.failRoute = $_.route }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $state = Read-State
        $state.steps[$step].state | Should -Be 'failed'
        $state.steps[$step].error | Should -Match 'injected'
        # A new process: the mirrors' tokens are gone, and the exporter step makes them anew.
        # A sitting that starts the DNS window confirms it; the DHCP window asks its choice.
        $resume = $(if ($step -like '5.*') { @('c', 'Continue') } else { @('c', 'corp.example.test', 'Continue') })
        Invoke-FakeRun -Answers $resume | Should -Be 3 -Because $script:lastError
        (Read-State).steps[$step].state | Should -Be 'done'
        @($script:world.tasks).Count | Should -Be 2
    }

    It 'stops at the finish''s <step> with exit 2, refuses -Reverse and resumes there' -ForEach @(
        @{ step = '6.tenko'; route = 'release$'; pre = { $script:world.failSkip = @($script:world.tzones.Keys).Count + 1 } }
        @{ step = '6.exporter'; block = 'RemoveExporter' }
        @{ step = '6.mirror-account'; block = 'RemoveAccount' }
        @{ step = '6.zone-objects'; block = 'RemoveZoneObject'; pre = { $script:world.directory += 'corp.example.test' } }
        @{ step = '6.mirrors'; route = '^DELETE /migrate/mirrors' }
        @{ step = '6.marker'; block = 'WriteMarker'; pre = { $script:world.failSkip = 1 } }
    ) {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        if ($_.ContainsKey('pre')) { & $_.pre }
        if ($_.ContainsKey('block')) { $script:world.failAt = $_.block } else { $script:world.failRoute = $_.route }
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 2
        Invoke-FakeRun -Reverse | Should -Be 1
        (Read-State).steps[$step].state | Should -Be 'failed'
        Invoke-FakeRun | Should -Be 0 -Because $script:lastError
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

    It 'a controller address to restore is checked against the sitting''s own discovery, never the state file''s' {
        $readings = [ordered]@{ controllers = @([ordered]@{ addresses = @('203.0.113.9') }); values = @('NoTransfer') }
        $script:TkFresh = @{ controllers = @(@{ addresses = @('192.0.2.11') }) }
        { Assert-TkRestoreValue -Readings $readings -Value '203.0.113.9' -Class address } | Should -Throw '*not one the discovery recorded*'
        { Assert-TkRestoreValue -Readings $readings -Value 'TransferAnyServer' -Class discovered } | Should -Throw '*not one the discovery recorded*'
        { Assert-TkRestoreValue -Readings $readings -Value '192.0.2.11' -Class address } | Should -Not -Throw
    }
}

Describe 'The refusals' {
    BeforeEach { Install-FakeWorld }

    It 'a zone that takes secure updates only is refused in phase 0 with the release''s sentence, nothing changed, no Tenko' {
        $script:world.zones['corp.example.test'].dc1.Update = 'Secure'
        Invoke-FakeRun -Answers @('corp.example.test', 'y', '1') | Should -Be 1
        (Get-WindowsChange) | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        Should -Invoke Connect-TkNode -Times 0
        $script:world.answers.Add('y') | Out-Null
        $readings = Get-TkDiscovery -Domain 'corp.example.test'
        $readings.refusals | Should -Contain 'The zone corp.example.test takes secure updates only. This release of Tenko cannot yet take over a zone that takes secure updates only without weakening it, because its secure updates (the Kerberos line of the identity plan) are not complete. Nothing was changed. Take over this domain with a release whose notes say the Kerberos line is complete.'
    }

    It 'a zone its reverse could not put back where it is (<case>) is refused in phase 0' -ForEach @(
        @{ case = 'not directory-integrated'; setup = { foreach ($dc in 'dc1', 'dc2') { $script:world.zones['corp.example.test'][$dc].Ds = $false } }; text = 'not directory-integrated' }
        @{ case = 'a custom partition not named'; setup = { foreach ($dc in 'dc1', 'dc2') { $script:world.zones['corp.example.test'][$dc].Scope = 'Custom' } }; text = "replicated to 'Custom'" }
    ) {
        & $setup
        $out = @(Invoke-FakeRun -Answers $script:FirstSitting 6>&1)
        $out[-1] | Should -Be 1
        ($out -join "`n") | Should -Match ([regex]::Escape("The zone corp.example.test is $text"))
        (Get-WindowsChange) | Should -BeNullOrEmpty
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

    It 'a name resolution policy that sends the domain''s names to fixed servers stops the first sitting before any change' {
        $script:world.nrpt = @([pscustomobject]@{ Namespace = @('.corp.example.test'); NameServers = @('192.0.2.11'); DirectAccessDnsServers = @() })
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'sends the names of corp\.example\.test to fixed servers by policy'
        (Get-WindowsChange) | Should -BeNullOrEmpty
        $script:world.tenkoCalls | Should -BeNullOrEmpty
    }

    It 'reads the name resolution policy again right before the DNS window''s check' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        Should -Invoke Get-TkNrptRule -Times 2 -Exactly
    }

    It 'a policy rule that appears before the DNS window''s check stops that step to resume, with exit 2' {
        $script:nrptReads = 0
        Mock Get-TkNrptRule { $script:nrptReads++; if ($script:nrptReads -gt 1) { @([pscustomobject]@{ Namespace = @('.corp.example.test'); NameServers = @('192.0.2.11'); DirectAccessDnsServers = @() }) } }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:lastError | Should -Match 'remove the rule on this machine and run the script again to resume, or run it with -Reverse'
        (Read-State).steps['4.check'].state | Should -Be 'failed'
    }

    It 'a node that cannot report answered clients is refused in the first sitting before any change' {
        foreach ($form in 'missing', 'malformed') {
            Install-FakeWorld
            $script:world.takeoverList = $form
            Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1 -Because $form
            $script:lastError | Should -Match "this node's version of Tenko cannot report answered clients per takeover.*no DNS or DHCP setting was changed; this run's marker on the PDC emulator stays, so run the script again from this machine"
            (Get-WindowsChange | Where-Object { $_ -notmatch '\|WriteMarker$' }) | Should -BeNullOrEmpty
            $script:world.marker.Run | Should -Be (Read-State).id -Because 'the message says the marker stays'
        }
    }

    It 'the dry run shows the change list and every refusal before it ends with the policy''s exit 1' {
        $script:world.nrpt = @([pscustomobject]@{ Namespace = @('.corp.example.test'); NameServers = @('192.0.2.11'); DirectAccessDnsServers = @() })
        $out = @(Invoke-FakeRun -DryRun -Answers @('corp.example.test', 'y', '1') 3>&1 6>&1)
        $out[-1] | Should -Be 1
        ($out -join "`n") | Should -Match 'Changes on Windows'
        (@($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Message -join ' ') | Should -Match 'fixed servers by policy'
    }

    It 'a second run recorded on the PDC emulator stops with exit 1' {
        $script:world.marker = @{ Run = 'another-run'; Host = 'ADM2'; Time = '2026-11-21T09:00:00Z' }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'another run'
    }

    It 'a marker another run wrote at the same moment stops before the approval' {
        $script:world.markerThief = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'at the same time'
        Should -Invoke Request-TkApproval -Times 0
    }

    It 'a second process on the same state stops with exit 1' {
        $held = Open-TkState -Domain 'corp.example.test'
        try { { Open-TkState -Domain 'corp.example.test' } | Should -Throw '*another run of the script*' } finally { Close-TkState $held }
    }

    It 'a declined change list changes nothing' {
        Invoke-FakeRun -Answers @('corp.example.test', 'y', '1', 'tenko.corp.example.test', 'no') | Should -Be 1
        (Get-WindowsChange) | Should -BeNullOrEmpty
    }

    It 'a window not confirmed at the console waits with exit 3 and changes nothing of phase 4' {
        Invoke-FakeRun -Answers @('corp.example.test', 'y', '1', 'tenko.corp.example.test', 'corp.example.test', 'no') | Should -Be 3
        $script:world.calls | Should -Not -Contain 'dc1|ConvertToSecondary'
    }

    It 'a node name that is a computer account or a service principal name of the domain is refused' {
        $script:world.nameUse = @{ Sid = 'S-1-5-21-1000-2000-3000-2000'; Spns = 1 }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'is taken'
        (Get-WindowsChange) | Should -BeNullOrEmpty
    }

    It 'an installer without the parameters of the scripted install is refused before any change' {
        Install-FakeWorld -RepositoryInstaller
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'has no -ComputerName, -SkipDryRun'
        (Get-WindowsChange) | Should -BeNullOrEmpty
    }
}

Describe 'The DHCP servers of the domain' {
    BeforeEach { Install-FakeWorld }

    It 'are only those whose computer object of the domain names their address; the rest is shown, never contacted' {
        $script:world.foreign = @(@{ Name = 'old-dhcp.corp.example.test'; Address = '192.0.2.99' }, @{ Name = 'dhcp.other.example.test'; Address = '198.51.100.67' })
        $out = @(Invoke-FakeRun -DryRun -Answers @('corp.example.test', 'y', '1') 3>&1 6>&1)
        $out[-1] | Should -Be 0
        @($script:world.calls | Where-Object { $_ -like 'old-dhcp|*' -or $_ -like 'dhcp|*' }) | Should -BeNullOrEmpty
        ($out -join "`n") | Should -Match 'old-dhcp.corp.example.test \(192.0.2.99\), which is no computer of corp.example.test'
    }

    It 'are shown and confirmed before any session to them' {
        Invoke-FakeRun -Answers @('corp.example.test', 'n') | Should -Be 1
        $script:world.calls | Should -Not -Contain 'dc1|ReadDhcpServer'
    }

    It 'refuse a listed name whose computer object a domain user made under the machine account quota' {
        $script:world.quotaComputer = $true
        $script:world.foreign = @(@{ Name = 'dhcp3.corp.example.test'; Address = '192.0.2.33' })
        Invoke-FakeRun -Answers @('corp.example.test', 'y', '1') | Should -Be 1
        $script:lastError | Should -Match 'dhcp3\.corp\.example\.test, whose computer object S-1-5-21-1000-2000-3000-1105 created under the machine account quota'
        $script:world.calls | Should -Not -Contain 'dhcp3|ReadDhcpServer'
    }

    It 'are read only on an explicit yes: Enter declines' {
        Invoke-FakeRun -Answers @('corp.example.test', '') | Should -Be 1
        $script:world.calls | Should -Not -Contain 'dc1|ReadDhcpServer'
    }

    It 'warn when the mirror host is trusted for unconstrained delegation' {
        $script:world.srvDelegation = $true
        $out = @(Invoke-FakeRun -DryRun -Answers @('corp.example.test', 'y', '1') 3>&1 6>&1)
        $out[-1] | Should -Be 0
        ($out -join "`n") | Should -Match 'mirror host srv1\.corp\.example\.test is trusted for unconstrained delegation'
    }
}

Describe 'The objects of the run' {
    BeforeEach { Install-FakeWorld }

    It 'an account of the run''s name that this run did not create is refused and survives the reverse' {
        $script:world.accounts['tenko-mirror'] = 'S-1-5-21-1000-2000-3000-999'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'carries neither the SID nor the mark of this run'
        Invoke-FakeRun -Reverse | Should -Be 5 -Because $script:lastError
        $script:world.accounts['tenko-mirror'] | Should -Be 'S-1-5-21-1000-2000-3000-999'
    }

    It 'an account a sitting created but could not record is known again by its own mark, whose secret the state file holds' {
        $script:world.crashAfterCreate = 'tenko-mirror'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $values = (Read-State).values
        $values.mark_secret | Should -Match '^[0-9a-f]{64}$'
        $mark = Get-TkRunMark -State @{ Data = @{ values = $values } } -Name 'tenko-mirror'
        $script:world.marks['tenko-mirror'] | Should -BeExactly $mark
        $mark | Should -Not -BeExactly (Get-TkRunMark -State @{ Data = @{ values = $values } } -Name 'tenko$') -Because 'a mark fits one name only'
        Invoke-FakeRun -Answers @('c', 'corp.example.test', 'Continue') | Should -Be 3 -Because $script:lastError
        (Read-State).values.mirror_account_sid | Should -Be $script:world.accounts['tenko-mirror']
    }

    It 'an account that carries the mark but was made under the machine account quota, or that another account may write, is refused' {
        $script:world.crashAfterCreate = 'tenko-mirror'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:world.creators['tenko-mirror'] = 'S-1-5-21-1000-2000-3000-1105'
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 1
        $script:lastError | Should -Match 'created by S-1-5-21-1000-2000-3000-1105 under the machine account quota'
        $script:world.creators.Remove('tenko-mirror')
        $script:world.objectAcl['tenko-mirror'] = 'O:DAG:DAD:(A;;GA;;;DA)(A;;WP;;;S-1-5-21-1000-2000-3000-1105)'
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 1
        $script:lastError | Should -Match 'may be written by S-1-5-21-1000-2000-3000-1105'
        $script:world.objectAcl['tenko-mirror'] = 'O:S-1-5-21-1000-2000-3000-1105G:DAD:(A;;GA;;;DA)'
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 1
        $script:lastError | Should -Match 'is owned by S-1-5-21-1000-2000-3000-1105'
    }

    It 'Tenko''s computer account planted with a mark copied from another object of the run is refused, its password untouched' {
        $script:TkKerberosLineComplete = $true
        try {
            $script:world.zones['corp.example.test'].dc1.Update = 'Secure'; $script:world.zones['corp.example.test'].dc2.Update = 'Secure'
            $script:world.forge = @{ Name = 'tenko$'; From = 'tenko-mirror' }
            Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
            $script:lastError | Should -Match 'the account tenko\$ exists and carries neither the SID nor the mark of this run'
            $script:world.calls | Should -Not -Contain 'dc1|NewTenkoAccount'
        } finally { $script:TkKerberosLineComplete = $false }
    }

    It 'a group policy object of the run''s name that this run did not make is refused' {
        $script:world.gpo = '00000000-0000-0000-0000-00000000abcd'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 1
        $script:lastError | Should -Match 'carries neither the SID nor the mark of this run'
    }

    It 'a remote folder owned by another account is refused, never adopted' {
        $script:world.badRemoteOwner = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:world.calls | Should -Not -Contain 'dc1|ExportDhcp'
    }
}

Describe 'The DHCP window' {
    BeforeAll {
        Install-FakeWorld
        $out = @(Invoke-FakeRun -Answers $script:FirstSitting 6>&1)
        $out[-1] | Should -Be 3 -Because $script:lastError
        $shown = ($out | Select-Object -SkipLast 1) -join "`n"
        $calls = @($script:world.calls)
        $tenko = @($script:world.tenkoCalls)
    }

    It 'puts the DHCP window''s warning into the DNS window''s own prompt, which stands for it within 15 minutes: no second question in one sitting' {
        $script:world.choices | Should -Be 0
        # In the prompt's text, which no redirection of the script's output can hide.
        $prompt = @($script:world.prompts | Where-Object { $_ -match 'start the DNS window' })
        $prompt.Count | Should -Be 1
        $prompt[0] | Should -Match 'The window was started by admin at 2026-11-21T10:00:00Z, according to Tenko'
        $prompt[0] | Should -Match 'stopped and disabled on dc1\.corp\.example\.test and dc2\.corp\.example\.test'
        $prompt[0] | Should -Match 'Tenko starts answering 192\.0\.2\.0/24 at once'
        $prompt[0] | Should -Match 'may take some minutes to reach every controller'
        $prompt[0] | Should -Match 'Tenko-Takeover\.ps1 -Reverse'
        $prompt[0] | Should -Match ([regex]::Escape((Get-TkSilenceText -Readings (Read-State).readings)))
        $shown | Should -Match "The DNS window's confirmation 0 minutes ago stands for the DHCP window"
    }

    It 'stops DHCPServer on both servers and reads the silence back, completes Tenko''s task, and only then removes both authorizations and reads them back on each controller' {
        $stop1 = [array]::IndexOf($calls, 'dc1|StopDhcp'); $stop2 = [array]::IndexOf($calls, 'dc2|StopDhcp')
        $task = [array]::IndexOf($calls, 'tenko|task-complete')
        $auth = [array]::IndexOf($calls, 'dc1|SetAuthorization')
        $read1 = [array]::LastIndexOf($calls, 'dc1|ReadAuthorization'); $read2 = [array]::LastIndexOf($calls, 'dc2|ReadAuthorization')
        $stop1 | Should -BeGreaterThan -1
        $stop2 | Should -BeGreaterThan $stop1
        $task | Should -BeGreaterThan $stop2 -Because 'Tenko goes on only once both silences are read back'
        $auth | Should -BeGreaterThan $task -Because 'the authorizations follow Tenko''s task'
        $read1 | Should -BeGreaterThan $auth
        $read2 | Should -BeGreaterThan $auth
        @($tenko | Where-Object { $_ -match '/steps/1/complete$' }).Count | Should -Be 1
        @((Read-State).values.barrier_pending).Count | Should -Be 0
    }

    It 'names the DHCP Server service exactly, never the DHCP client' {
        $text = $script:TkRemote.StopDhcp.ToString()
        $text | Should -Match '-Name DHCPServer'
        $text | Should -Not -Match '-Name Dhcp\b'
    }

    It 'is reversed with Windows ready before Tenko is silent: started unauthorized, the narrow write-back, authorized, and only then Tenko off and the restart' {
        $script:world.calls.Clear(); $script:world.tenkoCalls.Clear()
        $script:world.tenkoLeases = @(
            [ordered]@{ ip = '192.0.2.102'; client_id = '00-00-5e-00-53-12'; remaining_secs = 99999; host_name = 'planted' }
            [ordered]@{ ip = '192.0.2.155'; client_id = '00-00-5e-00-53-13'; remaining_secs = 60 }
            [ordered]@{ ip = '192.0.2.120'; client_id = '00-00-5e-00-53-14'; remaining_secs = 60 }
            [ordered]@{ ip = '198.51.100.7'; client_id = '00-00-5e-00-53-15'; remaining_secs = 60 }
            [ordered]@{ ip = '192.0.2.0103'; client_id = '00-00-5e-00-53-16'; remaining_secs = 60 }
            [ordered]@{ ip = '192.0.2.103'; client_id = 'evil"; Remove-Item'; remaining_secs = 60 }
        )
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $written = @($script:world.written | Where-Object { $_ -like 'dc1|*' })
        $written | Should -Contain 'dc1|192.0.2.101|00-00-5e-00-53-11|28800'
        $written | Should -Contain 'dc1|192.0.2.102|00-00-5e-00-53-12|28800'
        $written.Count | Should -Be 2 -Because 'the excluded, reserved, foreign, non-canonical and malformed leases are left out'
        $calls = @($script:world.calls)
        $startedUnauthorized = [array]::IndexOf($calls, 'dc1|serving=False')
        $write = [array]::IndexOf($calls, 'dc1|WriteLeases')
        $authorize = [array]::IndexOf($calls, 'dc1|SetAuthorization')
        $off = [array]::IndexOf($calls, 'tenko|scopes-off')
        $serving = [array]::IndexOf($calls, 'dc1|serving=True')
        $startedUnauthorized | Should -BeGreaterThan -1
        $write | Should -BeGreaterThan $startedUnauthorized
        $authorize | Should -BeGreaterThan $write
        $off | Should -BeGreaterThan $authorize -Because 'Tenko serves until Windows is ready'
        $serving | Should -BeGreaterThan $off
        $script:world.services.dc1.Status | Should -Be 'Running'
        $script:world.services.dc1.Start | Should -Be 'Automatic'
        (Read-State).values.Contains('reverted.takeover.192.0.2.0/24') | Should -BeTrue
    }
}

Describe 'A failure inside the DHCP window' {
    BeforeEach { Install-FakeWorld }

    It 'keeps the lease pairs read before the stop when the step resumes' {
        $script:world.failAt = 'ReadAuthorization'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        @((Read-State).values.leases['dc1.corp.example.test|192.0.2.0']).Count | Should -Be 1
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c', 'corp.example.test') | Should -Be 3 -Because $script:lastError
        $script:world.calls | Should -Not -Contain 'dc1|ReadLeases' -Because 'a resume never reads again what the state file holds'
        @((Read-State).values.leases['dc1.corp.example.test|192.0.2.0']).Count | Should -Be 1
    }

    It 'starts the first server again and leaves Tenko off when the stop of the second fails, and can still reverse' {
        $script:world.failAt = 'StopDhcp'; $script:world.failOn = 'dc2'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:lastError | Should -Match 'started again as they were and answer, and Tenko''s scopes stay off'
        $script:world.services.dc1.Status | Should -Be 'Running'
        $script:world.services.dc1.Serving | Should -BeTrue
        $script:world.scopesOn | Should -BeFalse
        $script:world.calls | Should -Not -Contain 'tenko|task-complete'
        $script:world.calls.Clear()
        Invoke-FakeRun -Reverse -Answers @() | Should -Be 5 -Because $script:lastError
        $script:world.services.dc1.Serving | Should -BeTrue
        $script:world.services.dc2.Serving | Should -BeTrue
    }

    It 'leaves Windows serving and Tenko off when a silence is not read back' {
        $script:world.stopFailsOn = 'dc2'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:lastError | Should -Match 'dc2\.corp\.example\.test is not silent'
        $script:world.services.dc1.Status | Should -Be 'Running'
        $script:world.services.dc1.Start | Should -Be 'Automatic'
        $script:world.services.dc2.Serving | Should -BeTrue
        $script:world.scopesOn | Should -BeFalse
        @($script:world.authorized).Count | Should -Be 2
        @((Read-State).values.stopped).Count | Should -Be 0
    }

    It 'asks Abort or Continue when more than 15 minutes have passed since the DNS window''s confirmation, and changes nothing on Abort, the default' {
        $script:TkWindowHoldSec = 0
        try {
            $answers = @($script:FirstSitting) + 'Abort'
            Invoke-FakeRun -Answers $answers | Should -Be 3
            $script:world.choices | Should -Be 1
            $script:world.lastChoice | Should -Match 'The DHCP window makes these changes'
            $script:lastError | Should -Match 'aborted at the console'
            $script:world.calls | Should -Not -Contain 'dc1|StopDhcp'
            $script:world.calls | Should -Not -Contain 'tenko|task-complete'
            $script:world.services.dc1.Serving | Should -BeTrue
        } finally { $script:TkWindowHoldSec = 900 }
        # A resumed sitting confirmed no DNS window in this process: it asks.
        Invoke-FakeRun -Answers @('c', '') | Should -Be 3 -Because 'a choice that names neither is Abort'
        $script:world.choices | Should -Be 2
        $script:world.calls | Should -Not -Contain 'dc1|StopDhcp'
        Invoke-FakeRun -Answers @('c', 'Continue') | Should -Be 3 -Because $script:lastError
        $script:world.choices | Should -Be 3
        $script:world.scopesOn | Should -BeTrue
    }

    It 'resumes after the silence into Tenko''s task without asking or stopping again' {
        $script:world.crashAtComplete = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        (Read-State).values.silenced | Should -BeTrue
        $script:world.scopesOn | Should -BeFalse
        Invoke-FakeRun -Answers @('c') | Should -Be 3 -Because $script:lastError
        $script:world.choices | Should -Be 0 -Because 'one sitting asks no second question, and a resume after the silence asks none'
        @($script:world.calls | Where-Object { $_ -like '*|StopDhcp' }).Count | Should -Be 2
        @($script:world.calls | Where-Object { $_ -eq 'tenko|task-complete' }).Count | Should -Be 1
        @($script:world.tenkoCalls | Where-Object { $_ -match '/takeover$' }).Count | Should -Be 1
    }

    It 'reads each service again on a resume and stops one that answers again before Tenko goes on' {
        $script:world.crashAtComplete = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        # Between the sittings someone starts dc1's service again.
        $script:world.services.dc1.Status = 'Running'; $script:world.services.dc1.Start = 'Automatic'
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c') | Should -Be 3 -Because $script:lastError
        $calls = @($script:world.calls)
        [array]::IndexOf($calls, 'dc1|ReadDhcpService') | Should -BeGreaterThan -1
        [array]::IndexOf($calls, 'dc1|StopDhcp') | Should -BeLessThan ([array]::IndexOf($calls, 'tenko|task-complete'))
        $calls | Should -Not -Contain 'dc2|StopDhcp' -Because 'dc2 was read back silent'
        $script:world.services.dc1.Status | Should -Be 'Stopped'
    }

    It 'starts Windows again, still authorized, and says who answers, when Tenko never completes its task' {
        $script:world.completeFails = $true
        $out = @(Invoke-FakeRun -Answers $script:FirstSitting 6>&1)
        $out[-1] | Should -Be 2
        $script:lastError | Should -Match 'Tenko did not complete the takeover of 192\.0\.2\.0/24 .*: Windows answers every scope again and Tenko is off; run Tenko-Takeover\.ps1 again to retry the DHCP window'
        ($out -join "`n") | Should -Match '192\.0\.2\.0/24: Windows answers \(dc1\.corp\.example\.test, dc2\.corp\.example\.test\); Tenko is off'
        $script:world.completes | Should -Be 3
        $script:world.services.dc1.Serving | Should -BeTrue
        $script:world.services.dc2.Serving | Should -BeTrue
        $script:world.scopesOn | Should -BeFalse
        @($script:world.authorized).Count | Should -Be 2
        (Read-State).values.Contains('silenced') | Should -BeFalse
        $script:world.completeFails = $false
        Invoke-FakeRun -Answers @('c', 'Continue') | Should -Be 3 -Because $script:lastError
        $script:world.scopesOn | Should -BeTrue
    }

    It 'reverts the completed takeover first, then starts Windows, when the second completion fails' {
        $script:world.twoScopes = $true; $script:world.completeOk = 1
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:lastError | Should -Match 'Windows answers every scope again and Tenko is off; run Tenko-Takeover\.ps1 -Reverse'
        $calls = @($script:world.calls)
        $off = [array]::IndexOf($calls, 'tenko|scopes-off')
        $off | Should -BeGreaterThan ([array]::IndexOf($calls, 'tenko|task-complete'))
        [array]::LastIndexOf($calls, 'dc1|serving=True') | Should -BeGreaterThan $off
        $script:world.services.dc1.Serving | Should -BeTrue
        $script:world.scopesOn | Should -BeFalse
        $script:world.completeOk = 0
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $script:world.services.dc1.Serving | Should -BeTrue
    }

    It 'reverts and starts Windows again when Tenko''s job fails after its task was completed' {
        $script:world.jobFailsAfter = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:lastError | Should -Match 'the takeover of 192\.0\.2\.0/24 ended failed after its task was completed: Windows answers every scope again'
        $script:world.services.dc1.Serving | Should -BeTrue
        $script:world.scopesOn | Should -BeFalse
        @($script:world.calls | Where-Object { $_ -like '*|ReadAuthorization' }).Count | Should -Be 0 -Because 'nothing waits for a replica before Windows answers'
    }

    It 'takes a completion Tenko already made as made, and a job that already succeeded as completed' {
        $script:world.completeThenFail = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.completes | Should -Be 1
        $script:world.scopesOn | Should -BeTrue
        # A record lost between the completion and the state file: the job's success counts.
        Install-FakeWorld
        $script:world.failAt = 'SetAuthorization'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $path = Join-Path (Get-TkStateDir 'corp.example.test') 'state.json'
        $data = ConvertFrom-TkJson -Chars ([System.IO.File]::ReadAllText($path)).ToCharArray()
        $data.values.Remove('completed.takeover.192.0.2.0/24')
        [System.IO.File]::WriteAllBytes($path, (ConvertTo-TkJsonByte $data))
        Invoke-FakeRun -Answers @('c') | Should -Be 3 -Because $script:lastError
        @($script:world.calls | Where-Object { $_ -eq 'tenko|task-complete' }).Count | Should -Be 1
    }

    It 'records a pending barrier beside the run''s marker, which a sitting without the state file offers to finish' {
        $script:TkReplicaWaitSec = 0
        try {
            $script:world.staleReads = 1000
            Invoke-FakeRun -Answers $script:FirstSitting 3>$null | Should -Be 3 -Because $script:lastError
            $script:world.markerPending | Should -Be 'dc1.corp.example.test,dc2.corp.example.test'
            Remove-Item -LiteralPath (Get-TkStateDir 'corp.example.test') -Recurse -Force
            $script:world.staleReads = 0
            $out = @(Invoke-FakeRun -Answers @('corp.example.test', 'y', 'y') 3>$null 6>&1)
            ($out -join "`n") | Should -Match 'has a pending step: the removal of the DHCP authorization of dc1\.corp\.example\.test, dc2\.corp\.example\.test'
            ($out -join "`n") | Should -Match 'the pending step is done'
            $script:world.markerPending | Should -Be ''
        } finally { $script:TkReplicaWaitSec = 300 }
    }

    It 'resumes inside the authorization barrier without completing Tenko''s task twice' {
        $script:world.failAt = 'SetAuthorization'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:world.scopesOn | Should -BeTrue
        Invoke-FakeRun -Answers @('c') | Should -Be 3 -Because $script:lastError
        @($script:world.calls | Where-Object { $_ -eq 'tenko|task-complete' }).Count | Should -Be 1
        $script:world.choices | Should -Be 0
        @($script:world.authorized).Count | Should -Be 0
    }

    It 'ends the sitting with the barrier pending and a warning when a replica does not catch up, and a later sitting clears it' {
        $script:TkReplicaWaitSec = 0
        try {
            $script:world.staleReads = 1000
            $out = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1)
            $out[-1] | Should -Be 3 -Because $script:lastError
            $script:world.scopesOn | Should -BeTrue
            @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'has not reached dc1\.corp\.example\.test, dc2\.corp\.example\.test yet'
            @((Read-State).values.barrier_pending) | Should -Be @('dc1.corp.example.test', 'dc2.corp.example.test')
            $script:world.staleReads = 0
            $out = @(Invoke-FakeRun -Answers @('', '') 6>&1)
            ($out -join "`n") | Should -Match 'Pending: the removal of the DHCP servers'' authorization has not reached'
            ($out -join "`n") | Should -Match 'has now reached every controller'
            @((Read-State).values.barrier_pending).Count | Should -Be 0
        } finally { $script:TkReplicaWaitSec = 300 }
    }

    It 'turns Tenko''s scopes on again when the restart of Windows fails, so that one side serves' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.restartFails = $true
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('r') | Should -Be 2
        $script:lastError | Should -Match "Tenko's scopes are on again"
        $script:world.scopesOn | Should -BeTrue
        $script:world.calls | Should -Contain 'tenko|scopes-on'
    }

    It 'stops the server that did restart before Tenko goes on again, when the other restart fails' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.restartFailsOn = 'dc2'
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('r') | Should -Be 2
        $calls = @($script:world.calls)
        $served = [array]::IndexOf($calls, 'dc1|serving=True')
        $stopped = [array]::LastIndexOf($calls, 'dc1|StopDhcp')
        $on = [array]::IndexOf($calls, 'tenko|scopes-on')
        $served | Should -BeGreaterThan -1
        $stopped | Should -BeGreaterThan $served
        $on | Should -BeGreaterThan $stopped -Because 'Tenko goes on only once no Windows server serves'
        $script:world.services.dc1.Status | Should -Be 'Stopped'
        $script:world.services.dc1.Start | Should -Be 'Disabled'
        @($script:world.authorized).Count | Should -Be 0 -Because 'the next reverse starts each server unauthorized again'
        $script:world.restartFailsOn = ''
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $script:world.services.dc1.Serving | Should -BeTrue
        $script:world.services.dc2.Serving | Should -BeTrue
    }

    It 'puts back the scopes already reverted when a later revert fails, with Windows stopped again' {
        $script:world.twoScopes = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.revertFailAt = 2
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('r') | Should -Be 2
        $script:lastError | Should -Match "Tenko's revert failed"
        @($script:world.calls | Where-Object { $_ -eq 'tenko|scopes-on' }).Count | Should -Be 1 -Because 'the one scope reverted is on again'
        $script:world.calls | Should -Not -Contain 'dc1|serving=True'
        $script:world.services.dc1.Status | Should -Be 'Stopped'
        $script:world.revertFailAt = 0
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
    }

    It 'tries the call that turns Tenko on again three times, then names what serves and the command that completes it' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.restartFails = $true; $script:world.resumeFails = 'down'
        Invoke-FakeRun -Answers @('r') | Should -Be 2
        $script:world.resumeCalls | Should -Be 3
        $script:lastError | Should -Match 'no server answers 192\.0\.2\.0/24 now, the Windows servers are stopped; run Tenko-Takeover\.ps1 -Reverse again once Tenko answers'
        $script:world.services.dc1.Status | Should -Be 'Stopped'
        $script:world.restartFails = $false; $script:world.resumeFails = ''
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $calls = @($script:world.calls)
        [array]::IndexOf($calls, 'tenko|scopes-on') | Should -BeLessThan ([array]::IndexOf($calls, 'dc1|serving=False')) -Because 'the next reverse turns Tenko on first'
    }

    It 'takes a refusal of that call as Tenko''s decision: no retry, and the next reverse brings Windows back without asking again' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.restartFails = $true; $script:world.resumeFails = 'refuse'
        Invoke-FakeRun -Answers @('r') | Should -Be 2
        $script:world.resumeCalls | Should -Be 1
        $script:lastError | Should -Match 'Tenko refused to turn 192\.0\.2\.0/24 on again .*make the Windows DHCP servers start again, then run Tenko-Takeover\.ps1 -Reverse'
        $script:world.restartFails = $false
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $script:world.resumeCalls | Should -Be 1
        $script:world.services.dc1.Serving | Should -BeTrue
    }

    It 'tells an ended session apart from a refusal: no permanent mark, and the next reverse asks Tenko again' {
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        $script:world.restartFails = $true; $script:world.resumeFails = 'session'
        Invoke-FakeRun -Answers @('r') | Should -Be 2
        $script:world.resumeCalls | Should -Be 1
        $script:lastError | Should -Match 'the session with Tenko ended before it turned 192\.0\.2\.0/24 on again .*asks for a new approval'
        (Read-State).values.Contains('refused.takeover.192.0.2.0/24') | Should -BeFalse
        $script:world.restartFails = $false; $script:world.resumeFails = ''
        Invoke-FakeRun -Answers @('r') | Should -Be 5 -Because $script:lastError
        $script:world.resumeCalls | Should -Be 2 -Because 'the next sitting turns Tenko on first'
    }

    It 'reads the replicas until they show the change, and judges the last read' {
        $script:world.staleReads = 3
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        @($script:world.calls | Where-Object { $_ -eq 'dc1|Replicate' }).Count | Should -BeGreaterThan 1
    }

    It 'finishes the check in a quiet network with the warning and the takeover recorded as unproven, and a later sitting says whether Tenko has answered since' {
        $script:TkAckWaitSec = 0
        try {
            $script:world.acks = 0
            $out = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1 6>&1)
            $out[-1] | Should -Be 3 -Because $script:lastError
            $text = @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' '
            $text | Should -Match ([regex]::Escape($script:TkQuietText))
            $text | Should -Match '87\.5 percent of the lease time.*ipconfig /renew.*or run -Reverse'
            $text | Should -Match 'Not answered yet: 192\.0\.2\.0/24\.'
            ($out -join "`n") | Should -Match "Tenko's scopes are on; not yet proven by an answered client: 192\.0\.2\.0/24"
            ($out -join "`n") | Should -Not -Match 'Tenko serves the scopes'
            (Read-State).steps['5.check'].state | Should -Be 'done'
            @((Read-State).values.unproven) | Should -Be @('192.0.2.0/24')
            $out = @(Invoke-FakeRun -Answers @('', '') 6>&1)
            ($out -join "`n") | Should -Match 'Tenko reports no answered client yet for 192\.0\.2\.0/24'
            @($script:world.prompts | Where-Object { $_ -match 'finish \(phase 6\)' })[-1] | Should -Match 'Tenko reports no answered client yet for 192\.0\.2\.0/24' -Because 'the finish names what is unproven, and does not refuse'
            $script:world.acks = 2
            $out = @(Invoke-FakeRun -Answers @('', '') 6>&1)
            ($out -join "`n") | Should -Match 'Tenko reports that it has answered a client of every scope since the DHCP window'
            (Read-State).values.Contains('unproven') | Should -BeFalse
        } finally { $script:TkAckWaitSec = 300 }
    }

    It 'proves each scope on its own: the one with no answered client is named, and the record clears only when both are answered' {
        $script:TkAckWaitSec = 0
        try {
            $script:world.twoScopes = $true
            $script:world.acksByScope = @{ '192.0.2.0/24' = 3; '198.51.100.0/24' = 0 }
            $out = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1)
            $out[-1] | Should -Be 3 -Because $script:lastError
            (@($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' ') | Should -Match 'Not answered yet: 198\.51\.100\.0/24\.$'
            @((Read-State).values.unproven) | Should -Be @('198.51.100.0/24')
            # A counter that is not a number counts as not answered, and ends nothing.
            $script:world.acksByScope['198.51.100.0/24'] = 'many'
            $out = @(Invoke-FakeRun -Answers @('', '') 6>&1)
            $out[-1] | Should -Be 3 -Because $script:lastError
            @((Read-State).values.unproven) | Should -Be @('198.51.100.0/24')
            $script:world.acksByScope['198.51.100.0/24'] = 1
            [void](Invoke-FakeRun -Answers @('', ''))
            (Read-State).values.Contains('unproven') | Should -BeFalse
        } finally { $script:TkAckWaitSec = 300 }
    }

    It 'reads only the item of the scope''s own job, whatever the server lists first, and counts a scope without a job as unproven' {
        $script:TkAckWaitSec = 0
        try {
            $script:world.acks = 0; $script:world.ignoreFilter = $true; $script:world.foreignFirst = $true
            Invoke-FakeRun -Answers $script:FirstSitting 3>$null | Should -Be 3 -Because $script:lastError
            @((Read-State).values.unproven) | Should -Be @('192.0.2.0/24') -Because 'another job''s counter is never this scope''s'
        } finally { $script:TkAckWaitSec = 300 }
        $state = @{ Data = @{ readings = [ordered]@{ dhcp = @([ordered]@{ scopes = @([ordered]@{ cidr = '198.51.100.0/24' }) }) }; jobs = [ordered]@{} } }
        @(Get-TkUnproven -State $state) | Should -Be @('198.51.100.0/24')
    }

    It 'tells a node that reports no ACK counter apart from a counter of 0, and refuses two items of one job with exit 4' {
        $script:TkAckWaitSec = 0
        try {
            # Right after the silence: the check stops and says which side serves.
            $script:world.noCounterByJob = $true
            Invoke-FakeRun -Answers $script:FirstSitting 3>$null | Should -Be 2
            $script:lastError | Should -Match "Tenko's node does not report answered clients for 192\.0\.2\.0/24 \(its takeover has no ACK counter\).*Tenko's scopes are on and the Windows DHCP services are stopped: update the node, then run the script again, or run it with -Reverse"
            (Read-State).steps['5.check'].state | Should -Be 'failed'
            $script:world.services.dc1.Serving | Should -BeFalse
            # A later sitting with no failed step reports it and goes on.
            Install-FakeWorld
            $script:world.acks = 0
            Invoke-FakeRun -Answers $script:FirstSitting 3>$null | Should -Be 3 -Because $script:lastError
            $script:world.noCounterByJob = $true
            $out = @(Invoke-FakeRun -Answers @('', '') 3>&1 6>&1)
            $out[-1] | Should -Be 3 -Because $script:lastError
            (@($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Message -join ' ') | Should -Match "does not report answered clients for 192\.0\.2\.0/24.*The scopes stay recorded as unproven\."
            ($out -join "`n") | Should -Not -Match 'Tenko reports no answered client yet'
            @((Read-State).values.unproven) | Should -Be @('192.0.2.0/24')
        } finally { $script:TkAckWaitSec = 300 }
        $job = '0190d1c2-0000-7000-8000-000000000001'
        $state = @{ Data = @{ readings = [ordered]@{ dhcp = @([ordered]@{ scopes = @([ordered]@{ cidr = '192.0.2.0/24' }) }) }; jobs = [ordered]@{ 'takeover.192.0.2.0/24' = $job } } }
        Mock Invoke-Tenko { [ordered]@{ items = @([ordered]@{ job = $job; acks = 0 }, [ordered]@{ job = $job; acks = 5 }) } }
        $caught = $null
        try { [void](Get-TkUnproven -State $state) } catch { $caught = $_.Exception }
        $caught.Data['tk.exit'] | Should -Be 4
        $caught.Message | Should -Match "lists the job $job of 192\.0\.2\.0/24 2 times"
    }

    It 'refuses with exit 4 a node that names one job for two scopes, while Windows still serves' {
        $script:world.twoScopes = $true; $script:world.sameJob = $true
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 4
        $script:lastError | Should -Match 'Tenko named the job \S+ for the takeover of 198\.51\.100\.0/24 and of 192\.0\.2\.0/24, so the script cannot prove each scope on its own\. Windows still serves\. Tenko may hold a takeover job for 198\.51\.100\.0/24 that this run did not record.*cancel it in Tenko before you run the script again'
        $script:world.calls | Should -Not -Contain 'dc1|StopDhcp'
        $script:world.services.dc1.Serving | Should -BeTrue
    }

    It 'refuses the DHCP window on a node that cannot report answered clients, before its question and any stop' {
        $script:world.failRoute = 'takeover$'
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:world.takeoverList = 'missing'
        $script:world.calls.Clear()
        Invoke-FakeRun -Answers @('c', 'Continue') | Should -Be 2
        $script:lastError | Should -Match "this node's version of Tenko cannot report answered clients per takeover .*so the DHCP window is not started and Windows answers as before: update the node"
        $script:world.choices | Should -Be 0
        $script:world.calls | Should -Not -Contain 'dc1|StopDhcp'
        $script:world.services.dc1.Serving | Should -BeTrue
    }

    It 'gives no warning when a client is answered within the wait' {
        $out = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1)
        $out[-1] | Should -Be 3 -Because $script:lastError
        @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] -and $_.Message -match 'has not answered a client yet' }) | Should -BeNullOrEmpty
        (Read-State).values.Contains('unproven') | Should -BeFalse
    }

    It 'lets no confirmation of an earlier run in the same process stand for the next' {
        $script:TkWindowWatch = [System.Diagnostics.Stopwatch]::StartNew()
        Mock Assert-TkHost { if ($null -ne $script:TkWindowWatch) { throw 'an earlier run''s confirmation was still held' } }
        $caught = ''
        try { [void](Invoke-Takeover -Directory '') } catch { $caught = $_.Exception.Message }
        $caught | Should -Not -Match 'still held'
    }
}

Describe 'The DNS reverse' {
    BeforeEach {
        Install-FakeWorld
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        # Tenko serves a new ordinary name and a locator record of its own after the flip.
        $script:world.tenkoAdds['_msdcs.corp.example.test'] = @([pscustomobject]@{ Name = '_ldap._tcp.dc'; Type = 'SRV'; Data = '0 100 389 evil.corp.example.test' })
        $script:world.tenkoAdds['corp.example.test'] = @([pscustomobject]@{ Name = 'new1'; Type = 'A'; Data = '192.0.2.140' })
        Invoke-FakeRun -Reverse | Should -Be 5 -Because $script:lastError
    }

    It 'shows the differences and keeps Tenko''s version only where the domain''s name is typed, with names listed apart kept at their flip-time records' {
        $out = @(Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no') 6>&1)
        $out[-1] | Should -Be 5 -Because $script:lastError
        ($out -join "`n") | Should -Match '!\+ _ldap\._tcp\.dc\._msdcs\.corp\.example\.test SRV 0 100 389 evil\.corp\.example\.test'
        ($out -join "`n") | Should -Match ' \+ new1\.corp\.example\.test A 192\.0\.2\.140'
        @($script:world.records['corp.example.test'] | Where-Object { $_.Name -eq 'new1' }).Count | Should -Be 1
        @($script:world.records['_msdcs.corp.example.test'] | Where-Object { $_.Data -match 'evil' }).Count | Should -Be 0
    }

    It 'restores the export of phase 2 when the domain''s name is not typed' {
        Invoke-FakeRun -Reverse -Answers @('no') | Should -Be 5 -Because $script:lastError
        @($script:world.restoredFromBackup) | Should -Contain 'corp.example.test'
        @($script:world.restoredFromBackup) | Should -Contain '_msdcs.corp.example.test'
        @($script:world.records['corp.example.test'] | Where-Object { $_.Name -eq 'new1' }).Count | Should -Be 0
    }

    It 'cuts the zones loose from Tenko before it reads them: a record Tenko adds after the read never reaches the directory' {
        $script:world.lateAdds['corp.example.test'] = @([pscustomobject]@{ Name = 'late'; Type = 'A'; Data = '203.0.113.7' })
        $script:world.calls.Clear()
        Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no') | Should -Be 5 -Because $script:lastError
        @($script:world.tenkoAdds['corp.example.test'] | Where-Object { $_.Name -eq 'late' }).Count | Should -Be 1 -Because 'Tenko did add it after the read'
        @($script:world.records['corp.example.test'] | Where-Object { $_.Name -eq 'late' }).Count | Should -Be 0
        $calls = @($script:world.calls)
        [array]::IndexOf($calls, 'dc1|FreezeZone') | Should -BeLessThan ([array]::IndexOf($calls, 'dc1|ReadRecords'))
    }

    It 'integrates nothing that differs from what was shown, record by record' {
        $script:world.fixIgnored = $true
        Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no') | Should -Be 4
        $script:lastError | Should -Match 'differs from what was shown in 1 records .*nothing of it reached the directory'
        @($script:world.records['_msdcs.corp.example.test'] | Where-Object { $_.Data -match 'evil' }).Count | Should -Be 0
        $script:world.zones['_msdcs.corp.example.test'].dc1.Ds | Should -BeFalse
    }

    It 'lists a delegation under _tcp apart and sets it back when its name is not typed; the start of authority goes back too' {
        $script:world.tenkoAdds['corp.example.test'] += [pscustomobject]@{ Name = '_tcp'; Type = 'NS'; Data = 'ns.evil.example.test' }
        $out = @(Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no', 'no') 6>&1)
        $out[-1] | Should -Be 5 -Because $script:lastError
        ($out -join "`n") | Should -Match '!\+ _tcp\.corp\.example\.test NS ns\.evil\.example\.test'
        ($out -join "`n") | Should -Match 'corp\.example\.test: A \+1 -0, NS \+1 -0; 1 marked !'
        @($script:world.records['corp.example.test'] | Where-Object { $_.Type -eq 'NS' }).Count | Should -Be 0
        $script:world.soaSet['corp.example.test'] | Should -Be 'dc1.corp.example.test. hostmaster.corp.example.test.'
    }

    It 'restores the export of a zone whose name listed apart differs in a type the script cannot write back' {
        $script:world.tenkoAdds['corp.example.test'] += [pscustomobject]@{ Name = 'DomainDnsZones'; Type = 'TXT'; Data = 'planted' }
        Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no', 'no') | Should -Be 5 -Because $script:lastError
        @($script:world.restoredFromBackup) | Should -Contain 'corp.example.test'
        @($script:world.records['corp.example.test'] | Where-Object { $_.Type -eq 'TXT' -or $_.Name -eq 'new1' }).Count | Should -Be 0
    }

    It 'integrates nothing whose time to live or start of authority timers changed after it was shown' {
        $script:world.ttlTamper = $true
        Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no') | Should -Be 4
        $script:lastError | Should -Match 'differs from what was shown in 2 records .*pc1\.corp\.example\.test\|a\|192\.0\.2\.120 ttl'
        $script:world.zones['corp.example.test'].dc1.Ds | Should -BeFalse
        $script:world.ttlTamper = $false; $script:world.timersTamper = $true
        Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no') | Should -Be 4
        $script:lastError | Should -Match 'start of authority timers 1 600 86400 3600 3600, shown 900 600 86400 3600 3600'
    }

    It 'puts each zone back into the partition the discovery read' {
        Invoke-FakeRun -Reverse -Answers @('corp.example.test', 'no') | Should -Be 5 -Because $script:lastError
        $script:world.integratedScope['corp.example.test'] | Should -Be 'Domain|'
        $script:world.integratedScope['_msdcs.corp.example.test'] | Should -Be 'Forest|'
    }

    It 'finishes a restore that stopped between the removal of the zone and its load' {
        $script:world.restoreBreaks = $true
        Invoke-FakeRun -Reverse -Answers @('no') | Should -Be 2
        $script:world.zones['corp.example.test'].dc1.Type | Should -Be 'Missing'
        Invoke-FakeRun -Reverse -Answers @('no') | Should -Be 5 -Because $script:lastError
        $script:world.zones['corp.example.test'].dc1.Ds | Should -BeTrue
        @($script:world.restoredFromBackup) | Should -Contain 'corp.example.test'
        @($script:world.records['corp.example.test'] | Where-Object { $_.Name -eq 'new1' }).Count | Should -Be 0
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

    It 'is created with one DNS name, AES only, no group and no delegation, and its rights are warned about by SID' {
        Mock Invoke-FakeTenko -ParameterFilter { $Path -eq '/dns/kerberos/adopt' } { $script:world.pwdLastSet = '200'; [void]$script:world.tenkoCalls.Add('POST /dns/kerberos/adopt'); [ordered]@{} }
        $warnings = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1)
        $warnings[-1] | Should -Be 3
        $script:world.accounts.Contains('tenko$') | Should -BeTrue
        $text = ($warnings | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' '
        $text | Should -Match 'S-1-5-21-1000-2000-3000-1234 may reset the password of Tenko''s account'
        $text | Should -Not -Match 'S-1-5-21-1000-2000-3000-512 may'
        $text | Should -Not -Match '-517 may|S-1-5-32-56[01] may' -Because 'a computer object''s default groups hold their default attributes'
        $script:TkRemote.NewTenkoAccount.ToString() | Should -Not -Match 'HTTP/'
    }

    It 'warns about Cert Publishers and the license servers beyond the attributes they hold by default' {
        Mock Invoke-FakeTenko -ParameterFilter { $Path -eq '/dns/kerberos/adopt' } { $script:world.pwdLastSet = '200'; [ordered]@{} }
        $script:world.tenkoAcl = 'O:DAG:DUD:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;WP;;;CA)(OA;;WP;bf967a79-0de6-11d0-a285-00aa003049e2;;S-1-5-32-561)'
        $warnings = @(Invoke-FakeRun -Answers $script:FirstSitting 3>&1)
        $warnings[-1] | Should -Be 3
        $text = ($warnings | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message }) -join ' '
        $text | Should -Match 'S-1-5-21-1000-2000-3000-517 may write Tenko''s account'
        $text | Should -Match 'S-1-5-32-561 may write Tenko''s account'
    }

    It 'is disabled when Tenko has not changed its password in time, by the stopwatch and pwdLastSet' {
        $script:TkPasswordChangeSec = 0
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 2
        $script:world.disabled | Should -Be $script:world.accounts['tenko$']
        $script:lastError | Should -Match 'disabled'
    }

    It 'is removed by the reverse, by its SID, only after every zone is back on its update setting' {
        Mock Invoke-FakeTenko -ParameterFilter { $Path -eq '/dns/kerberos/adopt' } { $script:world.pwdLastSet = '200'; [ordered]@{} }
        Invoke-FakeRun -Answers $script:FirstSitting | Should -Be 3 -Because $script:lastError
        foreach ($phase in 5, 4, 3, 2) { Invoke-FakeRun -Reverse | Should -Be 5 -Because $script:lastError }
        $script:world.accounts.Contains('tenko$') | Should -BeFalse
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
        $out[-1] | Should -Be 5 -Because $script:lastError
        ($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Message | Should -Match 'may still serve DHCP'
        $script:world.tenkoCalls | Should -BeNullOrEmpty
        $script:world.services.dc1.Status | Should -Be 'Running'
        @((Read-State).values['pending.5']).Count | Should -BeGreaterThan 0
    }
}

Describe 'The dry run' {
    It 'prints the change list, changes nothing on Windows and contacts no Tenko' {
        Install-FakeWorld
        $out = @(Invoke-FakeRun -DryRun -Answers @('corp.example.test', 'y', '1') 6>&1)
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
