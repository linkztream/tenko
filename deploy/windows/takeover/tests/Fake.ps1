# Shared by the suites: a fake domain (two controllers that are also the DHCP failover pair,
# a member server for the exporter) behind the script's one seam to Windows, Invoke-TkRemote,
# and a fake Tenko behind its one seam to the API, Invoke-TkCall. Both keep their state in
# $world, log every call, and fail once where a test says so. The fake DHCP servers answer
# their cmdlets only while their service runs and serve only when authorized at their last
# start; the fake installer takes only the parameters of the installer the payload carries.
# Nothing reaches a real server.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'mocks bind the parameters of the functions they replace')]
param()

$script:FakeDomain = 'corp.example.test'
$script:FakeSid = 'S-1-5-21-1000-2000-3000'
$script:MirrorDir = Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror') 'tests'
$script:ContractInstaller = Join-Path (Join-Path $PSScriptRoot 'fixtures') 'Install-TenkoDhcpMirror.contract.ps1'

function Get-FakeRaw {
    # The exporter's reads as the mirror's recorded fixtures hold them.
    $dir = Join-Path $script:MirrorDir 'fixtures'
    $read = { param($Name) $path = Join-Path $dir "$Name.json"; if (Test-Path -LiteralPath $path) { @(Get-Content -LiteralPath $path -Raw | ConvertFrom-Json) } else { @() } }
    $reservations = & $read 'Get-DhcpServerv4Reservation'
    $options = @{}
    foreach ($reservation in $reservations) {
        $ip = [string]$reservation.IPAddress.IPAddressToString
        $options[$ip] = & $read "Get-DhcpServerv4OptionValue-ReservedIP-$ip"
    }
    return @{
        scopes = & $read 'Get-DhcpServerv4Scope'; server_options = & $read 'Get-DhcpServerv4OptionValue'
        option_defs = & $read 'Get-DhcpServerv4OptionDefinition'; classes = & $read 'Get-DhcpServerv4Class'
        policies = @(& $read 'Get-DhcpServerv4Policy') + @(& $read 'Get-DhcpServerv4Policy-ScopeId-192.0.2.0')
        filter_lists = & $read 'Get-DhcpServerv4FilterList'; filters = & $read 'Get-DhcpServerv4Filter'
        superscopes = & $read 'Get-DhcpServerv4Superscope'; failover = & $read 'Get-DhcpServerv4Failover'
        exclusions = @{ '192.0.2.0' = & $read 'Get-DhcpServerv4ExclusionRange' }; reservations = @{ '192.0.2.0' = $reservations }
        scope_options = @{ '192.0.2.0' = & $read 'Get-DhcpServerv4OptionValue-ScopeId-192.0.2.0' }; reservation_options = $options
        dns = @{ '192.0.2.0' = & $read 'Get-DhcpServerv4DnsSetting-ScopeId-192.0.2.0' }; leases = @{ '192.0.2.0' = @() }
    }
}

function Use-FakePayload {
    # The release data as the release run fills it: the repository's exporter, and the
    # installer of the contract, or the repository's installer where a test asks for it.
    param([switch]$RepositoryInstaller)
    $mirror = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror'
    $files = @{
        'Tenko-DhcpMirror.ps1'        = (Join-Path $mirror 'Tenko-DhcpMirror.ps1')
        'Install-TenkoDhcpMirror.ps1' = $(if ($RepositoryInstaller) { Join-Path $mirror 'Install-TenkoDhcpMirror.ps1' } else { $script:ContractInstaller })
    }
    foreach ($name in $files.Keys) {
        $bytes = [System.IO.File]::ReadAllBytes($files[$name])
        $script:TkPayloadText[$name] = [System.Convert]::ToBase64String($bytes)
        $script:TkPayloadDigest[$name] = (Get-TkTextDigest $bytes).Digest
    }
    $script:TkVersion = '0.0.0-test'
}

function ConvertTo-FakeSecure {
    param([string]$Text)
    $secure = [securestring]::new()
    foreach ($char in $Text.ToCharArray()) { $secure.AppendChar($char) }
    return $secure
}

function Get-FakeWorld {
    $zones = [ordered]@{}
    foreach ($name in $script:FakeDomain, "_msdcs.$($script:FakeDomain)", '2.0.192.in-addr.arpa') {
        $zones[$name] = [ordered]@{}
        foreach ($dc in 'dc1', 'dc2') {
            $zones[$name][$dc] = @{ Type = 'Primary'; Ds = $true; Update = 'NonsecureAndSecure'; Scope = $(if ($name.StartsWith('_msdcs')) { 'Forest' } else { 'Domain' }); Partition = ''; Transfer = 'NoTransfer'; Notify = 'NoNotify'; Secondaries = @(); NotifyServers = @(); Registry = @{ Transfer = 3; Notify = 0 } }
        }
    }
    return @{
        zones = $zones
        records = @{
            $script:FakeDomain = @([pscustomobject]@{ Name = '@'; Type = 'A'; Data = '192.0.2.11' }, [pscustomobject]@{ Name = 'pc1'; Type = 'A'; Data = '192.0.2.120' })
            "_msdcs.$($script:FakeDomain)" = @([pscustomobject]@{ Name = '_ldap._tcp.dc'; Type = 'SRV'; Data = "0 100 389 dc1.$($script:FakeDomain)" })
            '2.0.192.in-addr.arpa' = @([pscustomobject]@{ Name = '120'; Type = 'PTR'; Data = "pc1.$($script:FakeDomain)" })
        }
        # Records Tenko serves beside the flip-time ones, which a secondary of it then holds.
        tenkoAdds = @{}
        directory = @($script:FakeDomain, "_msdcs.$($script:FakeDomain)", '2.0.192.in-addr.arpa')
        services = @{ dc1 = @{ Status = 'Running'; Start = 'Automatic'; Serving = $true }; dc2 = @{ Status = 'Running'; Start = 'Automatic'; Serving = $true } }
        authorized = [System.Collections.ArrayList]@('dc1', 'dc2')
        foreign = @()
        accounts = [ordered]@{}; marks = @{}; crashAfterCreate = ''; crashed = $false
        nextRid = 1400
        gpo = ''; gpoMark = ''
        # The PDC emulator's file-backed copies, records Tenko adds once read (lateAdds), a
        # restore that stops after the removal, a fix-up that writes nothing.
        copies = @{}; lateAdds = @{}; restoreBreaks = $false; restoreBroken = $false; fixIgnored = $false; soaSet = @{}
        twoScopes = $false; staleReads = 0; staleList = @(); restartFailsOn = ''
        reverts = 0; revertFailAt = 0; resumeFails = ''; resumeCalls = 0
        tenkoAcl = ''; srvDelegation = $false
        nrpt = @(); takeoverList = ''; foreignFirst = $false; ignoreFilter = $false; sameJob = $false; noCounterByJob = $false
        jobScopes = @{}; acksByScope = @{}; prompts = [System.Collections.ArrayList]@()
        forge = $null; creators = @{}; timersTamper = $false; stopFailsOn = ''; choices = 0; lastChoice = ''; objectAcl = @{}; quotaComputer = $false; ttlTamper = $false; zoneScope = @{}; integratedScope = @{}
        tasks = [System.Collections.ArrayList]@()
        batchRight = $false
        rsat = $true
        marker = $null
        markerThief = $false; markerPending = ''
        completes = 0; completeFails = $false; completeOk = 0; completeThenFail = $false; completeFailedOnce = $false; jobFailsAfter = $false; crashAtComplete = $false; crashedAtComplete = $false
        dnsUser = 'CORP\dhcp-dns'
        v6 = @(); leaseSeconds = 28800; startPolicy = @(); gpp = @(); timeSource = 'time.example.test'
        pwdLastSet = '100'
        written = [System.Collections.ArrayList]@()
        raw = (Get-FakeRaw)
        configChanged = $false
        tenkoRecordsDiffer = $false
        locator = @{ name = "dc1.$($script:FakeDomain)"; address = '192.0.2.11' }
        addresses = @{ "dc1.$($script:FakeDomain)" = @('192.0.2.11'); "dc2.$($script:FakeDomain)" = @('192.0.2.12') }
        nameUse = @{ Sid = ''; Spns = 0 }
        badRemoteOwner = $false
        calls = [System.Collections.ArrayList]@()
        failAt = ''; failOn = ''; failed = $false; acks = 3
        # Tenko
        mirrors = [ordered]@{}; tzones = [ordered]@{}; jobs = [ordered]@{}; window = $null; scopesOn = $false
        tenkoCalls = [System.Collections.ArrayList]@()
        failRoute = ''; tenkoFailed = $false
        badMirror = $false; badToken = $false; fingerprint = ''
        tenkoLeases = @()
        answers = [System.Collections.ArrayList]@()
        unreachable = $false; disabled = $null; leaveOpen = $false; gpoMembers = @(); restartFails = $false
    }
}

function Get-FakeShort { param([string]$Server) return $Server.Split('.')[0] }

function Assert-FakeServiceRunning {
    # The DHCP Server cmdlets talk to the running service.
    param([string]$Short)
    if ($script:world.services[$Short].Status -ne 'Running') { throw "Failed to get the information of the DHCP server ${Short}: the DHCP Server service is not running" }
}

function Add-FakeAccount {
    # The run's own account by the SID the script resolved; the mark goes into the new
    # object's description. A sitting may end right after the creation (crashAfterCreate).
    param([string]$Name, [string]$KnownSid, [string]$Mark)
    $w = $script:world
    if ($w.accounts.Contains($Name)) {
        if ($w.accounts[$Name] -ne $KnownSid) { throw "the account $Name exists and is not the run's own: it is not used and never removed" }
        return $w.accounts[$Name]
    }
    $w.nextRid++
    $w.accounts[$Name] = "$($script:FakeSid)-$($w.nextRid)"
    $w.marks[$Name] = $Mark
    if ($w.crashAfterCreate -eq $Name -and -not $w.crashed) { $w.crashed = $true; throw 'injected: the sitting ended right after the creation' }
    return $w.accounts[$Name]
}

function Get-FakeLive {
    # What a secondary of Tenko holds: the flip-time records and what Tenko serves beside them.
    param([string]$Zone)
    $w = $script:world
    return @(@($w.records[$Zone]) + @($(if ($w.tenkoAdds.ContainsKey($Zone)) { $w.tenkoAdds[$Zone] })) | Where-Object { $null -ne $_ })
}

function Invoke-FakeRemote {
    param([string]$Server, [string]$Name, [object[]]$Arguments)
    $w = $script:world
    [void]$w.calls.Add("$(Get-FakeShort $Server)|$Name")
    if ($w.failAt -eq $Name -and -not $w.failed -and (-not $w.failOn -or $w.failOn -eq (Get-FakeShort $Server))) { $w.failed = $true; throw "injected failure at $Name on $Server" }
    $s = Get-FakeShort $Server
    $a = $Arguments
    $domain = $script:FakeDomain
    switch ($Name) {
        'ReadProgramFiles' { 'C:\Program Files' }
        'ProtectDirectory' { if ($w.badRemoteOwner) { throw "$($a[0])\$($a[1] -join '\') is owned by an account other than SYSTEM and Administrators" } }
        'ReadDomain' {
            @{ Kind = 'domain'; DnsRoot = $domain; NetBIOSName = 'CORP'; DomainSid = $script:FakeSid; Pdc = "dc1.$domain"; DistinguishedName = 'DC=corp,DC=example,DC=test'; ComputersContainer = 'CN=Computers,DC=corp,DC=example,DC=test'; ForestRoot = $domain; Configuration = 'CN=Configuration,DC=corp,DC=example,DC=test'; Quota = '0'; Kds = $false }
            @{ Kind = 'controller'; Name = "dc1.$domain"; IPv4 = '192.0.2.11'; IPv6 = ''; Gc = $true }
            @{ Kind = 'controller'; Name = "dc2.$domain"; IPv4 = '192.0.2.12'; IPv6 = ''; Gc = $true }
        }
        'ReadZones' {
            foreach ($zone in $w.zones.Keys) {
                $z = $w.zones[$zone][$s]
                if ($null -eq $z) { continue }
                @{ Name = $zone; Type = $z.Type; Ds = $z.Ds; Scope = $z.Scope; Partition = $z.Partition; Update = $z.Update; Reverse = $zone.EndsWith('.arpa'); Transfer = $z.Transfer; Notify = $z.Notify; Secondaries = @($z.Secondaries); NotifyServers = @($z.NotifyServers); Masters = @(); Serial = '7'; Aging = $false }
            }
            @{ Name = '.'; Type = 'ServerForwarder'; Masters = @('198.51.100.53') }
            @{ Name = ''; Type = 'Scavenging'; Masters = @(); Aging = $false }
        }
        'ReadDirectoryZones' { foreach ($zone in $w.directory) { @{ Name = $zone; Dn = "DC=$zone,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example,DC=test" } } }
        'ReadDhcpInDirectory' {
            foreach ($dc in $w.authorized) { @{ Name = "$dc.$domain"; Address = $(if ($dc -eq 'dc1') { '192.0.2.11' } else { '192.0.2.12' }) } }
            foreach ($entry in $w.foreign) { $entry }
        }
        'ReadDhcpServer' {
            Assert-FakeServiceRunning $s
            $scopes = @(@{ Id = '192.0.2.0'; Mask = '255.255.255.0'; Start = '192.0.2.100'; End = '192.0.2.199'; State = 'Active'; LeaseSeconds = $w.leaseSeconds; Exclusions = @('192.0.2.150-192.0.2.159'); Reservations = @(@{ Ip = '192.0.2.120'; Client = '00-00-5e-00-53-01' }); Hosts = @('pc1') })
            if ($w.twoScopes) { $scopes += @{ Id = '198.51.100.0'; Mask = '255.255.255.0'; Start = '198.51.100.100'; End = '198.51.100.199'; State = 'Active'; LeaseSeconds = $w.leaseSeconds; Exclusions = @(); Reservations = @(); Hosts = @() } }
            @{
                Scopes     = $scopes
                Bindings   = @($(if ($s -eq 'dc1') { '192.0.2.11' } else { '192.0.2.12' }))
                Failover   = @(@{ Name = 'dc1-dc2'; Partner = $(if ($s -eq 'dc1') { "dc2.$domain" } else { 'dc1' }); Mode = 'LoadBalance'; Scopes = @('192.0.2.0') })
                DnsUser    = $w.dnsUser; V6Scopes = @($w.v6); Multicast = @(); AllowList = $false; DenyList = $false; Policies = @(); Superscope = @(); Service = 'Automatic'; Conflict = 0
            }
        }
        'ReadComputers' {
            @{ Name = "srv1.$domain"; Server = $true; IPv4 = '192.0.2.30'; Sid = "$($script:FakeSid)-1300"; Delegation = [bool]$w.srvDelegation }
            @{ Name = "pc1.$domain"; Server = $false; IPv4 = '192.0.2.120'; Sid = "$($script:FakeSid)-1301"; Delegation = $false }
            # A computer a domain user created under the quota, named like a stale DHCP server.
            if ($w.quotaComputer) { @{ Name = "dhcp3.$domain"; Server = $true; IPv4 = '192.0.2.33'; Sid = "$($script:FakeSid)-1302"; Delegation = $false; Creator = "$($script:FakeSid)-1105" } }
        }
        'ReadNameUse' { $w.nameUse }
        'ReadHardening' { @{ Kind = 'server'; LdapSigning = 2; ChannelBinding = 2; Spooler = 'Stopped'; TimeStatus = 'Last Successful Sync Time: 2026-11-21'; TimeSource = $(if ($s -eq 'dc1') { $w.timeSource } else { "dc1.$domain" }) } }
        'ReadLocalAdmins' { @{ Name = 'CORP\Domain Admins'; Sid = "$($script:FakeSid)-512"; Class = 'Group' } }
        'ReadFeature' { $w.rsat }
        'SetFeature' { $w.rsat = [bool]$a[1]; $w.rsat }
        'ReadMarker' { if ($w.marker) { $m = @{} + $w.marker; $m.Pending = $w.markerPending; [pscustomobject]$m } }
        'WriteMarkerPending' { if ($w.marker) { $w.markerPending = $a[1] } }
        'ReadDhcpService' { $service = $w.services[$s]; @{ Status = $service.Status; Start = $service.Start; Listening = $(if ($service.Status -eq 'Running') { 1 } else { 0 }) } }
        'WriteMarker' {
            if ($a[3]) { $w.marker = $null; $w.markerPending = '' }
            elseif ($w.markerThief) { $w.marker = @{ Run = 'another-run'; Host = 'ADM2'; Time = '2026-11-21T10:00:00Z' } }
            else { $w.marker = @{ Run = $a[1]; Host = $a[2]; Time = '2026-11-21T10:00:00Z' } }
        }
        'ExportDhcp' { Assert-FakeServiceRunning $s }
        'ExportZone' { "C:\Windows\System32\dns\$($a[1])" }
        'NewAccount' { Add-FakeAccount -Name $(if ($a[1]) { "$($a[0])$" } else { $a[0] }) -KnownSid $a[5] -Mark $a[7] }
        'RemoveAccount' { foreach ($key in @($w.accounts.Keys)) { if ($w.accounts[$key] -eq $a[0]) { $w.accounts.Remove($key) } } }
        'ResetPassword' { }
        'InstallExporter' {
            # The keys the block passes, against the parameters of the installer carried.
            $tokens = $null; $errors = $null
            $have = @([System.Management.Automation.Language.Parser]::ParseFile($script:FakeInstallerPath, [ref]$tokens, [ref]$errors).ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
            $block = $script:TkRemote.InstallExporter.Ast
            $keys = @($block.FindAll({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true) | Where-Object { @($_.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text }) -contains 'Url' } | ForEach-Object { $_.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text } }) + 'Credential'
            foreach ($key in $keys) { if ($have -notcontains $key) { throw "A parameter cannot be found that matches parameter name '$key'." } }
            if (-not ($a[6] -is [securestring])) { throw 'the token reached the installer as something else than a SecureString' }
            if ($w.tasks -notcontains $a[7]) { [void]$w.tasks.Add($a[7]) }
            $w.batchRight = $true
            @{ Pending = $false; Stored = $true }
        }
        'RemoveExporter' { $w.tasks.Remove($a[1]); @{ Pending = $false; Task = $false } }
        'RemoveBatchRight' { $w.batchRight = $false; $true }
        'StartExporter' { }
        'SetZoneLists' {
            $z = $w.zones[$a[0]][$s]
            $z.Secondaries = @($a[1]); $z.Transfer = $a[2]; $z.Notify = $a[3]; $z.NotifyServers = @($a[4])
            @{ Transfer = $z.Transfer; Notify = $z.Notify; Secondaries = @($z.Secondaries); NotifyServers = @($z.NotifyServers) }
        }
        'SetDnsCredential' { Assert-FakeServiceRunning $s; if ($a[1]) { '' } else { $a[0].UserName } }
        'NewTenkoAccount' {
            $sid = Add-FakeAccount -Name "$($a[0])$" -KnownSid $a[4] -Mark $a[5]
            # A computer object's defaults: Cert Publishers on userCertificate, the license
            # servers on the terminal server attribute; and a reset right of an ordinary account.
            $acl = $(if ($w.tenkoAcl) { $w.tenkoAcl } else { "O:DAG:DUD:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CR;;;$($script:FakeSid)-1234)(A;;RPWP;;;PS)(A;;RC;;;AU)(OA;;WP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RPWP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)" })
            @{ Dn = "CN=$($a[0]),$($a[1])"; Sid = $sid; Groups = @(); Uac = 4096; Encryption = 24; Spns = @($a[2]); DelegateTo = @(); PwdLastSet = $w.pwdLastSet; Sddl = $acl; AccountOps = 0 }
        }
        'ReadRunObject' {
            # Someone may plant an object of the run's name with a mark copied from another
            # object of the run (forge = @{ Name; From }).
            if ($a[0] -eq 'gpo') {
                if ($w.gpo) { @{ Id = $w.gpo; Mark = $w.gpoMark; Creator = ''; Sddl = 'O:DAG:DAD:(A;;GA;;;DA)(A;;GA;;;SY)(OA;;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)'; AccountOps = 0 } }
                return
            }
            if ($w.forge -and $w.forge.Name -eq $a[1] -and -not $w.accounts.Contains($a[1])) {
                $w.nextRid++; $w.accounts[$a[1]] = "$($script:FakeSid)-$($w.nextRid)"; $w.marks[$a[1]] = $w.marks[$w.forge.From]
            }
            if ($w.accounts.Contains($a[1])) {
                $sddl = $(if ($w.objectAcl.ContainsKey($a[1])) { $w.objectAcl[$a[1]] } else { 'O:DAG:DAD:(A;;GA;;;DA)(A;;GA;;;SY)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;WP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)' })
                @{ Id = $w.accounts[$a[1]]; Mark = [string]$w.marks[$a[1]]; Creator = [string]$w.creators[$a[1]]; Sddl = $sddl; AccountOps = 0 }
            }
        }
        'ReadPwdLastSet' { $w.pwdLastSet }
        'DisableAccount' { $w.disabled = $a[0]; $false }
        'NewGpo' {
            if ($w.gpo -and $w.gpo -ne $a[3]) { throw "a group policy object named '$($a[0])' exists and is not the run's own" }
            if (-not $w.gpo) { $w.gpoMark = $a[4] }
            $w.gpo = '6ac1786c-016f-11d2-945f-00c04fb984f9'; $w.gpoMembers = @($a[2]); $w.gpo
        }
        'RemoveGpo' { $w.gpo = '' }
        'Replicate' { @{ Exit = 0; Text = 'SyncAll terminated with no errors.' } }
        'ReadDhcpConfiguration' {
            Assert-FakeServiceRunning $s
            $raw = $w.raw
            if ($w.configChanged) {
                $raw = $raw.Clone(); $raw.reservations = @{ '192.0.2.0' = @($w.raw.reservations['192.0.2.0'] | Select-Object -Skip 1) }
            }
            $raw
        }
        'ReadRecords' {
            # A secondary holds what Tenko serves now, a file-backed copy what it froze, a
            # directory-integrated zone the directory's records. Tenko may add records once a
            # copy of the PDC emulator was read outside the directory (lateAdds).
            # Every record answers its time to live, 3600 unless it names its own.
            $z = $w.zones[$a[0]][$s]
            $held = $(if ($z.Type -eq 'Secondary') { Get-FakeLive $a[0] } elseif (-not $z.Ds) { @($w.copies[$a[0]]) } else { @($w.records[$a[0]]) })
            @($held | Where-Object { $null -ne $_ }) | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Type = $_.Type; Data = $_.Data; Ttl = $(if ($_.PSObject.Properties['Ttl']) { $_.Ttl } else { '3600' }) } }
            if ($s -eq 'dc1' -and -not $z.Ds -and $w.lateAdds.ContainsKey($a[0])) {
                $w.tenkoAdds[$a[0]] = @(@($(if ($w.tenkoAdds.ContainsKey($a[0])) { $w.tenkoAdds[$a[0]] })) + @($w.lateAdds[$a[0]]) | Where-Object { $null -ne $_ })
                $w.lateAdds.Remove($a[0])
            }
        }
        'ReadSoa' { @{ Mname = "dc1.$domain."; Rname = "hostmaster.$domain."; Timers = $(if ($w.timersTamper -and $w.soaSet.ContainsKey($a[0])) { '1 600 86400 3600 3600' } else { '900 600 86400 3600 3600' }) } }
        'ConvertToSecondary' {
            $z = $w.zones[$a[0]][$s]
            if ($a[3]) { $z.Type = 'Secondary'; $z.Ds = $false; $w.directory = @($w.directory | Where-Object { $_ -ne $a[0] }) }
            elseif ($z.Type -ne 'Secondary') { $z.Type = 'Secondary'; $z.Ds = $false }
            $z.Registry = @{ Transfer = 3; Notify = 0 }
            @{ Type = $z.Type; Transfer = 3; Notify = 0 }
        }
        'RegisterDns' { 0 }
        'FreezeZone' {
            $z = $w.zones[$a[0]][$s]
            if ($z.Type -eq 'Missing') { return @{ Type = 'Missing'; Ds = $false; Update = '' } }
            if ($z.Type -eq 'Secondary') { $w.copies[$a[0]] = @(Get-FakeLive $a[0]); $z.Type = 'Primary'; $z.Ds = $false }
            if (-not $z.Ds) { $z.Update = 'None' }
            @{ Type = $z.Type; Ds = $z.Ds; Update = $z.Update }
        }
        'ApplyZoneFix' {
            if (-not $w.fixIgnored) {
                foreach ($fix in @($a[1] | Where-Object { $null -ne $_ })) {
                    $w.copies[$a[0]] = @(@($w.copies[$a[0]] | Where-Object { -not ($_.Name -eq $fix.Name -and @($fix.Types) -contains $_.Type) }) + @($fix.Records | ForEach-Object { [pscustomobject]@{ Name = $fix.Name; Type = $_.Type; Data = $_.Data } }))
                }
            }
            # An administrator of the PDC emulator may change a time to live meanwhile (ttlTamper).
            if ($w.ttlTamper) { $w.copies[$a[0]] = @($w.copies[$a[0]] | ForEach-Object { if ($_.Name -eq 'pc1') { [pscustomobject]@{ Name = $_.Name; Type = $_.Type; Data = $_.Data; Ttl = '1' } } else { $_ } }) }
            $w.soaSet[$a[0]] = "$($a[2]) $($a[3])"
        }
        'RestoreZone' {
            $z = $w.zones[$a[0]][$s]
            if ($w.restoreBreaks -and -not $w.restoreBroken) { $w.restoreBroken = $true; $z.Type = 'Missing'; $z.Ds = $false; throw 'injected failure between the removal and the load' }
            if (-not $a[3]) { throw 'no digest of the export' }
            # The export of phase 2 holds the zone's records as they were before the run.
            $w.copies[$a[0]] = @($w.records[$a[0]]); $z.Type = 'Primary'; $z.Ds = $false
            if (@($w.restoredFromBackup) -notcontains $a[0]) { $w.restoredFromBackup += , $a[0] }
        }
        'IntegrateZone' {
            $z = $w.zones[$a[0]][$s]
            if (-not $z.Ds) { $w.records[$a[0]] = @($w.copies[$a[0]]) }
            $z.Type = 'Primary'; $z.Ds = $true; $z.Update = $a[3]
            $w.integratedScope[$a[0]] = "$($a[1])|$($a[2])"
            if ($w.directory -notcontains $a[0]) { $w.directory += $a[0] }
            @{ Type = 'Primary'; Ds = $true; Update = $(if ($w.leaveOpen) { 'NonsecureAndSecure' } else { $a[3] }) }
        }
        'RemoveSecondary' { $z = $w.zones[$a[0]][$s]; $z.Type = 'Primary'; $z.Ds = $true; $z.Update = $w.zones[$a[0]]['dc1'].Update }
        'ReadZone' { $z = $w.zones[$a[0]][$s]; @{ Type = $z.Type; Ds = $z.Ds; Update = $z.Update } }
        'ReadLeases' { Assert-FakeServiceRunning $s; if ($a[0] -eq '192.0.2.0') { @{ Ip = '192.0.2.101'; Client = '00-00-5e-00-53-11' } } }
        'StopDhcp' {
            # A service that does not stop (stopFailsOn) is read back as running.
            if ($w.stopFailsOn -eq $s) { return @{ Status = 'Running'; Start = 'Automatic'; Listening = 1 } }
            $w.services[$s].Status = 'Stopped'; $w.services[$s].Serving = $false; $w.services[$s].Start = 'Disabled'; @{ Status = 'Stopped'; Start = 'Disabled'; Listening = 0 }
        }
        'StartDhcp' {
            $service = $w.services[$s]
            $service.Start = $a[0]
            if ($a[1] -and ($w.restartFails -or $w.restartFailsOn -eq $s)) { $service.Status = 'Stopped'; $service.Serving = $false; return @{ Status = 'Stopped'; Start = $a[0]; Authorized = $false } }
            $service.Status = 'Running'
            # A server reads its authorization when its service starts.
            $service.Serving = ($w.authorized -contains $s)
            [void]$w.calls.Add("$s|serving=$($service.Serving)")
            @{ Status = 'Running'; Start = $a[0]; Authorized = $service.Serving }
        }
        'SetAuthorization' {
            $dc = Get-FakeShort $a[0]
            $w.staleList = @($w.authorized)
            if ($a[2]) { if ($w.authorized -notcontains $dc) { [void]$w.authorized.Add($dc) } } else { $w.authorized.Remove($dc) }
        }
        'ReadAuthorization' {
            # A replica that has not caught up yet answers the list before the last change.
            $list = $w.authorized
            if ($w.staleReads -gt 0) { $w.staleReads--; $list = $w.staleList }
            foreach ($dc in $list) { "i192.0.2.$(if ($dc -eq 'dc1') { 11 } else { 12 })`$rc$dc.$domain`$f0x00000000`$s$dc.$domain`$" }
        }
        'WriteLeases' {
            Assert-FakeServiceRunning $s
            foreach ($lease in $a[1]) { [void]$w.written.Add("$s|$($lease.Ip)|$($lease.Client)|$($lease.Seconds)") }
            @('192.0.2.101') + @($a[1] | ForEach-Object { $_.Ip })
        }
        'RemoveZoneObject' { }
        default { throw "the fake has no block $Name" }
    }
}

function Get-FakeJob {
    param([string]$Kind)
    $id = [guid]::NewGuid().ToString()
    $steps = @([ordered]@{ index = 0; kind = 'migrate.takeover.check'; state = [ordered]@{ state = 'done' } })
    $state = 'succeeded'
    if ($Kind -eq 'takeover') {
        $steps += [ordered]@{ index = 1; kind = 'migrate.takeover.silence'; state = [ordered]@{ state = 'waiting_for_manual' } }
        $state = 'waiting'
    }
    if ($Kind -eq 'revert') { $script:world.scopesOn = $false; [void]$script:world.calls.Add('tenko|scopes-off') }
    $script:world.jobs[$id] = [ordered]@{ id = $id; kind = $Kind; state = $state; steps = $steps }
    return [ordered]@{ id = $id }
}

function Invoke-FakeTenko {
    param([string]$Method, [string]$Path, [object]$Body)
    $w = $script:world
    [void]$w.tenkoCalls.Add("$Method $Path")
    if ($w.failRoute -and "$Method $Path" -match $w.failRoute -and -not $w.tenkoFailed) { $w.tenkoFailed = $true; throw "Tenko refused $Method $Path with 503 injected" }
    $route = "$Method $($Path -replace '\?.*$', '')"
    $query = $(if ($Path -match '\?(.*)$') { $Matches[1] } else { '' })
    switch -Regex ($route) {
        '^POST /migrate/mirrors$' {
            $id = [guid]::NewGuid().ToString()
            $w.mirrors[$id] = [ordered]@{ id = $id; name = $Body.name; last_sequence = 1 }
            return [ordered]@{ mirror = [ordered]@{ id = $(if ($w.badMirror) { 'not-an-id' } else { $id }); token = 'token-record-id' }; token = (ConvertTo-FakeSecure $(if ($w.badToken) { 'oops' } else { 'tnkc_' + ('a' * 40) })); ca_fingerprint = $w.fingerprint }
        }
        '^DELETE /migrate/mirrors/(.+)$' { $w.mirrors.Remove($Matches[1]); return $null }
        '^PATCH /migrate/mirrors/' { return [ordered]@{} }
        '^GET /migrate/mirrors/[^/]+/snapshot$' {
            $exporter = Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror') 'Tenko-DhcpMirror.ps1'
            return (Get-TkMappedSnapshot -Raw $w.raw -Server ($w.mirrors[$Path.Split('/')[3]].name) -ExporterPath $exporter)
        }
        '^GET /migrate/mirrors/[^/]+$' { return [ordered]@{ last_sequence = 1 } }
        '^POST /migrate/mirrors/[^/]+/scopes/[^/]+/revert$' {
            $w.reverts++
            if ($w.revertFailAt -eq $w.reverts) { throw "Tenko refused $Method $Path with 503 injected" }
            return (Get-FakeJob 'revert')
        }
        '^POST /migrate/mirrors/[^/]+/scopes/[^/]+/prepare$' { return (Get-FakeJob 'prepare') }
        '^POST /migrate/mirrors/[^/]+/scopes/([^/]+)/takeover$' {
            $scope = [uri]::UnescapeDataString($Matches[1])
            # A node that names one job for two scopes (sameJob).
            if ($w.sameJob -and $w.jobScopes.Count -gt 0) { return [ordered]@{ id = @($w.jobScopes.Keys)[0] } }
            $job = Get-FakeJob 'takeover'
            $w.jobScopes[$job.id] = $scope
            return $job
        }
        '^GET /jobs/(.+)$' { return [ordered]@{ job = $w.jobs[$Matches[1]] } }
        '^POST /jobs/([^/]+)/steps/(\d+)/complete$' {
            # Tenko may not answer the completion (completeFails, or after completeOk calls), may
            # answer after doing it (completeThenFail), and a job may fail once completed
            # (jobFailsAfter). A second completion of a done step is a 409.
            $job = $w.jobs[$Matches[1]]
            $step = $job.steps[[int]$Matches[2]]
            if ([string]$step.state.state -eq 'done') { throw "Tenko refused $Method $Path with 409 jobs.step.not_waiting: the step is done" }
            # The sitting itself ends here, before the call (crashAtComplete): not Tenko's failure.
            if ($w.crashAtComplete -and -not $w.crashedAtComplete) { $w.crashedAtComplete = $true; throw 'injected: the sitting ended' }
            $w.completes++
            if ($w.completeFails -or ($w.completeOk -gt 0 -and $w.completes -gt $w.completeOk)) { throw 'the connection to Tenko failed: injected' }
            $step.state = [ordered]@{ state = 'done' }
            $job.state = $(if ($w.jobFailsAfter) { 'failed' } else { 'succeeded' })
            if (-not $w.jobFailsAfter) { $w.scopesOn = $true }
            [void]$w.calls.Add('tenko|task-complete')
            if ($w.completeThenFail -and -not $w.completeFailedOnce) { $w.completeFailedOnce = $true; throw 'the connection to Tenko failed: injected after the completion' }
            return [ordered]@{}
        }
        '^GET /dns/zones$' {
            $name = ($query -replace '^name=', '')
            return [ordered]@{ items = @($w.tzones.Values | Where-Object { $_.name -eq $name }) }
        }
        '^POST /dns/zones$' { $id = [guid]::NewGuid().ToString(); $w.tzones[$id] = [ordered]@{ id = $id; name = $Body.name; kind = 'secondary'; served = $Body.served }; return $w.tzones[$id] }
        '^GET /dns/zones/[^/]+/records$' {
            $zone = $w.tzones[$Path.Split('/')[3]].name
            $items = @($w.records[$zone] | ForEach-Object { [ordered]@{ name = $(if ($_.Name -eq '@') { $zone } else { "$($_.Name).$zone" }); type = $_.Type; data = $_.Data } })
            if ($w.tenkoRecordsDiffer -and $zone -eq $script:FakeDomain) { $items += [ordered]@{ name = "rogue.$zone"; type = 'A'; data = '203.0.113.9' } }
            return [ordered]@{ items = $items }
        }
        '^GET /dns/zones/([^/]+)$' { return $w.tzones[$Matches[1]] }
        '^POST /dns/zones/([^/]+)/flip$' { $w.tzones[$Matches[1]].kind = $Body.to; return [ordered]@{} }
        '^DELETE /dns/zones/(.+)$' { $w.tzones.Remove($Matches[1]); return $null }
        '^(POST|PATCH) /dns/' { return [ordered]@{} }
        '^GET /migrate/runs/[^/]+/heartbeat$' { return [ordered]@{} }
        '^GET /migrate/runs/' { return [ordered]@{ window = $w.window } }
        '^PUT /migrate/runs/' { return [ordered]@{} }
        '^GET /migrate/takeovers$' {
            # One item per takeover job with its scope's ACK counter (acksByScope, the world's
            # otherwise). A node of an older release answers 501 (takeoverList 'missing') or items
            # without their fields ('malformed'); a server may ignore the job filter (ignoreFilter)
            # and list another job's takeover first (foreignFirst).
            if ($w.takeoverList -eq 'missing') { throw "Tenko refused $Method $Path with 501 api.not_implemented: not implemented" }
            $items = @(foreach ($id in $w.jobScopes.Keys) {
                    $scope = [string]$w.jobScopes[$id]
                    [ordered]@{ id = $id; job = $id; acks = $(if ($w.acksByScope.ContainsKey($scope)) { $w.acksByScope[$scope] } else { $w.acks }) }
                })
            if ($w.takeoverList -eq 'malformed') { $items = @([ordered]@{ id = '0190d1c2-0000-7000-8000-00000000f001'; acks = 1 }) }
            if ($w.foreignFirst) { $items = @([ordered]@{ id = '0190d1c2-0000-7000-8000-0000000000ff'; job = '0190d1c2-0000-7000-8000-0000000000ff'; acks = 9 }) + $items }
            $job = ($query -replace '^job=', '')
            if ($query -and -not $w.ignoreFilter) { $items = @($items | Where-Object { $_.job -eq $job }) }
            # A node that lists its takeovers by job without their counters (noCounterByJob).
            if ($query -and $w.noCounterByJob) { $items = @($items | ForEach-Object { [ordered]@{ id = $_.id; job = $_.job } }) }
            return [ordered]@{ items = $items }
        }
        '^POST /migrate/takeovers/[^/]+/resume$' {
            # Tenko may refuse the call (a person reverted it in the UI, or it is not this
            # session's revert), or not answer it.
            $w.resumeCalls++
            if ($w.resumeFails -eq 'refuse') { throw "Tenko refused $Method $Path with 409 migrate.takeover.not_resumable: reverted in the UI" }
            if ($w.resumeFails -eq 'down') { throw 'the connection to Tenko failed: injected' }
            if ($w.resumeFails -eq 'session') { throw "Tenko refused $Method $Path with 401 auth.session.expired: the session ended" }
            $w.scopesOn = $true; [void]$w.calls.Add('tenko|scopes-on'); return [ordered]@{}
        }
        '^GET /dhcp/leases$' { return [ordered]@{ items = $w.tenkoLeases } }
        default { throw "the fake Tenko has no route $route" }
    }
}

function Install-FakeWorld {
    # Mocks every seam; call inside a BeforeEach or an It.
    param([switch]$RepositoryInstaller)
    $script:world = Get-FakeWorld
    $script:world.restoredFromBackup = @()
    $script:lastError = ''
    $script:TkDataRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
    [void](New-Item -ItemType Directory -Path $script:TkDataRoot)
    Use-FakePayload -RepositoryInstaller:$RepositoryInstaller
    $script:FakeInstallerPath = $(if ($RepositoryInstaller) { Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror') 'Install-TenkoDhcpMirror.ps1' } else { $script:ContractInstaller })
    $script:TkTokens = @{}
    $script:TkMirrorPassword = $null
    $script:TkWindowWatch = $null
    $script:TkOffline = $false
    $script:TkPending = @()
    $script:TkPasswordChangeSec = 600
    Mock Assert-TkHost { }
    Mock Get-TkTokenSid { @("$($script:FakeSid)-1105", "$($script:FakeSid)-512", "S-1-5-32-544") }
    # The test drive belongs to the test's own account: the state tree is trusted here, and
    # the guard's own tests read real access lists.
    Mock Get-TkPathSecurity { @{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-18', 'S-1-5-32-544'); Reparse = $false } }
    Mock Initialize-TkProtectedDirectory { [void](New-Item -ItemType Directory -Path $Path) }
    Mock Start-Sleep { }
    Mock Test-WSMan { $true }
    Mock Get-TkPdcName { "dc1.$($script:FakeDomain)" }
    # The admin machine's Name Resolution Policy Table, as Get-DnsClientNrptPolicy -Effective answers it.
    Mock Get-TkNrptRule { @($script:world.nrpt) }
    Mock Get-TkDomainLocator { [ordered]@{ name = $script:world.locator.name; address = $script:world.locator.address } }
    Mock Get-TkHostAddress { @($script:world.addresses[$Name] | ForEach-Object { [System.Net.IPAddress]::Parse($_) }) }
    Mock Find-TkPolicyFinding { @{ Passwords = @($script:world.gpp); DhcpStart = @($script:world.startPolicy) } }
    Mock Invoke-TkRemote { Invoke-FakeRemote -Server $Server -Name $Name -Arguments $Arguments }
    Mock Copy-TkToServer { [void]$script:world.calls.Add("$(Get-FakeShort $Server)|Copy") }
    Mock Copy-TkFromServer { [void]$script:world.calls.Add("$(Get-FakeShort $Server)|CopyBack"); Set-Content -LiteralPath $LocalPath -Value 'backup' }
    Mock Resolve-DnsName { [pscustomobject]@{ Type = 'SRV'; NameTarget = "dc1.$($script:FakeDomain)" } }
    Mock Connect-TkNode {
        $script:TkConn.Host = 'tenko.corp.example.test'; $script:TkConn.Port = 8443; $script:TkConn.Address = [System.Net.IPAddress]::Parse('192.0.2.53')
    }
    Mock Test-TkReachable { -not $script:world.unreachable }
    Mock Request-TkApproval { $script:TkConn.Pinned = ('ab' * 32); '0190d1c2-0000-7000-8000-00000000b001' }
    Mock Test-TkServedRoot { }
    Mock Close-TkSession { }
    Mock Invoke-TkCall { Invoke-FakeTenko -Method $Method -Path $Path -Body $Body }
    Mock Read-TkAnswer {
        if ($script:world.answers.Count -eq 0) { throw "no answer queued for the prompt: $Prompt" }
        $next = $script:world.answers[0]
        $script:world.answers.RemoveAt(0)
        [void]$script:world.prompts.Add($Prompt)
        return [string]$next
    }
    # The host's choice prompt answers the next queued answer, Abort when it names no choice.
    Mock Read-TkChoice {
        if ($script:world.answers.Count -eq 0) { throw "no answer queued for the choice: $Caption" }
        $next = [string]$script:world.answers[0]
        $script:world.answers.RemoveAt(0)
        $script:world.choices++
        $script:world.lastChoice = $Message
        $picked = @($Choices | Where-Object { ($_ -replace '&', '') -eq $next })
        return $(if ($picked.Count -eq 1) { $picked[0] } else { $Choices[$Default] })
    }
    $script:world.window = [ordered]@{ started_by = 'admin'; started_at = '2026-11-21T10:00:00Z' }
}

function Invoke-FakeRun {
    # One sitting of the script, a new process: nothing held in memory survives the last one.
    param([string[]]$Answers = @(), [switch]$Reverse, [switch]$DryRun)
    $script:world.answers.Clear()
    foreach ($answer in $Answers) { [void]$script:world.answers.Add($answer) }
    $script:TkWindowWatch = $null
    $script:TkTokens = @{}
    $script:TkMirrorPassword = $null
    $script:TkRemoteBases = @{}
    $script:lastError = ''
    try {
        return (Invoke-Takeover -Reverse:$Reverse -DryRun:$DryRun -Directory '')
    } catch {
        $script:lastError = $_.Exception.Message
        if ($_.Exception.Data.Contains('tk.exit')) { return [int]$_.Exception.Data['tk.exit'] }
        return 2
    }
}

# The answers of a first sitting: the domain, the DHCP servers' confirmation, the mirror
# host, Tenko's address, the change list's confirmation, the window's confirmation (which
# stands for the DHCP window too within 15 minutes).
$script:FirstSitting = @('corp.example.test', 'y', '1', 'tenko.corp.example.test', 'corp.example.test', 'corp.example.test')
