# Shared by the suites: a fake domain (two controllers that are also the DHCP failover pair,
# a member server for the exporter) behind the script's one seam to Windows, Invoke-TkRemote,
# and a fake Tenko behind its one seam to the API, Invoke-Tenko. Both keep their state in
# $world, log every call, and fail once where a test says so. Nothing reaches a real server.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'mocks bind the parameters of the functions they replace')]
param()

$script:FakeDomain = 'corp.example.test'
$script:FakeSid = 'S-1-5-21-1000-2000-3000'
$script:MirrorDir = Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror') 'tests'

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
    # The release data as the release run fills it, from the repository's exporter and installer.
    $mirror = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror'
    foreach ($name in 'Tenko-DhcpMirror.ps1', 'Install-TenkoDhcpMirror.ps1') {
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $mirror $name))
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
            $zones[$name][$dc] = @{ Type = 'Primary'; Ds = $true; Update = 'NonsecureAndSecure'; Scope = $(if ($name.StartsWith('_msdcs')) { 'Forest' } else { 'Domain' }); Transfer = 'NoTransfer'; Notify = 'NoNotify'; Secondaries = @(); NotifyServers = @(); Registry = @{ Transfer = 3; Notify = 0 } }
        }
    }
    $world = @{
        zones = $zones
        records = @{
            $script:FakeDomain = @([pscustomobject]@{ Name = '@'; Type = 'A'; Data = '192.0.2.11' }, [pscustomobject]@{ Name = 'pc1'; Type = 'A'; Data = '192.0.2.120' })
            "_msdcs.$($script:FakeDomain)" = @([pscustomobject]@{ Name = '_ldap._tcp.dc'; Type = 'SRV'; Data = "0 100 389 dc1.$($script:FakeDomain)" })
            '2.0.192.in-addr.arpa' = @([pscustomobject]@{ Name = '120'; Type = 'PTR'; Data = "pc1.$($script:FakeDomain)" })
        }
        directory = @($script:FakeDomain, "_msdcs.$($script:FakeDomain)", '2.0.192.in-addr.arpa')
        services = @{ dc1 = @{ Status = 'Running'; Start = 'Automatic'; Role = $true }; dc2 = @{ Status = 'Running'; Start = 'Automatic'; Role = $true } }
        authorized = [System.Collections.ArrayList]@('dc1', 'dc2')
        accounts = [System.Collections.ArrayList]@()
        gpo = ''
        tasks = [System.Collections.ArrayList]@()
        batchRight = $false
        rsat = $true
        marker = $null
        dnsUser = 'CORP\dhcp-dns'
        v6 = @(); leaseSeconds = 28800; startPolicy = @(); gpp = @(); timeSource = 'time.example.test'
        update = 'NonsecureAndSecure'
        pwdLastSet = '100'; rotate = $true
        written = [System.Collections.ArrayList]@()
        raw = (Get-FakeRaw)
        configChanged = $false
        tenkoRecordsDiffer = $false
        locator = @{ name = "dc1.$($script:FakeDomain)"; address = '192.0.2.11' }
        addresses = @{ "dc1.$($script:FakeDomain)" = @('192.0.2.11'); "dc2.$($script:FakeDomain)" = @('192.0.2.12') }
        calls = [System.Collections.ArrayList]@()
        failAt = ''; failed = $false
        # Tenko
        mirrors = [ordered]@{}; tzones = [ordered]@{}; jobs = [ordered]@{}; window = $null
        tenkoCalls = [System.Collections.ArrayList]@()
        failRoute = ''; tenkoFailed = $false
        badMirror = $false; badToken = $false; fingerprint = ''
        tenkoLeases = @()
        answers = [System.Collections.ArrayList]@()
        unreachable = $false; disabled = $null; leaveOpen = $false; gpoMembers = @()
    }
    return $world
}

function Get-FakeShort { param([string]$Server) return $Server.Split('.')[0] }

function Invoke-FakeRemote {
    param([string]$Server, [string]$Name, [object[]]$Arguments)
    $w = $script:world
    [void]$w.calls.Add("$(Get-FakeShort $Server)|$Name")
    if ($w.failAt -eq $Name -and -not $w.failed) { $w.failed = $true; throw "injected failure at $Name on $Server" }
    $s = Get-FakeShort $Server
    $a = $Arguments
    $domain = $script:FakeDomain
    switch ($Name) {
        'ReadDomain' {
            @{ Kind = 'domain'; DnsRoot = $domain; NetBIOSName = 'CORP'; DomainSid = $script:FakeSid; Pdc = "dc1.$domain"; DistinguishedName = 'DC=corp,DC=example,DC=test'; ComputersContainer = 'CN=Computers,DC=corp,DC=example,DC=test'; ForestRoot = $domain; Configuration = 'CN=Configuration,DC=corp,DC=example,DC=test'; Quota = '0'; Kds = $false }
            @{ Kind = 'controller'; Name = "dc1.$domain"; IPv4 = '192.0.2.11'; IPv6 = ''; Gc = $true }
            @{ Kind = 'controller'; Name = "dc2.$domain"; IPv4 = '192.0.2.12'; IPv6 = ''; Gc = $true }
        }
        'ReadZones' {
            foreach ($zone in $w.zones.Keys) {
                $z = $w.zones[$zone][$s]
                if ($null -eq $z) { continue }
                @{ Name = $zone; Type = $z.Type; Ds = $z.Ds; Scope = $z.Scope; Update = $z.Update; Reverse = $zone.EndsWith('.arpa'); Transfer = $z.Transfer; Notify = $z.Notify; Secondaries = @($z.Secondaries); NotifyServers = @($z.NotifyServers); Masters = @(); Serial = '7'; Aging = $false }
            }
            @{ Name = '.'; Type = 'ServerForwarder'; Masters = @('198.51.100.53') }
            @{ Name = ''; Type = 'Scavenging'; Masters = @(); Aging = $false }
        }
        'ReadDirectoryZones' { foreach ($zone in $w.directory) { @{ Name = $zone; Dn = "DC=$zone,CN=MicrosoftDNS,DC=DomainDnsZones,DC=corp,DC=example,DC=test" } } }
        'ReadDhcpInDirectory' { foreach ($dc in $w.authorized) { @{ Name = "$dc.$domain"; Address = $(if ($dc -eq 'dc1') { '192.0.2.11' } else { '192.0.2.12' }) } } }
        'ReadDhcpServer' {
            @{
                Scopes     = @(@{ Id = '192.0.2.0'; Mask = '255.255.255.0'; Start = '192.0.2.100'; End = '192.0.2.199'; State = 'Active'; LeaseSeconds = $w.leaseSeconds; Exclusions = @('192.0.2.150-192.0.2.159'); Reservations = @(@{ Ip = '192.0.2.120'; Client = '00-00-5e-00-53-01' }); Hosts = @('pc1') })
                Bindings   = @($(if ($s -eq 'dc1') { '192.0.2.11' } else { '192.0.2.12' }))
                Failover   = @(@{ Name = 'dc1-dc2'; Partner = $(if ($s -eq 'dc1') { "dc2.$domain" } else { 'dc1' }); Mode = 'LoadBalance'; Scopes = @('192.0.2.0') })
                DnsUser    = $w.dnsUser; V6Scopes = @($w.v6); Multicast = @(); AllowList = $false; DenyList = $false; Policies = @(); Superscope = @(); Service = 'Automatic'
            }
        }
        'ReadComputers' {
            @{ Name = "srv1.$domain"; Server = $true; IPv4 = '192.0.2.30'; Sid = "$($script:FakeSid)-1300" }
            @{ Name = "pc1.$domain"; Server = $false; IPv4 = '192.0.2.120'; Sid = "$($script:FakeSid)-1301" }
        }
        'ReadHardening' { @{ Kind = 'server'; LdapSigning = 2; ChannelBinding = 2; Spooler = 'Stopped'; TimeStatus = 'Last Successful Sync Time: 2026-11-21'; TimeSource = $(if ($s -eq 'dc1') { $w.timeSource } else { "dc1.$domain" }) } }
        'ReadLocalAdmins' { @{ Name = 'CORP\Domain Admins'; Sid = "$($script:FakeSid)-512"; Class = 'Group' } }
        'ReadFeature' { $w.rsat }
        'SetFeature' { $w.rsat = [bool]$a[1]; $w.rsat }
        'ReadMarker' { if ($w.marker) { [pscustomobject]$w.marker } }
        'WriteMarker' { if ($a[3]) { $w.marker = $null } else { $w.marker = @{ Run = $a[1]; Host = $a[2]; Time = '2026-11-21T10:00:00Z' } } }
        'ExportDhcp' { }
        'ExportZone' { "C:\Windows\System32\dns\$($a[1])" }
        'NewMirrorAccount' { if ($w.accounts -notcontains $a[0]) { [void]$w.accounts.Add($a[0]) }; "$($script:FakeSid)-1400" }
        'RemoveMirrorAccount' { $w.accounts.Remove($a[0]) }
        'InstallExporter' {
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
        'SetDnsCredential' { if ($a[1]) { '' } else { $a[0].UserName } }
        'NewDnsUser' { }
        'NewTenkoAccount' {
            if ($w.accounts -notcontains "$($a[0])$") { [void]$w.accounts.Add("$($a[0])$") }
            @{ Dn = "CN=$($a[0]),$($a[1])"; Sid = "$($script:FakeSid)-1500"; Groups = @(); Uac = 4096; Encryption = 24; Spns = @($a[2]); DelegateTo = @(); PwdLastSet = $w.pwdLastSet; Rights = @(@{ Who = 'CORP\helpdesk'; Rights = 'ExtendedRight'; Object = ''; Allow = $true }); AccountOps = 0 }
        }
        'ReadPwdLastSet' { $w.pwdLastSet }
        'SetAccountState' { if ($a[1]) { $w.accounts.Remove("$($a[0])$") } else { $w.disabled = "$($a[0])$"; $false } }
        'NewGpo' { $w.gpo = '6ac1786c-016f-11d2-945f-00c04fb984f9'; $w.gpoMembers = @($a[2]); $w.gpo }
        'RemoveGpo' { $w.gpo = '' }
        'Replicate' { @{ Exit = 0; Text = 'SyncAll terminated with no errors.' } }
        'ReadDhcpConfiguration' {
            $raw = $w.raw
            if ($w.configChanged) {
                $raw = $raw.Clone(); $raw.reservations = @{ '192.0.2.0' = @($w.raw.reservations['192.0.2.0'] | Select-Object -Skip 1) }
            }
            $raw
        }
        'ReadRecords' { $w.records[$a[0]] }
        'ConvertToSecondary' {
            $z = $w.zones[$a[0]][$s]
            if ($a[3]) { $z.Type = 'Secondary'; $z.Ds = $false; $w.directory = @($w.directory | Where-Object { $_ -ne $a[0] }) }
            elseif ($z.Type -ne 'Secondary') { $z.Type = 'Secondary'; $z.Ds = $false }
            $z.Registry = @{ Transfer = 3; Notify = 0 }
            @{ Type = $z.Type; Transfer = 3; Notify = 0 }
        }
        'RegisterDns' { 0 }
        'ConvertToPrimary' {
            $z = $w.zones[$a[0]][$s]
            $z.Type = 'Primary'; $z.Ds = $true; $z.Update = $a[3]
            if ($w.directory -notcontains $a[0]) { $w.directory += $a[0] }
            @{ Type = 'Primary'; Ds = $true; Update = $(if ($w.leaveOpen) { 'NonsecureAndSecure' } else { $a[3] }) }
        }
        'RemoveSecondary' { $z = $w.zones[$a[0]][$s]; $z.Type = 'Primary'; $z.Ds = $true; $z.Update = $w.zones[$a[0]]['dc1'].Update }
        'ReadZone' { $z = $w.zones[$a[0]][$s]; @{ Type = $z.Type; Ds = $z.Ds; Update = $z.Update } }
        'ReadLeases' { @{ Ip = '192.0.2.101'; Client = '00-00-5e-00-53-11' } }
        'StopDhcp' { $w.services[$s].Status = 'Stopped'; $w.services[$s].Start = 'Disabled'; @{ Status = 'Stopped'; Start = 'Disabled'; Listening = 0 } }
        'StartDhcp' { $w.services[$s].Status = 'Running'; $w.services[$s].Start = $a[0]; @{ Status = 'Running'; Start = $a[0] } }
        'SetAuthorization' {
            $dc = Get-FakeShort $a[0]
            if ($a[2]) { if ($w.authorized -notcontains $dc) { [void]$w.authorized.Add($dc) } } else { $w.authorized.Remove($dc) }
        }
        'ReadAuthorization' { foreach ($dc in $w.authorized) { "$dc.$domain" } }
        'WriteLeases' { foreach ($lease in $a[1]) { [void]$w.written.Add("$s|$($lease.Ip)|$($lease.Client)|$($lease.Seconds)") }; @($a[1]).Count }
        'RemoveDhcpRole' { $w.services[$s].Role = $false; $false }
        'RestoreDhcpRole' { $w.services[$s].Role = $true; $w.services[$s].Start = 'Disabled'; $w.services[$s].Status = 'Stopped'; $true }
        'ReadGroups' { foreach ($group in $a[0]) { @{ Name = $group; Count = 1; Conflicts = 0 } } }
        'AddFailover' { }
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
            $script:FakeExporter = Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror') 'Tenko-DhcpMirror.ps1'
            return (Get-TkMappedSnapshot -Raw $w.raw -Server ($w.mirrors[$Path.Split('/')[3]].name) -ExporterPath $script:FakeExporter)
        }
        '^GET /migrate/mirrors/[^/]+$' { return [ordered]@{ last_sequence = 1 } }
        '^POST /migrate/mirrors/[^/]+/scopes/[^/]+/(prepare|revert)$' { return (Get-FakeJob $Matches[1]) }
        '^POST /migrate/mirrors/[^/]+/scopes/[^/]+/takeover$' { return (Get-FakeJob 'takeover') }
        '^GET /jobs/(.+)$' { return [ordered]@{ job = $w.jobs[$Matches[1]] } }
        '^POST /jobs/([^/]+)/steps/(\d+)/complete$' { $job = $w.jobs[$Matches[1]]; $job.steps[[int]$Matches[2]].state = [ordered]@{ state = 'done' }; $job.state = 'succeeded'; return [ordered]@{} }
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
        '^GET /migrate/takeovers$' { return [ordered]@{ items = @([ordered]@{ acks = 3 }) } }
        '^GET /dhcp/leases$' { return [ordered]@{ items = $w.tenkoLeases } }
        default { throw "the fake Tenko has no route $route" }
    }
}

function Install-FakeWorld {
    # Mocks every seam; call inside a BeforeEach or an It.
    $script:world = Get-FakeWorld
    $script:lastError = ''
    $env:ProgramData = Join-Path $TestDrive ([guid]::NewGuid().ToString())
    [void](New-Item -ItemType Directory -Path $env:ProgramData)
    Use-FakePayload
    $script:TkTokens = @{}
    $script:TkWindowWatch = $null
    $script:TkOffline = $false
    $script:TkPending = @()
    $script:TkPasswordChangeSec = 600
    Mock Assert-TkHost { }
    Mock Get-TkTokenSid { @("$($script:FakeSid)-1105", "$($script:FakeSid)-512", "S-1-5-32-544") }
    Mock Protect-TkDirectory { }
    Mock Start-Sleep { }
    Mock Test-WSMan { $true }
    Mock Get-TkPdcName { "dc1.$($script:FakeDomain)" }
    Mock Get-TkDomainLocator { [ordered]@{ name = $script:world.locator.name; address = $script:world.locator.address } }
    Mock Get-TkHostAddress { @($script:world.addresses[$Name] | ForEach-Object { [System.Net.IPAddress]::Parse($_) }) }
    Mock Find-TkGppPassword { , @($script:world.gpp) }
    Mock Find-TkDhcpStartPolicy { , @($script:world.startPolicy) }
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
        return [string]$next
    }
    $script:world.window = [ordered]@{ started_by = 'admin'; started_at = '2026-11-21T10:00:00Z' }
}

function Invoke-FakeRun {
    # One sitting of the script with the answers given, its exit code as the main block maps it.
    param([string[]]$Answers = @(), [switch]$Reverse, [switch]$DryRun)
    $script:world.answers.Clear()
    foreach ($answer in $Answers) { [void]$script:world.answers.Add($answer) }
    $script:TkWindowWatch = $null
    $script:lastError = ''
    try {
        return (Invoke-Takeover -Reverse:$Reverse -DryRun:$DryRun -Directory '')
    } catch {
        $script:lastError = $_.Exception.Message
        if ($_.Exception.Data.Contains('tk.exit')) { return [int]$_.Exception.Data['tk.exit'] }
        return 2
    }
}

# The answers of a first sitting: the domain, the mirror host, Tenko's address, the change
# list's confirmation, the window's confirmation.
$script:FirstSitting = @('corp.example.test', '1', 'tenko.corp.example.test', 'corp.example.test', 'corp.example.test')
