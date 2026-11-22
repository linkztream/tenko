# The script's guards (MIG-17): the refusals before anything is read, each with exit 1; the
# module path; the sessions it opens; the state tree and the remote folders; the payloads,
# checked by their digest before and after an organization's signature and again before use;
# the access lists read by SID.

BeforeDiscovery {
    $windows = $env:OS -eq 'Windows_NT'
    $elevated = $windows -and ([System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

BeforeAll {
    $savedPath = $env:PSModulePath
    $scriptPath = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1'
    . $scriptPath
    . (Join-Path $PSScriptRoot 'Fake.ps1')
    $loadedPath = $env:PSModulePath
    function Get-ExitCode {
        param([scriptblock]$Action)
        try { & $Action; return 0 } catch { if ($_.Exception.Data.Contains('tk.exit')) { return [int]$_.Exception.Data['tk.exit'] }; throw }
    }
}

AfterAll { $env:PSModulePath = $savedPath }

Describe 'The host' {
    BeforeEach {
        $script:TkVersion = '0.0.0-test'
        Mock Get-TkLanguageMode { 'FullLanguage' }
        Mock Test-TkElevated { $true }
        Mock Get-TkTokenSid { @('S-1-5-21-1000-2000-3000-512') }
    }

    It 'refuses <case> with exit 1' -Skip:(-not $windows) -ForEach @(
        @{ case = 'Constrained Language'; setup = { Mock Get-TkLanguageMode { 'ConstrainedLanguage' } }; message = '*App Control*' }
        @{ case = 'a copy that is not a release build'; setup = { $script:TkVersion = '' }; message = '*not a release build*' }
        @{ case = 'an unelevated process'; setup = { Mock Test-TkElevated { $false } }; message = '*elevated*' }
        @{ case = 'a logon outside Domain Admins'; setup = { Mock Get-TkTokenSid { @('S-1-5-21-1000-2000-3000-513', 'S-1-5-32-544') } }; message = '*Domain Admins*' }
    ) {
        # Runner: Windows only; the host check refuses any other system first.
        & $setup
        Get-ExitCode { Assert-TkHost } | Should -Be 1
        { Assert-TkHost } | Should -Throw $message
    }

    It 'passes an elevated member of Domain Admins in Full Language' -Skip:(-not $windows) {
        # Runner: Windows only.
        Get-ExitCode { Assert-TkHost } | Should -Be 0
    }

    It 'finds Domain Admins of the domain by its RID, and of another domain not' {
        Test-TkDomainAdmin -Sids @('S-1-5-21-1-2-3-512') -DomainSid 'S-1-5-21-1-2-3' | Should -BeTrue
        Test-TkDomainAdmin -Sids @('S-1-5-21-1-2-3-512') -DomainSid 'S-1-5-21-9-9-9' | Should -BeFalse
        Test-TkDomainAdmin -Sids @('S-1-5-21-1-2-3-519', 'S-1-5-32-544') -DomainSid '' | Should -BeFalse
    }
}

Describe 'The module path' {
    It 'is set from the platform''s folders before any command, whatever the environment says' -Skip:(-not $windows) {
        # Runner: Windows only (the folders are Windows').
        $expected = @("$PSHOME\Modules", ([System.Environment]::SystemDirectory + '\WindowsPowerShell\v1.0\Modules'), ([System.Environment]::GetFolderPath('ProgramFiles') + '\WindowsPowerShell\Modules'))
        @($loadedPath.Split(';')) | Should -Be $expected
        $saved = $env:ProgramFiles
        try {
            $env:ProgramFiles = Join-Path $TestDrive 'planted'
            . $scriptPath
            $env:PSModulePath | Should -Not -Match 'planted'
        } finally { $env:ProgramFiles = $saved }
    }

    It 'is the script''s first statement after its parameters' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
        $ast.EndBlock.Statements[0].Extent.Text | Should -Match '^if \(\[System\.Environment\]::OSVersion\.Platform'
        $ast.EndBlock.Statements[0].Extent.Text | Should -Match '\$env:PSModulePath = \$PSHOME'
    }
}

Describe 'The sessions' {
    It 'opens a Kerberos session by the host''s FQDN only for a host the discovery found' {
        $script:TkKnownHosts = @('dc1.corp.example.test')
        Mock Invoke-Command { 'ran' }
        Invoke-TkRemote -Server 'dc1.corp.example.test' -Name ReadMarker -Arguments @('HKLM:\SOFTWARE\Tenko\Takeover') | Should -Be 'ran'
        Should -Invoke Invoke-Command -Times 1 -ParameterFilter { $ComputerName -eq 'dc1.corp.example.test' -and $Authentication -eq 'Kerberos' -and $ScriptBlock -eq $script:TkRemote.ReadMarker }
        { Invoke-TkRemote -Server 'dc9.corp.example.test' -Name ReadMarker } | Should -Throw '*not a server this run discovered*'
        { Invoke-TkRemote -Server '192.0.2.11' -Name ReadMarker } | Should -Throw '*fully qualified*'
        { Invoke-TkRemote -Server 'dc1' -Name ReadMarker } | Should -Throw '*fully qualified*'
        { Invoke-TkRemote -Server 'dc1.corp.example.test' -Name NoSuchBlock } | Should -Throw '*no remote block*'
    }
}

Describe 'The state tree' {
    It 'refuses a level that another account owns' -Skip:(-not $windows) {
        # Runner: Windows only (NTFS owners). The test drive belongs to the test's account.
        [void](New-Item -ItemType Directory -Path (Join-Path $TestDrive 'Tenko'))
        Get-ExitCode { Assert-TkTrustedTree -Root $TestDrive -Levels @('Tenko') } | Should -Be 1
    }

    It 'refuses a level that is a link or that another account may write' {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        [void](New-Item -ItemType Directory -Path (Join-Path $root 'Tenko') -Force)
        Mock Get-TkPathSecurity { @{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-32-544'); Reparse = $true } }
        Get-ExitCode { Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 1
        Mock Get-TkPathSecurity { @{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-32-544', 'S-1-5-32-545'); Reparse = $false } }
        Get-ExitCode { Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 1
        Mock Get-TkPathSecurity { @{ Owner = 'S-1-5-21-1-2-3-1105'; Writers = @('S-1-5-32-544'); Reparse = $false } }
        Get-ExitCode { Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 1
        Mock Get-TkPathSecurity { @{ Owner = 'S-1-5-32-544'; Writers = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0'); Reparse = $false } }
        Get-ExitCode { $null = Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 0
    }

    It 'makes a missing level owned by Administrators, SYSTEM and Administrators only, as it is created' -Skip:(-not $elevated) {
        # Runner: an elevated Windows process (setting Administrators as owner needs it); CI's
        # Windows runners are elevated.
        $dir = Join-Path $TestDrive 'made'
        Initialize-TkProtectedDirectory $dir
        $security = Get-TkPathSecurity $dir
        $security.Owner | Should -Be 'S-1-5-32-544'
        @($security.Writers | Sort-Object) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
        Test-TkTrustedPath $security | Should -BeTrue
        $null = icacls.exe $dir /grant "*$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value):(OI)(CI)F"
    }

    It 'accepts the elevated process''s own user as the owner of a file inside the leaf, never of a level, never another user' {
        $root = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        [void](New-Item -ItemType Directory -Path (Join-Path $root 'Tenko') -Force)
        Set-Content -LiteralPath (Join-Path $root 'Tenko\state.json') -Value '{}'
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Mock Test-TkElevated { $true }
        Mock Get-TkPathSecurity { @{ Owner = $(if ($Path -like '*state.json') { $script:fileOwner } else { 'S-1-5-32-544' }); Writers = @('S-1-5-18', 'S-1-5-32-544'); Reparse = $false } }
        $script:fileOwner = $me
        Get-ExitCode { $null = Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 0
        $script:fileOwner = 'S-1-5-21-1-2-3-1105'
        Get-ExitCode { $null = Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 1
        $script:fileOwner = $me
        Mock Test-TkElevated { $false }
        Get-ExitCode { $null = Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 1
        Mock Test-TkElevated { $true }
        Mock Get-TkPathSecurity { @{ Owner = $me; Writers = @('S-1-5-18', 'S-1-5-32-544'); Reparse = $false } }
        Get-ExitCode { $null = Assert-TkTrustedTree -Root $root -Levels @('Tenko') } | Should -Be 1 -Because 'a level owned by the user is refused'
    }

    It 'keeps the remote work and backup folders out of folders a local user can write' {
        foreach ($name in $script:TkRemote.Keys) {
            $script:TkRemote[$name].ToString() | Should -Not -Match 'Windows\\Temp|SystemRoot ''Temp|C:\\ProgramData|C:\\Program Files' -Because $name
        }
    }

    It 'takes the remote base from the server''s own Program Files folder, of that form only' {
        $script:TkRemoteBases = @{}
        Mock Invoke-TkRemote -ParameterFilter { $Name -eq 'ReadProgramFiles' } { 'D:\Program Files' }
        Mock Invoke-TkRemote -ParameterFilter { $Name -eq 'ProtectDirectory' } { $script:protected = $Arguments }
        Protect-TkRemoteDirectory -Server 'dc1.corp.example.test' -Below @('takeover', 'backup') | Should -Be 'D:\Program Files\Tenko\takeover\backup'
        $script:protected[0] | Should -Be 'D:\Program Files\Tenko'
        $script:TkRemoteBases = @{}
        Mock Invoke-TkRemote -ParameterFilter { $Name -eq 'ReadProgramFiles' } { '\\attacker\share' }
        { Protect-TkRemoteDirectory -Server 'dc2.corp.example.test' -Below @('takeover') } | Should -Throw '*not <drive>:\Program Files*'
    }
}

Describe 'The remote folder block' {
    # The block's own logic, run here against a test folder: the access lists are what a
    # server would answer; setting the owner and the list (icacls) needs an elevated process
    # on the server and is recorded, not run.
    BeforeEach {
        $base = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        [void](New-Item -ItemType Directory -Path $base)
        $script:icacls = @()
        $acls = @{}
        function icacls.exe { $script:icacls += , ($args -join ' '); $global:LASTEXITCODE = 0 }
        Mock Get-Acl { $key = @($LiteralPath)[0]; [pscustomobject]@{ Sddl = $(if ($acls.ContainsKey($key)) { $acls[$key] } else { 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' }) } }
    }

    It 'creates the script''s levels, sets them to SYSTEM and Administrators, and leaves an existing base''s list' {
        & $script:TkRemote.ProtectDirectory $base @('takeover', 'backup')
        Test-Path -LiteralPath (Join-Path $base 'takeover\backup') | Should -BeTrue
        @($script:icacls | Where-Object { $_.StartsWith("$base ") }).Count | Should -Be 0
        @($script:icacls | Where-Object { $_ -eq "$(Join-Path $base 'takeover') /setowner *S-1-5-32-544" }).Count | Should -Be 1
    }

    It 'refuses an existing level that another account owns, that is a link, or that another account may write' {
        $acls[$base] = 'O:S-1-5-21-1-2-3-1105G:SYD:(A;OICI;FA;;;SY)'
        { & $script:TkRemote.ProtectDirectory $base @('takeover') } | Should -Throw '*owned by an account other than*'
        $acls[$base] = 'O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)'
        { & $script:TkRemote.ProtectDirectory $base @('takeover') } | Should -Throw '*may be written by BU*'
        $acls[$base] = 'O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;DCLC;;;S-1-5-21-1-2-3-1105)'
        { & $script:TkRemote.ProtectDirectory $base @('takeover') } | Should -Throw '*may be written by S-1-5-21-1-2-3-1105*'
        $acls[$base] = 'O:BAG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
        { & $script:TkRemote.ProtectDirectory $base @('takeover') } | Should -Not -Throw -Because 'reading and listing is no writing'
        Mock Get-Item { [pscustomobject]@{ Attributes = 'Directory, ReparsePoint' } }
        { & $script:TkRemote.ProtectDirectory $base @('takeover') } | Should -Throw '*is a link*'
    }

    It 'refuses a script level whose list keeps another writer after the change' {
        [void](New-Item -ItemType Directory -Path (Join-Path $base 'takeover'))
        $acls[(Join-Path $base 'takeover')] = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FW;;;AU)'
        { & $script:TkRemote.ProtectDirectory $base @('takeover') } | Should -Throw '*may be written by AU*'
    }
}

Describe 'The authorization block' {
    # Run here with the DHCP cmdlets answered by functions: an entry already in the wanted
    # state is not touched, so a resume of either direction passes.
    BeforeEach {
        $script:entries = @([pscustomobject]@{ DnsName = 'DC1.corp.example.test'; IPAddress = '192.0.2.11' })
        $script:changes = @()
        function Get-DhcpServerInDC { $script:entries }
        function Add-DhcpServerInDC { param($DnsName, $IPAddress) $script:changes += "add $DnsName $IPAddress"; throw 'the server is already authorized' }
        function Remove-DhcpServerInDC { [CmdletBinding(SupportsShouldProcess)] param($DnsName, $IPAddress) if ($PSCmdlet.ShouldProcess($DnsName)) { $script:changes += "remove $DnsName $IPAddress" } }
    }

    It 'adds only a server that is not listed, and removes only one that is' {
        & $script:TkRemote.SetAuthorization 'dc1.corp.example.test' '192.0.2.11' $true
        & $script:TkRemote.SetAuthorization 'dc2.corp.example.test' '192.0.2.12' $false
        $script:changes | Should -BeNullOrEmpty
        & $script:TkRemote.SetAuthorization 'dc1.corp.example.test' '192.0.2.11' $false
        $script:changes | Should -Be @('remove dc1.corp.example.test 192.0.2.11')
    }
}

Describe 'The names listed apart' {
    It '<name> <type> is <apart>' -ForEach @(
        @{ name = '_ldap._tcp.dc._msdcs.corp.example.test'; type = 'SRV'; apart = $true }
        @{ name = '_tcp.corp.example.test'; type = 'NS'; apart = $true }
        @{ name = '_kerberos._udp.corp.example.test'; type = 'SRV'; apart = $true }
        @{ name = 'site1._sites.corp.example.test'; type = 'SRV'; apart = $true }
        @{ name = 'domaindnszones.corp.example.test'; type = 'A'; apart = $true }
        @{ name = 'x.forestdnszones.corp.example.test'; type = 'A'; apart = $true }
        @{ name = 'corp.example.test'; type = 'A'; apart = $true }
        @{ name = 'corp.example.test'; type = 'NS'; apart = $true }
        @{ name = 'corp.example.test'; type = 'MX'; apart = $false }
        @{ name = 'branch.corp.example.test'; type = 'NS'; apart = $true }
        @{ name = 'alias.corp.example.test'; type = 'DNAME'; apart = $true }
        @{ name = 'dc1.corp.example.test'; type = 'A'; apart = $true }
        @{ name = 'dc1.corp.example.test'; type = 'TXT'; apart = $false }
        @{ name = 'pc1.corp.example.test'; type = 'A'; apart = $false }
        @{ name = 'corp.example.test'; type = 'DNAME'; apart = $true }
        @{ name = 'corp.example.test'; type = 'CNAME'; apart = $true }
        @{ name = '*.corp.example.test'; type = 'A'; apart = $true }
        @{ name = '*.branch.corp.example.test'; type = 'TXT'; apart = $true }
        @{ name = 'ns1.corp.example.test'; type = 'A'; apart = $true }
        @{ name = 'ns1.corp.example.test'; type = 'AAAA'; apart = $true }
        @{ name = 'dc9.child.corp.example.test'; type = 'A'; apart = $true }
        @{ name = 'child.corp.example.test'; type = 'AAAA'; apart = $true }
        @{ name = 'ns1.corp.example.test'; type = 'MX'; apart = $false }
        @{ name = 'nochild.corp.example.test'; type = 'A'; apart = $false }
    ) {
        Test-TkApartName -Name $name -Type $type -Zone 'corp.example.test' -Controllers @('dc1.corp.example.test') -NsTargets @('ns1.corp.example.test') -Delegated @('child.corp.example.test') | Should -Be $apart
    }
}

Describe 'The name resolution policy' {
    # Rules as Get-DnsClientNrptPolicy -Effective returns them (the properties the check reads,
    # named as the cmdlet names them).
    BeforeAll {
        function Get-TestRule {
            param([string[]]$Namespace, [string[]]$NameServers = @(), [string[]]$DirectAccess = @())
            [pscustomobject]@{ Namespace = $Namespace; QueryPolicy = ''; SecureNameQueryFallback = ''; NameServers = $NameServers; DirectAccessDnsServers = $DirectAccess; DnsSecValidationRequired = ($NameServers.Count -eq 0); NameEncoding = 'Utf8WithoutMapping' }
        }
    }

    It 'stops a run whose domain <case>' -ForEach @(
        @{ case = 'a rule with name servers covers by suffix'; rules = { @(Get-TestRule -Namespace '.corp.example.test' -NameServers '192.0.2.11') } }
        @{ case = 'has its locator name under an exact rule with name servers'; rules = { @(Get-TestRule -Namespace '_ldap._tcp.dc._msdcs.corp.example.test' -NameServers '192.0.2.11') } }
        @{ case = 'falls under a suffix rule written with a trailing dot'; rules = { @(Get-TestRule -Namespace '.corp.example.test.' -NameServers '192.0.2.11') } }
        @{ case = 'has its locator names under a rule with name servers'; rules = { @(Get-TestRule -Namespace '._msdcs.corp.example.test' -NameServers '192.0.2.11') } }
        @{ case = 'falls under a DirectAccess rule with its servers'; rules = { @(Get-TestRule -Namespace '.example.test' -DirectAccess '2001:db8::53') } }
        @{ case = 'falls under a rule for every name'; rules = { @(Get-TestRule -Namespace '.' -NameServers '192.0.2.11') } }
        # A more specific entry without servers inherits the covering entry's: the effective
        # policy lists either the child bare beside its parent, or the child with the parent's servers.
        @{ case = 'has its locator names under a DNSSEC-only child of a parent with servers'; rules = { @((Get-TestRule -Namespace '._msdcs.corp.example.test'), (Get-TestRule -Namespace '.example.test' -NameServers '192.0.2.11')) } }
        @{ case = 'has its locator names under a child that lists its parent''s servers'; rules = { @((Get-TestRule -Namespace '._msdcs.corp.example.test' -NameServers '192.0.2.11'), (Get-TestRule -Namespace '.example.test' -NameServers '192.0.2.11')) } }
    ) {
        Mock Get-TkNrptRule $rules
        { Assert-TkDirectAnswer -Domain 'corp.example.test' } | Should -Throw '*sends the names of corp.example.test to fixed servers by policy*run it from a machine without such a rule*'
    }

    It 'lets a run go on <case>' -ForEach @(
        @{ case = 'with no rule'; rules = { @() } }
        @{ case = 'with a covering rule that sets DNSSEC only'; rules = { @(Get-TestRule -Namespace '.corp.example.test') } }
        @{ case = 'with a rule for another namespace'; rules = { @((Get-TestRule -Namespace '.other.example.test' -NameServers '192.0.2.99'), (Get-TestRule -Namespace 'notcorp.example.test' -NameServers '192.0.2.99')) } }
        # Only the name the script asks a named server for counts: the bare domain is never asked so.
        @{ case = 'with an exact rule for the bare domain'; rules = { @(Get-TestRule -Namespace 'corp.example.test' -NameServers '192.0.2.11') } }
    ) {
        Mock Get-TkNrptRule $rules
        { Assert-TkDirectAnswer -Domain 'corp.example.test' } | Should -Not -Throw
    }

    It 'compares on label boundaries and in the names'' ASCII form' {
        Mock Get-TkNrptRule { @(Get-TestRule -Namespace '.corp.example.test' -NameServers '192.0.2.11') }
        { Assert-TkDirectAnswer -Domain 'notcorp.example.test' } | Should -Not -Throw -Because 'a suffix rule covers whole labels only'
        # A rule written as a Unicode name covers the domain written in its ASCII form.
        Mock Get-TkNrptRule { @(Get-TestRule -Namespace ('.b' + [char]0xFC + 'cher.example.test') -NameServers '192.0.2.11') }
        { Assert-TkDirectAnswer -Domain 'xn--bcher-kva.example.test' } | Should -Throw '*fixed servers by policy*'
    }

    It 'stops a run at a rule with name servers whose name is no DNS name, naming that rule' {
        Mock Get-TkNrptRule { @((Get-TestRule -Namespace '.bad..example.test'), (Get-TestRule -Namespace '.other.example.test' -NameServers '192.0.2.99'), (Get-TestRule -Namespace '.bad..example.test' -NameServers '192.0.2.11')) }
        { Assert-TkDirectAnswer -Domain 'corp.example.test' } | Should -Throw '*rule for .bad..example.test names 192.0.2.11 and its name cannot be read as a DNS name*run it from a machine without such a rule*'
        { Assert-TkDirectAnswer -Domain 'corp.example.test' -InWindow } | Should -Throw '*cannot be read as a DNS name*run the script again to resume*'
    }

    It 'stops a run when the policy cannot be read' {
        Mock Get-TkNrptRule { throw 'Access is denied' }
        { Assert-TkDirectAnswer -Domain 'corp.example.test' } | Should -Throw '*could not be read (Access is denied)*run it from a machine whose policy it can read*'
    }

    It 'stops inside the DNS window as a failed step to resume, never as a refusal before any change' {
        Mock Get-TkNrptRule { @(Get-TestRule -Namespace '.corp.example.test' -NameServers '192.0.2.11') }
        Get-ExitCode { Assert-TkDirectAnswer -Domain 'corp.example.test' -InWindow } | Should -Be 2
        { Assert-TkDirectAnswer -Domain 'corp.example.test' -InWindow } | Should -Throw '*remove the rule on this machine and run the script again to resume, or run it with -Reverse*'
        Get-ExitCode { Assert-TkDirectAnswer -Domain 'corp.example.test' } | Should -Be 1
    }
}

Describe 'The restore block' {
    # Run here against a test folder for the DNS server's own: the export is staged under its
    # own name and checked by its SHA-256 before the zone is touched.
    BeforeEach {
        # Windows PowerShell's crypto providers load from %SystemRoot%, which this test points
        # elsewhere: the digest is taken with the managed SHA-256.
        function Get-TestDigest { param([string]$LiteralPath) $sha = [System.Security.Cryptography.SHA256Managed]::new(); try { [System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($LiteralPath))).Replace('-', '') } finally { $sha.Dispose() } }
        Mock Get-FileHash { [pscustomobject]@{ Hash = (Get-TestDigest -LiteralPath $LiteralPath) } }
        $savedRoot = $env:SystemRoot
        $env:SystemRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        $dns = Join-Path $env:SystemRoot 'System32\dns'
        [void](New-Item -ItemType Directory -Path $dns -Force)
        [System.IO.File]::WriteAllText((Join-Path $dns 'tenko-backup-corp.example.test.dns'), "export`r`n")
        $digest = Get-TestDigest -LiteralPath (Join-Path $dns 'tenko-backup-corp.example.test.dns')
        $script:zoneCalls = @()
        function Get-DnsServerZone { [pscustomobject]@{ IsDsIntegrated = $false; ZoneFile = 'corp.example.test.dns' } }
        function Remove-DnsServerZone { [CmdletBinding(SupportsShouldProcess)] param($Name, [switch]$Force) if ($PSCmdlet.ShouldProcess($Name)) { $script:zoneCalls += "remove $Name $Force" } }
        function Add-DnsServerPrimaryZone { param($Name, $ZoneFile, [switch]$LoadExisting) $script:zoneCalls += "add $Name $ZoneFile $LoadExisting" }
    }
    AfterEach { $env:SystemRoot = $savedRoot }

    It 'loads the staged export when its digest is the run''s' {
        & $script:TkRemote.RestoreZone 'corp.example.test' 'tenko-backup-corp.example.test.dns' 'tenko-restore-corp.example.test.dns' $digest
        $script:zoneCalls | Should -Be @('remove corp.example.test True', 'add corp.example.test tenko-restore-corp.example.test.dns True')
    }

    It 'touches no zone when the export on the server is not the run''s' {
        [System.IO.File]::WriteAllText((Join-Path $dns 'tenko-backup-corp.example.test.dns'), "planted`r`n")
        [System.IO.File]::WriteAllText((Join-Path $dns 'tenko-restore-corp.example.test.dns'), "planted`r`n")
        { & $script:TkRemote.RestoreZone 'corp.example.test' 'tenko-backup-corp.example.test.dns' 'tenko-restore-corp.example.test.dns' $digest } | Should -Throw '*is not the export of phase 2*'
        $script:zoneCalls | Should -BeNullOrEmpty
    }
}

Describe 'The payloads' {
    BeforeEach {
        Use-FakePayload
        $mirror = Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror'
        $beside = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        [void](New-Item -ItemType Directory -Path $beside)
        $out = Join-Path $beside 'out'
        $original = [System.IO.File]::ReadAllBytes((Join-Path $mirror 'Tenko-DhcpMirror.ps1'))
    }

    It 'uses the embedded copy and writes exactly the bytes it checked' {
        $payload = Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $beside -OutDir $out
        $payload.Source | Should -Be 'embedded'
        [System.IO.File]::ReadAllBytes($payload.Path) | Should -Be $original
        $payload.Sha256 | Should -Be (Get-FileHash -LiteralPath $payload.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    It 'uses a copy beside it whose text is the release''s, also with a signature block added' {
        $text = [System.Text.Encoding]::ASCII.GetString($original).TrimEnd("`r", "`n") + "`r`n`r`n# SIG # Begin signature block`r`n# SIG # MIIFakeSignatureLine`r`n# SIG # End signature block`r`n"
        [System.IO.File]::WriteAllBytes((Join-Path $beside 'Tenko-DhcpMirror.ps1'), [System.Text.Encoding]::ASCII.GetBytes($text))
        $payload = Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $beside -OutDir $out
        $payload.Source | Should -Match 'beside'
        [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($payload.Path)) | Should -BeExactly $text
    }

    It 'refuses a copy beside it whose text differs, before and after a signature block' {
        $changed = [System.Text.Encoding]::ASCII.GetString($original) + "Write-Output 'added'`r`n"
        [System.IO.File]::WriteAllBytes((Join-Path $beside 'Tenko-DhcpMirror.ps1'), [System.Text.Encoding]::ASCII.GetBytes($changed))
        { Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $beside -OutDir $out } | Should -Throw '*not the release*'
        $smuggled = [System.Text.Encoding]::ASCII.GetString($original).TrimEnd("`r", "`n") + "`r`n# SIG # Begin signature block`r`n# SIG # MIIFakeSignatureLine`r`nWrite-Output 'after the block'`r`n"
        [System.IO.File]::WriteAllBytes((Join-Path $beside 'Tenko-DhcpMirror.ps1'), [System.Text.Encoding]::ASCII.GetBytes($smuggled))
        { Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $beside -OutDir $out } | Should -Throw '*not the release*'
    }

    It 'refuses an embedded copy that does not match its digest' {
        $script:TkPayloadDigest['Tenko-DhcpMirror.ps1'] = '0' * 64
        { Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $beside -OutDir $out } | Should -Throw '*damaged*'
    }

    It 'hashes the written copy again before it is dot-sourced, and runs nothing from a changed one' {
        $payload = Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $beside -OutDir $out
        [System.IO.File]::AppendAllText($payload.Path, "`r`nthrow 'planted code ran'`r`n")
        $raw = Get-FakeRaw
        { Get-TkMappedSnapshot -Raw $raw -Server 'dc1.corp.example.test' -ExporterPath $payload.Path } | Should -Throw '*is not the release*Tenko-DhcpMirror.ps1 any more*'
    }
}

Describe 'The installer the release carries' {
    It 'is accepted when it takes every parameter the scripted install passes, and refused by name otherwise' {
        # The repository's installer gains -ComputerName and -SkipDryRun in a change of its own;
        # until then phase 2 refuses it before any change, naming what it lacks.
        $installer = Join-Path (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') '..') 'mirror') 'Install-TenkoDhcpMirror.ps1'
        $text = [System.IO.File]::ReadAllText($installer)
        if ($text -match '\$ComputerName\b' -and $text -match '\$SkipDryRun\b') { { Assert-TkInstallerContract -Path $installer } | Should -Not -Throw }
        else { { Assert-TkInstallerContract -Path $installer } | Should -Throw '*has no -ComputerName, -SkipDryRun*nothing was changed*' }
    }

    It 'is held to the keys the remote block passes' {
        $keys = @($script:TkRemote.InstallExporter.Ast.Find({ param($node) $node -is [System.Management.Automation.Language.HashtableAst] }, $true) |
                ForEach-Object { $_.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text } }) + 'Credential' + 'Remove'
        foreach ($key in $keys) { $script:TkInstallerContract | Should -Contain $key }
    }
}

Describe 'The access lists' {
    It 'are read by SID from SDDL, aliases and the domain''s RIDs resolved, in any language' {
        $entries = ConvertFrom-TkSddl -Sddl 'O:DAD:(A;;RPWP;;;AU)(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;0x10000000;;;S-1-5-21-1-2-3-1234)(D;;GA;;;WD)' -DomainSid 'S-1-5-21-1-2-3'
        $entries.Count | Should -Be 3
        $entries[0].Sid | Should -Be 'S-1-5-11'
        $entries[0].Write | Should -BeTrue
        $entries[1].Sid | Should -Be 'S-1-5-21-1-2-3-513'
        $entries[1].Control | Should -BeTrue
        $entries[1].Object | Should -Be '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $entries[2].Write | Should -BeTrue
    }

    It 'warn about a template whose enrollee supplies the subject and that Domain Users may enroll in' {
        $rows = @(@{ Kind = 'template'; Name = 'WebLike'; NameFlag = 1; Usages = @('1.3.6.1.5.5.7.3.2'); Sddl = 'O:DAD:(OA;;CR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;GA;;;DA)' })
        $warnings = Find-TkHardeningWarning -Rows $rows -DomainSid 'S-1-5-21-1-2-3' -Quota '0' -Pdc 'dc1.corp.example.test'
        $warnings -join ' ' | Should -Match 'certificate template WebLike: S-1-5-21-1-2-3-513 may enroll in it'
    }

    It 'exempt a delegated group by its SID only, never by a name that holds Administrators' {
        Test-TkSidIn -Sid 'S-1-5-21-1-2-3-1234' -Sids $script:TkTrustedSids -Rids $script:TkTrustedRids -DomainSid 'S-1-5-21-1-2-3' | Should -BeFalse
        Test-TkSidIn -Sid 'S-1-5-21-1-2-3-512' -Sids $script:TkTrustedSids -Rids $script:TkTrustedRids -DomainSid 'S-1-5-21-1-2-3' | Should -BeTrue
        Test-TkSidIn -Sid 'S-1-5-21-9-9-9-512' -Sids $script:TkTrustedSids -Rids $script:TkTrustedRids -DomainSid 'S-1-5-21-1-2-3' | Should -BeFalse
    }
}
