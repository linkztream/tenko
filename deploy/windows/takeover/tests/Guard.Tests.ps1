# The script's guards (MIG-17): the refusals before anything is read, each with exit 1; the
# sessions it opens; the state directory's access list; the payloads it carries, checked by
# their digest before and after an organization's signature is added.

BeforeDiscovery {
    $windows = $env:OS -eq 'Windows_NT'
}

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    . (Join-Path $PSScriptRoot 'Fake.ps1')
    function Get-ExitCode {
        param([scriptblock]$Action)
        try { & $Action; return 0 } catch { if ($_.Exception.Data.Contains('tk.exit')) { return [int]$_.Exception.Data['tk.exit'] }; throw }
    }
    $savedPath = $env:PSModulePath
}

AfterAll { $env:PSModulePath = $savedPath }

Describe 'The host' {
    BeforeEach {
        $script:TkVersion = '0.0.0-test'
        Mock Get-TkLanguageMode { 'FullLanguage' }
        Mock Test-TkElevated { $true }
        Mock Get-TkTokenSid { @('S-1-5-21-1000-2000-3000-512') }
        Mock Use-TkSystemModulePath { }
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

    It 'passes an elevated member of Domain Admins in Full Language and loads modules from the system''s directories only' -Skip:(-not $windows) {
        # Runner: Windows only.
        Get-ExitCode { Assert-TkHost } | Should -Be 0
        Should -Invoke Use-TkSystemModulePath -Times 1
    }

    It 'finds Domain Admins of the domain by its RID, and of another domain not' {
        Test-TkDomainAdmin -Sids @('S-1-5-21-1-2-3-512') -DomainSid 'S-1-5-21-1-2-3' | Should -BeTrue
        Test-TkDomainAdmin -Sids @('S-1-5-21-1-2-3-512') -DomainSid 'S-1-5-21-9-9-9' | Should -BeFalse
        Test-TkDomainAdmin -Sids @('S-1-5-21-1-2-3-519', 'S-1-5-32-544') -DomainSid '' | Should -BeFalse
    }
}

Describe 'The module path' {
    It 'is the two system directories only' -Skip:(-not $windows) {
        # Runner: Windows only (the directories are Windows').
        try {
            Use-TkSystemModulePath
            $paths = @($env:PSModulePath.Split(';'))
        } finally {
            $env:PSModulePath = $savedPath
        }
        $paths.Count | Should -Be 2
        $paths[0] | Should -Be (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')
        $paths[1] | Should -Be (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules')
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

Describe 'The state directory' {
    It 'is readable by SYSTEM and Administrators only' -Skip:(-not $windows) {
        # Runner: Windows only (NTFS access lists).
        $dir = Join-Path $TestDrive 'state'
        [void](New-Item -ItemType Directory -Path $dir)
        Protect-TkDirectory $dir
        try {
            $acl = Get-Acl -LiteralPath $dir
            $acl.AreAccessRulesProtected | Should -BeTrue
            @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
        } finally {
            # The owner gives itself access back, so that the test drive can be removed.
            $null = icacls.exe $dir /grant "*$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value):(OI)(CI)F"
        }
    }

    It 'warns about a script folder that others may write' -Skip:(-not $windows) {
        # Runner: Windows only.
        $dir = Join-Path $TestDrive 'open'
        [void](New-Item -ItemType Directory -Path $dir)
        $acl = Get-Acl -LiteralPath $dir
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-11'), 'Modify', 'Allow'))
        Set-Acl -LiteralPath $dir -AclObject $acl
        Test-TkForeignWriter $dir | Should -BeTrue
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
}
