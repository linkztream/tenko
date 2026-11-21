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

    It 'keeps the remote work and backup folders out of folders a local user can write' {
        foreach ($name in $script:TkRemote.Keys) {
            $script:TkRemote[$name].ToString() | Should -Not -Match 'Windows\\Temp|SystemRoot ''Temp|C:\\ProgramData' -Because $name
        }
        $script:TkRemoteDir | Should -BeLike 'C:\Program Files\Tenko\*'
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
