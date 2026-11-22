# The release's part (MIG-17): the build fills the single file with the exporter and the
# installer, writes the loose files and the archive, all ASCII with CRLF line ends; the
# release notes' start line and the intake check's line are the same line, and that line
# starts the file only when its digest is the release's.

BeforeDiscovery {
    $windows = $env:OS -eq 'Windows_NT'
}

BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    $build = Join-Path (Join-Path $root 'build') 'New-TakeoverRelease.ps1'
    $mirror = Join-Path (Split-Path -Parent $root) 'mirror'
    $out = Join-Path $TestDrive 'dist'
    $names = @(& $build -Version '0.0.12' -OutDir $out)
    $built = Join-Path $out 'Tenko-Takeover.ps1'
    $digest = (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash
    $notes = (& $build -Notes -Tag 'v0.0.12' -Script $built) -join "`n"
    $startLine = @($notes -split "`n" | Where-Object { $_ -like '$f=*' })[0]
    function Get-Crlf { param([string]$Path) [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($Path)).Replace("`r`n", "`n").Replace("`n", "`r`n") }
}

Describe 'The build' {
    It 'writes the single file, the loose exporter and installer, and the archive' {
        $names | Should -Be @('Tenko-Takeover.ps1', 'Tenko-DhcpMirror.ps1', 'Install-TenkoDhcpMirror.ps1', 'tenko-takeover-0.0.12.zip')
    }

    It 'writes every script ASCII with CRLF line ends' {
        foreach ($name in $names | Where-Object { $_ -like '*.ps1' }) {
            $bytes = [System.IO.File]::ReadAllBytes((Join-Path $out $name))
            @($bytes | Where-Object { $_ -gt 0x7e }).Count | Should -Be 0 -Because $name
            ([regex]::Matches([System.Text.Encoding]::ASCII.GetString($bytes), "(?<!`r)`n")).Count | Should -Be 0 -Because $name
        }
    }

    It 'embeds copies equal to the repository''s exporter and installer, which the filled script accepts' {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($built, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
        . $built
        $script:TkVersion | Should -Be '0.0.12'
        foreach ($name in 'Tenko-DhcpMirror.ps1', 'Install-TenkoDhcpMirror.ps1') {
            $embedded = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(($script:TkPayloadText[$name] -replace '\s', '')))
            $embedded | Should -BeExactly (Get-Crlf (Join-Path $mirror $name))
            [System.IO.File]::ReadAllText((Join-Path $out $name)) | Should -BeExactly $embedded
            $payload = Get-TkPayload -Name $name -Directory '' -OutDir (Join-Path $TestDrive 'payload')
            $payload.Source | Should -Be 'embedded'
            $loose = Get-TkPayload -Name $name -Directory $out -OutDir (Join-Path $TestDrive 'payload-loose')
            $loose.Source | Should -Match 'beside'
        }
    }

    It 'puts the three scripts and the README into the archive' {
        $zip = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $out 'tenko-takeover-0.0.12.zip'))
        try {
            @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object) | Should -Be @('tenko-takeover/Install-TenkoDhcpMirror.ps1', 'tenko-takeover/README.md', 'tenko-takeover/Tenko-DhcpMirror.ps1', 'tenko-takeover/Tenko-Takeover.ps1')
        } finally { $zip.Dispose() }
    }

    It 'refuses a script that is not ASCII or not CRLF' {
        $bad = Join-Path $TestDrive 'bad'
        [void](New-Item -ItemType Directory -Path (Join-Path $bad 'takeover\build') -Force)
        [void](New-Item -ItemType Directory -Path (Join-Path $bad 'mirror') -Force)
        Copy-Item -LiteralPath $build -Destination (Join-Path $bad 'takeover\build')
        Copy-Item -LiteralPath (Join-Path $root 'README.md') -Destination (Join-Path $bad 'takeover')
        foreach ($name in 'Tenko-DhcpMirror.ps1', 'Install-TenkoDhcpMirror.ps1') { Copy-Item -LiteralPath (Join-Path $mirror $name) -Destination (Join-Path $bad 'mirror') }
        $text = [System.IO.File]::ReadAllText($built)
        [System.IO.File]::WriteAllText((Join-Path $bad 'takeover\Tenko-Takeover.ps1'), $text.Replace("`r`n", "`n"))
        { & (Join-Path $bad 'takeover\build\New-TakeoverRelease.ps1') -Version '0.0.12' -OutDir (Join-Path $bad 'out') } | Should -Throw '*LF line ends*'
        [System.IO.File]::WriteAllText((Join-Path $bad 'takeover\Tenko-Takeover.ps1'), $text + '# ' + [char]0xe9 + "`r`n")
        { & (Join-Path $bad 'takeover\build\New-TakeoverRelease.ps1') -Version '0.0.12' -OutDir (Join-Path $bad 'out') } | Should -Throw '*outside printable ASCII*'
    }
}

Describe 'The start line' {
    It 'is in the release notes with the file''s digest, and in the fetching form with the tag' {
        $startLine | Should -Match ([regex]::Escape("-eq '$digest'"))
        $notes | Should -Match ([regex]::Escape('https://github.com/linkztream/tenko/releases/download/v0.0.12/Tenko-Takeover.ps1; ' + $startLine))
    }

    It 'is what the intake check prints after its checks' {
        $readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
        $check = [regex]::Match($readme, '<!-- intake-check -->\s*```powershell\r?\n(?<code>.*?)```', 'Singleline').Groups['code'].Value
        $check | Should -Not -BeNullOrEmpty
        $intake = Join-Path $TestDrive 'intake'
        [void](New-Item -ItemType Directory -Path $intake)
        foreach ($name in 'Tenko-Takeover.ps1', 'tenko-takeover-0.0.12.zip') { Copy-Item -LiteralPath (Join-Path $out $name) -Destination $intake }
        $sums = foreach ($name in 'Tenko-Takeover.ps1', 'tenko-takeover-0.0.12.zip') { "$((Get-FileHash -LiteralPath (Join-Path $intake $name) -Algorithm SHA256).Hash.ToLowerInvariant())  $name" }
        Set-Content -LiteralPath (Join-Path $intake 'SHA256SUMS') -Value $sums -Encoding ascii
        function gh { $global:LASTEXITCODE = 0 }
        Push-Location $intake
        try {
            $printed = & ([scriptblock]::Create($check))
            $printed | Should -BeExactly $startLine
            Get-Content -LiteralPath Start-Tenko.txt | Should -BeExactly $startLine
            Add-Content -LiteralPath Tenko-Takeover.ps1 -Value '# changed'
            Remove-Item -LiteralPath Start-Tenko.txt
            { & ([scriptblock]::Create($check)) } | Should -Throw '*does not match SHA256SUMS*'
            Test-Path -LiteralPath Start-Tenko.txt | Should -BeFalse
        } finally { Pop-Location }
    }

    It 'starts the file only when its digest is the release''s, and names the digest it found' -Skip:(-not $windows) {
        # Runner: Windows only (the line names a Windows path under %ProgramFiles%).
        $programs = Join-Path $TestDrive 'programs'
        [void](New-Item -ItemType Directory -Path (Join-Path $programs 'Tenko\takeover') -Force)
        $target = Join-Path $programs 'Tenko\takeover\Tenko-Takeover.ps1'
        Copy-Item -LiteralPath $built -Destination $target
        # The folder and PowerShell come from the platform, not from the environment: the test
        # points the line's two names at its own folder and a recorder, and changes nothing else.
        $startLine | Should -Match ([regex]::Escape('$f=[Environment]::GetFolderPath(''ProgramFiles'')+''\Tenko\takeover\Tenko-Takeover.ps1''; '))
        $startLine | Should -Match ([regex]::Escape('& "$PSHOME\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $f'))
        $line = $startLine.Replace('[Environment]::GetFolderPath(''ProgramFiles'')', "'$programs'").Replace('& "$PSHOME\powershell.exe"', 'Write-Started')
        $script:started = @()
        function Write-Started { $script:started += , $args }
        Mock Unblock-File { }
        & ([scriptblock]::Create($line))
        $script:started.Count | Should -Be 1
        ($script:started[0] -join ' ') | Should -Be "-NoProfile -ExecutionPolicy Bypass -File $target"
        Add-Content -LiteralPath $target -Value '# changed'
        $script:started = @()
        # A console runs the line with the default preference; a caller's Stop would end the test here.
        $ErrorActionPreference = 'Continue'
        $errors = @(& ([scriptblock]::Create($line)) 2>&1)
        $script:started.Count | Should -Be 0
        "$errors" | Should -Match "does not match the release digest; nothing was run\. Its SHA-256 is $((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash)"
    }
}
