# The rules for the script's code (MIG-17, ADR 0038): it compiles nothing and runs no text,
# uses no cmdlet that follows redirects or logs a secret, asks for no credential, opens only
# Kerberos sessions, and is ASCII with CRLF line ends, so that a copy pasted into a file has
# the release digest.

BeforeAll {
    $path = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    $names = @($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
    $members = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) | ForEach-Object { $_.Member.Extent.Text })
}

Describe 'The code' {
    It 'parses' { $errors | Should -BeNullOrEmpty }

    It 'calls no <name>' -ForEach @(
        @{ name = 'Invoke-Expression' }, @{ name = 'iex' }, @{ name = 'Invoke-WebRequest' }, @{ name = 'iwr' }, @{ name = 'Invoke-RestMethod' },
        @{ name = 'irm' }, @{ name = 'curl' }, @{ name = 'wget' }, @{ name = 'Add-Type' }, @{ name = 'Get-Credential' }, @{ name = 'ConvertFrom-Json' },
        @{ name = 'ConvertTo-Json' }, @{ name = 'Start-Process' }, @{ name = 'New-Object' }, @{ name = 'Enable-WSManCredSSP' }, @{ name = 'Set-Item' }
    ) {
        $names | Should -Not -Contain $name
    }

    It 'makes no script block from text' {
        $scriptBlockTypes = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.TypeExpressionAst] -or $node -is [System.Management.Automation.Language.TypeConstraintAst] }, $true) |
                Where-Object { $_.TypeName.FullName -match '^(System\.Management\.Automation\.)?ScriptBlock$|PowerShell$|Runspace' })
        $scriptBlockTypes | Should -BeNullOrEmpty
        $members | Should -Not -Contain 'NewScriptBlock'
        $members | Should -Not -Contain 'InvokeScript'
        $members | Should -Not -Contain 'AddScript'
        ($ast.Extent.Text -match '\[scriptblock\]::') | Should -BeFalse
    }

    It 'invokes only its own step blocks and, on the mirror host, the installer it copied' {
        $targets = @($commands | Where-Object { $_.InvocationOperator -ne 'Unknown' -and $null -eq $_.GetCommandName() } | ForEach-Object { $_.CommandElements[0].Extent.Text } | Sort-Object -Unique)
        $targets | Should -Be @('$ExporterPath', '$installer', '$step.Do', '$step.Undo') -Because 'a dot-sourced exporter is the file whose digest was checked'
    }

    It 'opens every session with Kerberos, to a host name, and never with CredSSP or Negotiate' {
        foreach ($command in $commands | Where-Object { 'Invoke-Command', 'New-PSSession' -contains $_.GetCommandName() }) {
            $text = $command.Extent.Text
            if ($text -match '-Session \$session') { continue }
            $text | Should -Match '-Authentication Kerberos'
            $text | Should -Match '-ComputerName \$Server'
        }
        $ast.Extent.Text | Should -Not -Match 'CredSSP|Negotiate|TrustedHosts|SkipCACheck|SkipCNCheck'
    }

    It 'is ASCII with CRLF line ends, the bytes the release digest covers' {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        @($bytes | Where-Object { $_ -gt 0x7e -or ($_ -lt 0x20 -and $_ -ne 9 -and $_ -ne 10 -and $_ -ne 13) }).Count | Should -Be 0
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        ([regex]::Matches($text, "(?<!`r)`n")).Count | Should -Be 0
        $text.EndsWith("`r`n") | Should -BeTrue
    }
}
