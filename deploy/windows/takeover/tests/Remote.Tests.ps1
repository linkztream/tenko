# Every block the script runs on a server, in Constrained Language (MIG-17): where App
# Control for Business enforces on a controller, a remote session runs in that mode whatever
# the script's own, so the blocks use cmdlets and core types only. Each block runs in a
# runspace of that mode with every command it calls replaced by a stub that returns one
# object; an error of the language mode fails the test, and nothing else is judged here.

BeforeDiscovery {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    $blocks = @($script:TkRemote.Keys | Sort-Object | ForEach-Object { @{ Name = $_ } })
}

BeforeAll {
    . (Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..') -ChildPath 'Tenko-Takeover.ps1')
    # The pipeline cmdlets keep their meaning; everything else a block calls is a stub.
    $keep = 'ForEach-Object', 'Where-Object', 'Select-Object', 'Measure-Object', 'Sort-Object'
    $languageErrors = 'InvalidCastConstructorException|language mode|MethodInvocationNotSupportedInConstrainedLanguage|CannotCreateTypeConstrainedLanguage|ConversionSupportedOnlyToCoreTypes|PropertySetterNotSupportedInConstrainedLanguage|CantInvokeCallOperatorAcrossLanguageBoundaries|NoDotSourcingAcrossLanguages|TypeNotAllowed|NotSupportedInConstrainedLanguage|ConstrainedLanguage'

    function Get-SampleArgument {
        # A value for each parameter of a block, by its declared type.
        param([System.Management.Automation.Language.ScriptBlockAst]$Ast)
        $values = @()
        if ($null -eq $Ast.ParamBlock) { return , $values }
        foreach ($parameter in $Ast.ParamBlock.Parameters) {
            $type = $parameter.StaticType
            $secure = [securestring]::new(); $secure.AppendChar('x')
            $values += , $(switch ($type.Name) {
                    'String' { 'corp.example.test' }
                    'String[]' { , [string[]]@('192.0.2.11') }
                    'Boolean' { $true }
                    'SecureString' { $secure }
                    'PSCredential' { [pscredential]::new('CORP\x', $secure) }
                    'Hashtable' { $script:TkDhcpReadProperties }
                    'Object[]' { , @([pscustomobject]@{ Ip = '192.0.2.101'; Client = '00-00-5e-00-53-11'; Seconds = 60 }) }
                    default { $null }
                })
        }
        return , $values
    }
}

Describe 'The remote blocks' {
    It '<Name> runs in Constrained Language' -ForEach $blocks {
        $block = $script:TkRemote[$Name]
        $ast = $block.Ast
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -and $keep -notcontains $_ } | Select-Object -Unique)
        $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        foreach ($command in $commands) {
            $state.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($command, '[pscustomobject]@{ Name = "x"; Status = "Stopped"; StartType = "Disabled" }'))
        }
        $state.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage
        $runspace = [runspacefactory]::CreateRunspace($state)
        $runspace.Open()
        $shell = [powershell]::Create()
        $shell.Runspace = $runspace
        try {
            $mode = $shell.AddScript('$ExecutionContext.SessionState.LanguageMode').Invoke()
            [string]$mode[0] | Should -Be 'ConstrainedLanguage'
            $shell.Commands.Clear()
            [void]$shell.AddScript($block.ToString())
            foreach ($value in (Get-SampleArgument $ast)) { [void]$shell.AddArgument($value) }
            $failures = @()
            try { [void]$shell.Invoke() } catch { $failures += $_.Exception.InnerException; $failures += $_.Exception }
            $failures += @($shell.Streams.Error | ForEach-Object { $_.Exception; $_.FullyQualifiedErrorId })
            $language = @($failures | Where-Object { $_ } | Where-Object { "$($_.GetType().Name) $_ $(if ($_ -is [System.Management.Automation.IContainsErrorRecord]) { $_.ErrorRecord.FullyQualifiedErrorId })" -match $languageErrors })
            $language | Should -BeNullOrEmpty -Because "a block on a server runs in Constrained Language ($($language -join '; '))"
        } finally {
            $shell.Dispose()
            $runspace.Dispose()
        }
    }

    It 'the remote blocks call no command that compiles or runs text' {
        foreach ($name in $script:TkRemote.Keys) {
            $text = $script:TkRemote[$name].ToString()
            $text | Should -Not -Match '\b(Invoke-Expression|iex|Add-Type|New-Object|Invoke-Command|Start-Process)\b' -Because $name
            $text | Should -Not -Match '\[scriptblock\]' -Because $name
        }
    }
}
