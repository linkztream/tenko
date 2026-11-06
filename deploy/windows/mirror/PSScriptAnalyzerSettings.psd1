@{
    # PSScriptAnalyzer rules for deploy/windows/mirror (plan section 4, WP14.1; exit check
    # E72: nothing above this file). Run with
    #   deploy/windows/mirror/tests/Invoke-Analysis.ps1
    # which runs PSUseCorrectCasing in a pass of its own (see the script for why).
    # Every default rule applies, the compatibility rules on top; the two exclusions are
    # named with their reason.
    Severity     = @('Error', 'Warning', 'Information')
    IncludeDefaultRules = $true
    ExcludeRules = @(
        # Pester's BeforeAll, Mock and It blocks assign variables that later blocks read;
        # the rule cannot see across them.
        'PSUseDeclaredVarsMoreThanAssignments',
        # The installer prompts for the token with Read-Host -AsSecureString and the
        # exporter reads a stored DPAPI string; both are SecureString parameters by design,
        # and the one plain-text string (token.pending) is a file the first run deletes.
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )
    Rules        = @{
        # The exporter and the installer run on Windows PowerShell 5.1 and PowerShell 7.
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
        }
        PSPlaceOpenBrace = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSPlaceCloseBrace = @{
            Enable             = $true
            NewLineAfter       = $false
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }
        PSUseConsistentIndentation = @{
            Enable              = $true
            IndentationSize     = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            Kind                = 'space'
        }
        PSUseConsistentWhitespace = @{
            Enable                          = $true
            CheckInnerBrace                 = $true
            CheckOpenBrace                  = $true
            CheckOpenParen                  = $true
            CheckOperator                   = $false
            CheckPipe                       = $true
            CheckPipeForRedundantWhitespace = $false
            CheckSeparator                  = $true
            CheckParameter                  = $false
        }
        PSAlignAssignmentStatement = @{
            Enable         = $false
            CheckHashtable = $false
        }
        PSUseCorrectCasing = @{
            Enable = $true
        }
    }
}
