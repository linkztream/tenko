<#
.SYNOPSIS
    Runs PSScriptAnalyzer over deploy/windows/mirror with PSScriptAnalyzerSettings.psd1.

.DESCRIPTION
    The rules of the settings file run in two passes over the same files: every rule but
    PSUseCorrectCasing, then PSUseCorrectCasing alone with its settings. Run in one pass,
    PSScriptAnalyzer 1.24.0 and 1.25.0 fail in about one call of two with an error of their
    own: PSUseCorrectCasing reads CommandInfo.Parameters on its rule thread while other rules
    (PSUseShouldProcessCorrectly, PSAvoidUsingCmdletAliases) run Get-Command in the same
    runspace of the analyzer's command cache, so that runspace is used from two threads at
    once. The result is a null reference in CommandInfo.Parameters, a runspace that no
    longer knows Get-Command (for the rest of the process), a crash or a hang. Neither pass
    on its own has failed.

    Exit code 0: no finding. Exit code 1: findings, printed with rule, severity, file, line
    and message. Exit code 2: the analyzer itself failed (an error, not a finding); the
    errors are printed with their exception.
#>
[CmdletBinding()]
param(
    [string]$Path = (Split-Path -Path $PSScriptRoot -Parent),
    [string]$Settings = (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'PSScriptAnalyzerSettings.psd1')
)

$ErrorActionPreference = 'Stop'
if (-not (Get-Module -Name PSScriptAnalyzer)) { Import-Module -Name PSScriptAnalyzer }

# The rule that runs in a pass of its own (see the description above).
$apart = 'PSUseCorrectCasing'
$base = Import-PowerShellDataFile -Path $Settings

$main = @{}
foreach ($key in $base.Keys) { $main[$key] = $base[$key] }
$main.ExcludeRules = [string[]](@($base.ExcludeRules | Where-Object { $_ }) + $apart)
$main.Rules = @{}
foreach ($rule in $base.Rules.Keys) {
    if ($rule -ne $apart) { $main.Rules[$rule] = $base.Rules[$rule] }
}

$single = @{
    Severity     = $base.Severity
    IncludeRules = @($apart)
    Rules        = @{ $apart = $base.Rules[$apart] }
}

$findings = @()
$failures = @()
foreach ($pass in @(@{ Name = "all rules but $apart"; Settings = $main }, @{ Name = $apart; Settings = $single })) {
    $errors = $null
    $result = @(Invoke-ScriptAnalyzer -Path $Path -Recurse -Settings $pass.Settings -ErrorAction SilentlyContinue -ErrorVariable errors)
    Write-Output "Pass '$($pass.Name)': $($result.Count) findings, $(@($errors).Count) analyzer errors"
    $findings += $result
    $failures += @($errors)
}

if ($findings.Count -gt 0) {
    $findings |
        Select-Object -Property RuleName, Severity, @{ Name = 'File'; Expression = { Resolve-Path -LiteralPath $_.ScriptPath -Relative } }, Line, Message |
        Format-Table -AutoSize -Wrap |
        Out-String -Width 200 |
        Write-Output
}
Write-Output "$($findings.Count) findings"

if ($failures.Count -gt 0) {
    Write-Output "The analyzer itself failed $($failures.Count) times; this is not a finding about the scripts:"
    foreach ($failure in $failures) {
        Write-Output "--- $($failure.FullyQualifiedErrorId)"
        Write-Output $failure.Exception.ToString()
    }
    exit 2
}
if ($findings.Count -gt 0) { exit 1 }
exit 0
