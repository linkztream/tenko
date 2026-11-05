# Shared by the suites: stubs of the DhcpServer cmdlets the exporter calls, and mocks that
# answer them with the recorded output under fixtures/ (one file per cmdlet and level, as
# ConvertTo-Json -Depth 6 wrote it; see README.md, "Running the tests"). The stubs declare
# the cmdlets' parameters and use none, hence the suppression.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'stubs of the DhcpServer cmdlets')]
param()

function Read-Fixture {
    param([string]$Name)
    $path = Join-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'fixtures') -ChildPath "$Name.json"
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $json = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    return @($json)
}

# The stubs carry the parameters the exporter passes, so that Mock can bind them.
function Get-DhcpServerv4Scope { param([string]$ScopeId) }
function Get-DhcpServerv4ExclusionRange { param([string]$ScopeId) }
function Get-DhcpServerv4Reservation { param([string]$ScopeId) }
function Get-DhcpServerv4OptionValue { param([string]$ScopeId, [string]$ReservedIP, [switch]$All) }
function Get-DhcpServerv4OptionDefinition { param([switch]$All) }
function Get-DhcpServerv4Class { param() }
function Get-DhcpServerv4DnsSetting { param([string]$ScopeId) }
function Get-DhcpServerv4Lease { param([string]$ScopeId) }
function Get-DhcpServerv4Policy { param([string]$ScopeId) }
function Get-DhcpServerv4Filter { param() }
function Get-DhcpServerv4Superscope { param() }
function Get-DhcpServerv4Failover { param() }

function Install-DhcpServerMock {
    Mock Get-DhcpServerv4Scope { Read-Fixture 'Get-DhcpServerv4Scope' }
    Mock Get-DhcpServerv4ExclusionRange { Read-Fixture 'Get-DhcpServerv4ExclusionRange' }
    Mock Get-DhcpServerv4Reservation { Read-Fixture 'Get-DhcpServerv4Reservation' }
    Mock Get-DhcpServerv4OptionValue {
        if ($ReservedIP) { Read-Fixture "Get-DhcpServerv4OptionValue-ReservedIP-$ReservedIP" }
        elseif ($ScopeId) { Read-Fixture "Get-DhcpServerv4OptionValue-ScopeId-$ScopeId" }
        else { Read-Fixture 'Get-DhcpServerv4OptionValue' }
    }
    Mock Get-DhcpServerv4OptionDefinition { Read-Fixture 'Get-DhcpServerv4OptionDefinition' }
    Mock Get-DhcpServerv4Class { Read-Fixture 'Get-DhcpServerv4Class' }
    Mock Get-DhcpServerv4DnsSetting { Read-Fixture "Get-DhcpServerv4DnsSetting-ScopeId-$ScopeId" }
    Mock Get-DhcpServerv4Lease { Read-Fixture "Get-DhcpServerv4Lease-ScopeId-$ScopeId" }
    Mock Get-DhcpServerv4Policy {
        if ($ScopeId) { Read-Fixture "Get-DhcpServerv4Policy-ScopeId-$ScopeId" } else { Read-Fixture 'Get-DhcpServerv4Policy' }
    }
    Mock Get-DhcpServerv4Filter { Read-Fixture 'Get-DhcpServerv4Filter' }
    Mock Get-DhcpServerv4Superscope { Read-Fixture 'Get-DhcpServerv4Superscope' }
    Mock Get-DhcpServerv4Failover { Read-Fixture 'Get-DhcpServerv4Failover' }
}
