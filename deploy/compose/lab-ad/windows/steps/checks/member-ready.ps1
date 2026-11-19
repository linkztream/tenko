# Readiness check on a domain member, as SYSTEM: exits 0 when the computer is a member of
# corp.example.test, Netlogon runs and its secure channel to a controller verifies, 1
# otherwise.
$ErrorActionPreference = 'Stop'
try {
    $system = Get-CimInstance Win32_ComputerSystem
    if (-not $system.PartOfDomain -or $system.Domain -ne 'corp.example.test') { throw 'not a member of corp.example.test' }
    if ((Get-Service Netlogon).Status -ne 'Running') { throw 'Netlogon is not running' }
    if (-not (Test-ComputerSecureChannel)) { throw 'the secure channel does not verify' }
    exit 0
} catch {
    "not ready: $($_.Exception.Message)"
    exit 1
}
