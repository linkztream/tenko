# Readiness check on a domain controller, as SYSTEM: exits 0 when the directory service
# answers (NTDS, ADWS and Netlogon run, SYSVOL and NETLOGON are shared, and the domain
# corp.example.test can be read on this controller), 1 otherwise.
$ErrorActionPreference = 'Stop'
try {
    foreach ($service in 'NTDS', 'ADWS', 'Netlogon') {
        if ((Get-Service $service).Status -ne 'Running') { throw "$service is not running" }
    }
    foreach ($share in 'SYSVOL', 'NETLOGON') { Get-SmbShare -Name $share | Out-Null }
    if ((Get-ADDomain -Server localhost).DNSRoot -ne 'corp.example.test') { throw 'not corp.example.test' }
    exit 0
} catch {
    "not ready: $($_.Exception.Message)"
    exit 1
}
