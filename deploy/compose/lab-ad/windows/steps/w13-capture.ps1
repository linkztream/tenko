# W13, on dc1 and on pc1: the registration after a restart of the Tenko node (README.md
# section W13), as SYSTEM. One script for both entries.
#
# Expects: the ns1 entry before it restarted the Tenko service.
# Leaves: the machine's records registered again.
# Keeps: <machine>.pcapng (to captures/w13-dc1.pcapng or captures/w13-pc1.pcapng),
# pktmon.txt, register.txt.
# Checks: none here: BADKEY, the new TKEY and the update are read from the capture by a
# person, and "nothing refused for ownership" by the last ns1 entry of W13.
$common = 'C:\lab\run\lab-common.ps1'
if (-not (Test-Path $common)) { "FAIL: $common is missing (the entry's needs_files copies it)"; exit 1 }
. $common

Invoke-Step -Pass "a capture of $Computer's registration after the node's restart is kept" {
    Start-Capture $Computer 53
    Invoke-Native 'register.txt' { ipconfig /registerdns }
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { Invoke-Native 'register.txt' { nltest /dsregdns } }
    Start-Sleep -Seconds 60
    Stop-Capture $Computer
}
