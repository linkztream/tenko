# What every step of the Windows interop lab on a Windows machine needs (README.md,
# "Running the steps unattended"). A step script dot-sources this file from the fixed path
# C:\lab\run\lab-common.ps1 and hands its body to Invoke-Step. Windows PowerShell 5.1, in-box
# modules only.
#
# - Strict mode; the entry's id is the script's file name (C:\lab\run\<id>.ps1), and its step
#   directory C:\lab\<id>\ holds what the runbook keeps and nothing secret: step.log (the
#   transcript), the outputs the runbook names, verdict.txt, and on a failure failure.txt (the
#   error and the warnings and errors of the System and Application logs since the step
#   began).
# - The last line of the output is the verdict: `PASS <id>: ...` or `FAIL <id>: ...`.
# - Secrets are files under C:\lab\secrets\ (one value and a newline each); Invoke-Step
#   refuses to start without the ones the step names, and a secret becomes a SecureString or
#   a credential object for the cmdlet that takes one, never an argument of a process.
# - A step that must act as CORP\Administrator (the AD, DNS Server and group policy cmdlets,
#   which take no credential, and dcdiag) runs its own script again through a one-shot
#   scheduled task registered for CORP\Administrator with the password from the secret file:
#   Start-Process -Credential does not work from SYSTEM, and a remote session on the
#   controller itself cannot reach the directory on the user's behalf (the second hop). The
#   task is removed when it ends; its part logs to admin.log in the same step directory.
# - Every step on a machine other than dc1 first compares the clock with dc1's and stops
#   when they are more than two
#   minutes apart (Kerberos allows five). The query is `w32tm /stripchart` (NTP, which every
#   controller answers and which needs no account), so it works before a machine joins.

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Lab = 'C:\lab'
$Id = [IO.Path]::GetFileNameWithoutExtension($MyInvocation.PSCommandPath)
$StepDir = Join-Path $Lab $Id
$In = Join-Path $Lab 'in'
$Started = Get-Date
$Computer = $env:COMPUTERNAME.ToLowerInvariant()
$Address = @{ dc1 = '192.0.2.5'; dc2 = '192.0.2.6'; srv1 = '192.0.2.20'; pc1 = '192.0.2.30' }[$Computer]
$Tenko = '192.0.2.53'
New-Item -ItemType Directory -Force $StepDir | Out-Null

function Fail([string]$Reason) { throw $Reason }

function Read-Secret([string]$Name) {
    $path = Join-Path $Lab "secrets\$Name"
    if (-not (Test-Path -LiteralPath $path)) { Fail "the secret file $path is missing; the job places it before this step" }
    $value = [IO.File]::ReadAllText($path).TrimEnd("`r", "`n")
    if (-not $value) { Fail "the secret file $path is empty" }
    $value
}

function Get-SecureSecret([string]$Name) { ConvertTo-SecureString (Read-Secret $Name) -AsPlainText -Force }

function Get-DomainAdminCredential {
    New-Object System.Management.Automation.PSCredential('CORP\Administrator', (Get-SecureSecret 'domain_admin_password'))
}

function Assert-File([string]$Path, [string]$From) {
    if (-not (Test-Path -LiteralPath $Path)) { Fail "$Path is missing: $From" }
}

# Invoke-Native <file> { native command }: runs it, appends what it prints to the file in the
# step directory and to the log, and fails when its exit status is not in -Allow (with
# -AnyStatus it only collects: dcdiag's status says nothing about its tests).
function Invoke-Native([string]$File, [scriptblock]$Command, [int[]]$Allow = @(0), [switch]$AnyStatus) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # A command that cannot start leaves the status of the earlier native command behind: clear it.
    $global:LASTEXITCODE = $null
    try { $raw = @(& $Command 2>&1) } finally { $ErrorActionPreference = $previous }
    $status = $LASTEXITCODE
    $output = @($raw | ForEach-Object { "$_" })
    if ($null -eq $status -and @($raw | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count) {
        $output | Out-File -Append -Encoding utf8 (Join-Path $StepDir $File)
        Fail "{$Command} did not run: $($output -join ' ') ($File)"
    }
    $output | Out-File -Append -Encoding utf8 (Join-Path $StepDir $File)
    $output | Out-Host
    if (-not $AnyStatus -and $Allow -notcontains $status) { Fail "{$Command} exited with $status ($File)" }
}

# Test-Replication [<file>]: repadmin /replsummary into the file; fails on any failed
# replication or operational error, as W7 and W14 expect.
function Test-Replication([string]$File = 'replication.txt') {
    # Only this summary: the file keeps the earlier attempts of a repeated entry.
    $path = Join-Path $StepDir $File
    $before = if (Test-Path $path) { @(Get-Content $path).Count } else { 0 }
    Invoke-Native $File { repadmin /replsummary } -AnyStatus
    $text = @(Get-Content $path | Select-Object -Skip $before)
    $counts = @($text | ForEach-Object { if ($_ -match '\s(\d+)\s*/\s*\d+\s+\d+(\s|$)') { [int]$Matches[1] } })
    if ($counts.Count -eq 0) { Fail "repadmin /replsummary listed no replication partner ($File)" }
    if (($counts | Measure-Object -Sum).Sum -gt 0 -or ($text -match 'operational errors')) {
        Fail "repadmin /replsummary reports failed replications ($File)"
    }
}

# ... | Save-Output <file>: the lines into the file in the step directory (UTF-8) and the log.
function Save-Output([string]$File) {
    $lines = @($input | ForEach-Object { "$_" })
    $lines | Out-File -Encoding utf8 (Join-Path $StepDir $File)
    $lines | Out-Host
}

# Wait-Until { condition } <seconds> <what>: polls every five seconds until it holds.
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$What) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        try { if (& $Condition) { return } } catch { "waiting for ${What}: $($_.Exception.Message)" | Out-Host }
        if ((Get-Date) -gt $deadline) { Fail "$What did not happen within $Seconds s" }
        Start-Sleep -Seconds 5
    }
}

# Set-DnsServerOfLab <address>: the DNS client of the lab adapter asks this server only.
function Set-DnsServerOfLab([string]$Server) {
    $adapter = (Get-NetIPAddress -IPAddress $Address).InterfaceAlias
    # Both address families: a controller promoted with the DNS role has ::1 as its IPv6
    # server and would go on asking, and updating, itself.
    Set-DnsClientServerAddress -InterfaceAlias $adapter -ResetServerAddresses
    Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $Server
    Clear-DnsClientCache
    $left = @(Get-DnsClientServerAddress -InterfaceAlias $adapter | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -ne $Server })
    if ($left.Count -gt 0) { Fail "the DNS client of $adapter still lists $($left -join ', ') beside $Server" }
}

# Assert-ZonePrimary: the primary the DNS client itself finds for the domain, which is where
# its updates go; anything but the expected server means the registration would go elsewhere.
function Assert-ZonePrimary([string]$Primary) {
    $soa = @(Resolve-DnsName corp.example.test -Type SOA -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Section -eq 'Answer' -and "$($_.Type)" -eq 'SOA' })
    if ($soa.Count -ne 1) { Fail "the DNS client found $($soa.Count) SOA records for corp.example.test" }
    $found = "$($soa[0].PrimaryServer)".TrimEnd('.')
    if ($found -ne $Primary) { Fail "the DNS client finds $found as the primary of corp.example.test, not $($Primary): its updates would go there" }
}

# Start-Capture <name> <ports> and Stop-Capture <name>: the runbook's pktmon capture, into
# <name>.pcapng in the step directory (the .etl is removed once converted).
function Start-Capture([string]$Name, [int[]]$Ports) {
    Invoke-Native 'pktmon.txt' { pktmon stop } -Allow 0, 1
    Invoke-Native 'pktmon.txt' { pktmon filter remove }
    foreach ($port in $Ports) { Invoke-Native 'pktmon.txt' { pktmon filter add -p $port } }
    Invoke-Native 'pktmon.txt' { pktmon start --capture --pkt-size 0 -f (Join-Path $StepDir "$Name.etl") }
}

function Stop-Capture([string]$Name) {
    $etl = Join-Path $StepDir "$Name.etl"
    Invoke-Native 'pktmon.txt' { pktmon stop }
    Invoke-Native 'pktmon.txt' { pktmon etl2pcap $etl -o (Join-Path $StepDir "$Name.pcapng") }
    Remove-Item -LiteralPath $etl
}

# Test-NetlogonRecords: the runbook's check of W5: every record of this controller's
# Netlogon.dns asked of Tenko; writes netlogon-check.txt and fails on a missing record.
function Test-NetlogonRecords {
    $missing = @()
    foreach ($line in Get-Content "$env:SystemRoot\System32\config\netlogon.dns") {
        $fields = $line -split '\s+'
        if ($fields.Count -lt 5 -or $fields[2] -ne 'IN') { continue }
        $name, $type = $fields[0].TrimEnd('.'), $fields[3]
        $want = ($fields[4..($fields.Count - 1)] -join ' ').TrimEnd('.')
        # Only the answers of the asked type: a server also sends the targets' addresses along,
        # and those records do not have the properties of an answer.
        $got = @(Resolve-DnsName -Name $name -Type $type -Server $Tenko -DnsOnly -NoHostsFile -ErrorAction SilentlyContinue |
                Where-Object { $_.Section -eq 'Answer' -and "$($_.Type)" -eq $type })
        $text = ($got | ForEach-Object {
                if ($type -eq 'SRV') { "$($_.Priority) $($_.Weight) $($_.Port) $($_.NameTarget)" }
                elseif ($type -eq 'CNAME') { $_.NameHost }
                elseif ($type -in 'A', 'AAAA') { $_.IPAddress }
                else { $_.ToString() }
            }) -join '|'
        if (-not ($text -split '\|' | Where-Object { $_.TrimEnd('.') -eq $want })) { $missing += "$name $type $want" }
    }
    @("records not in Tenko: $($missing.Count)") + $missing | Save-Output 'netlogon-check.txt'
    if ($missing.Count -gt 0) { Fail "$($missing.Count) records of Netlogon.dns are not in Tenko (netlogon-check.txt)" }
}

# Assert-Clock: this machine's clock against dc1's; skipped on dc1, the lab's time source.
function Assert-Clock {
    if ($Computer -eq 'dc1') { return }
    Invoke-Native 'clock.txt' { w32tm /stripchart /computer:192.0.2.5 /dataonly /samples:3 } -Allow 0, 1
    $offset = Get-Content (Join-Path $StepDir 'clock.txt') |
        ForEach-Object { if ($_ -match ',\s*([+-]\d+\.\d+)s\s*$') { [math]::Abs([double]$Matches[1]) } } |
        Select-Object -Last 1
    if ($null -eq $offset) { Fail 'dc1 (192.0.2.5) did not answer the time query (clock.txt)' }
    if ($offset -gt 120) { Fail "the clock is $([int]$offset) s away from dc1's (more than two minutes): Kerberos would fail" }
}

# Protect-Lab: SYSTEM and the domain administrator run what is in C:\lab\run, so only SYSTEM
# and Administrators may hold any right on C:\lab and C:\lab\run (and, by inheritance, on
# every step directory). Sets that, then reads it back and refuses to run when it is wider.
function Protect-Lab {
    $ok = 'S-1-5-18', 'S-1-5-32-544'
    foreach ($dir in $Lab, (Join-Path $Lab 'run')) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        & "$env:SystemRoot\System32\icacls.exe" $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "icacls could not set the access rights of $dir" }
        # The owner may always rewrite the rights, and files already there keep their own.
        & "$env:SystemRoot\System32\icacls.exe" $dir /setowner '*S-1-5-32-544' /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "icacls could not give $dir to Administrators" }
        & "$env:SystemRoot\System32\icacls.exe" (Join-Path $dir '*') /reset /T /C | Out-Null
        $acl = Get-Acl -LiteralPath $dir
        $owner = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $ok) { Fail "$dir is owned by $($acl.Owner); only SYSTEM or Administrators may own it" }
        $wide = @($acl.Access | Where-Object {
                $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $ok })
        if ($wide) { Fail "$dir is open to $(($wide | ForEach-Object { $_.IdentityReference }) -join ', '); only SYSTEM and Administrators may have access" }
    }
}

# Invoke-AsDomainAdmin <script> <minutes>: runs the script again with -Inner as
# CORP\Administrator through a one-shot scheduled task and fails unless that part passed.
function Invoke-AsDomainAdmin([string]$Script, [int]$Minutes) {
    $task = "lab-$Id"
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`" -Inner"
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $Minutes)
    Register-ScheduledTask -TaskName $task -Action $action -Settings $settings -User 'CORP\Administrator' `
        -Password (Read-Secret 'domain_admin_password') -RunLevel Highest -Force | Out-Null
    try {
        $begun = (Get-Date).AddSeconds(-1)
        Start-ScheduledTask -TaskName $task
        $deadline = $begun.AddMinutes($Minutes)
        do {
            Start-Sleep -Seconds 5
            $info = Get-ScheduledTaskInfo -TaskName $task
            $state = (Get-ScheduledTask -TaskName $task).State
            # 267009 (0x41301): the task is running; 267011 (0x41303): it has not run yet.
            $done = $state -eq 'Ready' -and $info.LastRunTime -ge $begun -and $info.LastTaskResult -notin 267009, 267011
        } until ($done -or (Get-Date) -gt $deadline)
        $inner = Join-Path $StepDir 'verdict-admin.txt'
        $said = if (Test-Path $inner) { (Get-Content $inner -Raw).Trim() } else { 'no verdict (admin.log)' }
        if (-not $done) { Stop-ScheduledTask -TaskName $task; Fail "the part as CORP\Administrator did not end within $Minutes minutes: $said" }
        if ($info.LastTaskResult -ne 0) { Fail "the part as CORP\Administrator ended with $($info.LastTaskResult): $said" }
    } finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
}

# Invoke-Step -Pass <verdict> { body }: the frame of every step: the transcript, the
# secrets, the clock, the body (as CORP\Administrator with -AsDomainAdmin), the verdict and
# the exit status. A script with -AsDomainAdmin declares param([switch]$Inner) and passes it.
function Invoke-Step {
    param(
        [Parameter(Mandatory)][string]$Pass,
        [Parameter(Mandatory)][scriptblock]$Body,
        [string[]]$Secrets = @(),
        [switch]$AsDomainAdmin,
        [switch]$Inner,
        [int]$AdminMinutes = 30,
        [switch]$NoClock
    )
    $suffix = if ($Inner) { '-admin' } else { '' }
    Start-Transcript -Path (Join-Path $StepDir "step$suffix.log") -Append | Out-Null
    try {
        if (-not $Inner) { Protect-Lab }
        foreach ($name in $Secrets + @(if ($AsDomainAdmin) { 'domain_admin_password' })) { Read-Secret $name | Out-Null }
        if (-not ($Inner -or $NoClock)) { Assert-Clock }
        if ($AsDomainAdmin -and -not $Inner) {
            Invoke-AsDomainAdmin $MyInvocation.PSCommandPath $AdminMinutes
        } else {
            & $Body | Out-Host
        }
        $line = "PASS ${Id}: $Pass"
        $code = 0
    } catch {
        $where = "$(Split-Path -Leaf $_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
        $line = "FAIL ${Id}: $($_.Exception.Message) (at $where; failure.txt has the stack)"
        $report = Join-Path $StepDir "failure$suffix.txt"
        $_ | Format-List * -Force | Out-File -Encoding utf8 $report
        Get-WinEvent -FilterHashtable @{ LogName = 'System', 'Application'; Level = 1, 2, 3; StartTime = $Started } -ErrorAction SilentlyContinue |
            Format-List TimeCreated, LogName, ProviderName, Id, Message | Out-File -Append -Encoding utf8 $report
        $code = 1
    }
    $line | Out-File -Encoding utf8 (Join-Path $StepDir "verdict$suffix.txt")
    Write-Host $line
    Stop-Transcript | Out-Null
    exit $code
}
