<#
.SYNOPSIS
  Installs or removes the scheduled task of the Tenko DHCP mirror exporter (MIG-08).

.DESCRIPTION
  Copies Tenko-DhcpMirror.ps1 to a directory only administrators can write, writes the
  configuration (controller URL, mirror id, certificate authority fingerprint), leaves the
  token for the exporter's account to store with DPAPI on its first run, and registers the
  task "Tenko DHCP mirror": every minute, under the given account, "run whether the user
  is logged on or not", no highest privileges, a new instance not started while one runs.
  Running it again changes the configuration and the token in place and registers the task
  anew. -Remove unregisters the task and deletes the stored token, the state and the log.

  The account is a member of DHCP Users and of no privileged group (plan section 2.1,
  point 4): a group managed service account (CORP\gmsa-mirror$, no password) or a user
  account with a long random password (-Credential). It gets the right to log on as a
  batch job when the task is registered.

  Run in an elevated PowerShell on the DHCP server, from the directory the two scripts
  were copied to after their digests were compared with SHA256SUMS of the release.

.PARAMETER Url
  The controller, https://<host>:<port>; the API path is fixed.

.PARAMETER MirrorId
  The mirror's id, from the mirror card.

.PARAMETER Fingerprint
  The SHA-256 fingerprint of Tenko's certificate authority, from the mirror card.

.PARAMETER Account
  The task's account, DOMAIN\name or DOMAIN\gmsa$.

.PARAMETER Credential
  The account's credential, for a user account; not for a group managed service account.

.PARAMETER Token
  The mirror's token, shown once on the mirror card. Prompted for when -PromptToken is
  given; omitted, the stored token stays as it is.

.PARAMETER PromptToken
  Ask for the token at the console instead of taking -Token.

.PARAMETER PowerShell
  The interpreter the task runs: powershell.exe (Windows PowerShell 5.1, the default) or
  the path of pwsh.exe.

.PARAMETER Remove
  Unregister the task and delete everything the install created.

.EXAMPLE
  .\Install-TenkoDhcpMirror.ps1 -Url https://tenko1.corp.example.test:8443 -MirrorId 01J... `
    -Fingerprint AB:CD:... -Account 'CORP\gmsa-mirror$' -PromptToken

.EXAMPLE
  .\Install-TenkoDhcpMirror.ps1 -Remove
#>
[CmdletBinding(DefaultParameterSetName = 'Install', SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'Install')][string]$Url,
    [Parameter(ParameterSetName = 'Install')][string]$MirrorId,
    [Parameter(ParameterSetName = 'Install')][string]$Fingerprint,
    [Parameter(ParameterSetName = 'Install')][string]$Account,
    [Parameter(ParameterSetName = 'Install')][pscredential]$Credential,
    [Parameter(ParameterSetName = 'Install')][securestring]$Token,
    [Parameter(ParameterSetName = 'Install')][switch]$PromptToken,
    [Parameter(ParameterSetName = 'Install')][string]$PowerShell = 'powershell.exe',
    [Parameter(ParameterSetName = 'Remove', Mandatory)][switch]$Remove,
    [string]$InstallDir,
    [string]$DataDir,
    [string]$TaskName = 'Tenko DHCP mirror',
    [string]$TaskPath = '\Tenko\'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ExporterName = 'Tenko-DhcpMirror.ps1'
$script:Interval = New-TimeSpan -Minutes 1
$script:TimeLimit = New-TimeSpan -Minutes 5
$script:WaitSeconds = 90

# ---------------------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------------------

function Write-Note {
    # What the operator sees; the information stream, so that the install's own output
    # (the task) stays separate.
    param([string]$Text)
    Write-Information -MessageData $Text -InformationAction Continue
}

function Test-WindowsHost {
    return ($env:OS -eq 'Windows_NT')
}

function Test-Elevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-FingerprintText {
    # 64 hexadecimal digits, with or without colons, stored as colon-separated uppercase
    # pairs, the way the mirror card shows it.
    param([string]$Fingerprint)
    $hex = ($Fingerprint -replace '[:\s\-]', '').ToUpperInvariant()
    if ($hex -notmatch '^[0-9A-F]{64}$') {
        throw 'the fingerprint must be the SHA-256 of the certificate authority as shown on the mirror card, 64 hexadecimal digits'
    }
    return (($hex -split '(?<=\G.{2})(?!$)') -join ':')
}

function Test-ControllerUrl {
    param([string]$Url)
    $uri = $null
    if (-not [uri]::TryCreate($Url.Trim(), [System.UriKind]::Absolute, [ref]$uri)) { throw "the URL $Url does not parse" }
    if ($uri.Scheme -ne 'https') { throw "the controller URL must start with https://, not $($uri.Scheme)://" }
    if ($uri.PathAndQuery -ne '/' -and $uri.PathAndQuery -ne '') { throw 'the controller URL names the host and the port only; the path is fixed' }
    if (-not [string]::IsNullOrEmpty($uri.UserInfo)) { throw 'the controller URL carries no credentials' }
    return "$($uri.Scheme)://$($uri.Authority)"
}

function Test-MirrorId {
    param([string]$MirrorId)
    if ($MirrorId -notmatch '^[A-Za-z0-9_\-]{1,64}$') { throw 'the mirror id is letters, digits, hyphens and underscores, as shown on the mirror card' }
    return $MirrorId
}

function Test-AccountName {
    # DOMAIN\name; a group managed service account ends with $ and needs no credential.
    param([string]$Account, [pscredential]$Credential)
    if ($Account -notmatch '^[^\\\s]+\\[^\\\s]+$') { throw 'the account is written DOMAIN\name (or DOMAIN\name$ for a group managed service account)' }
    $gmsa = $Account.EndsWith('$')
    if ($gmsa -and $null -ne $Credential) { throw 'a group managed service account has no password; leave -Credential out' }
    if (-not $gmsa -and $null -eq $Credential) { throw 'a user account needs -Credential (its password registers the task to run whether the user is logged on or not)' }
    if ($null -ne $Credential -and $Credential.UserName -ne $Account) { throw "the credential is for $($Credential.UserName), not for $Account" }
    return [ordered]@{ name = $Account; gmsa = $gmsa }
}

function Resolve-AccountSid {
    param([string]$Account)
    $nt = [System.Security.Principal.NTAccount]::new($Account)
    return $nt.Translate([System.Security.Principal.SecurityIdentifier])
}

# ---------------------------------------------------------------------------------------
# What the install writes
# ---------------------------------------------------------------------------------------

function Get-DefaultInstallDir { return (Join-Path (Join-Path $env:ProgramFiles 'Tenko') 'mirror') }
function Get-DefaultDataDir { return (Join-Path (Join-Path $env:ProgramData 'Tenko') 'mirror') }

function Get-MirrorConfigText {
    param([string]$Url, [string]$MirrorId, [string]$Fingerprint)
    # Three strings, no escaping needed: the values were checked to be plain.
    return "{`"url`":`"$Url`",`"mirror`":`"$MirrorId`",`"fingerprint`":`"$Fingerprint`"}"
}

function Protect-MirrorDirectory {
    # Only SYSTEM, Administrators and the account: read on the configuration, modify on
    # the state (the token, the sequence, the log). Inheritance from ProgramData is cut.
    param([string]$Path, [System.Security.Principal.SecurityIdentifier]$AccountSid, [switch]$Modify)
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', $inherit, $propagate, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($admins, 'FullControl', $inherit, $propagate, $allow))
    $rights = $(if ($Modify) { 'Modify' } else { 'ReadAndExecute' })
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($AccountSid, $rights, $inherit, $propagate, $allow))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-PendingToken {
    # The exporter's first run under the account stores it with DPAPI and deletes this.
    param([string]$StateDir, [securestring]$Token)
    $pointer = [System.IntPtr]::Zero
    try {
        $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
        $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [System.IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
    if ([string]::IsNullOrWhiteSpace($plain)) { throw 'the token is empty' }
    if ($plain -match '\s') { throw 'the token contains whitespace; paste it as shown on the mirror card' }
    $path = Join-Path $StateDir 'token.pending'
    Set-Content -LiteralPath $path -Value $plain -Encoding ASCII -NoNewline
    $plain = $null
    return $path
}

function Get-TaskArgumentText {
    param([string]$ScriptPath)
    return "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`""
}

function Register-MirrorTask {
    # Every minute, under the account, no highest privileges, one instance at a time.
    param(
        [string]$TaskName, [string]$TaskPath, [string]$PowerShell, [string]$ScriptPath,
        [hashtable]$AccountInfo, [pscredential]$Credential
    )
    $action = New-ScheduledTaskAction -Execute $PowerShell -Argument (Get-TaskArgumentText $ScriptPath)
    $start = (Get-Date).AddMinutes(1)
    $start = $start.AddSeconds(-$start.Second)
    $trigger = New-ScheduledTaskTrigger -Once -At $start -RepetitionInterval $script:Interval
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit $script:TimeLimit `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -Compatibility Win8
    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($null -ne $existing) { Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false }
    if ($AccountInfo.gmsa) {
        $principal = New-ScheduledTaskPrincipal -UserId $AccountInfo.name -LogonType Password -RunLevel Limited
        return Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Settings $settings -Principal $principal
    }
    $password = $Credential.GetNetworkCredential().Password
    try {
        return Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $trigger -Settings $settings `
            -User $AccountInfo.name -Password $password -RunLevel Limited
    } finally {
        $password = $null
    }
}

function Wait-FirstRun {
    # Waits for the first run to store the token and write its log line.
    param([string]$StateDir, [switch]$TokenPending)
    $deadline = [datetime]::UtcNow.AddSeconds($script:WaitSeconds)
    $pending = Join-Path $StateDir 'token.pending'
    while ([datetime]::UtcNow -lt $deadline) {
        $stored = -not (Test-Path -LiteralPath $pending)
        $log = Get-ChildItem -LiteralPath $StateDir -Filter 'mirror-*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc | Select-Object -Last 1
        if ((-not $TokenPending -or $stored) -and $null -ne $log) {
            return (Get-Content -LiteralPath $log.FullName | Select-Object -Last 1)
        }
        Start-Sleep -Seconds 3
    }
    return $null
}

function Get-FileDigest {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# ---------------------------------------------------------------------------------------
# Install and remove
# ---------------------------------------------------------------------------------------

function Install-Mirror {
    param(
        [string]$Url, [string]$MirrorId, [string]$Fingerprint, [string]$Account, [pscredential]$Credential,
        [securestring]$Token, [string]$PowerShell, [string]$InstallDir, [string]$DataDir, [string]$TaskName,
        [string]$TaskPath, [string]$SourceDir
    )
    $url = Test-ControllerUrl $Url
    $mirror = Test-MirrorId $MirrorId
    $fingerprint = ConvertTo-FingerprintText $Fingerprint
    $accountInfo = Test-AccountName -Account $Account -Credential $Credential
    $sid = Resolve-AccountSid $accountInfo.name
    $source = Join-Path $SourceDir $script:ExporterName
    if (-not (Test-Path -LiteralPath $source)) { throw "$script:ExporterName is not beside this script; copy both from the release" }

    # The exporter, where only administrators write (ADR 0023, I1 in reverse: the task's
    # account never runs a file it can write).
    $stateDir = Join-Path $DataDir 'state'
    foreach ($dir in $InstallDir, $DataDir, $stateDir) {
        if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir) }
    }
    $target = Join-Path $InstallDir $script:ExporterName
    Copy-Item -LiteralPath $source -Destination $target -Force
    Write-Note "installed $target (sha256 $(Get-FileDigest $target))"

    Protect-MirrorDirectory -Path $DataDir -AccountSid $sid
    Protect-MirrorDirectory -Path $stateDir -AccountSid $sid -Modify
    $configPath = Join-Path $DataDir 'config.json'
    Set-Content -LiteralPath $configPath -Value (Get-MirrorConfigText -Url $url -MirrorId $mirror -Fingerprint $fingerprint) -Encoding ASCII
    Write-Note "wrote $configPath"

    $tokenPending = $false
    if ($null -ne $Token) {
        [void](Write-PendingToken -StateDir $stateDir -Token $Token)
        $tokenPending = $true
        Write-Note "the token waits in $stateDir for the first run, which stores it with DPAPI for $($accountInfo.name)"
    } elseif (-not (Test-Path -LiteralPath (Join-Path $stateDir 'token.dpapi'))) {
        Write-Warning 'no token is stored and none was given; the task will fail until one is (run again with -PromptToken)'
    }

    # The dry run, as the installer: the counts and the losses the first push will carry.
    Write-Note 'reading the DHCP server once (nothing is pushed):'
    $json = & $PowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $target -Once -Url $url -MirrorId $mirror -Fingerprint $fingerprint 3>$null
    if ($LASTEXITCODE -ne 0) { throw "the dry run failed (exit $LASTEXITCODE); nothing was registered" }
    $snapshot = ($json -join "`n") | ConvertFrom-Json
    $reservations = 0
    foreach ($scope in $snapshot.dhcp.scopes) { $reservations += @($scope.reservations).Count }
    Write-Note "  scopes $(@($snapshot.dhcp.scopes).Count), reservations $reservations, leases $(@($snapshot.dhcp.leases).Count), loss entries $(@($snapshot.losses.entries).Count)"
    foreach ($entry in $snapshot.losses.entries) { Write-Note "  loss $($entry.code): $($entry.detail)" }

    $task = Register-MirrorTask -TaskName $TaskName -TaskPath $TaskPath -PowerShell $PowerShell -ScriptPath $target -AccountInfo $accountInfo -Credential $Credential
    Write-Note "registered the task $TaskPath$TaskName under $($accountInfo.name), every minute"
    Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
    $line = Wait-FirstRun -StateDir $stateDir -TokenPending:$tokenPending
    if ($null -eq $line) {
        Write-Warning "the first run has not finished within $script:WaitSeconds s; read the log in $stateDir and the task's history"
    } else {
        Write-Note "first run: $line"
    }
    if (Test-Path -LiteralPath (Join-Path $stateDir 'token.pending')) {
        Remove-Item -LiteralPath (Join-Path $stateDir 'token.pending') -Force
        throw 'the first run did not store the token; the plain file was deleted. Check that the account can log on as a batch job and read the DHCP server, then run again with -PromptToken'
    }
    return $task
}

function Remove-Mirror {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$InstallDir, [string]$DataDir, [string]$TaskName, [string]$TaskPath)
    if (-not $PSCmdlet.ShouldProcess("$TaskPath$TaskName, $InstallDir and $DataDir", 'remove the mirror task, its token, state and log')) { return }
    $existing = Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Stop-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
        Write-Note "unregistered the task $TaskPath$TaskName"
    } else {
        Write-Note "the task $TaskPath$TaskName was not registered"
    }
    foreach ($dir in $DataDir, $InstallDir) {
        if (Test-Path -LiteralPath $dir) {
            Remove-Item -LiteralPath $dir -Recurse -Force
            Write-Note "removed $dir (the token, the state, the log and the script)"
        }
    }
}

# Dot-sourced by the tests: define the functions and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

try {
    if (-not (Test-WindowsHost)) { throw 'this script runs on the Windows DHCP server' }
    if (-not (Test-Elevated)) { throw 'run this script in an elevated PowerShell (Run as administrator)' }
    if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Get-DefaultInstallDir }
    if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Get-DefaultDataDir }
    if ($Remove) {
        Remove-Mirror -InstallDir $InstallDir -DataDir $DataDir -TaskName $TaskName -TaskPath $TaskPath
        exit 0
    }
    foreach ($required in 'Url', 'MirrorId', 'Fingerprint', 'Account') {
        if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $required -ValueOnly))) { throw "-$required is required (or -Remove)" }
    }
    if ($PromptToken) { $Token = Read-Host -Prompt 'The mirror token (shown once on the mirror card)' -AsSecureString }
    if ($PSCmdlet.ShouldProcess("$TaskPath$TaskName under $Account", 'install the mirror task')) {
        [void](Install-Mirror -Url $Url -MirrorId $MirrorId -Fingerprint $Fingerprint -Account $Account -Credential $Credential -Token $Token `
                -PowerShell $PowerShell -InstallDir $InstallDir -DataDir $DataDir -TaskName $TaskName -TaskPath $TaskPath -SourceDir $PSScriptRoot)
    }
    exit 0
} catch {
    [Console]::Error.WriteLine("Install-TenkoDhcpMirror: $($_.Exception.Message)")
    exit 1
}
