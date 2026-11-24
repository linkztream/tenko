<#
.SYNOPSIS
  Moves an Active Directory domain's DNS zones and DHCP scopes from its Windows servers to
  Tenko DDI, phase by phase, each phase but the finish reversible (MIG-17, MIG-08; ADR 0038).

.DESCRIPTION
  Run elevated, as a member of the domain's Domain Admins, on a domain controller or a
  privileged access workstation of the domain. The script uses the logon it runs under and
  asks for no credential. It reads Windows, shows what it will change, and signs in to Tenko
  through an approval that a signed-in administrator gives in Tenko's UI by typing the code
  the script shows. It never runs text that Tenko sends: every value from Tenko is checked
  against what Windows reports and used in fixed commands.

  Phases: 0 discover (read only), 1 approval, 2 prepare (nothing served), 3 review (the
  window is started in Tenko's UI), 4 the DNS window, 5 the DHCP window, then the parallel
  period; 6 the finish, in a later sitting, which leaves the DHCP Server role installed and
  has no scripted way back. Started without a parameter it runs or resumes the next phase;
  when a run exists it offers to reverse the latest phase instead, until the finish starts.

  Exit codes: 0 the phase is done; 1 refused before any change; 2 stopped at a failed step
  (named in the state file); 3 waiting for the review or the parallel period; 4 a value from
  Tenko disagreed with Windows, and nothing further was changed; 5 reversed.

  The file must be the release's: check it with the start line of the release notes (or of
  the intake's check command) before it runs. See README.md beside it.

.PARAMETER DryRun
  Discover and print the change list. Changes nothing on Windows and contacts no Tenko.

.PARAMETER Reverse
  Undo the latest phase done, both halves. Run again to walk one more phase back. Refused
  once the finish (phase 6) has started.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Reverse
)

# First, before any command that can load a module: modules load from the system's
# directories only, named by the platform and not by an environment variable a user sets.
if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $env:PSModulePath = $PSHOME + '\Modules;' + [System.Environment]::SystemDirectory + '\WindowsPowerShell\v1.0\Modules;' +
    [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles) + '\WindowsPowerShell\Modules'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# BEGIN RELEASE DATA
# The release run fills this block (build/New-TakeoverRelease.ps1): the version of the
# release, and the exporter and its installer as base64 of their released bytes with the
# SHA-256 of their text before any signature block. A copy with an empty version is not a
# release and refuses to run.
$script:TkVersion = ''
$script:TkPayloadDigest = @{
    'Tenko-DhcpMirror.ps1'        = ''
    'Install-TenkoDhcpMirror.ps1' = ''
}
$script:TkPayloadText = @{
    'Tenko-DhcpMirror.ps1'        = ''
    'Install-TenkoDhcpMirror.ps1' = ''
}
# END RELEASE DATA

# ---------------------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------------------

# Whether this release can take over a zone that takes secure updates only (the Kerberos
# line of docs/plans/identity-plan.md). Never read from the node.
$script:TkKerberosLineComplete = $false

$script:TkExit = @{ Done = 0; Refused = 1; Failed = 2; Waiting = 3; Disagreed = 4; Reversed = 5 }
$script:TkPort = 8443
$script:TkApprovalAnswerMs = 5000          # the approval's id and nonce must come within 5 s
$script:TkHttpTimeoutMs = 30000            # one request, connect to last byte
$script:TkHttpMaxBytes = 4MB               # an answer; resource bound, not a property of the data
$script:TkJsonMaxDepth = 64
$script:TkAckWaitSec = 300                 # the check waits 5 minutes for Tenko's first answer to a client
$script:TkWindowHoldSec = 900              # the DNS window's confirmation stands for the DHCP window for 15 minutes
$script:TkPasswordChangeSec = 600          # Tenko changes its account's password within 10 minutes
$script:TkMinLeaseSec = 3600               # a scope under an hour refuses the DHCP window
$script:TkPollSec = 5
$script:TkReplicaWaitSec = 300             # a controller's replica shows an authorization change within 5 minutes
$script:TkResumeTries = 3                  # calls to turn Tenko's scopes on again before the run stops
$script:TkGpoName = 'Tenko takeover: DNS client registration off'
$script:TkMarkerKey = 'HKLM:\SOFTWARE\Tenko\Takeover'
$script:TkMirrorAccount = 'tenko-mirror'
$script:TkDnsCredentialUser = 'tenko-dhcp-dns'
$script:TkDeniedNodeNames = @('wpad', 'isatap', 'localhost')
$script:TkSecretFields = @('secret', 'token')
$script:TkRidDomainAdmins = 512
$script:TkSignatureMarker = '# SIG # Begin signature block'
$script:TkCodeContext = 'tenko-takeover-approval-v1'
$script:TkCollectContext = 'tenko-takeover-collect-v1'
$script:TkAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
$script:TkUuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
$script:TkSessionPattern = '^tnka_[A-Za-z0-9_\-]{16,123}$'
$script:TkTokenPattern = '^tnk[cb]?_[A-Za-z0-9_\-]{16,123}$'
$script:TkLabelPattern = '^(?!-)[a-z0-9-]{1,63}(?<!-)$'
# The state's root: %ProgramData% as the platform names it.
$script:TkDataRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
# On every server: the one folder the script writes to, admin-only, created with that list,
# below the Program Files folder the server itself names (Protect-TkRemoteDirectory).
$script:TkRemoteBases = @{}
# Well-known SIDs and the RIDs of a domain's own groups.
$script:TkTrustedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-10')                 # SYSTEM, Administrators, SELF
$script:TkTrustedRids = @(512, 519, 526, 527)                                      # Domain, Enterprise, Key, Enterprise Key Admins
# Groups a computer object grants rights by default, trusted for those attributes only:
# Cert Publishers its userCertificate, Terminal Server License Servers its terminal server
# attribute and license property set.
$script:TkScopedRids = @{ 517 = @('bf967a7f-0de6-11d0-a285-00aa003049e2') }
$script:TkScopedSids = @{ 'S-1-5-32-561' = @('6db69a1c-9422-11d1-aebd-0000f80367c1', '5805bc62-bdc9-4428-a5e2-856a0f4c185e') }
$script:TkLowSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-7')                            # Everyone, Authenticated Users, Anonymous
$script:TkLowRids = @(513, 515)                                                    # Domain Users, Domain Computers
$script:TkSddlAlias = @{ WD = 'S-1-1-0'; AU = 'S-1-5-11'; AN = 'S-1-5-7'; SY = 'S-1-5-18'; PS = 'S-1-5-10'; BA = 'S-1-5-32-544'; BU = 'S-1-5-32-545'; AO = 'S-1-5-32-548'; CO = 'S-1-3-0'; ED = 'S-1-5-9' }
$script:TkSddlDomainAlias = @{ DA = 512; DU = 513; DC = 515; CA = 517; EA = 519 }

# The properties the exporter reads, by name (a whole CIM object carries about 69 KB); the
# window's cross-check reads the same, and the exporter's mapping runs on this host.
$script:TkDhcpReadProperties = @{
    Scope       = 'ScopeId', 'SubnetMask', 'Name', 'Description', 'State', 'LeaseDuration', 'StartRange', 'EndRange', 'Delay', 'Type'
    OptionValue = 'OptionId', 'Value', 'VendorClass', 'UserClass', 'PolicyName'
    OptionDef   = 'OptionId', 'Name', 'Type', 'MultiValued', 'VendorClass', 'Description', 'DefaultValue'
    Class       = 'Name', 'Type', 'Data', 'AsciiData', 'Description'
    Exclusion   = 'StartRange', 'EndRange'
    Reservation = 'IPAddress', 'ClientId', 'Name', 'Description', 'Type'
    DnsSetting  = 'DynamicUpdates', 'DeleteDnsRROnLeaseExpiry', 'UpdateDnsRRForOlderClients', 'NameProtection', 'DisableDnsPtrRRUpdate', 'DnsSuffix'
    Policy      = 'Name', 'ScopeId', 'Enabled', 'ProcessingOrder', 'Condition', 'VendorClass', 'UserClass', 'MacAddress', 'ClientId', 'RelayAgent', 'CircuitId', 'RemoteId', 'SubscriberId', 'Fqdn'
    FilterList  = 'Allow', 'Deny'
    Filter      = 'MacAddress', 'List', 'Description'
    Superscope  = 'SuperscopeName', 'ScopeId'
    Failover    = 'Name', 'PartnerServer', 'Mode', 'ScopeId'
}

# The connection to Tenko for this process: the host the person typed, the pinned root and
# the delegated session's secret, which reaches no cmdlet. It is managed memory: a page file
# or a crash dump of this process may hold it, so the host must be one only its
# administrators use.
$script:TkConn = @{ Host = ''; Port = 0; Address = $null; Local = $null; Pinned = ''; Session = $null; LastTls = $null }
$script:TkTokens = @{}
$script:TkOffline = $false
$script:TkWindowWatch = $null
$script:TkMirrorPassword = $null
$script:TkPending = @()
$script:TkFresh = @{ controllers = @() }

# ---------------------------------------------------------------------------------------
# Console and text
# ---------------------------------------------------------------------------------------

function Write-TkNote {
    param([string]$Text)
    Write-Information -MessageData $Text -InformationAction Continue
}

function ConvertTo-TkSafeText {
    # Text from Tenko or a server as one line that reads as written: control and format
    # characters that hide or reorder text become spaces, at most 200 characters remain.
    param([object]$Text)
    $hidden = '\p{Cc}|[\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\uFFF9-\uFFFB]|\uDB40[\uDC01\uDC20-\uDC7F]'
    $line = [regex]::Replace([string]$Text, $hidden, ' ').Trim()
    if ($line.Length -gt 200) { $line = $line.Substring(0, 200) }
    return $line
}

function Exit-TkTakeover {
    # Stops the run with an exit state; the main block maps it.
    param([int]$Code, [string]$Message)
    $failure = [System.Exception]::new($Message)
    $failure.Data['tk.exit'] = $Code
    throw $failure
}

function Read-TkAnswer {
    param([string]$Prompt)
    return [string](Read-Host -Prompt $Prompt)
}

function Confirm-TkTyped {
    # The person types the exact text; anything else declines.
    param([string]$Prompt, [string]$Expected)
    $typed = (Read-TkAnswer $Prompt).Trim()
    return ($typed -ceq $Expected) -or ($typed.ToLowerInvariant() -eq $Expected.ToLowerInvariant())
}

# ---------------------------------------------------------------------------------------
# The host, the process and its rights
# ---------------------------------------------------------------------------------------

function Test-TkElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return ([System.Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-TkTokenSid {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return @(@($identity.User) + @($identity.Groups) | Where-Object { $null -ne $_ } | ForEach-Object { $_.Value })
}

function Test-TkDomainAdmin {
    # Domain Admins of the given domain SID, or of any domain when none is given yet.
    param([string[]]$Sids, [string]$DomainSid)
    foreach ($sid in $Sids) {
        if ($sid -match '^(S-1-5-21-\d+-\d+-\d+)-(\d+)$' -and [int]$Matches[2] -eq $script:TkRidDomainAdmins) {
            if ([string]::IsNullOrEmpty($DomainSid) -or $Matches[1] -eq $DomainSid) { return $true }
        }
    }
    return $false
}

function Get-TkPathSecurity {
    # A path's owner, the SIDs that may write, delete or change it, and whether it is a
    # reparse point, which a less privileged account could point elsewhere.
    param([string]$Path)
    $write = [System.Security.AccessControl.FileSystemRights]'Write, Modify, FullControl, CreateFiles, AppendData, ChangePermissions, TakeOwnership, Delete, DeleteSubdirectoriesAndFiles'
    $acl = Get-Acl -LiteralPath $Path
    $writers = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $write) -ne 0 } | ForEach-Object { $_.IdentityReference.Value } | Select-Object -Unique)
    $reparse = ((Get-Item -LiteralPath $Path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    return @{ Owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; Writers = $writers; Reparse = $reparse }
}

function Test-TkTrustedPath {
    # Owned by SYSTEM, Administrators or TrustedInstaller (or the given owner), written by
    # them alone (CREATOR OWNER only for what they create), and no reparse point.
    param([hashtable]$Security, [string]$AlsoOwner = '')
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($Security.Reparse -or (@($trusted) + @($AlsoOwner | Where-Object { $_ })) -notcontains $Security.Owner) { return $false }
    return @($Security.Writers | Where-Object { $trusted -notcontains $_ -and $_ -ne 'S-1-3-0' }).Count -eq 0
}

function Initialize-TkProtectedDirectory {
    # A folder owned by Administrators whose access list (SYSTEM and Administrators only, not
    # inherited) is set as it is created, so that no one else ever holds it.
    param([string]$Path)
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetAccessRuleProtection($true, $false)
    $admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $security.SetOwner($admins)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $security.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop') { [void][System.IO.Directory]::CreateDirectory($Path, $security) }
    else { [void][System.IO.FileSystemAclExtensions]::CreateDirectory($security, $Path) }
}

function Assert-TkTrustedTree {
    # Every level from below the data root to the given folder, and everything inside it, is
    # trusted; a missing level is made protected. Exit 1 otherwise, before anything is read.
    param([string]$Root, [string[]]$Levels)
    $path = $Root
    foreach ($level in $Levels) {
        $path = Join-Path $path $level
        if (-not (Test-Path -LiteralPath $path)) { Initialize-TkProtectedDirectory $path }
        if (-not (Test-TkTrustedPath (Get-TkPathSecurity $path))) { Exit-TkTakeover 1 "$path is owned or writable by an account other than SYSTEM and Administrators, or is a link: remove it and run again" }
    }
    # Where the policy "Default owner for objects created by members of the Administrators
    # group" is "Object creator", the files this elevated process writes are owned by its own
    # user: inside the leaf, that SID is accepted as an owner while this process is elevated
    # (the token holds Administrators enabled), never for a level.
    $creator = $(if (Test-TkElevated) { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } else { '' })
    foreach ($item in @(Get-ChildItem -LiteralPath $path -Recurse -Force)) {
        if (-not (Test-TkTrustedPath -Security (Get-TkPathSecurity $item.FullName) -AlsoOwner $creator)) { Exit-TkTakeover 1 "$($item.FullName) is owned or writable by an account other than SYSTEM and Administrators, or is a link: remove it and run again" }
    }
    return $path
}

function Get-TkLanguageMode {
    return [string]$ExecutionContext.SessionState.LanguageMode
}

function Assert-TkHost {
    # Refusals before anything is read: exit 1 each.
    if ($env:OS -ne 'Windows_NT') { Exit-TkTakeover 1 'the takeover runs on a domain-joined Windows machine' }
    $mode = Get-TkLanguageMode
    if ($mode -ne 'FullLanguage') {
        Exit-TkTakeover 1 "PowerShell runs this script in ${mode}: the domain's AppLocker or App Control for Business policy must allow the file, by the organization's signature or its hash (README.md, 'Where application control enforces script rules')"
    }
    # A version tells a release build from a repository copy; only the start line's digest
    # proves the file is the release's.
    if ([string]::IsNullOrEmpty($script:TkVersion)) { Exit-TkTakeover 1 'this copy is not a release build (it proves nothing about integrity either: the start line checks the digest); take Tenko-Takeover.ps1 from the release' }
    if (-not (Test-TkElevated)) { Exit-TkTakeover 1 'run the script elevated (Run as administrator)' }
    if (-not (Test-TkDomainAdmin -Sids (Get-TkTokenSid))) { Exit-TkTakeover 1 'the logon this runs under is not a member of Domain Admins' }
}

# ---------------------------------------------------------------------------------------
# JSON: the script's own writer and parser. Answers of Tenko are parsed here and nowhere
# else; a secret field becomes a SecureString inside the parser and is never passed to a
# cmdlet. Objects are ordered dictionaries, arrays object arrays.
# ---------------------------------------------------------------------------------------

function Add-TkJsonValue {
    param([System.Text.StringBuilder]$Out, [object]$Value)
    if ($null -eq $Value) { [void]$Out.Append('null'); return }
    if ($Value -is [bool]) { [void]$Out.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [securestring]) {
        $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
        try {
            [void]$Out.Append('"')
            for ($i = 0; $i -lt $Value.Length; $i++) {
                $char = [char][System.Runtime.InteropServices.Marshal]::ReadInt16($pointer, $i * 2)
                if ($char -eq '"' -or $char -eq '\' -or [int]$char -lt 0x20) { throw 'a secret holds a character JSON would escape' }
                [void]$Out.Append($char)
            }
            [void]$Out.Append('"')
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
        }
        return
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [guid] -or $Value -is [System.Net.IPAddress]) {
        [void]$Out.Append('"')
        foreach ($char in ([string]$Value).ToCharArray()) {
            switch ($char) {
                '"' { [void]$Out.Append('\"') }
                '\' { [void]$Out.Append('\\') }
                default {
                    if ([int]$char -lt 0x20 -or [int]$char -gt 0x7e) { [void]$Out.Append('\u' + ([int]$char).ToString('x4')) } else { [void]$Out.Append($char) }
                }
            }
        }
        [void]$Out.Append('"')
        return
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [decimal]) {
        [void]$Out.Append($Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)); return
    }
    if ($Value -is [double]) { [void]$Out.Append($Value.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)); return }
    if ($Value -is [System.Collections.IDictionary]) {
        [void]$Out.Append('{')
        $first = $true
        foreach ($key in $Value.Keys) {
            if (-not $first) { [void]$Out.Append(',') }
            $first = $false
            Add-TkJsonValue $Out ([string]$key)
            [void]$Out.Append(':')
            Add-TkJsonValue $Out $Value[$key]
        }
        [void]$Out.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Out.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) { [void]$Out.Append(',') }
            $first = $false
            Add-TkJsonValue $Out $item
        }
        [void]$Out.Append(']')
        return
    }
    Add-TkJsonValue $Out ([string]$Value)
}

function ConvertTo-TkJsonByte {
    # Compact JSON, ASCII only (anything else escaped), the bytes that are hashed and sent.
    param([object]$Value)
    $out = [System.Text.StringBuilder]::new()
    Add-TkJsonValue $out $Value
    return , ([System.Text.Encoding]::ASCII.GetBytes($out.ToString()))
}

function Skip-TkJsonSpace {
    param([hashtable]$Reader)
    $text = $Reader.Text
    while ($Reader.At -lt $text.Length -and ' ', "`t", "`r", "`n" -contains [string]$text[$Reader.At]) { $Reader.At++ }
}

function Read-TkJsonValue {
    param([hashtable]$Reader, [int]$Depth, [bool]$Top)
    if ($Depth -gt $script:TkJsonMaxDepth) { throw 'the JSON nests too deep' }
    Skip-TkJsonSpace $Reader
    $text = $Reader.Text
    if ($Reader.At -ge $text.Length) { throw 'the JSON ends early' }
    $char = $text[$Reader.At]
    if ($char -eq '{') {
        $Reader.At++
        $object = [System.Collections.Specialized.OrderedDictionary]::new([System.StringComparer]::Ordinal)
        Skip-TkJsonSpace $Reader
        if ($Reader.At -lt $text.Length -and $text[$Reader.At] -eq '}') { $Reader.At++; return , $object }
        while ($true) {
            Skip-TkJsonSpace $Reader
            if ($Reader.At -ge $text.Length -or $text[$Reader.At] -ne '"') { throw "a JSON key is expected at $($Reader.At)" }
            $key = Read-TkJsonString $Reader
            if ($object.Contains($key)) { throw "the JSON key $(ConvertTo-TkSafeText $key) is repeated" }
            Skip-TkJsonSpace $Reader
            if ($Reader.At -ge $text.Length -or $text[$Reader.At] -ne ':') { throw "a colon is expected at $($Reader.At)" }
            $Reader.At++
            if ($Top -and $script:TkSecretFields -contains $key) {
                Skip-TkJsonSpace $Reader
                $object[$key] = Read-TkJsonSecret $Reader
            } else {
                $object[$key] = Read-TkJsonValue -Reader $Reader -Depth ($Depth + 1) -Top $false
            }
            Skip-TkJsonSpace $Reader
            if ($Reader.At -ge $text.Length) { throw 'the JSON ends early' }
            if ($text[$Reader.At] -eq ',') { $Reader.At++; continue }
            if ($text[$Reader.At] -eq '}') { $Reader.At++; return , $object }
            throw "a comma or a brace is expected at $($Reader.At)"
        }
    }
    if ($char -eq '[') {
        $Reader.At++
        $list = [System.Collections.ArrayList]::new()
        Skip-TkJsonSpace $Reader
        if ($Reader.At -lt $text.Length -and $text[$Reader.At] -eq ']') { $Reader.At++; return , @() }
        while ($true) {
            [void]$list.Add((Read-TkJsonValue -Reader $Reader -Depth ($Depth + 1) -Top $false))
            Skip-TkJsonSpace $Reader
            if ($Reader.At -ge $text.Length) { throw 'the JSON ends early' }
            if ($text[$Reader.At] -eq ',') { $Reader.At++; continue }
            if ($text[$Reader.At] -eq ']') { $Reader.At++; return , $list.ToArray() }
            throw "a comma or a bracket is expected at $($Reader.At)"
        }
    }
    if ($char -eq '"') { return (Read-TkJsonString $Reader) }
    foreach ($word in @(@('true', $true), @('false', $false), @('null', $null))) {
        if ([string]::CompareOrdinal($text, $Reader.At, $word[0], 0, $word[0].Length) -eq 0) {
            $Reader.At += $word[0].Length
            return $word[1]
        }
    }
    $match = [regex]::Match($text.Substring($Reader.At, [math]::Min(40, $text.Length - $Reader.At)), '^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?')
    if (-not $match.Success) { throw "a JSON value is expected at $($Reader.At)" }
    $Reader.At += $match.Length
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    if ($match.Groups[2].Success -or $match.Groups[3].Success) { return [double]::Parse($match.Value, $culture) }
    $long = [long]0
    if ([long]::TryParse($match.Value, [System.Globalization.NumberStyles]::AllowLeadingSign, $culture, [ref]$long)) { return $long }
    return [decimal]::Parse($match.Value, $culture)
}

function Read-TkJsonString {
    param([hashtable]$Reader)
    $text = $Reader.Text
    $Reader.At++
    $out = [System.Text.StringBuilder]::new()
    while ($true) {
        $next = $text.IndexOfAny([char[]]@('"', '\'), $Reader.At)
        if ($next -lt 0) { throw 'a JSON string does not end' }
        $chunk = $text.Substring($Reader.At, $next - $Reader.At)
        if ($chunk -match '[\u0000-\u001f]') { throw 'a JSON string holds a control character' }
        [void]$out.Append($chunk)
        $Reader.At = $next + 1
        if ($text[$next] -eq '"') { return $out.ToString() }
        if ($Reader.At -ge $text.Length) { throw 'a JSON escape ends early' }
        $escape = $text[$Reader.At]
        $Reader.At++
        switch -CaseSensitive ([string]$escape) {
            '"' { [void]$out.Append('"') }
            '\' { [void]$out.Append('\') }
            '/' { [void]$out.Append('/') }
            'b' { [void]$out.Append([char]8) }
            'f' { [void]$out.Append([char]12) }
            'n' { [void]$out.Append([char]10) }
            'r' { [void]$out.Append([char]13) }
            't' { [void]$out.Append([char]9) }
            'u' {
                if ($Reader.At + 4 -gt $text.Length -or $text.Substring($Reader.At, 4) -notmatch '^[0-9a-fA-F]{4}$') { throw 'a JSON \u escape is malformed' }
                [void]$out.Append([char][System.Convert]::ToInt32($text.Substring($Reader.At, 4), 16))
                $Reader.At += 4
            }
            default { throw 'a JSON escape is unknown' }
        }
    }
}

function Read-TkJsonSecret {
    # A secret: a plain string of printable ASCII without escapes, straight into a SecureString.
    param([hashtable]$Reader)
    $text = $Reader.Text
    if ($Reader.At -ge $text.Length -or $text[$Reader.At] -ne '"') { throw 'a secret field is not a string' }
    $secure = [securestring]::new()
    $Reader.At++
    while ($Reader.At -lt $text.Length -and $text[$Reader.At] -ne '"') {
        $char = $text[$Reader.At]
        if ([int]$char -lt 0x21 -or [int]$char -gt 0x7e -or $char -eq '\') { throw 'a secret field holds a character outside printable ASCII' }
        $secure.AppendChar($char)
        $Reader.At++
    }
    if ($Reader.At -ge $text.Length) { throw 'a secret field does not end' }
    $Reader.At++
    $secure.MakeReadOnly()
    return $secure
}

function ConvertFrom-TkJson {
    # Parses a whole JSON text given as characters; the caller passes no string.
    param([char[]]$Chars)
    $reader = @{ Text = [string]::new($Chars); At = 0 }
    $value = Read-TkJsonValue -Reader $reader -Depth 0 -Top $true
    Skip-TkJsonSpace $reader
    if ($reader.At -ne $reader.Text.Length) { throw "text follows the JSON value at $($reader.At)" }
    return , $value
}

function Test-TkSecurePattern {
    # Whether a SecureString matches a pattern, without a string reaching a cmdlet.
    param([securestring]$Secret, [string]$Pattern)
    if ($null -eq $Secret) { return $false }
    $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
    try {
        return [regex]::IsMatch([System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer), $Pattern)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-TkField {
    # A field of a parsed object, or $null.
    param([object]$Object, [string]$Name)
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
    return $null
}

# ---------------------------------------------------------------------------------------
# Bytes, digests and encodings
# ---------------------------------------------------------------------------------------

function Get-TkSha256 {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return , $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
}

function ConvertTo-TkHex {
    param([byte[]]$Bytes)
    return [System.BitConverter]::ToString($Bytes).Replace('-', '').ToLowerInvariant()
}

function ConvertFrom-TkHex {
    param([string]$Hex)
    if ($Hex -notmatch '^([0-9a-fA-F]{2})*$') { throw 'not hexadecimal' }
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [System.Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
    return , $bytes
}

function ConvertTo-TkBase64Url {
    param([byte[]]$Bytes)
    return [System.Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-TkBase64Url {
    param([string]$Text)
    if ($Text -notmatch '^[A-Za-z0-9_\-]*$') { throw 'not base64url' }
    $padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) { 2 { $padded += '==' } 3 { $padded += '=' } 1 { throw 'not base64url' } }
    return , [System.Convert]::FromBase64String($padded)
}

function Join-TkByte {
    param([object[]]$Parts)
    $buffer = [System.IO.MemoryStream]::new()
    foreach ($part in $Parts) {
        [byte[]]$bytes = [byte[]]@()
        if ($part -is [string]) { $bytes = [System.Text.Encoding]::ASCII.GetBytes($part) } else { $bytes = [byte[]]$part }
        $buffer.Write($bytes, 0, $bytes.Length)
    }
    return , $buffer.ToArray()
}

function Get-TkTextDigest {
    # SHA-256 of a script's text before an Authenticode signature block, trailing line ends
    # removed, so that an organization's signature does not change it. Returns the digest and
    # whether what follows the block's start is signature lines only.
    param([byte[]]$Bytes)
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $at = $text.IndexOf("`r`n$($script:TkSignatureMarker)`r`n", [System.StringComparison]::Ordinal)
    $body = $text
    $clean = $true
    if ($at -ge 0) {
        $body = $text.Substring(0, $at)
        foreach ($line in $text.Substring($at + 2).Split(@("`r`n"), [System.StringSplitOptions]::RemoveEmptyEntries)) {
            if (-not $line.StartsWith('# SIG # ')) { $clean = $false }
        }
    }
    $body = $body.TrimEnd("`r", "`n")
    return @{ Digest = (ConvertTo-TkHex (Get-TkSha256 ([System.Text.Encoding]::ASCII.GetBytes($body)))); SignatureOnly = $clean }
}

# ---------------------------------------------------------------------------------------
# The payloads: the exporter and its installer. Copies beside the script (an organization's
# signed ones) are used when their text digest is the one this release carries; otherwise
# the embedded copies. Exactly the bytes that were hashed are written and used.
# ---------------------------------------------------------------------------------------

function Get-TkPayload {
    param([string]$Name, [string]$Directory, [string]$OutDir)
    $expected = $script:TkPayloadDigest[$Name]
    if ([string]::IsNullOrEmpty($expected)) { Exit-TkTakeover 1 "this copy carries no digest for $Name" }
    $beside = $(if ($Directory) { Join-Path $Directory $Name } else { '' })
    if ($beside -and (Test-Path -LiteralPath $beside)) {
        $bytes = [System.IO.File]::ReadAllBytes($beside)
        $check = Get-TkTextDigest $bytes
        if ($check.Digest -ne $expected -or -not $check.SignatureOnly) {
            Exit-TkTakeover 1 "$beside is not the release's $Name (text digest $($check.Digest), expected $expected); remove it or put the release's file there"
        }
        $source = "beside the script ($beside)"
    } else {
        $bytes = [System.Convert]::FromBase64String(($script:TkPayloadText[$Name] -replace '\s', ''))
        $check = Get-TkTextDigest $bytes
        if ($check.Digest -ne $expected) { Exit-TkTakeover 1 "the embedded $Name does not match its digest; this copy of the script is damaged" }
        $source = 'embedded'
    }
    if (-not (Test-Path -LiteralPath $OutDir)) { [void](New-Item -ItemType Directory -Path $OutDir) }
    $path = Join-Path $OutDir $Name
    [System.IO.File]::WriteAllBytes($path, $bytes)
    return @{ Name = $Name; Path = $path; Bytes = $bytes; Sha256 = (ConvertTo-TkHex (Get-TkSha256 $bytes)); Source = $source }
}

function Assert-TkPayloadFile {
    # A payload file is checked again right before it is used: a copy written in an earlier
    # sitting is never run on trust.
    param([string]$Name, [string]$Path)
    $check = Get-TkTextDigest ([System.IO.File]::ReadAllBytes($Path))
    if ($check.Digest -ne $script:TkPayloadDigest[$Name] -or -not $check.SignatureOnly) { Exit-TkTakeover 1 "$Path is not the release's $Name any more; nothing was run from it" }
}

# ---------------------------------------------------------------------------------------
# TLS: the root the script binds is the self-signed end of a chain built from the leaf by
# signature verification over the certificates the server presented, with the host name
# matched. A partial chain is refused; the last certificate listed is never taken as the
# root. Plain PowerShell: the check runs as a script block while AuthenticateAsClient runs.
# ---------------------------------------------------------------------------------------

function Test-TkServerChain {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Leaf,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Presented,
        [System.Net.Security.SslPolicyErrors]$Errors,
        [string]$Pinned
    )
    $result = @{ Ok = $false; Root = $null; RootSha256 = ''; Failure = ''; MachineTrusted = $false }
    if ($null -eq $Leaf) { $result.Failure = 'the server presented no certificate'; return $result }
    if (($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0) {
        $result.Failure = 'the server certificate does not match the host name'; return $result
    }
    $result.MachineTrusted = (($Errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -eq 0)
    if (@(@($Presented) | Where-Object { $null -ne $_ -and $_.Thumbprint -ne $Leaf.Thumbprint }).Count -eq 0) {
        $result.Failure = 'the node presented its leaf certificate alone, without the root the approval binds: a Tenko node of the release this script comes from presents its root in the handshake, an older node does not; update the node'
        return $result
    }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
        # No issuer is fetched from a URL the leaf names (PowerShell 7; 5.1 has no such switch).
        if ($null -ne $chain.ChainPolicy.PSObject.Properties['DisableCertificateDownloads']) { $chain.ChainPolicy.DisableCertificateDownloads = $true }
        foreach ($certificate in @($Presented)) { if ($null -ne $certificate) { [void]$chain.ChainPolicy.ExtraStore.Add($certificate) } }
        [void]$chain.Build($Leaf)
        foreach ($status in $chain.ChainStatus) {
            if ($status.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError -and
                $status.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::UntrustedRoot) {
                $result.Failure = "the certificate chain does not verify: $($status.Status)"; return $result
            }
        }
        $count = $chain.ChainElements.Count
        if ($count -lt 2) { $result.Failure = 'the chain ends in the leaf itself, not in a certificate authority'; return $result }
        # Only presented certificates: the platform's chain engine may complete a chain from
        # its stores or its cache.
        $sent = @(@($Presented) | Where-Object { $null -ne $_ } | ForEach-Object { $_.Thumbprint })
        for ($i = 1; $i -lt $count; $i++) {
            if ($sent -notcontains $chain.ChainElements[$i].Certificate.Thumbprint) {
                $result.Failure = 'the chain is partial: the server did not present every certificate up to its root'; return $result
            }
        }
        $root = $chain.ChainElements[$count - 1].Certificate
        if ($root.SubjectName.RawData.Length -ne $root.IssuerName.RawData.Length -or
            (ConvertTo-TkHex $root.SubjectName.RawData) -ne (ConvertTo-TkHex $root.IssuerName.RawData)) {
            $result.Failure = 'the chain is partial: it does not end in a self-signed certificate'; return $result
        }
        $result.Root = $root
        $result.RootSha256 = ConvertTo-TkHex (Get-TkSha256 $root.RawData)
        if ($Pinned -and $result.RootSha256 -ne $Pinned) {
            $result.Failure = "the chain ends in the root $($result.RootSha256), not the pinned one"; return $result
        }
        $result.Ok = $true
        return $result
    } finally {
        $chain.Dispose()
    }
}

function Get-TkTlsCallback {
    # The validation callback: records the result for the caller and answers it.
    return [System.Net.Security.RemoteCertificateValidationCallback] {
        param($source, $certificate, $chain, $errors)
        $null = $source
        $leaf = $null
        if ($null -ne $certificate) { $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate) }
        # What the server sent beside the leaf. PowerShell 7 on Windows leaves ExtraStore empty
        # and hands the presented certificates over as the chain's elements only, which may
        # also hold a certificate authority of this machine's stores: the pin and the code
        # bind whichever root the chain ends in, so another root than the node's fails there.
        # Windows PowerShell 5.1 hands over what Schannel received; an empty list there is
        # refused, never completed from the platform's chain.
        $presented = @()
        if ($null -ne $chain) {
            $presented = @($chain.ChainPolicy.ExtraStore)
            if ($presented.Count -eq 0 -and $PSVersionTable.PSEdition -eq 'Core') { $presented = @($chain.ChainElements | ForEach-Object { $_.Certificate }) }
        }
        if ($presented.Count -eq 0 -and $PSVersionTable.PSEdition -ne 'Core' -and $null -ne $certificate) {
            $script:TkConn.LastTls = @{ Ok = $false; Failure = 'Windows PowerShell handed the check no certificate the server presented (an empty extra store); the script takes no chain the platform completed on its own'; RootSha256 = ''; MachineTrusted = $false }
            return $false
        }
        if (($errors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable) -ne 0) {
            $script:TkConn.LastTls = @{ Ok = $false; Failure = 'the server presented no certificate'; RootSha256 = ''; MachineTrusted = $false }
            return $false
        }
        $script:TkConn.LastTls = Test-TkServerChain -Leaf $leaf -Presented $presented -Errors $errors -Pinned $script:TkConn.Pinned
        return [bool]$script:TkConn.LastTls.Ok
    }
}

# ---------------------------------------------------------------------------------------
# HTTP: one request per connection, HTTP/1.0, JSON only, no redirect, the answer's size and
# time capped. The delegated session's secret goes from its SecureString into the socket.
# ---------------------------------------------------------------------------------------

function Invoke-TkHttp {
    param(
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')][string]$Method,
        [string]$Path,
        [byte[]]$Body,
        [switch]$Pem,
        [switch]$NoSession
    )
    if ($Path -notmatch '^/api/v1/[A-Za-z0-9/_\-.%?=&]*$') { throw "the path $Path is not one the script sends" }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $client = $null
    $ssl = $null
    try {
        if ($null -ne $script:TkConn.Local) {
            $client = [System.Net.Sockets.TcpClient]::new([System.Net.IPEndPoint]::new($script:TkConn.Local, 0))
        } else {
            $family = $(if ($null -ne $script:TkConn.Address) { $script:TkConn.Address.AddressFamily } else { [System.Net.Sockets.AddressFamily]::InterNetwork })
            $client = [System.Net.Sockets.TcpClient]::new($family)
        }
        $target = $(if ($null -ne $script:TkConn.Address) { $script:TkConn.Address } else { $script:TkConn.Host })
        $connect = $client.ConnectAsync($target, $script:TkConn.Port)
        if (-not $connect.Wait($script:TkHttpTimeoutMs)) { throw "Tenko at $($script:TkConn.Host):$($script:TkConn.Port) did not accept a connection within $($script:TkHttpTimeoutMs / 1000) s" }
        if ($null -eq $script:TkConn.Local) { $script:TkConn.Local = ([System.Net.IPEndPoint]$client.Client.LocalEndPoint).Address }
        $network = $client.GetStream()
        $network.ReadTimeout = $script:TkHttpTimeoutMs
        $network.WriteTimeout = $script:TkHttpTimeoutMs
        $script:TkConn.LastTls = $null
        try {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                # The platform's own chain build fetches no issuer from a URL the leaf names.
                $ssl = [System.Net.Security.SslStream]::new($network, $false)
                $options = [System.Net.Security.SslClientAuthenticationOptions]::new()
                $options.TargetHost = $script:TkConn.Host
                $options.RemoteCertificateValidationCallback = Get-TkTlsCallback
                $options.CertificateChainPolicy = [System.Security.Cryptography.X509Certificates.X509ChainPolicy]::new()
                $options.CertificateChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                $options.CertificateChainPolicy.DisableCertificateDownloads = $true
                $ssl.AuthenticateAsClient($options)
            } else {
                $ssl = [System.Net.Security.SslStream]::new($network, $false, (Get-TkTlsCallback))
                $ssl.AuthenticateAsClient($script:TkConn.Host)
            }
        } catch {
            $why = $(if ($null -ne $script:TkConn.LastTls -and $script:TkConn.LastTls.Failure) { $script:TkConn.LastTls.Failure } else { $_.Exception.Message })
            throw "TLS to $($script:TkConn.Host) failed: $why"
        }

        $head = [System.Text.StringBuilder]::new()
        [void]$head.Append("$Method $Path HTTP/1.0`r`nHost: $($script:TkConn.Host):$($script:TkConn.Port)`r`n")
        [void]$head.Append("User-Agent: Tenko-Takeover.ps1/$($script:TkVersion)`r`nAccept: application/json`r`nConnection: close`r`n")
        if ($null -ne $Body) { [void]$head.Append("Content-Type: application/json`r`nContent-Length: $($Body.Length)`r`n") }
        $buffer = [System.IO.MemoryStream]::new()
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($head.ToString())
        $buffer.Write($bytes, 0, $bytes.Length)
        if (-not $NoSession -and $null -ne $script:TkConn.Session) {
            $bytes = [System.Text.Encoding]::ASCII.GetBytes('Authorization: Bearer ')
            $buffer.Write($bytes, 0, $bytes.Length)
            $secret = $script:TkConn.Session
            $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
            try {
                for ($i = 0; $i -lt $secret.Length; $i++) { $buffer.WriteByte([byte][System.Runtime.InteropServices.Marshal]::ReadInt16($pointer, $i * 2)) }
            } finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            }
            $buffer.WriteByte(13); $buffer.WriteByte(10)
        }
        $buffer.WriteByte(13); $buffer.WriteByte(10)
        if ($null -ne $Body) { $buffer.Write($Body, 0, $Body.Length) }
        $request = $buffer.ToArray()
        [System.Array]::Clear($buffer.GetBuffer(), 0, [int]$buffer.Length)
        $ssl.Write($request, 0, $request.Length)
        [System.Array]::Clear($request, 0, $request.Length)
        $ssl.Flush()

        $answer = [System.IO.MemoryStream]::new()
        $chunk = [byte[]]::new(16384)
        while ($true) {
            if ($watch.ElapsedMilliseconds -gt $script:TkHttpTimeoutMs) { throw "Tenko's answer took longer than $($script:TkHttpTimeoutMs / 1000) s" }
            $read = $ssl.Read($chunk, 0, $chunk.Length)
            if ($read -le 0) { break }
            $answer.Write($chunk, 0, $read)
            if ($answer.Length -gt $script:TkHttpMaxBytes + 65536) { throw "Tenko's answer is larger than $($script:TkHttpMaxBytes / 1MB) MiB" }
        }
        return (ConvertFrom-TkHttpAnswer -Bytes $answer.ToArray() -Pem:$Pem)
    } catch [System.IO.IOException] {
        throw "the connection to Tenko failed: $($_.Exception.Message)"
    } finally {
        if ($null -ne $ssl) { $ssl.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
    }
}

function ConvertFrom-TkHttpAnswer {
    # The status, the parsed JSON body (or the PEM text), and a problem's code and detail.
    param([byte[]]$Bytes, [switch]$Pem)
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
    $end = $text.IndexOf("`r`n`r`n", [System.StringComparison]::Ordinal)
    if ($end -lt 0) { throw 'Tenko answered without a complete HTTP head' }
    $lines = $text.Substring(0, $end).Split(@("`r`n"), [System.StringSplitOptions]::None)
    if ($lines[0] -notmatch '^HTTP/1\.[01] ([1-5][0-9]{2})( |$)') { throw 'Tenko answered something that is not HTTP' }
    $status = [int]$Matches[1]
    $headers = @{}
    foreach ($line in $lines | Select-Object -Skip 1) {
        $colon = $line.IndexOf(':')
        if ($colon -le 0) { throw 'Tenko answered a malformed header' }
        $headers[$line.Substring(0, $colon).Trim().ToLowerInvariant()] = $line.Substring($colon + 1).Trim()
    }
    if ($status -ge 300 -and $status -lt 400) { throw "Tenko answered a redirect ($status); the script follows none" }
    if ($headers.ContainsKey('transfer-encoding')) { throw 'Tenko answered with a transfer encoding the script does not read' }
    $bodyStart = $end + 4
    $length = $Bytes.Length - $bodyStart
    if ($length -gt $script:TkHttpMaxBytes) { throw "Tenko's answer is larger than $($script:TkHttpMaxBytes / 1MB) MiB" }
    if ($headers.ContainsKey('content-length') -and [string]$length -ne $headers['content-length']) { throw "Tenko's answer is truncated" }
    $result = @{ Status = $status; Json = $null; Text = ''; Code = ''; Detail = '' }
    if ($length -eq 0) { return $result }
    $type = [string]$headers['content-type']
    $body = [byte[]]::new($length)
    [System.Array]::Copy($Bytes, $bodyStart, $body, 0, $length)
    if ($Pem -and $status -eq 200) {
        if ($type -notmatch '^application/x-pem-file(;|$)') { throw "Tenko answered $(ConvertTo-TkSafeText $type), not a PEM file" }
        $result.Text = [System.Text.Encoding]::ASCII.GetString($body)
        return $result
    }
    if ($type -notmatch '^application/(problem\+)?json(;|$)') { throw "Tenko answered $(ConvertTo-TkSafeText $type), not JSON" }
    $chars = [System.Text.UTF8Encoding]::new($false, $true).GetChars($body)
    try {
        $result.Json = ConvertFrom-TkJson -Chars $chars
    } finally {
        [System.Array]::Clear($chars, 0, $chars.Length)
        [System.Array]::Clear($body, 0, $body.Length)
    }
    if ($status -ge 400) {
        $result.Code = ConvertTo-TkSafeText (Get-TkField $result.Json 'code')
        $result.Detail = ConvertTo-TkSafeText (Get-TkField $result.Json 'detail')
    }
    return $result
}

function Invoke-Tenko {
    # One call to Tenko's API that must succeed; a refusal stops the step with its code.
    param([string]$Method, [string]$Path, [object]$Body, [int[]]$Expect = @(200, 201, 202, 204))
    if ($script:TkOffline) {
        # The Windows half of a reverse without Tenko: Tenko's half is recorded as pending.
        $script:TkPending += "$Method $Path"
        return $null
    }
    return , (Invoke-TkCall -Method $Method -Path $Path -Body $Body -Expect $Expect)
}

function Invoke-TkCall {
    param([string]$Method, [string]$Path, [object]$Body, [int[]]$Expect)
    [byte[]]$bytes = $null
    if ($null -ne $Body) { $bytes = ConvertTo-TkJsonByte $Body }
    $answer = Invoke-TkHttp -Method $Method -Path "/api/v1$Path" -Body $bytes
    if ($Expect -notcontains $answer.Status) {
        $hint = $(if ($answer.Code -eq 'auth.delegation.refused') { " (this node's release does not open $Method $Path to a takeover's session: the takeover cannot go on with it)" } else { '' })
        throw "Tenko refused $Method $Path with $($answer.Status) $($answer.Code): $($answer.Detail)$hint"
    }
    return , $answer.Json
}

# ---------------------------------------------------------------------------------------
# The approval (ADR 0038 decision 4)
# ---------------------------------------------------------------------------------------

function Get-TkRunKey {
    return [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
}

function Get-TkPublicPoint {
    param([System.Security.Cryptography.ECDsa]$Key)
    $q = $Key.ExportParameters($false).Q
    return , (Join-TkByte @(([byte[]]@(4)), $q.X, $q.Y))
}

function ConvertTo-TkUuidByte {
    param([string]$Id)
    if ($Id -cnotmatch $script:TkUuidPattern) { throw 'not an approval id' }
    return , (ConvertFrom-TkHex ($Id -replace '-', ''))
}

function Get-TkApprovalPreimage {
    # context || 0x00 || len(domain) || domain || root_sha256 || request_sha256 || key || id
    param([string]$Domain, [byte[]]$RootSha256, [byte[]]$RequestSha256, [byte[]]$Key, [string]$Id)
    $domainBytes = [System.Text.Encoding]::ASCII.GetBytes($Domain.ToLowerInvariant().TrimEnd('.'))
    return , (Join-TkByte @($script:TkCodeContext, ([byte[]]@(0, $domainBytes.Length)), $domainBytes, $RootSha256, $RequestSha256, $Key, (ConvertTo-TkUuidByte $Id)))
}

function Get-TkApprovalCode {
    param([string]$Domain, [byte[]]$RootSha256, [byte[]]$RequestSha256, [byte[]]$Key, [string]$Id)
    $digest = Get-TkSha256 (Get-TkApprovalPreimage -Domain $Domain -RootSha256 $RootSha256 -RequestSha256 $RequestSha256 -Key $Key -Id $Id)
    $code = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt 16; $i++) {
        $value = 0
        for ($b = 0; $b -lt 5; $b++) {
            $bit = $i * 5 + $b
            $value = ($value -shl 1) -bor (($digest[$bit -shr 3] -shr (7 - ($bit -band 7))) -band 1)
        }
        if ($i -gt 0 -and $i % 4 -eq 0) { [void]$code.Append('-') }
        [void]$code.Append($script:TkAlphabet[$value])
    }
    return $code.ToString()
}

function Get-TkCollectMessage {
    param([string]$Id, [byte[]]$Nonce)
    return , (Join-TkByte @($script:TkCollectContext, ([byte[]]@(0)), (ConvertTo-TkUuidByte $Id), $Nonce))
}

function ConvertTo-TkApprovalBody {
    # The request as sent: purpose, plan, key, client. These bytes are hashed for the code.
    param([System.Collections.IDictionary]$Plan, [byte[]]$Key, [string]$Machine, [string]$User)
    return ConvertTo-TkJsonByte ([ordered]@{
            purpose = 'windows-takeover'
            plan    = $Plan
            key     = (ConvertTo-TkBase64Url $Key)
            client  = [ordered]@{ machine = $Machine; user = $User; version = $script:TkVersion }
        })
}

function Request-TkApproval {
    # Sends the request, computes the code over the root the TLS check built, shows it and
    # collects the delegated session once the person approved. Returns the run's id.
    param([System.Collections.IDictionary]$Plan, [string]$Domain)
    $key = Get-TkRunKey
    try {
        $point = Get-TkPublicPoint $key
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $body = ConvertTo-TkApprovalBody -Plan $Plan -Key $point -Machine ([System.Environment]::MachineName) -User $user
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $answer = Invoke-TkHttp -Method POST -Path '/api/v1/auth/approvals' -Body $body -NoSession
        $elapsed = $watch.ElapsedMilliseconds
        $tls = $script:TkConn.LastTls
        if ($answer.Status -ne 201) {
            $hint = $(if ($answer.Code -eq 'tls.no_internal_ca') { ' (Tenko does not serve its own certificate authority on this port: the approval needs Tenko''s own TLS, not a proxy)' } else { '' })
            Exit-TkTakeover 1 "Tenko refused the approval request: $($answer.Status) $($answer.Code) $($answer.Detail)$hint"
        }
        if ($elapsed -gt $script:TkApprovalAnswerMs) { Exit-TkTakeover 4 "Tenko's answer to the approval request came after $elapsed ms, more than $($script:TkApprovalAnswerMs) ms; start again" }
        $id = [string](Get-TkField $answer.Json 'id')
        $nonceText = [string](Get-TkField $answer.Json 'nonce')
        if ($id -cnotmatch $script:TkUuidPattern -or $nonceText -notmatch '^[A-Za-z0-9_\-]{43}$') { Exit-TkTakeover 4 'Tenko answered an approval id or nonce that is not of the exact form' }
        $nonce = ConvertFrom-TkBase64Url $nonceText
        # Pinned from here: every collect, and every request after it, must reach the root
        # the code binds.
        $script:TkConn.Pinned = $tls.RootSha256
        if ($tls.MachineTrusted) {
            Write-Warning "the TLS root of $($script:TkConn.Host) is trusted by this machine's own store: if a proxy ends TLS in front of Tenko, the code cannot match and the run cannot start"
        }
        $code = Get-TkApprovalCode -Domain $Domain -RootSha256 (ConvertFrom-TkHex $tls.RootSha256) -RequestSha256 (Get-TkSha256 $body) -Key $point -Id $id
        Write-TkNote ''
        Write-TkNote "Open https://$($script:TkConn.Host):$($script:TkConn.Port)/approve, sign in, and type this code:"
        Write-TkNote ''
        Write-TkNote "    $code"
        Write-TkNote ''
        Write-TkNote 'The page shows the plan this script sent; approve it only if it is what you read here.'
        $message = Get-TkCollectMessage -Id $id -Nonce $nonce
        $signature = ConvertTo-TkBase64Url ($key.SignData($message, [System.Security.Cryptography.HashAlgorithmName]::SHA256))
        $collect = ConvertTo-TkJsonByte ([ordered]@{ signature = $signature })
        while ($true) {
            try {
                $answer = Invoke-TkHttp -Method POST -Path "/api/v1/auth/approvals/$id/collect" -Body $collect -NoSession
            } catch {
                if ($null -ne $script:TkConn.LastTls -and -not $script:TkConn.LastTls.Ok) { Exit-TkTakeover 4 "the collect reached another TLS root than the approval request ($($script:TkConn.LastTls.Failure)); nothing was collected" }
                throw
            }
            if ($answer.Status -eq 200) { break }
            if ($answer.Status -eq 409 -and $answer.Code -eq 'auth.approval.pending') { Start-Sleep -Seconds $script:TkPollSec; continue }
            # An approval denied, withdrawn, or whose approver can no longer give it, is never
            # collected again: a new approval is the way on.
            $why = switch ($answer.Code) {
                { 'auth.approval.denied', 'auth.unauthenticated' -contains $_ } { 'the approval was denied or withdrawn in Tenko''s UI, or the administrator who gave it signed out everywhere, was disabled or lost the administrator role' }
                'auth.approval.expired' { 'the approval expired before it was collected' }
                default { "Tenko refused to hand over the approval ($($answer.Status) $($answer.Code): $($answer.Detail))" }
            }
            Write-TkNote "$why."
            if ('y', 'yes' -contains (Read-TkAnswer 'Ask for a new approval, with a new code? [y/N]').Trim().ToLowerInvariant()) { return (Request-TkApproval -Plan $Plan -Domain $Domain) }
            Exit-TkTakeover 1 "$why; nothing was collected: run the script again for a new approval"
        }
        $secret = Get-TkField $answer.Json 'secret'
        $run = [string](Get-TkField $answer.Json 'delegation')
        if (-not ($secret -is [securestring]) -or -not (Test-TkSecurePattern $secret $script:TkSessionPattern) -or $run -cnotmatch $script:TkUuidPattern) {
            Exit-TkTakeover 4 'Tenko answered the collect with a session that is not of the exact form'
        }
        $script:TkConn.Session = $secret
        return $run
    } finally {
        $key.Dispose()
    }
}

function Close-TkSession {
    if ($null -eq $script:TkConn.Session) { return }
    try { [void](Invoke-TkHttp -Method POST -Path '/api/v1/auth/logout') } catch { Write-Warning "the session could not be ended: $($_.Exception.Message); it lapses after 15 minutes" }
    $script:TkConn.Session.Dispose()
    $script:TkConn.Session = $null
}

function Get-TkNrptRule {
    # This machine's effective Name Resolution Policy Table.
    return @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
}

function Test-TkNamespaceMatch {
    # A rule's namespace: '.suffix' covers the suffix and every name below it, '.' every name,
    # anything else that one name.
    # Both compared in their ASCII form, without a trailing dot.
    param([string]$Namespace, [string]$Name)
    $space = $Namespace.Trim()
    if ($space -eq '.' -or $space -eq '*') { return $true }
    $suffix = $space.StartsWith('.')
    $idn = [System.Globalization.IdnMapping]::new()
    $space = $idn.GetAscii($space.Trim('.')).ToLowerInvariant()
    $target = $idn.GetAscii($Name.TrimEnd('.')).ToLowerInvariant()
    if ($suffix) { return ($target -eq $space -or $target.EndsWith(".$space")) }
    return ($target -eq $space)
}

function Assert-TkDirectAnswer {
    # A query sent to a named server is answered by that server only where the effective Name
    # Resolution Policy Table lists no name server for the queried name; no query form goes
    # around such an entry. Decided for the exact names the script queries, from every
    # effective entry that covers them: a more specific entry without servers inherits those
    # of a covering one, so any covering entry with servers redirects. Local rules and Group
    # Policy rules alike; an entry with DNSSEC settings only and no covering entry with servers
    # changes no server; a policy that cannot be read stops the run as well.
    # Before any change the run is refused (exit 1); inside the DNS window (-InWindow), after the
    # flip, the step stops (exit 2) and the run resumes once the rule is gone.
    param([string]$Domain, [switch]$InWindow)
    $next = $(if ($InWindow) { 'remove the rule on this machine and run the script again to resume, or run it with -Reverse' } else { 'run it from a machine without such a rule' })
    $code = $(if ($InWindow) { 2 } else { 1 })
    $rules = @()
    try { $rules = @(Get-TkNrptRule) } catch { Exit-TkTakeover $code "this machine's Name Resolution Policy Table could not be read ($(ConvertTo-TkSafeText $_.Exception.Message)), so the script cannot check which server answers the names of ${Domain}: $(if ($InWindow) { 'make it readable on this machine and run the script again to resume, or run it with -Reverse' } else { 'run it from a machine whose policy it can read' })" }
    # The one name the script asks a named server for.
    $names = @("_ldap._tcp.dc._msdcs.$Domain")
    foreach ($rule in $rules) {
        $servers = @(@($rule.NameServers) + @($rule.DirectAccessDnsServers) | Where-Object { $_ -and [string]$_ })
        if ($servers.Count -eq 0) { continue }
        foreach ($space in @($rule.Namespace | Where-Object { $_ })) {
            $covers = $false
            try { $covers = @($names | Where-Object { Test-TkNamespaceMatch -Namespace ([string]$space) -Name $_ }).Count -gt 0 }
            catch { Exit-TkTakeover $code "the Name Resolution Policy Table rule for $(ConvertTo-TkSafeText $space) names $(ConvertTo-TkSafeText ($servers -join ', ')) and its name cannot be read as a DNS name ($(ConvertTo-TkSafeText $_.Exception.Message)), so the script cannot check which server answers the names of ${Domain}: $next" }
            if ($covers) {
                Exit-TkTakeover $code "this machine sends the names of $Domain to fixed servers by policy (the Name Resolution Policy Table rule for $(ConvertTo-TkSafeText $space) names $(ConvertTo-TkSafeText ($servers -join ', '))), so the script cannot check which server answers them: $next"
            }
        }
    }
}

function Get-TkHostAddress {
    param([string]$Name)
    return @([System.Net.Dns]::GetHostAddresses($Name))
}

function Connect-TkNode {
    # The node's address: a host name or an address, port 8443 unless host:port. Checks the
    # version and, once pinned, that the CA root the node serves is the pinned one.
    param([string]$Address)
    $text = $Address.Trim()
    $port = $script:TkPort
    if ($text -match '^\[([0-9A-Fa-f:]+)\](:(\d{1,5}))?$') {
        $hostName = $Matches[1]; if ($Matches[3]) { $port = [int]$Matches[3] }
    } elseif ($text -match '^([A-Za-z0-9.\-]+)(:(\d{1,5}))?$') {
        $hostName = $Matches[1]; if ($Matches[3]) { $port = [int]$Matches[3] }
    } else {
        Exit-TkTakeover 1 "$(ConvertTo-TkSafeText $Address) is not a host name, an address or host:port"
    }
    if ($port -lt 1 -or $port -gt 65535) { Exit-TkTakeover 1 "the port $port is outside 1 to 65535" }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($hostName, [ref]$ip)) { $candidates = @($ip) }
    else {
        $all = @(Get-TkHostAddress $hostName)
        if ($all.Count -eq 0) { Exit-TkTakeover 1 "$hostName does not resolve" }
        # IPv4 first: Tenko's approval bounds count an IPv6 /64 as one source, so a neighbor
        # on the segment could use them up for a script that came over IPv6.
        $candidates = @(@($all | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }) + @($all | Where-Object { $_.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork }))
    }
    $script:TkConn.Host = $hostName
    $script:TkConn.Port = $port
    $health = $null
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        $script:TkConn.Address = $candidates[$i]
        $script:TkConn.Local = $null
        try {
            $health = Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession
            break
        } catch {
            # Only an address that takes no connection is passed over; any other failure stops.
            if ($i -eq $candidates.Count - 1 -or $_.Exception.Message -notmatch 'did not accept a connection|the connection to Tenko failed') { throw }
            Write-Warning "Tenko at $($candidates[$i]) takes no connection ($($_.Exception.Message)); trying $($candidates[$i + 1])"
        }
    }
    $version = [string](Get-TkField $health.Json 'version')
    if ($health.Status -ne 200 -or $version -ne $script:TkVersion) {
        Exit-TkTakeover 1 "Tenko at $hostName runs version $(ConvertTo-TkSafeText $version); this script is version $($script:TkVersion): take the script of the node's own release"
    }
}

function Test-TkServedRoot {
    # GET /system/ca-root names the pinned root.
    $answer = Invoke-TkHttp -Method GET -Path '/api/v1/system/ca-root' -Pem
    if ($answer.Status -ne 200) { Exit-TkTakeover 4 "Tenko does not serve its CA root ($($answer.Status) $($answer.Code))" }
    $base64 = ($answer.Text -replace '-----(BEGIN|END) CERTIFICATE-----', '' -replace '\s', '')
    $der = [System.Convert]::FromBase64String($base64)
    if ((ConvertTo-TkHex (Get-TkSha256 $der)) -ne $script:TkConn.Pinned) { Exit-TkTakeover 4 'the CA root Tenko serves is not the root its TLS chain ends in' }
}

# ---------------------------------------------------------------------------------------
# Windows: every server is reached by its own Kerberos session, by its FQDN as Active
# Directory reports it, never by an address, never through a second hop. The blocks below
# run on the servers in Constrained Language: cmdlets and core types only, values as
# arguments, the cmdlets' output selected by property name.
# ---------------------------------------------------------------------------------------

$script:TkKnownHosts = @()

function Assert-TkHostName {
    param([string]$Name)
    # The last label holds a letter, so that no address passes for a name.
    if ($Name -notmatch '^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9-]{1,63}$') { throw "$Name is not a fully qualified host name" }
    if ($script:TkKnownHosts -notcontains $Name.ToLowerInvariant()) { throw "$Name is not a server this run discovered in Active Directory" }
}

function Invoke-TkRemote {
    # The one way the script acts on a server: a block of this file, its values as arguments.
    param([string]$Server, [string]$Name, [object[]]$Arguments = @())
    Assert-TkHostName $Server
    $block = $script:TkRemote[$Name]
    if ($null -eq $block) { throw "no remote block $Name" }
    return @(Invoke-Command -ComputerName $Server -Authentication Kerberos -ScriptBlock $block -ArgumentList $Arguments -ErrorAction Stop)
}

function Copy-TkToServer {
    # Files to a server through its own session; the digest is checked there.
    param([string]$Server, [hashtable[]]$Files, [string]$Directory)
    Assert-TkHostName $Server
    $session = New-PSSession -ComputerName $Server -Authentication Kerberos -ErrorAction Stop
    try {
        foreach ($file in $Files) {
            Copy-Item -LiteralPath $file.Path -Destination (Join-Path $Directory $file.Name) -ToSession $session -Force -ErrorAction Stop
            $remote = Invoke-Command -Session $session -ScriptBlock $script:TkRemote.FileDigest -ArgumentList (Join-Path $Directory $file.Name) -ErrorAction Stop
            if ($remote -ne $file.Sha256) { throw "$($file.Name) on $Server has the digest $remote after the copy, not $($file.Sha256)" }
        }
    } finally {
        Remove-PSSession -Session $session
    }
}

function Copy-TkFromServer {
    param([string]$Server, [string]$RemotePath, [string]$LocalPath)
    Assert-TkHostName $Server
    $session = New-PSSession -ComputerName $Server -Authentication Kerberos -ErrorAction Stop
    try { Copy-Item -LiteralPath $RemotePath -Destination $LocalPath -FromSession $session -Force -ErrorAction Stop } finally { Remove-PSSession -Session $session }
}

function Protect-TkRemoteDirectory {
    # The script's folder on a server, below the Program Files folder that server names in
    # its own registry (checked to be <drive>:\Program Files); returns the folder's path.
    param([string]$Server, [string[]]$Below)
    if (-not $script:TkRemoteBases.ContainsKey($Server)) {
        $programs = [string](Invoke-TkRemote -Server $Server -Name ReadProgramFiles | Select-Object -Last 1)
        if ($programs -notmatch '^[A-Za-z]:\\Program Files$') { throw "$Server names $(ConvertTo-TkSafeText $programs) as its Program Files folder, not <drive>:\Program Files" }
        $script:TkRemoteBases[$Server] = $programs + '\Tenko'
    }
    $base = $script:TkRemoteBases[$Server]
    [void](Invoke-TkRemote -Server $Server -Name ProtectDirectory -Arguments @($base, [string[]]$Below))
    return (@($base) + $Below) -join '\'
}

$script:TkRemote = @{
    ReadProgramFiles      = {
        (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion').ProgramFilesDir
    }
    ProtectDirectory      = {
        # The script's folder on a server, below Program Files: every level owned by SYSTEM or
        # Administrators, written by SYSTEM, Administrators and TrustedInstaller alone, and no
        # link; the script's own levels set to SYSTEM and Administrators only. Anything else
        # is refused, never adopted.
        param([string]$Path, [string[]]$Below)
        $rights = @{ CC = 0x1; DC = 0x2; LC = 0x4; SW = 0x8; RP = 0x10; WP = 0x20; DT = 0x40; LO = 0x80; CR = 0x100; SD = 0x10000; RC = 0x20000; WD = 0x40000; WO = 0x80000; GA = 0x10000000; GX = 0x20000000; GW = 0x40000000; GR = 0x80000000; FA = 0x1F01FF; FR = 0x120089; FW = 0x120116; FX = 0x1200A0 }
        # Write data, append, extended attributes, delete child, attributes, delete, the list, the owner.
        $writing = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000
        $trusted = @('SY', 'BA', 'CO', 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
        $current = $Path
        foreach ($level in @('') + $Below) {
            if ($level) { $current = $current + '\' + $level }
            $created = $false
            if (Test-Path -LiteralPath $current) {
                if ([string](Get-Item -LiteralPath $current -Force).Attributes -match 'ReparsePoint') { throw "$current is a link" }
                if ((Get-Acl -LiteralPath $current).Sddl -notmatch '^O:(BA|SY)') { throw "$current is owned by an account other than SYSTEM and Administrators" }
            } else {
                $null = New-Item -ItemType Directory -Path $current
                $created = $true
            }
            # The base (...\Program Files\Tenko) keeps its list unless the script made it.
            if ($level -or $created) {
                $null = icacls.exe $current /setowner '*S-1-5-32-544'
                $null = icacls.exe $current /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
                if ($LASTEXITCODE -ne 0) { throw "the access list of $current could not be set" }
            }
            foreach ($entry in [regex]::Matches([string](Get-Acl -LiteralPath $current).Sddl, '\(A;[^;]*;(?<r>[^;]*);[^;]*;[^;]*;(?<s>[^)]*)\)')) {
                if ($trusted -contains $entry.Groups['s'].Value) { continue }
                $text = $entry.Groups['r'].Value
                $mask = 0
                if ($text -match '^0x([0-9A-Fa-f]+)$') { $mask = [System.Convert]::ToInt64($Matches[1], 16) }
                else { for ($i = 0; $i + 1 -lt $text.Length; $i += 2) { $mask = $mask -bor [long]$rights[$text.Substring($i, 2)] } }
                if (($mask -band $writing) -ne 0) { throw "$current may be written by $($entry.Groups['s'].Value), not only by SYSTEM and Administrators" }
            }
        }
    }
    FileDigest            = {
        param([string]$Path)
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    ReadDomain            = {
        $domain = Get-ADDomain
        $forest = Get-ADForest
        @{
            Kind               = 'domain'
            DnsRoot            = [string]$domain.DNSRoot
            NetBIOSName        = [string]$domain.NetBIOSName
            DomainSid          = [string]$domain.DomainSID
            Pdc                = [string]$domain.PDCEmulator
            DistinguishedName  = [string]$domain.DistinguishedName
            ComputersContainer = [string]$domain.ComputersContainer
            ForestRoot         = [string]$forest.RootDomain
            Configuration      = [string](Get-ADRootDSE).configurationNamingContext
            Quota              = [string](Get-ADObject -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
            Kds                = @(Get-KdsRootKey).Count -gt 0
        }
        Get-ADDomainController -Filter * | ForEach-Object {
            @{ Kind = 'controller'; Name = ([string]$_.HostName).ToLowerInvariant(); IPv4 = [string]$_.IPv4Address; IPv6 = [string]$_.IPv6Address; Gc = [bool]$_.IsGlobalCatalog }
        }
    }
    ReadComputers         = {
        param([string[]]$Controllers)
        Get-ADComputer -Filter 'Enabled -eq $true' -Properties DNSHostName, OperatingSystem, IPv4Address, TrustedForDelegation, 'mS-DS-CreatorSID' | ForEach-Object {
            $name = ([string]$_.DNSHostName).ToLowerInvariant()
            if ($name -and $Controllers -notcontains $name) {
                @{ Name = $name; Server = ([string]$_.OperatingSystem -like '*Server*'); IPv4 = [string]$_.IPv4Address; Sid = [string]$_.SID; Delegation = [bool]$_.TrustedForDelegation; Creator = [string]$_.'mS-DS-CreatorSID' }
            }
        }
    }
    ReadNameUse           = {
        # Whether a name is taken: a computer object, a service principal name for it.
        param([string]$Name, [string]$Domain)
        $computer = Get-ADComputer -Filter "SamAccountName -eq '$Name$'" -ErrorAction SilentlyContinue
        @{
            Sid  = $(if ($null -ne $computer) { [string]$computer.SID } else { '' })
            Spns = @(Get-ADObject -LDAPFilter "(|(servicePrincipalName=*/$Name)(servicePrincipalName=*/$Name.$Domain))" -ErrorAction SilentlyContinue).Count
        }
    }
    ReadHardening         = {
        param([string]$Configuration)
        $ntds =Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
        $signing = $null; $binding = $null
        if ($null -ne $ntds) {
            $signing = $ntds.LDAPServerIntegrity; $binding = $ntds.LdapEnforceChannelBinding
        }
        $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
        @{
            Kind       = 'server'
            LdapSigning = $(if ($null -ne $signing) { [int]$signing } else { -1 })
            ChannelBinding = $(if ($null -ne $binding) { [int]$binding } else { -1 })
            Spooler    = $(if ($null -ne $spooler) { [string]$spooler.Status } else { 'absent' })
            TimeStatus = (@(w32tm /query /status) -join "`n")
            TimeSource = (@(w32tm /query /source) -join ' ').Trim()
        }
        Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$Configuration" -Filter 'objectClass -eq "pKIEnrollmentService"' -Properties dNSHostName -ErrorAction SilentlyContinue | ForEach-Object {
            @{ Kind = 'ca'; Name = [string]$_.Name; Host = [string]$_.dNSHostName }
        }
        Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$Configuration" -Filter 'objectClass -eq "pKICertificateTemplate"' -Properties 'msPKI-Certificate-Name-Flag', pKIExtendedKeyUsage, DistinguishedName -ErrorAction SilentlyContinue | ForEach-Object {
            # The access list as SDDL: SIDs, whatever language the controller speaks.
            @{ Kind = 'template'; Name = [string]$_.Name; NameFlag = [int]$_.'msPKI-Certificate-Name-Flag'; Usages = @($_.pKIExtendedKeyUsage | ForEach-Object { [string]$_ }); Sddl = [string](Get-Acl -Path ('AD:\' + $_.DistinguishedName)).Sddl }
        }
        Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties 'msDS-SupportedEncryptionTypes' | ForEach-Object {
            $types = $_.'msDS-SupportedEncryptionTypes'
            if ($null -eq $types -or ([int]$types -band 4) -ne 0 -or ([int]$types -band 24) -eq 0) { @{ Kind = 'rc4'; Name = [string]$_.SamAccountName } }
        }
    }
    ReadZones             = {
        Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' } | ForEach-Object {
            $zone = $_
            $serial = $null
            if ($zone.ZoneType -eq 'Primary' -or $zone.ZoneType -eq 'Secondary') {
                $soa = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType Soa -Name '@' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($null -ne $soa) { $serial = [string]$soa.RecordData.SerialNumber }
            }
            $aging = $null
            if ($zone.IsDsIntegrated) { $aging = [bool](Get-DnsServerZoneAging -Name $zone.ZoneName -ErrorAction SilentlyContinue).AgingEnabled }
            @{
                Name          = ([string]$zone.ZoneName).ToLowerInvariant()
                Type          = [string]$zone.ZoneType
                Ds            = [bool]$zone.IsDsIntegrated
                Scope         = [string]$zone.ReplicationScope
                Partition     = $(if ([string]$zone.ReplicationScope -eq 'Custom') { [string]$zone.DirectoryPartitionName } else { '' })
                Update        = [string]$zone.DynamicUpdate
                Reverse       = [bool]$zone.IsReverseLookupZone
                Transfer      = [string]$zone.SecureSecondaries
                Notify        = [string]$zone.Notify
                Secondaries   = @($zone.SecondaryServers | ForEach-Object { [string]$_ })
                NotifyServers = @($zone.NotifyServers | ForEach-Object { [string]$_ })
                Masters       = @($zone.MasterServers | ForEach-Object { [string]$_ })
                Serial        = $serial
                Aging         = $aging
            }
        }
        $forwarders = Get-DnsServerForwarder -ErrorAction SilentlyContinue
        @{ Name = '.'; Type = 'ServerForwarder'; Masters = @($forwarders.IPAddress | ForEach-Object { [string]$_ }) }
        @{ Name = ''; Type = 'Scavenging'; Masters = @(); Aging = [bool](Get-DnsServerScavenging).ScavengingState }
    }
    ReadDirectoryZones    = {
        param([string]$DomainDn, [string]$ForestDn)
        foreach ($base in @("DC=DomainDnsZones,$DomainDn", "DC=ForestDnsZones,$ForestDn")) {
            Get-ADObject -SearchBase $base -Filter 'objectClass -eq "dnsZone"' -ErrorAction SilentlyContinue | ForEach-Object {
                @{ Name = ([string]$_.Name).ToLowerInvariant(); Dn = [string]$_.DistinguishedName }
            }
        }
    }
    ReadDhcpInDirectory   = {
        Get-DhcpServerInDC | ForEach-Object { @{ Name = ([string]$_.DnsName).ToLowerInvariant(); Address = [string]$_.IPAddress } }
    }
    ReadDhcpServer        = {
        $scopes = @(Get-DhcpServerv4Scope | ForEach-Object {
                $id = [string]$_.ScopeId
                @{
                    Id           = $id
                    Mask         = [string]$_.SubnetMask
                    Start        = [string]$_.StartRange
                    End          = [string]$_.EndRange
                    State        = [string]$_.State
                    LeaseSeconds = [int]$_.LeaseDuration.TotalSeconds
                    Exclusions   = @(Get-DhcpServerv4ExclusionRange -ScopeId $id | ForEach-Object { [string]$_.StartRange + '-' + [string]$_.EndRange })
                    Reservations = @(Get-DhcpServerv4Reservation -ScopeId $id | ForEach-Object { @{ Ip = [string]$_.IPAddress; Client = ([string]$_.ClientId).ToLowerInvariant() } })
                    Hosts        = @(Get-DhcpServerv4Lease -ScopeId $id -AllLeases | Where-Object { $_.HostName } | ForEach-Object { ([string]$_.HostName).ToLowerInvariant() })
                }
            })
        $credential = Get-DhcpServerDnsCredential -ErrorAction SilentlyContinue
        $lists = Get-DhcpServerv4FilterList
        @{
            Scopes     = $scopes
            Bindings   = @(Get-DhcpServerv4Binding | Where-Object { $_.BindingState } | ForEach-Object { [string]$_.IPAddress })
            Failover   = @(Get-DhcpServerv4Failover | ForEach-Object { @{ Name = [string]$_.Name; Partner = ([string]$_.PartnerServer).ToLowerInvariant(); Mode = [string]$_.Mode; Scopes = @($_.ScopeId | ForEach-Object { [string]$_ }) } })
            DnsUser    = $(if ($null -ne $credential -and $credential.UserName) { [string]$credential.DomainName + '\' + [string]$credential.UserName } else { '' })
            V6Scopes   = @(Get-DhcpServerv6Scope -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Prefix })
            Multicast  = @(Get-DhcpServerv4MulticastScope -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name })
            AllowList  = [bool]$lists.Allow
            DenyList   = [bool]$lists.Deny
            Policies   = @(Get-DhcpServerv4Policy | ForEach-Object { [string]$_.Name })
            Superscope = @(Get-DhcpServerv4Superscope | Where-Object { $_.SuperscopeName } | ForEach-Object { [string]$_.SuperscopeName })
            Service    = [string](Get-Service -Name DHCPServer).StartType
            Conflict   = [int](Get-DhcpServerSetting).ConflictDetectionAttempts
        }
    }
    ReadDhcpConfiguration = {
        # The reads of the exporter, by property name; the mapping runs on the script's host.
        param([hashtable]$Properties)
        $scopes = @(Get-DhcpServerv4Scope | Select-Object -Property $Properties.Scope)
        $result = @{
            scopes = $scopes; server_options = @(Get-DhcpServerv4OptionValue -All | Select-Object -Property $Properties.OptionValue)
            option_defs = @(Get-DhcpServerv4OptionDefinition -All | Select-Object -Property $Properties.OptionDef)
            classes = @(Get-DhcpServerv4Class | Select-Object -Property $Properties.Class)
            exclusions = @{}; reservations = @{}; scope_options = @{}; reservation_options = @{}; dns = @{}; leases = @{}
            policies = @(Get-DhcpServerv4Policy | Select-Object -Property $Properties.Policy)
            filter_lists = @(Get-DhcpServerv4FilterList | Select-Object -Property $Properties.FilterList)
            filters = @(Get-DhcpServerv4Filter | Select-Object -Property $Properties.Filter)
            superscopes = @(Get-DhcpServerv4Superscope | Select-Object -Property $Properties.Superscope)
            failover = @(Get-DhcpServerv4Failover | Select-Object -Property $Properties.Failover)
        }
        foreach ($scope in $scopes) {
            $id = [string]$scope.ScopeId
            $result.exclusions[$id] = @(Get-DhcpServerv4ExclusionRange -ScopeId $id | Select-Object -Property $Properties.Exclusion)
            $result.reservations[$id] = @(Get-DhcpServerv4Reservation -ScopeId $id | Select-Object -Property $Properties.Reservation)
            $result.scope_options[$id] = @(Get-DhcpServerv4OptionValue -ScopeId $id -All | Select-Object -Property $Properties.OptionValue)
            $result.dns[$id] = @(Get-DhcpServerv4DnsSetting -ScopeId $id | Select-Object -Property $Properties.DnsSetting)
            $result.leases[$id] = @()
            $result.policies += @(Get-DhcpServerv4Policy -ScopeId $id | Select-Object -Property $Properties.Policy)
            foreach ($reservation in $result.reservations[$id]) {
                $ip = [string]$reservation.IPAddress
                $result.reservation_options[$ip] = @(Get-DhcpServerv4OptionValue -ReservedIP $ip -All | Select-Object -Property $Properties.OptionValue)
            }
        }
        $result
    }
    ReadLeases            = {
        param([string]$ScopeId)
        Get-DhcpServerv4Lease -ScopeId $ScopeId -AllLeases | Where-Object { [string]$_.AddressState -like 'Active*' } | ForEach-Object {
            @{ Ip = [string]$_.IPAddress; Client = ([string]$_.ClientId).ToLowerInvariant() }
        }
    }
    ReadLocalAdmins       = {
        Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { @{ Name = [string]$_.Name; Sid = [string]$_.SID; Class = [string]$_.ObjectClass } }
    }
    ReadFeature           = {
        param([string]$Name)
        [bool](Get-WindowsFeature -Name $Name).Installed
    }
    SetFeature            = {
        param([string]$Name, [bool]$Installed)
        if ($Installed) { $null = Install-WindowsFeature -Name $Name } else { $null = Uninstall-WindowsFeature -Name $Name }
        [bool](Get-WindowsFeature -Name $Name).Installed
    }
    WriteMarker           = {
        # A removal that names a finished run leaves that run's id as Finished.
        param([string]$Key, [string]$Run, [string]$Machine, [bool]$Remove, [string]$Finished)
        if ($Remove) {
            if (Test-Path -LiteralPath $Key) { Remove-Item -LiteralPath $Key -Recurse -Force }
            if ($Finished) { $null = New-Item -Path $Key -Force; $null = New-ItemProperty -Path $Key -Name Finished -Value $Finished -PropertyType String -Force }
            return
        }
        if (-not (Test-Path -LiteralPath $Key)) { $null = New-Item -Path $Key -Force }
        $null = New-ItemProperty -Path $Key -Name Run -Value $Run -PropertyType String -Force
        $null = New-ItemProperty -Path $Key -Name Host -Value $Machine -PropertyType String -Force
        $null = New-ItemProperty -Path $Key -Name Time -Value ((Get-Date).ToUniversalTime().ToString('s') + 'Z') -PropertyType String -Force
    }
    ReadMarker            = {
        param([string]$Key)
        if (Test-Path -LiteralPath $Key) {
            $values = Get-ItemProperty -LiteralPath $Key
            @{ Run = [string]$values.Run; Host = [string]$values.Host; Time = [string]$values.Time; Pending = [string]$values.Pending; Finished = [string]$values.Finished }
        }
    }
    WriteMarkerPending    = {
        # The DHCP servers whose authorization removal has not reached every controller yet,
        # beside the run's marker, for a sitting that has no state file.
        param([string]$Key, [string]$Pending)
        if (Test-Path -LiteralPath $Key) { $null = New-ItemProperty -Path $Key -Name Pending -Value $Pending -PropertyType String -Force }
    }
    ExportDhcp            = {
        # Into the script's admin-only folder (made by ProtectDirectory first).
        param([string]$Path)
        Export-DhcpServer -File $Path -Leases -Force
    }
    ExportZone            = {
        param([string]$Zone, [string]$File)
        Export-DnsServerZone -Name $Zone -FileName $File
        Join-Path $env:SystemRoot "System32\dns\$File"
    }
    SetZoneLists          = {
        # Transfer to the list only, notify the list; the PDC emulator keeps them per zone.
        param([string]$Zone, [string[]]$Secondaries, [string]$Transfer, [string]$Notify, [string[]]$NotifyServers)
        $arguments = @{ Name = $Zone; SecureSecondaries = $Transfer; Notify = $Notify }
        if ($Secondaries.Count -gt 0) { $arguments.SecondaryServers = $Secondaries }
        if ($NotifyServers.Count -gt 0) { $arguments.NotifyServers = $NotifyServers }
        Set-DnsServerPrimaryZone @arguments
        $found = Get-DnsServerZone -Name $Zone
        @{ Transfer = [string]$found.SecureSecondaries; Notify = [string]$found.Notify; Secondaries = @($found.SecondaryServers | ForEach-Object { [string]$_ }); NotifyServers = @($found.NotifyServers | ForEach-Object { [string]$_ }) }
    }
    NewAccount            = {
        # A user or a group managed service account the run creates, its mark in the
        # description. One that exists is used only by the SID the script resolved as the
        # run's own (Resolve-TkRunObject); any other is refused, never adopted.
        param([string]$Name, [bool]$Gmsa, [string]$Domain, [string]$MirrorHost, [securestring]$Password, [string]$KnownSid, [bool]$DhcpUsers, [string]$Mark)
        $account = Get-ADObject -Filter "sAMAccountName -eq '$(if ($Gmsa) { "$Name$" } else { $Name })'" -Properties objectSid
        if ($null -ne $account) {
            if ([string]$account.objectSid -ne $KnownSid) { throw "the account $Name exists and is not the run's own: it is not used and never removed" }
        } elseif ($Gmsa) {
            New-ADServiceAccount -Name $Name -Description $Mark -DNSHostName "$Name.$Domain" -PrincipalsAllowedToRetrieveManagedPassword $MirrorHost -KerberosEncryptionType AES128, AES256
        } else {
            New-ADUser -Name $Name -Description $Mark -SamAccountName $Name -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -KerberosEncryptionType AES128, AES256
        }
        $account = Get-ADObject -Filter "sAMAccountName -eq '$(if ($Gmsa) { "$Name$" } else { $Name })'" -Properties objectSid
        if ($DhcpUsers) { Add-ADGroupMember -Identity 'DHCP Users' -Members ([string]$account.objectSid) }
        [string]$account.objectSid
    }
    RemoveAccount         = {
        # Only an account this run created, by the SID it recorded.
        param([string]$Sid)
        Get-ADObject -Filter "objectSid -eq '$Sid'" | Remove-ADObject -Recursive -Confirm:$false
    }
    ResetPassword         = {
        # A new password for an account this run created, whose old one lived in an earlier
        # process only.
        param([string]$Sid, [securestring]$Password)
        Set-ADAccountPassword -Identity $Sid -NewPassword $Password -Reset
    }
    InstallExporter       = {
        # The installer is hashed again just before it runs.
        param([string]$Directory, [string]$Url, [string]$Mirror, [string]$Fingerprint, [string]$Account, [pscredential]$Credential, [securestring]$Token, [string]$TaskName, [string]$DataDir, [string]$Server, [string]$Digest)
        $installer = Join-Path $Directory 'Install-TenkoDhcpMirror.ps1'
        if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $Digest) { throw "$installer is not the installer that was copied" }
        $arguments = @{ Url = $Url; MirrorId = $Mirror; Fingerprint = $Fingerprint; Account = $Account; Token = $Token; TaskName = $TaskName; DataDir = $DataDir; ComputerName = $Server; SkipDryRun = $true }
        if ($null -ne $Credential) { $arguments.Credential = $Credential }
        & $installer @arguments
        @{ Pending = (Test-Path -LiteralPath (Join-Path $DataDir 'state\token.pending')); Stored = (Test-Path -LiteralPath (Join-Path $DataDir 'state\token.dpapi')) }
    }
    RemoveExporter        = {
        param([string]$Directory, [string]$TaskName, [string]$DataDir, [string]$Digest)
        $installer = Join-Path $Directory 'Install-TenkoDhcpMirror.ps1'
        if (Test-Path -LiteralPath $installer) {
            if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $Digest) { throw "$installer is not the installer that was copied" }
            & $installer -Remove -TaskName $TaskName -DataDir $DataDir -Confirm:$false
        }
        @{ Pending = (Test-Path -LiteralPath (Join-Path $DataDir 'state\token.pending')); Task = ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) }
    }
    StartExporter         = {
        param([string]$TaskName)
        Start-ScheduledTask -TaskPath '\Tenko\' -TaskName $TaskName
    }
    RemoveBatchRight      = {
        # The right to log on as a batch job that the task's registration granted the account.
        # Its work folder is the script's admin-only folder (made by ProtectDirectory first).
        param([string]$Sid, [string]$Work)
        $inf = Join-Path $Work 'rights.inf'
        $null = secedit /export /cfg $inf /areas USER_RIGHTS
        $lines = @(Get-Content -LiteralPath $inf)
        $changed = $false
        $out = foreach ($line in $lines) {
            if ($line -like 'SeBatchLogonRight*') {
                $parts = @(($line -split '=', 2)[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ne "*$Sid" })
                $changed = $true
                'SeBatchLogonRight = ' + ($parts -join ',')
            } else { $line }
        }
        if ($changed) {
            Set-Content -LiteralPath $inf -Value $out -Encoding Unicode
            $null = secedit /configure /db (Join-Path $Work 'rights.sdb') /cfg $inf /areas USER_RIGHTS
        }
        $null = secedit /export /cfg $inf /areas USER_RIGHTS
        $still = @(Get-Content -LiteralPath $inf | Where-Object { $_ -like 'SeBatchLogonRight*' -and $_ -like "*$Sid*" }).Count -gt 0
        Remove-Item -LiteralPath $inf, (Join-Path $Work 'rights.sdb') -Force -ErrorAction SilentlyContinue
        -not $still
    }
    SetDnsCredential      = {
        param([pscredential]$Credential, [bool]$Remove)
        if ($Remove) { Remove-DhcpServerDnsCredential -Force } else { Set-DhcpServerDnsCredential -Credential $Credential }
        $now = Get-DhcpServerDnsCredential -ErrorAction SilentlyContinue
        $(if ($null -ne $now -and $now.UserName) { [string]$now.DomainName + '\' + [string]$now.UserName } else { '' })
    }
    NewTenkoAccount       = {
        # Tenko's computer account: no privileged group, no delegation, AES only, one SPN, its
        # mark in the description. One that exists and is not the SID the script resolved as
        # the run's own is refused.
        param([string]$Name, [string]$Path, [string]$Spn, [securestring]$Password, [string]$KnownSid, [string]$Mark)
        $existing = Get-ADComputer -Filter "SamAccountName -eq '$Name$'"
        if ($null -ne $existing -and [string]$existing.SID -ne $KnownSid) { throw "the computer account $Name$ exists and is not the run's own: it is not used and never removed" }
        # The run's own account found again gets this sitting's one-time password.
        if ($null -ne $existing) { Set-ADAccountPassword -Identity $existing.DistinguishedName -NewPassword $Password -Reset }
        else {
            New-ADComputer -Name $Name -Description $Mark -SAMAccountName "$Name$" -Path $Path -AccountPassword $Password -Enabled $true -KerberosEncryptionType AES128, AES256 -ServicePrincipalNames $Spn -TrustedForDelegation $false
        }
        $account = Get-ADComputer -Identity "$Name$" -Properties MemberOf, userAccountControl, 'msDS-SupportedEncryptionTypes', servicePrincipalName, 'msDS-AllowedToDelegateTo', pwdLastSet, DistinguishedName
        @{
            Dn          = [string]$account.DistinguishedName
            Sid         = [string]$account.SID
            Groups      = @($account.MemberOf | ForEach-Object { [string]$_ })
            Uac         = [int]$account.userAccountControl
            Encryption  = [int]$account.'msDS-SupportedEncryptionTypes'
            Spns        = @($account.servicePrincipalName | ForEach-Object { [string]$_ })
            DelegateTo  = @($account.'msDS-AllowedToDelegateTo' | ForEach-Object { [string]$_ })
            PwdLastSet  = [string]$account.pwdLastSet
            Sddl        = [string](Get-Acl -Path ('AD:\' + $account.DistinguishedName)).Sddl
            AccountOps  = @(Get-ADGroupMember -Identity 'S-1-5-32-548' -ErrorAction SilentlyContinue).Count
        }
    }
    ReadRunObject         = {
        # An object of the run's name as the directory holds it: its SID or id, its mark, the
        # creator a quota computer names, its access list and Account Operators' size.
        param([string]$Kind, [string]$Name)
        $dn = ''
        if ($Kind -eq 'gpo') {
            $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
            if ($null -eq $gpo) { return }
            $id = [string]$gpo.Id; $mark = [string]$gpo.Description; $creator = ''; $dn = [string]$gpo.Path
        } else {
            $object = Get-ADObject -Filter "sAMAccountName -eq '$Name'" -Properties objectSid, description, 'mS-DS-CreatorSID'
            if ($null -eq $object) { return }
            $id = [string]$object.objectSid; $mark = [string]$object.description; $creator = [string]$object.'mS-DS-CreatorSID'; $dn = [string]$object.DistinguishedName
        }
        @{ Id = $id; Mark = $mark; Creator = $creator; Sddl = [string](Get-Acl -Path ('AD:\' + $dn)).Sddl; AccountOps = @(Get-ADGroupMember -Identity 'S-1-5-32-548' -ErrorAction SilentlyContinue).Count }
    }
    ReadPwdLastSet        = {
        param([string]$Sid)
        [string](Get-ADComputer -Identity $Sid -Properties pwdLastSet).pwdLastSet
    }
    DisableAccount        = {
        param([string]$Sid)
        Disable-ADAccount -Identity $Sid
        [bool](Get-ADComputer -Identity $Sid).Enabled
    }
    NewGpo                = {
        # The run's own object, by the id the script resolved as the run's own, its mark in
        # the comment; one of that name with another id is refused.
        param([string]$Name, [string]$DomainDn, [string[]]$Members, [string]$KnownId, [string]$Mark)
        $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $gpo -and [string]$gpo.Id -ne $KnownId) { throw "a group policy object named '$Name' exists and is not the run's own" }
        if ($null -eq $gpo) { $gpo = New-GPO -Name $Name -Comment $Mark }
        $null = Set-GPRegistryValue -Guid $gpo.Id -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'RegistrationEnabled' -Type DWord -Value 0
        $null = Set-GPPermission -Guid $gpo.Id -TargetName 'Authenticated Users' -TargetType Group -PermissionLevel GpoRead -Replace
        foreach ($member in $Members) { $null = Set-GPPermission -Guid $gpo.Id -TargetName $member -TargetType Computer -PermissionLevel GpoApply }
        if (-not (@((Get-GPInheritance -Target $DomainDn).GpoLinks | Where-Object { [string]$_.GpoId -eq [string]$gpo.Id }).Count)) { $null = New-GPLink -Guid $gpo.Id -Target $DomainDn }
        [string]$gpo.Id
    }
    RemoveGpo             = {
        param([string]$Id)
        Remove-GPO -Guid $Id -ErrorAction SilentlyContinue
    }
    Replicate             = {
        $out = @(repadmin /syncall /AdeP)
        @{ Exit = $LASTEXITCODE; Text = ($out -join "`n") }
    }
    ReadRecords           = {
        # Every record of a zone as type and presentation data, SOA left out.
        param([string]$Zone)
        Get-DnsServerResourceRecord -ZoneName $Zone | Where-Object { $_.RecordType -ne 'SOA' } | ForEach-Object {
            $data = $_.RecordData
            $text = switch ([string]$_.RecordType) {
                'A' { [string]$data.IPv4Address }
                'AAAA' { [string]$data.IPv6Address }
                'CNAME' { ([string]$data.HostNameAlias).ToLowerInvariant().TrimEnd('.') }
                'NS' { ([string]$data.NameServer).ToLowerInvariant().TrimEnd('.') }
                'PTR' { ([string]$data.PtrDomainName).ToLowerInvariant().TrimEnd('.') }
                'MX' { [string]$data.Preference + ' ' + ([string]$data.MailExchange).ToLowerInvariant().TrimEnd('.') }
                'SRV' { [string]$data.Priority + ' ' + [string]$data.Weight + ' ' + [string]$data.Port + ' ' + ([string]$data.DomainName).ToLowerInvariant().TrimEnd('.') }
                'TXT' { [string]$data.DescriptiveText }
                'DNAME' { ([string]$data.DomainNameAlias).ToLowerInvariant().TrimEnd('.') }
                # Any other type by every property of its data, so that a change shows.
                default { (@($data.CimInstanceProperties | ForEach-Object { [string]$_.Name + '=' + [string]$_.Value }) -join ';') }
            }
            @{ Name = ([string]$_.HostName).ToLowerInvariant(); Type = [string]$_.RecordType; Data = $text; Ttl = [string][int]$_.TimeToLive.TotalSeconds }
        }
    }
    ConvertToSecondary    = {
        param([string]$Zone, [string]$Master, [string]$File, [bool]$Convert)
        $found = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($Convert) {
            if ($null -ne $found -and [string]$found.ZoneType -ne 'Secondary') { ConvertTo-DnsServerSecondaryZone -Name $Zone -MasterServers $Master -ZoneFile $File -Force }
        } elseif ($null -eq $found) {
            Add-DnsServerSecondaryZone -Name $Zone -MasterServers $Master -ZoneFile $File
        }
        $null = dnscmd /ZoneResetSecondaries $Zone /NoXfr /NoNotify
        $values = Get-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\' + $Zone)
        @{ Type = [string](Get-DnsServerZone -Name $Zone).ZoneType; Transfer = [int]$values.SecureSecondaries; Notify = [int]$values.NotifyLevel }
    }
    RegisterDns           = {
        $null = nltest /dsregdns
        $null = ipconfig /registerdns
        $LASTEXITCODE
    }
    ReadSoa               = {
        param([string]$Zone)
        $soa = Get-DnsServerResourceRecord -ZoneName $Zone -RRType Soa -Name '@' | Select-Object -First 1
        $data = $soa.RecordData
        @{
            Mname  = ([string]$data.PrimaryServer).ToLowerInvariant(); Rname = ([string]$data.ResponsiblePerson).ToLowerInvariant()
            Timers = "$([int]$data.RefreshInterval.TotalSeconds) $([int]$data.RetryDelay.TotalSeconds) $([int]$data.ExpireLimit.TotalSeconds) $([int]$data.MinimumTimeToLive.TotalSeconds) $([int]$soa.TimeToLive.TotalSeconds)"
        }
    }
    FreezeZone            = {
        # The first step back on the PDC emulator: its secondary becomes a file-backed primary
        # that takes no transfer, no notify and no update, so that what is read next is what
        # reaches the directory. A zone this step finds directory-integrated is done; one it
        # does not find is a restore that ended halfway.
        param([string]$Zone, [string]$File)
        $found = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($null -eq $found) { return @{ Type = 'Missing'; Ds = $false; Update = '' } }
        if ([string]$found.ZoneType -eq 'Secondary') { ConvertTo-DnsServerPrimaryZone -Name $Zone -ZoneFile $File -Force }
        $found = Get-DnsServerZone -Name $Zone
        if (-not $found.IsDsIntegrated) { Set-DnsServerPrimaryZone -Name $Zone -DynamicUpdate None; $found = Get-DnsServerZone -Name $Zone }
        @{ Type = [string]$found.ZoneType; Ds = [bool]$found.IsDsIntegrated; Update = [string]$found.DynamicUpdate }
    }
    ApplyZoneFix          = {
        # On the frozen copy: at each name to set back, the records of the given types replaced
        # by their flip-time ones; the start of authority back on its flip-time names.
        param([string]$Zone, [object[]]$Fix, [string]$Mname, [string]$Rname)
        foreach ($name in @($Fix)) {
            if ($null -eq $name) { continue }
            Get-DnsServerResourceRecord -ZoneName $Zone -Name $name.Name -ErrorAction SilentlyContinue | Where-Object { @($name.Types) -contains [string]$_.RecordType } | Remove-DnsServerResourceRecord -ZoneName $Zone -Force
            foreach ($record in @($name.Records)) {
                $part = ([string]$record.Data).Split(' ')
                switch ([string]$record.Type) {
                    'A' { Add-DnsServerResourceRecordA -ZoneName $Zone -Name $name.Name -IPv4Address $record.Data }
                    'AAAA' { Add-DnsServerResourceRecordAAAA -ZoneName $Zone -Name $name.Name -IPv6Address $record.Data }
                    'CNAME' { Add-DnsServerResourceRecordCName -ZoneName $Zone -Name $name.Name -HostNameAlias $record.Data }
                    'PTR' { Add-DnsServerResourceRecordPtr -ZoneName $Zone -Name $name.Name -PtrDomainName $record.Data }
                    'NS' { Add-DnsServerResourceRecord -NS -ZoneName $Zone -Name $name.Name -NameServer $record.Data }
                    'MX' { Add-DnsServerResourceRecordMX -ZoneName $Zone -Name $name.Name -Preference $part[0] -MailExchange $part[1] }
                    'SRV' { Add-DnsServerResourceRecord -Srv -ZoneName $Zone -Name $name.Name -Priority $part[0] -Weight $part[1] -Port $part[2] -DomainName $part[3] }
                    default { throw "the record type $($record.Type) at $($name.Name) cannot be set back" }
                }
            }
        }
        if ($Mname) {
            $old = Get-DnsServerResourceRecord -ZoneName $Zone -RRType Soa -Name '@' | Select-Object -First 1
            $new = $old.Clone()
            $new.RecordData.PrimaryServer = $Mname
            $new.RecordData.ResponsiblePerson = $Rname
            Set-DnsServerResourceRecord -ZoneName $Zone -OldInputObject $old -NewInputObject $new
        }
    }
    RestoreZone           = {
        # The export of phase 2 put in place under a name of its own and checked first; then
        # the frozen copy replaced by it. Run again after a stop between the removal and the
        # load, it finds the zone missing and loads it; after the load, it finds it done.
        param([string]$Zone, [string]$Backup, [string]$Staged, [string]$Digest)
        $dir = Join-Path $env:SystemRoot 'System32\dns'
        $found = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($null -ne $found -and -not $found.IsDsIntegrated -and [string]$found.ZoneFile -eq $Staged) { return }
        $target = Join-Path $dir $Staged
        if (-not (Test-Path -LiteralPath $target) -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $Digest) { Copy-Item -LiteralPath (Join-Path $dir $Backup) -Destination $target -Force }
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $Digest) { throw "$target is not the export of phase 2 (its SHA-256 differs from the copy this run holds)" }
        if ($null -ne $found) { Remove-DnsServerZone -Name $Zone -Force }
        Add-DnsServerPrimaryZone -Name $Zone -ZoneFile $Staged -LoadExisting
    }
    IntegrateZone         = {
        # The checked copy into the directory partition the discovery read, then the zone's own
        # update setting.
        param([string]$Zone, [string]$Scope, [string]$Partition, [string]$Update)
        if (-not (Get-DnsServerZone -Name $Zone).IsDsIntegrated) {
            if ($Scope -eq 'Custom') { ConvertTo-DnsServerPrimaryZone -Name $Zone -ReplicationScope Custom -DirectoryPartitionName $Partition -Force }
            else { ConvertTo-DnsServerPrimaryZone -Name $Zone -ReplicationScope $Scope -Force }
        }
        Set-DnsServerPrimaryZone -Name $Zone -DynamicUpdate $Update
        $found = Get-DnsServerZone -Name $Zone
        @{ Type = [string]$found.ZoneType; Ds = [bool]$found.IsDsIntegrated; Update = [string]$found.DynamicUpdate }
    }
    RemoveSecondary       = {
        param([string]$Zone)
        $found = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($null -ne $found -and [string]$found.ZoneType -eq 'Secondary') { Remove-DnsServerZone -Name $Zone -Force }
    }
    ReadZone              = {
        param([string]$Zone)
        $found = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($null -ne $found) { @{ Type = [string]$found.ZoneType; Ds = [bool]$found.IsDsIntegrated; Update = [string]$found.DynamicUpdate } }
    }
    StopDhcp              = {
        # DHCPServer, never Dhcp (the DHCP client a controller needs for its own registration).
        Stop-Service -Name DHCPServer -Force
        Set-Service -Name DHCPServer -StartupType Disabled
        $service = Get-Service -Name DHCPServer
        @{ Status = [string]$service.Status; Start = [string]$service.StartType; Listening = @(Get-NetUDPEndpoint -LocalPort 67 -ErrorAction SilentlyContinue).Count }
    }
    ReadDhcpService       = {
        # Read only: whether DHCPServer is stopped, disabled and silent on UDP 67.
        $service = Get-Service -Name DHCPServer
        @{ Status = [string]$service.Status; Start = [string]$service.StartType; Listening = @(Get-NetUDPEndpoint -LocalPort 67 -ErrorAction SilentlyContinue).Count }
    }
    StartDhcp             = {
        # Started, or restarted so that it reads its authorization again.
        # After a restart, the server's own log answers whether it serves: event 1044
        # (authorized) or 1046 (not), written after the restart by this server's clock.
        param([string]$Start, [bool]$Restart)
        Set-Service -Name DHCPServer -StartupType $Start
        $since = Get-Date
        if ($Restart) { Restart-Service -Name DHCPServer -Force } else { Start-Service -Name DHCPServer }
        $authorized = $false
        if ($Restart) {
            for ($i = 0; $i -lt 30; $i++) {
                $found = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 1044, 1046; StartTime = $since } -ErrorAction SilentlyContinue | Select-Object -First 1)
                if ($found.Count -gt 0) { $authorized = ([int]$found[0].Id -eq 1044); break }
                Start-Sleep -Seconds 2
            }
        }
        $service = Get-Service -Name DHCPServer
        @{ Status = [string]$service.Status; Start = [string]$service.StartType; Authorized = $authorized }
    }
    SetAuthorization      = {
        # Read first: an entry already in the wanted state is left as it is, so a resume passes.
        param([string]$Name, [string]$Address, [bool]$Authorized)
        $listed = @(Get-DhcpServerInDC | Where-Object { ([string]$_.DnsName).ToLowerInvariant() -eq $Name.ToLowerInvariant() -and [string]$_.IPAddress -eq $Address }).Count -gt 0
        if ($Authorized -and -not $listed) { Add-DhcpServerInDC -DnsName $Name -IPAddress $Address }
        elseif (-not $Authorized -and $listed) { Remove-DhcpServerInDC -DnsName $Name -IPAddress $Address -Confirm:$false }
    }
    ReadAuthorization     = {
        # The controller's own replica of the authorized DHCP servers.
        param([string]$Configuration)
        Get-ADObject -Server $env:COMPUTERNAME -SearchBase "CN=NetServices,CN=Services,$Configuration" -Filter 'objectClass -eq "dHCPClass"' -Properties dhcpServers |
            ForEach-Object { @($_.dhcpServers | ForEach-Object { [string]$_ }) }
    }
    WriteLeases           = {
        # The narrow write-back: address, client identifier and end; the state active.
        # Then conflict detection on, and the scope's active addresses read back.
        param([string]$ScopeId, [object[]]$Leases, [int]$Conflict)
        $known = @(Get-DhcpServerv4Lease -ScopeId $ScopeId -AllLeases | ForEach-Object { [string]$_.IPAddress })
        foreach ($lease in $Leases) {
            if ($known -contains [string]$lease.Ip) { continue }
            Add-DhcpServerv4Lease -ScopeId $ScopeId -IPAddress $lease.Ip -ClientId $lease.Client -AddressState Active -LeaseExpiryTime ((Get-Date).AddSeconds([int]$lease.Seconds))
        }
        Set-DhcpServerSetting -ConflictDetectionAttempts $Conflict
        @(Get-DhcpServerv4Lease -ScopeId $ScopeId -AllLeases | ForEach-Object { [string]$_.IPAddress })
    }
    RemoveZoneObject      = {
        param([string]$Dn)
        Remove-ADObject -Identity $Dn -Recursive -Confirm:$false
    }
}

# ---------------------------------------------------------------------------------------
# The state file: %ProgramData%\Tenko\takeover\<domain>\state.json, SYSTEM and
# Administrators only, held under an exclusive lock while the script runs. It holds no
# password, token, session or code.
# ---------------------------------------------------------------------------------------

function Get-TkStateDir {
    param([string]$Domain)
    if ($Domain -notmatch '^[a-z0-9.\-]{1,253}$') { throw "the domain $Domain is not a DNS name" }
    return Join-Path (Join-Path (Join-Path $script:TkDataRoot 'Tenko') 'takeover') $Domain
}

function Open-TkState {
    # Creates or reads the run's state and holds its lock: every level below %ProgramData%
    # owned and written by SYSTEM and Administrators only, else exit 1 before anything is read.
    # A second process stops with exit 1.
    param([string]$Domain)
    [void](Get-TkStateDir $Domain)
    $dir = Assert-TkTrustedTree -Root $script:TkDataRoot -Levels @('Tenko', 'takeover', $Domain)
    foreach ($sub in 'payload', 'backup') { [void](Assert-TkTrustedTree -Root $dir -Levels @($sub)) }
    try {
        $lock = [System.IO.File]::Open((Join-Path $dir 'state.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    } catch [System.IO.IOException] {
        Exit-TkTakeover 1 "another run of the script holds $dir; let it finish first"
    }
    $path = Join-Path $dir 'state.json'
    $state = [ordered]@{ format = 1; id = [guid]::NewGuid().ToString(); version = $script:TkVersion; domain = $Domain; tenko = [ordered]@{}; readings = $null; plan = $null; run = ''; phases = [ordered]@{}; steps = [ordered]@{}; values = [ordered]@{}; mirrors = [ordered]@{}; jobs = [ordered]@{} }
    if (Test-Path -LiteralPath $path) {
        $state = ConvertFrom-TkJson -Chars ([System.IO.File]::ReadAllText($path).ToCharArray())
    }
    return @{ Dir = $dir; Path = $path; Lock = $lock; Data = $state }
}

function Save-TkState {
    param([hashtable]$State)
    $temp = "$($State.Path).new"
    [System.IO.File]::WriteAllBytes($temp, (ConvertTo-TkJsonByte $State.Data))
    Move-Item -LiteralPath $temp -Destination $State.Path -Force
}

function Close-TkState {
    param([hashtable]$State)
    if ($null -ne $State -and $null -ne $State.Lock) { $State.Lock.Dispose(); $State.Lock = $null }
}

function Assert-TkRestoreValue {
    # A value the reverse writes to Windows: a controller's address as Active Directory reports
    # it in this sitting's own discovery, or a value present at the recorded discovery.
    # Anything else stops the reverse with exit 4.
    param([System.Collections.IDictionary]$Readings, [string]$Value, [ValidateSet('address', 'discovered')][string]$Class)
    $allowed = $(if ($Class -eq 'address') { @($script:TkFresh.controllers | ForEach-Object { $_.addresses }) } else { @($Readings.values) })
    if ($allowed -notcontains $Value) { Exit-TkTakeover 4 "the value $(ConvertTo-TkSafeText $Value) to restore is not one the discovery recorded; nothing further was changed" }
}

# ---------------------------------------------------------------------------------------
# Phase 0: discovery (read only). Every session is opened here first, so that a host that
# cannot be reached stops the run before anything is shown.
# ---------------------------------------------------------------------------------------

function ConvertTo-TkCidr {
    param([string]$Address, [string]$Mask)
    $bits = 0
    foreach ($octet in ([System.Net.IPAddress]::Parse($Mask)).GetAddressBytes()) {
        for ($i = 7; $i -ge 0; $i--) { if (($octet -band (1 -shl $i)) -ne 0) { $bits++ } }
    }
    return "$Address/$bits"
}

function ConvertTo-TkUInt32 {
    param([string]$Address)
    $bytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    [array]::Reverse($bytes)
    return [System.BitConverter]::ToUInt32($bytes, 0)
}

function Get-TkReverseZone {
    # The reverse zones that cover a scope's network or lie inside it, on octet boundaries.
    param([string[]]$Cidrs, [string[]]$Zones)
    $found = @()
    foreach ($zone in $Zones) {
        if ($zone -notmatch '^((\d{1,3}\.){1,3})in-addr\.arpa$') { continue }
        $labels = @($Matches[1].TrimEnd('.').Split('.'))
        [array]::Reverse($labels)
        $len = $labels.Count * 8
        foreach ($cidr in $Cidrs) {
            $address, $prefix = $cidr.Split('/')
            if (Test-TkInNetwork -Address ((@($labels) + @('0', '0', '0', '0'))[0..3] -join '.') -Network $address -Prefix ([math]::Min($len, [int]$prefix))) { $found += $zone; break }
        }
    }
    return , $found
}

function Test-TkInNetwork {
    # Whether an IPv4 address lies in a network of the given prefix length.
    param([string]$Address, [string]$Network, [int]$Prefix)
    $mask = [uint64]0
    if ($Prefix -gt 0) { $mask = ([uint64]4294967295 -shl (32 - $Prefix)) -band [uint64]4294967295 }
    return (([uint64](ConvertTo-TkUInt32 $Address) -band $mask) -eq ([uint64](ConvertTo-TkUInt32 $Network) -band $mask))
}

function ConvertFrom-TkSddl {
    # The allow entries of an access list in SDDL, by SID (aliases resolved), whether each
    # writes (all, write, the access list, the owner, a property) or holds a control right.
    param([string]$Sddl, [string]$DomainSid)
    $entries = @()
    foreach ($match in [regex]::Matches($Sddl, '\((?<type>O?A);[^;]*;(?<rights>[^;]*);(?<object>[^;]*);[^;]*;(?<sid>[^)]*)\)')) {
        $sid = $match.Groups['sid'].Value
        if ($script:TkSddlAlias.ContainsKey($sid)) { $sid = $script:TkSddlAlias[$sid] }
        elseif ($script:TkSddlDomainAlias.ContainsKey($sid)) { $sid = "$DomainSid-$($script:TkSddlDomainAlias[$sid])" }
        $rights = $match.Groups['rights'].Value
        $codes = @()
        if ($rights -match '^0x([0-9a-fA-F]+)$') {
            $mask = [System.Convert]::ToInt64($Matches[1], 16)
            foreach ($bit in @(@(0x10000000, 'GA'), @(0x40000000, 'GW'), @(0x40000, 'WD'), @(0x80000, 'WO'), @(0x20, 'WP'), @(0x100, 'CR'))) { if (($mask -band $bit[0]) -ne 0) { $codes += $bit[1] } }
        } else {
            for ($i = 0; $i + 1 -lt $rights.Length; $i += 2) { $codes += $rights.Substring($i, 2) }
        }
        $entries += @{ Sid = $sid; Write = (@($codes | Where-Object { 'GA', 'GW', 'WD', 'WO', 'WP' -contains $_ }).Count -gt 0); Control = (@($codes | Where-Object { 'GA', 'CR' -contains $_ }).Count -gt 0); Object = $match.Groups['object'].Value.ToLowerInvariant() }
    }
    return , $entries
}

function Test-TkSidIn {
    # Whether a SID is one of the well-known SIDs or the domain's RIDs given.
    param([string]$Sid, [string[]]$Sids, [int[]]$Rids, [string]$DomainSid)
    if ($Sids -contains $Sid) { return $true }
    return ($Sid -match '^(S-1-5-21-\d+-\d+-\d+)-(\d+)$' -and $Matches[1] -eq $DomainSid -and $Rids -contains [int]$Matches[2])
}

function Find-TkHardeningWarning {
    param([object[]]$Rows, [string]$DomainSid, [string]$Quota, [string]$Pdc)
    $warnings = @()
    $enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    foreach ($row in $Rows) {
        switch ($row.Kind) {
            'server' {
                if ($row.LdapSigning -lt 2) { $warnings += "$($row.Server): LDAP signing is not required" }
                if ($row.ChannelBinding -lt 2) { $warnings += "$($row.Server): LDAP channel binding is not always required" }
                if ($row.Spooler -eq 'Running') { $warnings += "$($row.Server): the print spooler runs on a controller" }
                if ($row.Server -eq $Pdc -and $row.TimeSource -match 'Local CMOS Clock|Free-running System Clock') { $warnings += "$($row.Server): the PDC emulator takes its time from its own hardware clock ($($row.TimeSource))" }
                if ($row.Server -ne $Pdc -and $row.TimeSource -match 'Local CMOS Clock|Free-running System Clock|time\.windows\.com') { $warnings += "$($row.Server): the controller does not follow the domain's time hierarchy ($($row.TimeSource))" }
                if ($row.TimeStatus -match 'unspecified') { $warnings += "$($row.Server): the time service reports no last synchronization" }
            }
            'ca' { $warnings += "certificate authority $($row.Name) on $($row.Host): check that its web enrollment requires Extended Protection and that EDITF_ATTRIBUTESUBJECTALTNAME2 is off" }
            'template' {
                $risky = (($row.NameFlag -band 1) -ne 0) -or @($row.Usages).Count -eq 0 -or @($row.Usages) -contains '2.5.29.37.0'
                foreach ($entry in (ConvertFrom-TkSddl -Sddl $row.Sddl -DomainSid $DomainSid)) {
                    if (-not (Test-TkSidIn -Sid $entry.Sid -Sids $script:TkLowSids -Rids $script:TkLowRids -DomainSid $DomainSid)) { continue }
                    $enrolls = $entry.Control -and ($entry.Object -eq $enroll -or $entry.Object -eq '')
                    if ($entry.Write -or ($risky -and $enrolls)) { $warnings += "certificate template $($row.Name): $($entry.Sid) may $(if ($entry.Write) { 'write' } else { 'enroll in' }) it$(if ($risky) { ' and it lets the enrollee supply the subject or allows any purpose' })"; break }
                }
            }
            'rc4' { $warnings += "account $($row.Name) has a service principal name and allows RC4" }
        }
    }
    if ($Quota -and $Quota -ne '0') { $warnings += "ms-DS-MachineAccountQuota is ${Quota}: any domain user may create computer accounts" }
    return , $warnings
}

function Find-TkSysvolMatch {
    # The policy files in SYSVOL of one name that hold a pattern.
    param([string]$Domain, [string]$Filter, [string]$Pattern, [string]$Encoding)
    $root = "\\$Domain\SYSVOL\$Domain\Policies"
    if (-not (Test-Path -LiteralPath $root)) { return , @() }
    return , @(Get-ChildItem -LiteralPath $root -Recurse -Filter $Filter -ErrorAction SilentlyContinue |
            Select-String -Pattern $Pattern -Encoding $Encoding -List -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
}

function Find-TkPolicyFinding {
    # Passwords left in Group Policy Preferences, and policies that set the start mode of
    # DHCPServer: in a security template (UTF-16) or as a preference service (Services.xml).
    param([string]$Domain)
    return @{
        Passwords = Find-TkSysvolMatch -Domain $Domain -Filter '*.xml' -Pattern 'cpassword="[^"]+"' -Encoding UTF8
        DhcpStart = @(Find-TkSysvolMatch -Domain $Domain -Filter 'GptTmpl.inf' -Pattern '^\s*"?DHCPServer"?\s*,' -Encoding Unicode) +
        @(Find-TkSysvolMatch -Domain $Domain -Filter 'Services.xml' -Pattern 'serviceName="DHCPServer"' -Encoding UTF8)
    }
}

function Get-TkDomainLocator {
    # The DC locator's answer, with rediscovery forced (nltest /dsgetdc:<domain> /force).
    param([string]$Domain)
    $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $Domain)
    $found = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($context, [System.DirectoryServices.ActiveDirectory.LocatorOptions]::ForceRediscovery)
    return [ordered]@{ name = $found.Name.ToLowerInvariant(); address = [string]$found.IPAddress }
}

function Get-TkPdcName {
    param([string]$Domain)
    $context = [System.DirectoryServices.ActiveDirectory.DirectoryContext]::new('Domain', $Domain)
    return [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context).PdcRoleOwner.Name.ToLowerInvariant()
}

function Get-TkDiscovery {
    # Reads everything the plan, the change list and the warnings need. A DHCP server this
    # run stopped is not read (its recorded reading stands); a list of DHCP servers other than
    # the recorded one is shown and confirmed before any session to them.
    param([string]$Domain, [string[]]$Stopped = @(), [object[]]$Recorded = @(), [string[]]$KnownDhcp = @())
    $pdc = Get-TkPdcName $Domain
    $script:TkKnownHosts = @($pdc)
    $rows = Invoke-TkRemote -Server $pdc -Name ReadDomain
    $info = $rows | Where-Object { $_.Kind -eq 'domain' } | Select-Object -First 1
    if ($null -eq $info -or $info.DnsRoot.ToLowerInvariant() -ne $Domain) { Exit-TkTakeover 1 "the PDC emulator $pdc does not report the domain $Domain" }
    $controllers = @($rows | Where-Object { $_.Kind -eq 'controller' } | ForEach-Object {
            [ordered]@{ name = $_.Name; addresses = @(@($_.IPv4, $_.IPv6) | Where-Object { $_ }); pdc = ($_.Name -eq $pdc); gc = $_.Gc }
        })
    $names = @($controllers | ForEach-Object { $_.name })
    $script:TkKnownHosts = @($names)
    $r = [ordered]@{
        domain = $Domain; forest_root = $info.ForestRoot.ToLowerInvariant(); netbios = $info.NetBIOSName; domain_sid = $info.DomainSid
        domain_dn = $info.DistinguishedName; configuration = $info.Configuration; computers = $info.ComputersContainer
        pdc = $pdc; controllers = $controllers; locator = (Get-TkDomainLocator $Domain); kds = [bool]$info.Kds
        zones = @(); forwarders = @(); directory_zones = @(); dhcp = @(); servers = @(); members = @(); warnings = @(); refusals = @(); window_refusals = @(); values = @()
    }
    if (-not (Test-TkDomainAdmin -Sids (Get-TkTokenSid) -DomainSid $r.domain_sid)) { Exit-TkTakeover 1 "the logon this runs under is not a member of the Domain Admins of $Domain" }

    # DNS, each controller on its own: the lists are per server and never replicate.
    $zoneSet = [ordered]@{}
    foreach ($controller in $names) {
        foreach ($row in (Invoke-TkRemote -Server $controller -Name ReadZones)) {
            if ($row.Type -eq 'ServerForwarder') {
                if ($controller -eq $pdc -and @($row.Masters).Count -gt 0) { $r.forwarders += , [ordered]@{ zone = '.'; servers = @($row.Masters) } }
                continue
            }
            if ($row.Type -eq 'Scavenging') {
                if ($row.Aging) { $r.warnings += "${controller}: server-level scavenging is on" }
                continue
            }
            if ($row.Type -eq 'Forwarder') {
                if ($controller -eq $pdc) { $r.forwarders += , [ordered]@{ zone = $row.Name; servers = @($row.Masters) } }
                continue
            }
            if (-not $zoneSet.Contains($row.Name)) { $zoneSet[$row.Name] = [ordered]@{ name = $row.Name; type = $row.Type; ds = $row.Ds; scope = $row.Scope; partition = [string](Get-TkField $row 'Partition'); update = $row.Update; reverse = $row.Reverse; aging = $row.Aging; servers = [ordered]@{} } }
            $zoneSet[$row.Name].servers[$controller] = [ordered]@{ transfer = $row.Transfer; notify = $row.Notify; secondaries = @($row.Secondaries); notify_servers = @($row.NotifyServers); serial = $row.Serial; type = $row.Type }
            $r.values += @($row.Secondaries) + @($row.NotifyServers) + @($row.Transfer, $row.Notify, $row.Update, $row.Scope, [string](Get-TkField $row 'Partition'))
        }
    }
    foreach ($controller in $controllers) { if (-not (@($zoneSet.Values) | Where-Object { $_.servers.Contains($controller.name) })) { $r.warnings += "$($controller.name) serves no zone (it was never enlisted in the DNS application partitions)" } }
    $r.directory_zones = @(Invoke-TkRemote -Server $pdc -Name ReadDirectoryZones -Arguments @($r.domain_dn, ('DC=' + ($r.forest_root -replace '\.', ',DC='))) | ForEach-Object { [ordered]@{ name = $_.Name; dn = $_.Dn } })
    foreach ($object in $r.directory_zones) {
        if (-not $zoneSet.Contains($object.name) -and $object.name -notmatch '^\.\.') { $r.warnings += "the directory holds the zone object $($object.name), which no server loads: a DNS Server role installed later serves it at once with its old data" }
    }

    # The domain's computers: the member servers the exporter may run on, the members that are
    # DHCP clients, and the DHCP servers' own objects.
    $computers = @(Invoke-TkRemote -Server $pdc -Name ReadComputers -Arguments (, [string[]]$names))
    $r.servers = @($computers | Where-Object { $_.Server -and $_.IPv4 } | ForEach-Object { [ordered]@{ name = $_.Name; address = $_.IPv4; delegation = [bool]$_.Delegation } })

    # DHCP: the forest's authorization list holds other domains' servers and stale names. Only
    # a controller of this domain, or an enabled computer of this domain, each at the address
    # its object names, is a DHCP server of the plan; the rest is shown, never contacted.
    $authorized = @()
    foreach ($entry in @(Invoke-TkRemote -Server $pdc -Name ReadDhcpInDirectory)) {
        $own = @($controllers | Where-Object { $_.name -eq $entry.Name -and @($_.addresses) -contains $entry.Address }).Count -gt 0 -or
        @($computers | Where-Object { $_.Name -eq $entry.Name -and $_.IPv4 -eq $entry.Address }).Count -gt 0
        # A computer any domain user may create (the machine account quota) is no DHCP server.
        $quota = @($computers | Where-Object { $_.Name -eq $entry.Name -and $_.Creator } | Select-Object -First 1)
        if ($quota.Count -gt 0) { Exit-TkTakeover 1 "the DHCP authorization list names $($entry.Name), whose computer object $(ConvertTo-TkSafeText $quota[0].Creator) created under the machine account quota: such an object is no DHCP server of the plan; remove the entry or the object and run again" }
        if ($own) { $authorized += $entry } else { $r.warnings += "the DHCP authorization list names $($entry.Name) ($($entry.Address)), which is no computer of $Domain at that address: it is not contacted" }
    }
    $listed = @($authorized | ForEach-Object { $_.Name } | Sort-Object)
    if ($KnownDhcp.Count -eq 0 -or @($listed | Where-Object { $KnownDhcp -notcontains $_ }).Count -gt 0) {
        foreach ($entry in $authorized) { Write-TkNote "  DHCP server of ${Domain}: $($entry.Name) ($($entry.Address))" }
        if ('y', 'yes' -notcontains (Read-TkAnswer 'Read these DHCP servers? [y/N]').Trim().ToLowerInvariant()) { Exit-TkTakeover 1 'the DHCP servers were not confirmed; nothing was changed' }
    }
    foreach ($computer in $computers | Where-Object { $_.Delegation -and ($listed -contains $_.Name) }) { $r.warnings += "$($computer.Name) is trusted for unconstrained delegation: a session of this script there could hand on its ticket" }
    $script:TkKnownHosts = @($names) + $listed
    foreach ($server in $authorized) {
        if ($Stopped -contains $server.Name) {
            # Its DHCP Server service was stopped by this run: its cmdlets do not answer, and the
            # recorded reading stands.
            $r.warnings += "$($server.Name) is not read: this run stopped its DHCP Server service"
            $r.dhcp += , @($Recorded | Where-Object { $_.name -eq $server.Name })[0]
            continue
        }
        $read = Invoke-TkRemote -Server $server.Name -Name ReadDhcpServer | Select-Object -First 1
        $scopes = @($read.Scopes | ForEach-Object {
                [ordered]@{ id = $_.Id; cidr = (ConvertTo-TkCidr $_.Id $_.Mask); start = $_.Start; end = $_.End; state = $_.State; lease_secs = $_.LeaseSeconds; exclusions = @($_.Exclusions); reservations = @($_.Reservations | ForEach-Object { [ordered]@{ ip = $_.Ip; client = $_.Client } }); hosts = @($_.Hosts) }
            })
        $r.dhcp += , [ordered]@{ name = $server.Name; address = $server.Address; scopes = $scopes; bindings = @($read.Bindings); failover = @($read.Failover | ForEach-Object { [ordered]@{ name = $_.Name; partner = $_.Partner; mode = $_.Mode; scopes = @($_.Scopes) } }); dns_user = $read.DnsUser; v6 = @($read.V6Scopes); multicast = @($read.Multicast); allow_list = $read.AllowList; service_start = $read.Service; conflict = [int]$read.Conflict; policies = @($read.Policies); superscopes = @($read.Superscope) }
        $r.values += @($read.Service)
        foreach ($scope in $scopes) {
            if ($scope.lease_secs -lt $script:TkMinLeaseSec) { $r.window_refusals += "the scope $($scope.cidr) on $($server.Name) has a lease time under an hour ($($scope.lease_secs) s): the DHCP window is refused" }
            if (-not (@($read.Bindings) | Where-Object { Test-TkInNetwork -Address $_ -Network $scope.id -Prefix ([int]$scope.cidr.Split('/')[1]) })) { $r.warnings += "the scope $($scope.cidr) is relayed: the gateway's relay must point at Tenko (a manual change)" }
        }
        if (@($read.V6Scopes).Count -gt 0 -or @($read.Multicast).Count -gt 0) { $r.window_refusals += "$($server.Name) serves DHCPv6 or multicast scopes that Tenko does not take over: stopping the service would silence them" }
        if (@($read.Policies).Count -gt 0) { $r.warnings += "$($server.Name): policies ($(@($read.Policies) -join ', ')) are not taken over" }
        if ($read.AllowList -or $read.DenyList) { $r.warnings += "$($server.Name): filter lists are enabled and are not taken over" }
        if (@($read.Superscope).Count -gt 0) { $r.warnings += "$($server.Name): superscopes are not taken over" }
    }
    $users = @($r.dhcp | ForEach-Object { $_.dns_user } | Select-Object -Unique)
    $r.dns_credential = $(if ($users.Count -eq 1 -and $users[0]) { 'same' } else { 'create' })
    $policies = Find-TkPolicyFinding $Domain
    foreach ($policy in $policies.DhcpStart) { $r.window_refusals += "the group policy $policy sets the start mode of DHCPServer: its owner must remove that setting before the DHCP window" }
    $leaseHosts = @($r.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.hosts })
    $r.members = @($computers | Where-Object { $leaseHosts -contains $_.Name -or $leaseHosts -contains ($_.Name.Split('.')[0]) } | ForEach-Object { $_.Name })

    # The zones of the plan: the domain, _msdcs of the forest root, the scopes' reverse zones.
    $cidrs = @($r.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.cidr } | Select-Object -Unique)
    $planZones = @($Domain, "_msdcs.$($r.forest_root)") + (Get-TkReverseZone -Cidrs $cidrs -Zones @($zoneSet.Keys))
    $r.zones = @($planZones | Where-Object { $zoneSet.Contains($_) } | ForEach-Object { $zoneSet[$_] })
    foreach ($zone in $r.zones) {
        if ($zone.update -eq 'Secure' -and -not $script:TkKerberosLineComplete) {
            $r.refusals += "The zone $($zone.name) takes secure updates only. This release of Tenko cannot yet take over a zone that takes secure updates only without weakening it, because its secure updates (the Kerberos line of the identity plan) are not complete. Nothing was changed. Take over this domain with a release whose notes say the Kerberos line is complete."
        }
        if ($zone.aging) { $r.warnings += "the zone $($zone.name) has aging enabled: a server-level scavenging switched on later writes in it" }
        # The reverse puts a zone back into the partition it was read in.
        if (-not $zone.ds -or 'Domain', 'Forest', 'Legacy', 'Custom' -notcontains [string]$zone.scope -or ($zone.scope -eq 'Custom' -and -not $zone.partition)) {
            $r.refusals += "The zone $($zone.name) is $(if ($zone.ds) { "replicated to '$($zone.scope)'" } else { 'not directory-integrated' }): its reverse could not put it back where it is. Nothing was changed."
        }
    }

    # What a compromised DNS authority with a domain computer account could use.
    $hardening = @()
    foreach ($controller in $names) {
        foreach ($row in (Invoke-TkRemote -Server $controller -Name ReadHardening -Arguments @($r.configuration))) {
            if ($row.Kind -eq 'server') { $row.Server = $controller; $hardening += $row }
            elseif ($controller -eq $pdc) { $hardening += $row }
        }
    }
    $r.warnings += Find-TkHardeningWarning -Rows $hardening -DomainSid $r.domain_sid -Quota $info.Quota -Pdc $pdc
    foreach ($path in $policies.Passwords) { $r.warnings += "a password is left in Group Policy Preferences: $path" }
    $r.values = @($r.values | Where-Object { $null -ne $_ -and $_ -ne '' } | Select-Object -Unique)
    return $r
}

function Select-TkMirrorHost {
    # The member server the exporter runs on, from the domain's reachable member servers.
    param([System.Collections.IDictionary]$Readings, [string]$Chosen)
    $candidates = @($Readings.servers)
    if ($Chosen) { $pick = @($candidates | Where-Object { $_.name -eq $Chosen }) }
    else {
        if ($candidates.Count -eq 0) { Exit-TkTakeover 1 'the domain has no member server for the exporter; a controller is never the mirror host' }
        for ($i = 0; $i -lt $candidates.Count; $i++) { Write-TkNote ("  {0,3}  {1} ({2})" -f ($i + 1), $candidates[$i].name, $candidates[$i].address) }
        $answer = Read-TkAnswer 'The member server the exporter runs on (number)'
        $number = 0
        if (-not [int]::TryParse($answer, [ref]$number) -or $number -lt 1 -or $number -gt $candidates.Count) { Exit-TkTakeover 1 'no mirror host was chosen' }
        $pick = @($candidates[$number - 1])
    }
    if ($pick.Count -ne 1) { Exit-TkTakeover 1 "$Chosen is not a member server of the domain" }
    if (Get-TkField $pick[0] 'delegation') { $Readings.warnings += "the mirror host $($pick[0].name) is trusted for unconstrained delegation: a session of this script there could hand on its ticket" }
    $script:TkKnownHosts += $pick[0].name
    if (-not (Test-WSMan -ComputerName $pick[0].name -Authentication Kerberos -ErrorAction SilentlyContinue)) { Exit-TkTakeover 1 "WinRM does not answer on $($pick[0].name), port 5985" }
    $admins = @(Invoke-TkRemote -Server $pick[0].name -Name ReadLocalAdmins)
    foreach ($admin in $admins) {
        if ($admin.Sid -notmatch "^$([regex]::Escape($Readings.domain_sid))-(500|512|519)$" -and $admin.Sid -notmatch '-500$') {
            $Readings.warnings += "$($admin.Name) is a local administrator of the mirror host $($pick[0].name): it could read the exporter's tokens and forge pushes"
        }
    }
    $tools = Invoke-TkRemote -Server $pick[0].name -Name ReadFeature -Arguments @('RSAT-DHCP')
    $Readings.mirror_host = [ordered]@{ name = $pick[0].name; address = $pick[0].address; tools = [bool]($tools | Select-Object -First 1) }
}

function Get-TkNodeName {
    # The node's name: the label of the typed host name under the domain. Not on the deny
    # list, no computer object and no service principal name of the domain, and every address
    # it resolves to is the node's.
    param([string]$HostName, [string]$Domain, [string]$Pdc, [string]$Address)
    $candidate = ''
    if ($HostName.ToLowerInvariant().EndsWith(".$Domain")) { $candidate = $HostName.ToLowerInvariant().Substring(0, $HostName.Length - $Domain.Length - 1) }
    if ($candidate -cnotmatch $script:TkLabelPattern) { $candidate = '' }
    if (-not $candidate) { Exit-TkTakeover 1 "type Tenko's address as its host name under $Domain (for example tenko.$Domain), so that its name in the zones is known" }
    if ($script:TkDeniedNodeNames -contains $candidate) { Exit-TkTakeover 1 "the node's name $candidate is on the deny list (wpad, isatap, localhost)" }
    $use = Invoke-TkRemote -Server $Pdc -Name ReadNameUse -Arguments @($candidate, $Domain) | Select-Object -Last 1
    if ($use.Sid -or $use.Spns -gt 0) { Exit-TkTakeover 1 "the name $candidate is taken in ${Domain} (a computer account or a service principal name): Tenko's name must be its own" }
    $resolved = @()
    try { $resolved = @(Get-TkHostAddress "$candidate.$Domain") } catch { $resolved = @() }
    foreach ($found in $resolved) {
        if ([string]$found -ne $Address) { Exit-TkTakeover 1 "$candidate.$Domain resolves to $found, which is not the node's address $Address" }
    }
    return $candidate
}

function Get-TkPlan {
    # The plan as sent in the approval: what the person reads and what Tenko holds the run to.
    param([System.Collections.IDictionary]$Readings, [string]$NodeName)
    $scopes = @($Readings.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.cidr } | Select-Object -Unique)
    $relationship = @($Readings.dhcp | ForEach-Object { $_.failover } | ForEach-Object { $_.name } | Select-Object -Unique)
    $operations = @('mirrors', 'secondary_zones')
    if (@($Readings.forwarders).Count -gt 0) { $operations += 'forwarding_rules' }
    $operations += 'update_policy'
    if (@($Readings.zones | Where-Object { $_.update -eq 'Secure' }).Count -gt 0) { $operations += 'kerberos_adopt' }
    $operations += 'prepare', 'flip', 'takeover', 'release'
    $plan = [ordered]@{
        domain       = $Readings.domain
        forest_root  = $Readings.forest_root
        controllers  = @($Readings.controllers | ForEach-Object { [ordered]@{ name = $_.name; addresses = @($_.addresses); pdc = [bool]$_.pdc } })
        zones        = @($Readings.zones | ForEach-Object { $_.name })
        forwarders   = @($Readings.forwarders | ForEach-Object { [ordered]@{ zone = $_.zone; servers = @($_.servers) } })
        dhcp_servers = @($Readings.dhcp | ForEach-Object { [ordered]@{ name = $_.name; address = $_.address } })
    }
    if ($relationship.Count -eq 1) { $plan.relationship = $relationship[0] }
    $plan.scopes = $scopes
    $plan.mirror_host = [ordered]@{ name = $Readings.mirror_host.name; address = $Readings.mirror_host.address }
    $plan.node_name = $NodeName
    $plan.operations = $operations
    # Tenko's computer account, exactly when the run adopts one.
    if ($operations -contains 'kerberos_adopt') { $plan.kerberos = [ordered]@{ realm = $Readings.domain.ToUpperInvariant(); account = "$($NodeName.ToUpperInvariant())$"; spns = @("DNS/$NodeName.$($Readings.domain)") } }
    return $plan
}

function Show-TkChangeList {
    # The change list, per system and machine, each line with its reverse.
    param([System.Collections.IDictionary]$Readings, [string]$NodeName)
    $pdc = $Readings.pdc
    $lines = @()
    $lines += "This script acts as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) with the rights of a domain administrator."
    $lines += 'Changes on Windows (each with its reverse):'
    foreach ($server in $Readings.dhcp) { $lines += "  $($server.name): backup with Export-DhcpServer -Leases (kept)" }
    foreach ($zone in $Readings.zones) { $lines += "  ${pdc}: backup of $($zone.name) with Export-DnsServerZone (kept)" }
    $lines += "  domain: the exporter's account $($script:TkMirrorAccount) ($(if ($Readings.kds) { 'group managed service account' } else { 'user with a random password' })) in DHCP Users (removed)"
    if (-not $Readings.mirror_host.tools) { $lines += "  $($Readings.mirror_host.name): the DHCP management tools added (removed)" }
    foreach ($server in $Readings.dhcp) { $lines += "  $($Readings.mirror_host.name): the exporter's task for $($server.name) (removed with its token, state and batch logon right)" }
    foreach ($zone in $Readings.zones) { $lines += "  ${pdc}: Tenko added to the transfer and notify lists of $($zone.name) (the old lists restored)" }
    if ($Readings.dns_credential -eq 'create') { $lines += "  domain and every DHCP server: the DNS credential user $($script:TkDnsCredentialUser) (removed)" }
    if (@($Readings.zones | Where-Object { $_.update -eq 'Secure' }).Count -gt 0) { $lines += "  domain: Tenko's computer account $NodeName$ in $($Readings.computers), DNS/$NodeName.$($Readings.domain), AES only, no delegation (removed after the zones are set back)" }
    $lines += "  domain: the group policy object '$($script:TkGpoName)' for $(@($Readings.members).Count) member computers (removed)"
    foreach ($zone in $Readings.zones) { $lines += "  every controller, at the DNS window: $($zone.name) becomes a secondary of Tenko (made directory-integrated again, its update setting $($zone.update) restored)" }
    foreach ($server in $Readings.dhcp) { $lines += "  $($server.name), at the DHCP window: the DHCP Server service stopped and disabled, its authorization removed (authorized and started again)" }
    $lines += '  after the parallel period, the finish: the exporter, its accounts, the zone objects and the mirrors removed, the DHCP Server role left installed (no scripted way back)'
    $lines += 'Changes on Tenko: the mirrors, the secondary zones (not served), the forwarding rules (inactive), the prepare, then at the windows the flip and the takeover (each reverted).'
    if (@($Readings.warnings).Count -gt 0) { $lines += 'Warnings:'; foreach ($w in $Readings.warnings) { $lines += "  - $w" } }
    $minimum = @($Readings.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.lease_secs } | Measure-Object -Minimum).Minimum
    if ($minimum) { $lines += "Clients move to Tenko within seven eighths of the lease time: $([math]::Round($minimum * 7 / 8 / 3600, 1)) hours for the shortest scope." }
    foreach ($line in $lines) { Write-TkNote $line }
}

# ---------------------------------------------------------------------------------------
# Steps: each checks the actual state and acts only when it differs, records itself in the
# state file, and has its reverse.
# ---------------------------------------------------------------------------------------

function Invoke-TkStepList {
    param([hashtable]$State, [string]$Phase, [object[]]$Steps)
    foreach ($step in $Steps) {
        $key = "$Phase.$($step.Name)"
        $record = Get-TkField $State.Data.steps $key
        if ($null -ne $record -and $record.state -eq 'done') { continue }
        $State.Data.steps[$key] = [ordered]@{ state = 'running'; at = [datetime]::UtcNow.ToString('o') }
        Save-TkState $State
        try {
            & $step.Do
        } catch {
            $State.Data.steps[$key] = [ordered]@{ state = 'failed'; at = [datetime]::UtcNow.ToString('o'); error = (ConvertTo-TkSafeText $_.Exception.Message) }
            $State.Data.phases[$Phase] = 'failed'
            Save-TkState $State
            if (-not $_.Exception.Data.Contains('tk.exit')) { $_.Exception.Data['tk.exit'] = 2 }
            Write-TkNote "The step $key failed. Run the script again to resume at this step after reading the actual state$(if ($Phase -ne '6') { ", or run it with -Reverse to undo the phase's done steps" })."
            throw
        }
        $State.Data.steps[$key] = [ordered]@{ state = 'done'; at = [datetime]::UtcNow.ToString('o') }
        Save-TkState $State
    }
    $State.Data.phases[$Phase] = 'done'
    Save-TkState $State
}

function Undo-TkStepList {
    param([hashtable]$State, [string]$Phase, [object[]]$Steps)
    [array]::Reverse($Steps)
    foreach ($step in $Steps) {
        $key = "$Phase.$($step.Name)"
        $record = Get-TkField $State.Data.steps $key
        if ($null -eq $record -or $record.state -eq 'reversed') { continue }
        if ($step.ContainsKey('Undo') -and $null -ne $step.Undo) { & $step.Undo }
        $State.Data.steps[$key] = [ordered]@{ state = 'reversed'; at = [datetime]::UtcNow.ToString('o') }
        Save-TkState $State
    }
    $State.Data.phases[$Phase] = 'reversed'
    Save-TkState $State
}

function Get-TkRandomSecret {
    # A random password of 32 characters as a SecureString; it exists nowhere else.
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_.!'
    $bytes = [byte[]]::new(32)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $secret = [securestring]::new()
    $secret.AppendChar('T'); $secret.AppendChar('k'); $secret.AppendChar('1'); $secret.AppendChar('-')
    foreach ($byte in $bytes) { $secret.AppendChar($alphabet[$byte % $alphabet.Length]) }
    [System.Array]::Clear($bytes, 0, $bytes.Length)
    $secret.MakeReadOnly()
    return $secret
}

function Get-TkZoneId {
    # Tenko's id of a plan zone, found by name among the zones it lists.
    param([string]$Name)
    $page = Invoke-Tenko -Method GET -Path "/dns/zones?name=$Name"
    foreach ($item in @(Get-TkField $page 'items')) {
        if ([string](Get-TkField $item 'name') -eq $Name -and [string](Get-TkField $item 'id') -cmatch $script:TkUuidPattern) { return [string]$item.id }
    }
    return ''
}

function Wait-TkJob {
    # A job of the run until it reaches a final state, or until a step waits for a person.
    param([string]$Id, [string]$ManualKind)
    if ($Id -cnotmatch $script:TkUuidPattern) { Exit-TkTakeover 4 'Tenko named a job that is not of the exact form' }
    while ($true) {
        $detail = Invoke-Tenko -Method GET -Path "/jobs/$Id"
        $job = Get-TkField $detail 'job'
        $state = [string](Get-TkField $job 'state')
        if ($ManualKind) {
            foreach ($step in @(Get-TkField $job 'steps')) {
                if ([string](Get-TkField $step 'kind') -eq $ManualKind -and [string](Get-TkField (Get-TkField $step 'state') 'state') -eq 'waiting_for_manual') {
                    return @{ State = $state; Step = [int](Get-TkField $step 'index') }
                }
            }
        }
        if ('succeeded', 'failed', 'rolled_back', 'canceled' -contains $state) { return @{ State = $state; Step = -1 } }
        Start-Sleep -Seconds $script:TkPollSec
    }
}

# ---------------------------------------------------------------------------------------
# Phase 2: prepare, nothing served
# ---------------------------------------------------------------------------------------

function Assert-TkSid {
    param([string]$Sid)
    if ($Sid -cnotmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { Exit-TkTakeover 4 "$(ConvertTo-TkSafeText $Sid) is not the SID of an account of the domain" }
    return $Sid
}

function Get-TkMirrorToken {
    # The mirror of a DHCP server and its token, which lives in this process only: a mirror
    # whose token an earlier sitting held is made anew, within five minutes of the approval.
    param([hashtable]$State, [System.Collections.IDictionary]$Server)
    $r = $State.Data.readings
    $old = Get-TkField $State.Data.mirrors $Server.name
    if ($old) { [void](Invoke-Tenko -Method DELETE -Path "/migrate/mirrors/$old" -Expect @(200, 204, 404)) }
    $created = Invoke-Tenko -Method POST -Path '/migrate/mirrors' -Body ([ordered]@{ name = $Server.name; kind = 'windows-dhcp'; source_prefixes = @("$($r.mirror_host.address)/32") })
    $id = [string](Get-TkField (Get-TkField $created 'mirror') 'id')
    $token = Get-TkField $created 'token'
    $fingerprint = ([string](Get-TkField $created 'ca_fingerprint') -replace '[:\s]', '').ToLowerInvariant()
    if ($id -cnotmatch $script:TkUuidPattern -or -not ($token -is [securestring]) -or -not (Test-TkSecurePattern $token $script:TkTokenPattern)) { Exit-TkTakeover 4 "Tenko answered a mirror id or token for $($Server.name) that is not of the exact form" }
    if ($fingerprint -and $fingerprint -ne $State.Data.tenko.fingerprint) { Exit-TkTakeover 4 'the fingerprint Tenko names for the mirror is not the pinned root' }
    $State.Data.mirrors[$Server.name] = $id
    $script:TkTokens[$Server.name] = $token
    Save-TkState $State
}

function Get-TkRunMark {
    # The mark of one object of the run: SHA-256 over a secret that only the state file holds
    # and the object's name, so that the mark one object carries fits no other name. The
    # secret is recorded before the run creates its first object.
    param([hashtable]$State, [string]$Name)
    $secret = [string](Get-TkField $State.Data.values 'mark_secret')
    if ($secret -cnotmatch '^[0-9a-f]{64}$') {
        $bytes = [byte[]]::new(32)
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $secret = ConvertTo-TkHex $bytes
        $State.Data.values.mark_secret = $secret
        Save-TkState $State
    }
    return 'Tenko takeover ' + (ConvertTo-TkHex (Get-TkSha256 ([System.Text.Encoding]::UTF8.GetBytes("$secret|$($Name.ToLowerInvariant())"))))
}

function Get-TkForeignWriter {
    # The entries of an object's access list that may write it or hold a control right over
    # it, outside the closed list: SYSTEM, Administrators, SELF, the object itself, the
    # domain's Domain, Enterprise, Key and Enterprise Key Admins, Account Operators while
    # empty, and a computer object's default groups for their default attributes only. The
    # rights to change a password knowing the old one and to apply a group policy are no
    # control over the object.
    param([string]$Sddl, [string]$DomainSid, [string]$Self, [int]$AccountOps)
    $trusted = @($script:TkTrustedSids) + @('S-1-3-0', $Self) + @($(if ($AccountOps -eq 0) { 'S-1-5-32-548' }))
    $harmless = @('ab721a53-1e2f-11d0-9819-00aa0040529b', 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')
    $scoped = @{}
    foreach ($key in $script:TkScopedSids.Keys) { $scoped[$key] = $script:TkScopedSids[$key] }
    foreach ($rid in $script:TkScopedRids.Keys) { $scoped["$DomainSid-$rid"] = $script:TkScopedRids[$rid] }
    foreach ($entry in (ConvertFrom-TkSddl -Sddl $Sddl -DomainSid $DomainSid)) {
        if (Test-TkSidIn -Sid $entry.Sid -Sids $trusted -Rids $script:TkTrustedRids -DomainSid $DomainSid) { continue }
        if ($entry.Write -and -not $entry.Control -and $scoped.ContainsKey($entry.Sid) -and $scoped[$entry.Sid] -contains $entry.Object) { continue }
        if ($entry.Write -or ($entry.Control -and $harmless -notcontains $entry.Object)) { $entry }
    }
}

function Resolve-TkRunObject {
    # An object of the run's name that exists: the run's own by the SID or id the state file
    # recorded, or, after a sitting that ended between the creation and that record, by its
    # mark, and then only while no one made it under the machine account quota, the Domain
    # Admins of this domain own it, and no one outside the closed list may write it. Anything
    # else is refused, never adopted. Returns the id to go on with.
    param([hashtable]$State, [string]$Kind, [string]$Name, [string]$Known)
    $r = $State.Data.readings
    $found = Invoke-TkRemote -Server $r.pdc -Name ReadRunObject -Arguments @($Kind, $Name) | Select-Object -Last 1
    if ($null -eq $found -or -not [string]$found.Id -or [string]$found.Id -eq $Known) { return $Known }
    $what = $(if ($Kind -eq 'gpo') { "the group policy object '$Name'" } else { "the account $Name" })
    if ([string]$found.Mark -cne (Get-TkRunMark -State $State -Name $Name)) { Exit-TkTakeover 1 "$what exists and carries neither the SID nor the mark of this run: it is not used and never removed" }
    if ([string]$found.Creator) { Exit-TkTakeover 1 "$what carries this run's mark but was created by $(ConvertTo-TkSafeText $found.Creator) under the machine account quota: it is not used and never removed" }
    $owner = $(if ([string]$found.Sddl -match '^O:([^:]+?)G:') { $Matches[1] } else { '' })
    if ($owner -ne 'DA' -and $owner -ne "$($r.domain_sid)-512") { Exit-TkTakeover 1 "$what carries this run's mark but is owned by $(ConvertTo-TkSafeText $owner), not by the Domain Admins of $($r.domain): it is not used and never removed" }
    $writers = @(Get-TkForeignWriter -Sddl ([string]$found.Sddl) -DomainSid $r.domain_sid -Self ([string]$found.Id) -AccountOps ([int]$found.AccountOps) | ForEach-Object { $_.Sid } | Select-Object -Unique)
    if ($writers.Count -gt 0) { Exit-TkTakeover 1 "$what carries this run's mark but may be written by $($writers -join ', '): it is not used and never removed" }
    return [string]$found.Id
}

function Add-TkRunAccount {
    # An account of the run: created, or the one this run created before (by its recorded
    # SID or its mark), with a new password where it has one. The SID is recorded at once.
    param([hashtable]$State, [string]$Key, [string]$Name, [bool]$Gmsa, [bool]$DhcpUsers)
    $r = $State.Data.readings
    $account = $(if ($Gmsa) { "$Name$" } else { $Name })
    $mark = Get-TkRunMark -State $State -Name $account
    $known = Resolve-TkRunObject -State $State -Kind 'account' -Name $account -Known ([string](Get-TkField $State.Data.values $Key))
    $password = $(if ($Gmsa) { $null } else { Get-TkRandomSecret })
    $sid = Assert-TkSid ([string](Invoke-TkRemote -Server $r.pdc -Name NewAccount -Arguments @($Name, $Gmsa, $r.domain, ($r.mirror_host.name.Split('.')[0] + '$'), $password, $known, $DhcpUsers, $mark) | Select-Object -Last 1))
    $State.Data.values[$Key] = $sid
    Save-TkState $State
    # An account found rather than made has a password no process of this run holds.
    if (-not $Gmsa) { [void](Invoke-TkRemote -Server $r.pdc -Name ResetPassword -Arguments @($sid, $password)) }
    return $password
}

function Clear-TkRunAccount {
    # Only an account this run created, by the SID it recorded.
    param([hashtable]$State, [string]$Key)
    $sid = [string](Get-TkField $State.Data.values $Key)
    if (-not $sid) { return }
    [void](Invoke-TkRemote -Server $State.Data.readings.pdc -Name RemoveAccount -Arguments @((Assert-TkSid $sid)))
    $State.Data.values.Remove($Key)
    Save-TkState $State
}

$script:TkInstallerContract = @('Url', 'MirrorId', 'Fingerprint', 'Account', 'Credential', 'Token', 'TaskName', 'DataDir', 'ComputerName', 'SkipDryRun', 'Remove')

function Assert-TkInstallerContract {
    # The installer this release carries takes every parameter the scripted install passes;
    # read from its parameter block, never run here.
    param([string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    $have = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    $missing = @($script:TkInstallerContract | Where-Object { $have -notcontains $_ })
    if ($missing.Count -gt 0) { Exit-TkTakeover 1 "the exporter's installer of this release has no -$($missing -join ', -'): the scripted install of the exporter cannot run with it; nothing was changed" }
}

function Get-TkPhase2 {
    param([hashtable]$State, [hashtable]$Payloads)
    $r = $State.Data.readings
    $pdc = $r.pdc
    $mirrorHost = $r.mirror_host.name
    $tenkoIp = [string]$State.Data.tenko.address
    $gmsa = [bool]$r.kds
    $url = "https://$($State.Data.tenko.host):$($State.Data.tenko.port)"
    $account = "$($r.netbios)\$($script:TkMirrorAccount)$(if ($gmsa) { '$' })"
    $exporterFile = $Payloads.exporter
    $installerFile = $Payloads.installer
    $steps = @(
        @{ Name = 'mirrors'
            # First, within five minutes of the approval: the creation mints the tokens.
            Do = { foreach ($server in $r.dhcp) { if (-not $script:TkTokens.ContainsKey($server.name)) { Get-TkMirrorToken -State $State -Server $server } } }
            Undo = { foreach ($id in @($State.Data.mirrors.Values)) { [void](Invoke-Tenko -Method DELETE -Path "/migrate/mirrors/$id" -Expect @(200, 204, 404)) }; $State.Data.mirrors = [ordered]@{} }
        }
        @{ Name = 'backups'
            Do = {
                $backup = Join-Path $State.Dir 'backup'
                foreach ($server in $r.dhcp) {
                    $folder = Protect-TkRemoteDirectory -Server $server.name -Below @('takeover', 'backup')
                    [void](Invoke-TkRemote -Server $server.name -Name ExportDhcp -Arguments @("$folder\dhcp-export.xml"))
                    Copy-TkFromServer -Server $server.name -RemotePath "$folder\dhcp-export.xml" -LocalPath (Join-Path $backup "dhcp-$($server.name).xml")
                }
                foreach ($zone in $r.zones) {
                    $file = "tenko-backup-$($zone.name).dns"
                    $remote = [string](Invoke-TkRemote -Server $pdc -Name ExportZone -Arguments @($zone.name, $file) | Select-Object -Last 1)
                    Copy-TkFromServer -Server $pdc -RemotePath $remote -LocalPath (Join-Path $backup $file)
                }
            }
        }
        @{ Name = 'mirror-account'
            Do = { $script:TkMirrorPassword = Add-TkRunAccount -State $State -Key 'mirror_account_sid' -Name $script:TkMirrorAccount -Gmsa $gmsa -DhcpUsers $true }
            Undo = { Clear-TkRunAccount -State $State -Key 'mirror_account_sid' }
        }
        @{ Name = 'mirror-tools'
            Do = { if (-not $r.mirror_host.tools) { [void](Invoke-TkRemote -Server $mirrorHost -Name SetFeature -Arguments @('RSAT-DHCP', $true)) } }
            Undo = { if (-not $r.mirror_host.tools) { [void](Invoke-TkRemote -Server $mirrorHost -Name SetFeature -Arguments @('RSAT-DHCP', $false)) } }
        }
        @{ Name = 'exporter'
            Do = {
                Assert-TkInstallerContract -Path $installerFile.Path
                $payloadDir = Protect-TkRemoteDirectory -Server $mirrorHost -Below @('takeover', 'payload')
                $mirrorDir = Protect-TkRemoteDirectory -Server $mirrorHost -Below @('takeover', 'mirror')
                Copy-TkToServer -Server $mirrorHost -Files @($exporterFile, $installerFile) -Directory $payloadDir
                $credential = $null
                if (-not $gmsa) {
                    if ($null -eq $script:TkMirrorPassword) { $script:TkMirrorPassword = Add-TkRunAccount -State $State -Key 'mirror_account_sid' -Name $script:TkMirrorAccount -Gmsa $false -DhcpUsers $true }
                    $credential = [pscredential]::new($account, $script:TkMirrorPassword)
                }
                foreach ($server in $r.dhcp) {
                    $short = $server.name.Split('.')[0]
                    if (-not $script:TkTokens.ContainsKey($server.name)) { Get-TkMirrorToken -State $State -Server $server }
                    $result = Invoke-TkRemote -Server $mirrorHost -Name InstallExporter -Arguments @($payloadDir, $url, $State.Data.mirrors[$server.name], $State.Data.tenko.fingerprint, $account, $credential, $script:TkTokens[$server.name], "Tenko DHCP mirror $short", "$mirrorDir\$short", $server.name, $installerFile.Sha256) | Select-Object -Last 1
                    if ($result.Pending -or -not $result.Stored) { throw "the exporter's first run for $($server.name) did not store its token (token.pending left or no token.dpapi)" }
                }
            }
            Undo = {
                $payloadDir = Protect-TkRemoteDirectory -Server $mirrorHost -Below @('takeover', 'payload')
                $mirrorDir = Protect-TkRemoteDirectory -Server $mirrorHost -Below @('takeover', 'mirror')
                foreach ($server in $r.dhcp) {
                    $short = $server.name.Split('.')[0]
                    $result = Invoke-TkRemote -Server $mirrorHost -Name RemoveExporter -Arguments @($payloadDir, "Tenko DHCP mirror $short", "$mirrorDir\$short", $installerFile.Sha256) | Select-Object -Last 1
                    if ($result.Pending -or $result.Task) { throw "the exporter of $($server.name) is not fully removed from $mirrorHost" }
                }
                $sid = [string](Get-TkField $State.Data.values 'mirror_account_sid')
                if ($sid) {
                    $work = Protect-TkRemoteDirectory -Server $mirrorHost -Below @('takeover', 'work')
                    if (-not (Invoke-TkRemote -Server $mirrorHost -Name RemoveBatchRight -Arguments @((Assert-TkSid $sid), $work) | Select-Object -Last 1)) { throw "the batch logon right of the exporter's account is still granted on $mirrorHost" }
                }
            }
        }
        @{ Name = 'zone-lists'
            Do = {
                foreach ($zone in $r.zones) {
                    $before = $zone.servers[$pdc]
                    $secondaries = @(@($before.secondaries) + $tenkoIp | Select-Object -Unique)
                    $notify = @(@($before.notify_servers) + $tenkoIp | Select-Object -Unique)
                    $now = Invoke-TkRemote -Server $pdc -Name SetZoneLists -Arguments @($zone.name, [string[]]$secondaries, 'TransferToSecureServers', 'NotifyServers', [string[]]$notify) | Select-Object -Last 1
                    if (@($now.Secondaries) -notcontains $tenkoIp -or @($now.NotifyServers) -notcontains $tenkoIp) { throw "the transfer and notify lists of $($zone.name) on $pdc do not name Tenko after the change" }
                }
            }
            Undo = { foreach ($zone in $r.zones) { Restore-TkZoneList -Readings $r -Zone $zone } }
        }
        @{ Name = 'dns-credential'
            Do = {
                if ($r.dns_credential -ne 'create') { return }
                $password = Add-TkRunAccount -State $State -Key 'dns_user_sid' -Name $script:TkDnsCredentialUser -Gmsa $false -DhcpUsers $false
                $credential = [pscredential]::new("$($r.netbios)\$($script:TkDnsCredentialUser)", $password)
                foreach ($server in $r.dhcp) { [void](Invoke-TkRemote -Server $server.name -Name SetDnsCredential -Arguments @($credential, $false)) }
            }
            Undo = {
                if ($r.dns_credential -ne 'create') { return }
                foreach ($server in $r.dhcp) {
                    if ($server.dns_user) { Write-Warning "$($server.name) had the DNS credential $($server.dns_user) before; set it again there with Set-DhcpServerDnsCredential (its password was never read)" }
                    [void](Invoke-TkRemote -Server $server.name -Name SetDnsCredential -Arguments @($null, $true))
                }
                Clear-TkRunAccount -State $State -Key 'dns_user_sid'
            }
        }
        @{ Name = 'tenko-account'
            Do = { Invoke-TkTenkoAccount -State $State }
            Undo = {
                # Only once every zone is back on its update setting, read back.
                foreach ($zone in $r.zones) {
                    $now = Invoke-TkRemote -Server $pdc -Name ReadZone -Arguments @($zone.name) | Select-Object -Last 1
                    if ($null -ne $now -and $now.Update -ne $zone.update) { throw "the zone $($zone.name) is not back on its update setting $($zone.update); Tenko's account stays until it is" }
                }
                Clear-TkRunAccount -State $State -Key 'tenko_account_sid'
            }
        }
        @{ Name = 'gpo'
            Do = {
                $members = @($r.members | Where-Object { $_ } | ForEach-Object { $_.Split('.')[0] })
                $mark = Get-TkRunMark -State $State -Name $script:TkGpoName
                $known = Resolve-TkRunObject -State $State -Kind 'gpo' -Name $script:TkGpoName -Known ([string](Get-TkField $State.Data.values 'gpo'))
                $State.Data.values.gpo = [string](Invoke-TkRemote -Server $pdc -Name NewGpo -Arguments @($script:TkGpoName, $r.domain_dn, [string[]]$members, $known, $mark) | Select-Object -Last 1)
                Save-TkState $State
            }
            Undo = { if ($State.Data.values.Contains('gpo')) { [void](Invoke-TkRemote -Server $pdc -Name RemoveGpo -Arguments @($State.Data.values.gpo)) } }
        }
        @{ Name = 'tenko-zones'
            Do = {
                foreach ($zone in $r.zones) {
                    if (-not (Get-TkZoneId $zone.name)) {
                        [void](Invoke-Tenko -Method POST -Path '/dns/zones' -Body ([ordered]@{ name = $zone.name; kind = 'secondary'; catalog = $false; served = $false; primaries = @([ordered]@{ address = ($r.controllers | Where-Object { $_.pdc } | Select-Object -First 1).addresses[0] }) }))
                    }
                    [void](Invoke-Tenko -Method POST -Path "/dns/zones/$(Get-TkZoneId $zone.name)/transfer")
                }
                foreach ($forwarder in $r.forwarders) {
                    if ($forwarder.zone -eq '.') { continue }
                    [void](Invoke-Tenko -Method POST -Path '/dns/forwarders' -Body ([ordered]@{ suffix = $forwarder.zone; upstreams = @($forwarder.servers | ForEach-Object { [ordered]@{ address = $_ } }); enabled = $false }) -Expect @(200, 201, 409))
                }
            }
            Undo = {
                foreach ($zone in $r.zones) { $id = Get-TkZoneId $zone.name; if ($id) { [void](Invoke-Tenko -Method DELETE -Path "/dns/zones/$id" -Expect @(200, 204, 404)) } }
            }
        }
        @{ Name = 'tenko-pair'
            Do = {
                $ids = @($State.Data.mirrors.Values)
                if ($ids.Count -eq 2) {
                    [void](Invoke-Tenko -Method PATCH -Path "/migrate/mirrors/$($ids[0])" -Body ([ordered]@{ partner = $ids[1] }))
                }
                foreach ($id in $ids) {
                    while ($null -eq (Get-TkField (Invoke-Tenko -Method GET -Path "/migrate/mirrors/$id") 'last_sequence')) { Start-Sleep -Seconds $script:TkPollSec }
                }
                foreach ($server in $r.dhcp) {
                    foreach ($scope in $server.scopes) {
                        $key = "prepare.$($scope.cidr)"
                        if (Get-TkField $State.Data.jobs $key) { continue }
                        $job = Invoke-Tenko -Method POST -Path "/migrate/mirrors/$($State.Data.mirrors[$server.name])/scopes/$($scope.cidr -replace '/', '%2F')/prepare"
                        $State.Data.jobs[$key] = [string](Get-TkField $job 'id')
                        $done = Wait-TkJob -Id $State.Data.jobs[$key]
                        if ($done.State -ne 'succeeded') { throw "the prepare of $($scope.cidr) ended $($done.State)" }
                    }
                }
            }
        }
    )
    return , $steps
}

function Restore-TkZoneList {
    # The PDC emulator's transfer and notify lists of a zone as the discovery recorded them.
    param([System.Collections.IDictionary]$Readings, [System.Collections.IDictionary]$Zone)
    $before = $Zone.servers[$Readings.pdc]
    foreach ($value in @($before.secondaries) + @($before.notify_servers) + @($before.transfer, $before.notify)) { if ($value) { Assert-TkRestoreValue -Readings $Readings -Value $value -Class discovered } }
    [void](Invoke-TkRemote -Server $Readings.pdc -Name SetZoneLists -Arguments @($Zone.name, [string[]]@($before.secondaries), $before.transfer, $before.notify, [string[]]@($before.notify_servers)))
}

function Invoke-TkTenkoAccount {
    # Tenko's computer account for zones that took secure updates, with a one-time password
    # made here; disabled when Tenko has not changed it within ten minutes of the adoption.
    param([hashtable]$State)
    $r = $State.Data.readings
    if (@($r.zones | Where-Object { $_.update -eq 'Secure' }).Count -eq 0) { return }
    $node = $State.Data.tenko.node
    if ($node -cnotmatch $script:TkLabelPattern) { Exit-TkTakeover 4 "the node's name in the state file is not a host label" }
    $password = Get-TkRandomSecret
    $mark = Get-TkRunMark -State $State -Name "$node$"
    $known = Resolve-TkRunObject -State $State -Kind 'account' -Name "$node$" -Known ([string](Get-TkField $State.Data.values 'tenko_account_sid'))
    $account = Invoke-TkRemote -Server $r.pdc -Name NewTenkoAccount -Arguments @($node, $r.computers, "DNS/$node.$($r.domain)", $password, $known, $mark) | Select-Object -Last 1
    $sid = Assert-TkSid $account.Sid
    $State.Data.values.tenko_account_sid = $sid
    Save-TkState $State
    if (@($account.Groups).Count -gt 0) { throw "Tenko's account is a member of $(@($account.Groups) -join ', ')" }
    if (($account.Uac -band 0x1080000) -ne 0 -or @($account.DelegateTo).Count -gt 0) { throw "Tenko's account allows delegation" }
    if ($account.Encryption -ne 24) { throw "Tenko's account's encryption types are $($account.Encryption), not AES only (24)" }
    if (@($account.Spns).Count -ne 1 -or $account.Spns[0] -ne "DNS/$node.$($r.domain)") { throw "Tenko's account carries the names $(@($account.Spns) -join ', ')" }
    # By SID against a closed list, the account itself included; a computer object's default
    # groups only for the attributes they hold by default.
    foreach ($entry in (Get-TkForeignWriter -Sddl $account.Sddl -DomainSid $r.domain_sid -Self $sid -AccountOps $account.AccountOps)) {
        Write-Warning "$($entry.Sid) may $(if ($entry.Write) { 'write' } else { 'reset the password of' }) Tenko's account"
    }
    if ($account.AccountOps -gt 0) { Write-Warning "Account Operators is not empty: its members may reset Tenko's account" }
    $before = $account.PwdLastSet
    [void](Invoke-Tenko -Method POST -Path '/dns/kerberos/adopt' -Body ([ordered]@{ realm = $r.domain.ToUpperInvariant(); name = "$($node.ToUpperInvariant())$"; password = $password; spns = @("DNS/$node.$($r.domain)") }))
    $password.Dispose()
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $script:TkPasswordChangeSec) {
        if ([string](Invoke-TkRemote -Server $r.pdc -Name ReadPwdLastSet -Arguments @($sid) | Select-Object -Last 1) -ne $before) { return }
        Start-Sleep -Seconds $script:TkPollSec
    }
    [void](Invoke-TkRemote -Server $r.pdc -Name DisableAccount -Arguments @($sid))
    Exit-TkTakeover 2 "Tenko did not change its account's password within ten minutes of the adoption: the account $node$ is disabled"
}

# ---------------------------------------------------------------------------------------
# Phase 3: the review. The window is a value from Tenko; the console decides.
# ---------------------------------------------------------------------------------------

function Confirm-TkWindow {
    param([hashtable]$State)
    while ($true) {
        $run = Invoke-Tenko -Method GET -Path "/migrate/runs/$($State.Data.run)"
        $window = Get-TkField $run 'window'
        if ($null -ne $window) { break }
        [void](Invoke-Tenko -Method GET -Path "/migrate/runs/$($State.Data.run)/heartbeat")
        Write-TkNote 'Waiting for the window to be started on the run page (Ctrl+C ends the script with nothing changed; run it again later).'
        Start-Sleep -Seconds 30
    }
    $by = ConvertTo-TkSafeText (Get-TkField $window 'started_by')
    $at = ConvertTo-TkSafeText (Get-TkField $window 'started_at')
    # Who started the window and the DHCP window's warning are part of the prompt itself, as
    # in the DHCP window's own choice, so that no redirection of the script's output hides
    # what the typed name approves.
    $prompt = "The window was started by $by at $at, according to Tenko; next the DNS window (phase 4), then the DHCP window (phase 5).`n" + (Get-TkSilenceText -Readings $State.Data.readings) + "`nThis confirmation stands for the DHCP window too when its stop begins within 15 minutes; later, or in another sitting, it asks Abort or Continue.`nType the domain's name to start the DNS window and then the DHCP window"
    if (-not (Confirm-TkTyped $prompt $State.Data.domain)) { Exit-TkTakeover 3 'the window was not confirmed at the console; nothing was changed' }
    $script:TkWindowWatch = [System.Diagnostics.Stopwatch]::StartNew()
    return , $window
}

# ---------------------------------------------------------------------------------------
# Phase 4: the DNS window
# ---------------------------------------------------------------------------------------

function ConvertTo-TkCanonicalConfiguration {
    # The configuration part of a snapshot (no sequence, time, leases or lease losses), keys
    # sorted, null and empty values left out: the same text whatever produced the snapshot.
    param([object]$Value, [int]$Depth = 0)
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object { $_ } -CaseSensitive)) {
            if ($Depth -eq 0 -and 'sequence', 'taken_at' -contains $key) { continue }
            if ($Depth -eq 1 -and $key -eq 'leases') { continue }
            $item = ConvertTo-TkCanonicalConfiguration $Value[$key] ($Depth + 1)
            if ($null -eq $item -or ($item -is [array] -and $item.Count -eq 0) -or ($item -is [System.Collections.IDictionary] -and $item.Count -eq 0)) { continue }
            $out[$key] = $item
        }
        return , $out
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $leaseCodes = @('mirror.lease.state', 'migrate.loss.lease_state')
        return , @($Value | Where-Object { -not ($_ -is [System.Collections.IDictionary] -and $leaseCodes -contains [string](Get-TkField $_ 'code')) } | ForEach-Object { , (ConvertTo-TkCanonicalConfiguration $_ ($Depth + 1)) })
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $table = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) { $table[$property.Name] = $property.Value }
        return , (ConvertTo-TkCanonicalConfiguration $table $Depth)
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [uint16] -or $Value -is [byte]) { return [long]$Value }
    return $Value
}

function Get-TkConfigurationDigest {
    param([object]$Snapshot)
    $canonical = ConvertTo-TkCanonicalConfiguration $Snapshot
    $bytes = ConvertTo-TkJsonByte $canonical
    return ConvertTo-TkHex (Get-TkSha256 $bytes)
}

function Get-TkMappedSnapshot {
    # The exporter's mapping of one server's configuration, on this host: the copy of the
    # exporter is hashed again from its bytes and dot-sourced here, in this function's scope
    # only.
    param([object]$Raw, [string]$Server, [string]$ExporterPath)
    Assert-TkPayloadFile -Name 'Tenko-DhcpMirror.ps1' -Path $ExporterPath
    . $ExporterPath
    $table = @{}
    foreach ($key in 'scopes', 'server_options', 'option_defs', 'classes', 'policies', 'filter_lists', 'filters', 'superscopes', 'failover') { $table[$key] = @($Raw.$key) }
    foreach ($key in 'exclusions', 'reservations', 'scope_options', 'reservation_options', 'dns', 'leases') {
        $map = @{}
        $source = $Raw.$key
        if ($source -is [System.Collections.IDictionary]) { foreach ($k in $source.Keys) { $map[[string]$k] = @($source[$k]) } }
        else { foreach ($p in $source.PSObject.Properties) { $map[$p.Name] = @($p.Value) } }
        $table[$key] = $map
    }
    $snapshot = ConvertTo-MirrorSnapshot -Raw $table -Sequence 1 -TakenAt '1970-01-01T00:00:00Z' -ServerName $Server
    return (ConvertFrom-TkJson -Chars (ConvertTo-CanonicalJson $snapshot).ToCharArray())
}

function Test-TkConfiguration {
    # Each DHCP server's configuration as Windows reports it now, mapped here, against the
    # configuration of the push the window bound. Leases are not compared.
    param([hashtable]$State, [string]$ExporterPath)
    $r = $State.Data.readings
    foreach ($server in $r.dhcp) {
        $raw = Invoke-TkRemote -Server $server.name -Name ReadDhcpConfiguration -Arguments @($script:TkDhcpReadProperties) | Select-Object -Last 1
        $mine = Get-TkMappedSnapshot -Raw $raw -Server $server.name -ExporterPath $ExporterPath
        $stored = Invoke-Tenko -Method GET -Path "/migrate/mirrors/$($State.Data.mirrors[$server.name])/snapshot"
        if ((Get-TkConfigurationDigest $mine) -ne (Get-TkConfigurationDigest $stored)) {
            Exit-TkTakeover 4 "the configuration of $($server.name) differs from the one the window bound: the window stops before any change; review the run page again"
        }
    }
}

function Get-TkWindowsRecord {
    # A zone's records on one server as 'name|type|data', the name absolute, SOA left out;
    # with -Ttl each line ends in a tab and the record's time to live.
    param([string]$Server, [string]$Zone, [switch]$Ttl)
    return , @(Invoke-TkRemote -Server $Server -Name ReadRecords -Arguments @($Zone) | ForEach-Object {
            $name = $(if ($_.Name -eq '@') { $Zone } else { "$($_.Name).$Zone" })
            "$name|$($_.Type)|$(([string]$_.Data).ToLowerInvariant())$(if ($Ttl) { "`t$([string]$_.Ttl)" })"
        } | Sort-Object -Unique)
}

function Compare-TkZoneCopy {
    # Tenko's copy of a zone against every controller's records, type by type; the record set
    # is kept in the state file, for the reverse to compare with.
    param([hashtable]$State, [string]$Zone, [string]$ZoneId)
    $page = Invoke-Tenko -Method GET -Path "/dns/zones/$ZoneId/records"
    $theirs = @(@(Get-TkField $page 'items') | Where-Object { [string](Get-TkField $_ 'type') -ne 'SOA' } | ForEach-Object {
            "$(([string]$_.name).ToLowerInvariant().TrimEnd('.'))|$([string]$_.type)|$(([string]$_.data).TrimEnd('.').ToLowerInvariant())"
        } | Sort-Object -Unique)
    foreach ($controller in $State.Data.readings.controllers) {
        $diff = @(Compare-Object -ReferenceObject (Get-TkWindowsRecord -Server $controller.name -Zone $Zone) -DifferenceObject $theirs)
        if ($diff.Count -gt 0) { Exit-TkTakeover 4 "Tenko's copy of $Zone differs from $($controller.name) in $($diff.Count) records (first: $(ConvertTo-TkSafeText $diff[0].InputObject)); the flip is refused" }
    }
    $State.Data.values["records.$Zone"] = $theirs
    # The start of authority's names as the PDC emulator holds them, for the way back.
    $soa = Invoke-TkRemote -Server $State.Data.readings.pdc -Name ReadSoa -Arguments @($Zone) | Select-Object -Last 1
    $State.Data.values["soa.$Zone"] = [ordered]@{ mname = [string]$soa.Mname; rname = [string]$soa.Rname }
    Save-TkState $State
}

function Test-TkApartName {
    # Records that steer authentication or hand a subtree away: everything at or under the
    # _msdcs, _tcp, _udp and _sites names and the DomainDnsZones and ForestDnsZones
    # partitions, the Kerberos, LDAP and global catalog locator names, every NS and DNAME
    # below the apex, the apex's own A, AAAA, NS, CNAME and DNAME, every wildcard, the
    # controllers' own addresses, and the addresses of a name server the zone names or of a
    # name below a delegation (its glue).
    param([string]$Name, [string]$Type, [string]$Zone, [string[]]$Controllers, [string[]]$NsTargets = @(), [string[]]$Delegated = @())
    if ($Name -match '(^|\.)(_msdcs|_tcp|_udp|_sites|domaindnszones|forestdnszones|_kerberos|_kpasswd|_ldap|_gc)(\.|$)') { return $true }
    if ($Name.StartsWith('*.')) { return $true }
    if ($Name -eq $Zone) { return ('A', 'AAAA', 'NS', 'CNAME', 'DNAME' -contains $Type) }
    if ('NS', 'DNAME' -contains $Type) { return $true }
    if ('A', 'AAAA' -notcontains $Type) { return $false }
    if ($Controllers -contains $Name -or $NsTargets -contains $Name) { return $true }
    return @($Delegated | Where-Object { $Name -eq $_ -or $Name.EndsWith(".$_") }).Count -gt 0
}

function Get-TkZoneReturn {
    # What the reverse of the DNS window writes into the directory, decided by the person on
    # the PDC emulator's frozen copies: their records against those read at the flip, counted
    # by zone and type, then shown by name. Typing the domain's name keeps the copy, except at
    # a name listed apart, whose differing types go back to their flip-time records unless
    # that name is typed too; anything else, or a type that cannot be written back, restores
    # the export of phase 2. Returns, per zone, whether to restore, the names to set back, and
    # the record set the directory may receive, which is checked before the integration.
    param([hashtable]$State, [object[]]$Zones)
    $r = $State.Data.readings
    $controllers = @($r.controllers | ForEach-Object { $_.name })
    $writable = @('A', 'AAAA', 'CNAME', 'SRV', 'PTR', 'NS', 'MX')
    $result = [ordered]@{}
    $changes = [ordered]@{}
    foreach ($zone in $Zones) {
        # The copy as shown, with every time to live and the start of authority's timers, for
        # the check before the integration.
        $shown = Get-TkWindowsRecord -Server $r.pdc -Zone $zone.name -Ttl
        $now = @($shown | ForEach-Object { $_.Split("`t")[0] } | Sort-Object -Unique)
        $flip = @(Get-TkField $State.Data.values "records.$($zone.name)")
        $soa = Invoke-TkRemote -Server $r.pdc -Name ReadSoa -Arguments @($zone.name) | Select-Object -Last 1
        $result[$zone.name] = @{ Restore = $false; Fix = @(); Expected = $now; Shown = $shown; Timers = [string]$soa.Timers }
        # Name servers the zone names and the delegations it holds, at the flip or now.
        $ns = @(@($flip) + $now | Where-Object { $_.Split('|', 3)[1] -eq 'NS' })
        $targets = @($ns | ForEach-Object { $_.Split('|', 3)[2] } | Select-Object -Unique)
        $delegated = @($ns | ForEach-Object { $_.Split('|', 3)[0] } | Where-Object { $_ -ne $zone.name } | Select-Object -Unique)
        $diff = @(Compare-Object -ReferenceObject $flip -DifferenceObject $now | ForEach-Object {
                $owner, $type, $data = ([string]$_.InputObject).Split('|', 3)
                @{ Line = [string]$_.InputObject; Owner = $owner; Type = $type; Data = $data; Added = ($_.SideIndicator -eq '=>'); Apart = (Test-TkApartName -Name $owner -Type $type -Zone $zone.name -Controllers $controllers -NsTargets $targets -Delegated $delegated) }
            })
        if ($diff.Count -gt 0) { $changes[$zone.name] = $diff }
    }
    if ($changes.Count -eq 0) { return $result }
    Write-TkNote 'The zones Tenko served differ from what they held at the flip (+ added, - removed; ! steers authentication or hands a subtree away):'
    foreach ($name in $changes.Keys) {
        $counts = @($changes[$name] | Group-Object { $_.Type } | Sort-Object Name | ForEach-Object { "$($_.Name) +$(@($_.Group | Where-Object { $_.Added }).Count) -$(@($_.Group | Where-Object { -not $_.Added }).Count)" })
        Write-TkNote "  ${name}: $($counts -join ', '); $(@($changes[$name] | Where-Object { $_.Apart }).Count) marked !"
    }
    foreach ($name in $changes.Keys) {
        foreach ($change in $changes[$name]) {
            Write-TkNote ("  {0}{1} {2} {3} {4}" -f $(if ($change.Apart) { '!' } else { ' ' }), $(if ($change.Added) { '+' } else { '-' }), (ConvertTo-TkSafeText $change.Owner), $change.Type, (ConvertTo-TkSafeText $change.Data))
        }
    }
    if (-not (Confirm-TkTyped "Type the domain's name to keep what Tenko served in the directory; anything else restores the export of phase 2" $r.domain)) {
        foreach ($name in $changes.Keys) { $result[$name].Restore = $true }
        return $result
    }
    foreach ($name in $changes.Keys) {
        $flip = @(Get-TkField $State.Data.values "records.$name")
        foreach ($owner in @($changes[$name] | Where-Object { $_.Apart } | ForEach-Object { $_.Owner } | Select-Object -Unique)) {
            if (Confirm-TkTyped "Type $owner to keep what Tenko served there; anything else sets it back to the flip" $owner) { continue }
            $types = @($changes[$name] | Where-Object { $_.Apart -and $_.Owner -eq $owner } | ForEach-Object { $_.Type } | Select-Object -Unique)
            $unwritable = @($types | Where-Object { $writable -notcontains $_ })
            if ($unwritable.Count -gt 0) {
                Write-TkNote "  $owner differs in $($unwritable -join ', '), which this script cannot write back: the export of phase 2 is restored for $name"
                $result[$name].Restore = $true
                break
            }
            $back = @($flip | Where-Object { $part = $_.Split('|', 3); $part[0] -eq $owner -and $types -contains $part[1] })
            $relative = $(if ($owner -eq $name) { '@' } else { $owner.Substring(0, $owner.Length - $name.Length - 1) })
            $result[$name].Fix += , @{ Name = $relative; Owner = $owner; Types = $types; Records = @($back | ForEach-Object { $part = $_.Split('|', 3); @{ Type = $part[1]; Data = $part[2] } }) }
            $result[$name].Expected = @(@($result[$name].Expected | Where-Object { $part = $_.Split('|', 3); -not ($part[0] -eq $owner -and $types -contains $part[1]) }) + $back | Sort-Object -Unique)
        }
    }
    return $result
}

function Get-TkPhase4 {
    param([hashtable]$State, [hashtable]$Payloads)
    $r = $State.Data.readings
    $pdc = $r.pdc
    $tenkoIp = [string]$State.Data.tenko.address
    $node = "$($State.Data.tenko.node).$($r.domain)"
    $ordered = @(@($r.zones | Where-Object { -not $_.name.StartsWith('_msdcs.') -and -not $_.reverse }) + @($r.zones | Where-Object { $_.reverse }) + @($r.zones | Where-Object { $_.name.StartsWith('_msdcs.') }))
    $others = @($r.controllers | Where-Object { -not $_.pdc })
    $exporterPath = $Payloads.exporter.Path
    return , @(
        @{ Name = 'configuration'; Do = { Test-TkConfiguration -State $State -ExporterPath $exporterPath } }
        @{ Name = 'replicate'; Do = { $out = Invoke-TkRemote -Server $pdc -Name Replicate | Select-Object -Last 1; if ($out.Exit -ne 0) { throw "repadmin /syncall failed: $(ConvertTo-TkSafeText $out.Text)" } } }
        @{ Name = 'tenko-flip'
            Do = {
                foreach ($zone in $ordered) {
                    $id = Get-TkZoneId $zone.name
                    if (-not $id) { Exit-TkTakeover 4 "Tenko holds no zone $($zone.name)" }
                    $view = Invoke-Tenko -Method GET -Path "/dns/zones/$id"
                    if ([string](Get-TkField $view 'kind') -eq 'primary') { continue }
                    [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/transfer")
                    Compare-TkZoneCopy -State $State -Zone $zone.name -ZoneId $id
                    [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/flip" -Body ([ordered]@{ to = 'primary'; soa = [ordered]@{ mname = $node; rname = "hostmaster.$($r.domain)" }; ns = @($node) }))
                    $addresses = @($r.controllers | ForEach-Object { $_.addresses } | ForEach-Object { $_ })
                    [void](Invoke-Tenko -Method PATCH -Path "/dns/zones/$id" -Body ([ordered]@{ transfer = [ordered]@{ allow = $addresses; notify = $addresses } }))
                }
            }
            Undo = {
                $primary = ($r.controllers | Where-Object { $_.pdc } | Select-Object -First 1).addresses[0]
                Assert-TkRestoreValue -Readings $r -Value $primary -Class address
                foreach ($zone in $ordered) {
                    $id = Get-TkZoneId $zone.name
                    if ($id -and [string](Get-TkField (Invoke-Tenko -Method GET -Path "/dns/zones/$id") 'kind') -eq 'primary') {
                        [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/flip" -Body ([ordered]@{ to = 'secondary'; primaries = @([ordered]@{ address = $primary }) }))
                    }
                }
            }
        }
        @{ Name = 'windows-secondaries'
            Do = {
                foreach ($zone in $ordered) {
                    $file = "$($zone.name).dns"
                    $now = Invoke-TkRemote -Server $pdc -Name ConvertToSecondary -Arguments @($zone.name, $tenkoIp, $file, $true) | Select-Object -Last 1
                    if ($now.Type -ne 'Secondary' -or $now.Transfer -ne 3 -or $now.Notify -ne 0) { throw "$($zone.name) on $pdc is not a secondary that refuses transfers after the conversion" }
                    foreach ($controller in $others) {
                        $now = Invoke-TkRemote -Server $controller.name -Name ConvertToSecondary -Arguments @($zone.name, $tenkoIp, $file, $false) | Select-Object -Last 1
                        if ($now.Type -ne 'Secondary' -or $now.Transfer -ne 3 -or $now.Notify -ne 0) { throw "$($zone.name) on $($controller.name) is not a secondary that refuses transfers" }
                    }
                }
            }
            Undo = {
                # First every zone on the PDC emulator cut loose from Tenko, so that nothing
                # changes it any more; then what goes into the directory decided at the console
                # on those copies, written, and checked record by record against what was
                # shown; only then the directory. The others answer from their secondaries
                # meanwhile, then each loads the directory copy by its own polling.
                # Each zone goes back into the partition the discovery read; one this script cannot
                # put back there is refused before anything changes.
                foreach ($zone in $ordered) {
                    $partition = [string](Get-TkField $zone 'partition')
                    if (-not $zone.ds -or 'Domain', 'Forest', 'Legacy', 'Custom' -notcontains [string]$zone.scope -or ($zone.scope -eq 'Custom' -and -not $partition)) {
                        Exit-TkTakeover 1 "$($zone.name) was read as $(if ($zone.ds) { "replicated to '$(ConvertTo-TkSafeText $zone.scope)'" } else { 'not directory-integrated' }) at the discovery, which this script cannot put back; nothing was changed"
                    }
                    foreach ($value in @($zone.scope, $partition) | Where-Object { $_ }) { Assert-TkRestoreValue -Readings $r -Value $value -Class discovered }
                }
                $open = @()
                foreach ($zone in $ordered) {
                    $frozen = Invoke-TkRemote -Server $pdc -Name FreezeZone -Arguments @($zone.name, "$($zone.name).dns") | Select-Object -Last 1
                    if ($frozen.Type -eq 'Missing' -and -not (Get-TkField $State.Data.values "restore.$($zone.name)")) { throw "$($zone.name) is missing on $pdc and no restore of it was started" }
                    if (-not $frozen.Ds) { $open += $zone }
                }
                $return = Get-TkZoneReturn -State $State -Zones @($open | Where-Object { -not (Get-TkField $State.Data.values "restore.$($_.name)") })
                foreach ($zone in $open) {
                    Assert-TkRestoreValue -Readings $r -Value $zone.update -Class discovered
                    if ((Get-TkField $State.Data.values "restore.$($zone.name)") -or $return[$zone.name].Restore) {
                        $State.Data.values["restore.$($zone.name)"] = $true
                        Save-TkState $State
                        $digest = (Get-FileHash -LiteralPath (Join-Path (Join-Path $State.Dir 'backup') "tenko-backup-$($zone.name).dns") -Algorithm SHA256).Hash
                        [void](Invoke-TkRemote -Server $pdc -Name RestoreZone -Arguments @($zone.name, "tenko-backup-$($zone.name).dns", "tenko-restore-$($zone.name).dns", $digest))
                    } else {
                        $soa = Get-TkField $State.Data.values "soa.$($zone.name)"
                        $mname = [string](Get-TkField $soa 'mname'); $rname = [string](Get-TkField $soa 'rname')
                        foreach ($value in $mname, $rname) { if ($value -and $value -notmatch '^([a-z0-9_-]{1,63}\.)+[a-z0-9_-]{1,63}\.?$') { Exit-TkTakeover 4 "the start of authority recorded for $($zone.name) names $(ConvertTo-TkSafeText $value), which is not a host name" } }
                        $plan = $return[$zone.name]
                        [void](Invoke-TkRemote -Server $pdc -Name ApplyZoneFix -Arguments @($zone.name, [object[]]$plan.Fix, $mname, $rname))
                        # Record by record, and every time to live and timer kept as shown.
                        $after = Get-TkWindowsRecord -Server $pdc -Zone $zone.name -Ttl
                        $diff = @(Compare-Object -ReferenceObject @($plan.Expected) -DifferenceObject @($after | ForEach-Object { $_.Split("`t")[0] } | Sort-Object -Unique))
                        if ($diff.Count -eq 0) {
                            $setBack = @($plan.Fix | ForEach-Object { $fix = $_; $fix.Types | ForEach-Object { "$($fix.Owner)|$_" } })
                            $shownKept = @($plan.Shown | Where-Object { $part = $_.Split('|', 3); $setBack -notcontains "$($part[0])|$($part[1])" })
                            $afterKept = @($after | Where-Object { $part = $_.Split('|', 3); $setBack -notcontains "$($part[0])|$($part[1])" })
                            $diff = @(Compare-Object -ReferenceObject $shownKept -DifferenceObject $afterKept)
                            $timers = [string](Invoke-TkRemote -Server $pdc -Name ReadSoa -Arguments @($zone.name) | Select-Object -Last 1).Timers
                            if ($timers -ne $plan.Timers) { $diff += [pscustomobject]@{ InputObject = "start of authority timers $timers, shown $($plan.Timers)" } }
                        }
                        if ($diff.Count -gt 0) { Exit-TkTakeover 4 "the copy of $($zone.name) on $pdc differs from what was shown in $($diff.Count) records (first: $(ConvertTo-TkSafeText (([string]$diff[0].InputObject) -replace "`t", ' ttl '))); nothing of it reached the directory" }
                    }
                    $now = Invoke-TkRemote -Server $pdc -Name IntegrateZone -Arguments @($zone.name, [string]$zone.scope, [string](Get-TkField $zone 'partition'), $zone.update) | Select-Object -Last 1
                    if (-not $now.Ds -or $now.Update -ne $zone.update) { Exit-TkTakeover 2 "$($zone.name) on $pdc is $($now.Type), update $($now.Update) after the way back, not directory-integrated with $($zone.update): a zone left open to unsigned updates fails the reverse" }
                    $State.Data.values.Remove("restore.$($zone.name)")
                    Save-TkState $State
                }
                foreach ($zone in $ordered) { Restore-TkZoneList -Readings $r -Zone $zone }
                foreach ($controller in $others) {
                    foreach ($zone in $ordered) { [void](Invoke-TkRemote -Server $controller.name -Name RemoveSecondary -Arguments @($zone.name)) }
                    $watch = [System.Diagnostics.Stopwatch]::StartNew()
                    foreach ($zone in $ordered) {
                        while ($true) {
                            $now = Invoke-TkRemote -Server $controller.name -Name ReadZone -Arguments @($zone.name) | Select-Object -Last 1
                            if ($null -ne $now -and $now.Ds) { if ($now.Update -ne $zone.update) { throw "$($zone.name) on $($controller.name) loads with update $($now.Update), not $($zone.update)" }; break }
                            if ($watch.Elapsed.TotalMinutes -gt 10) { throw "$($controller.name) has not loaded $($zone.name) from the directory within ten minutes" }
                            Start-Sleep -Seconds 15
                        }
                    }
                }
            }
        }
        @{ Name = 'register'; Do = { foreach ($controller in $r.controllers) { [void](Invoke-TkRemote -Server $controller.name -Name RegisterDns) } } }
        @{ Name = 'check'
            Do = {
                # The one place the script decides from which server answered a DNS query.
                Assert-TkDirectAnswer -Domain $r.domain -InWindow
                $answer = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($r.domain)" -Type SRV -Server $tenkoIp -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'SRV' })
                $names = @($r.controllers | ForEach-Object { $_.name })
                if (@($answer | Where-Object { $names -contains ([string]$_.NameTarget).ToLowerInvariant().TrimEnd('.') }).Count -eq 0) { throw "Tenko does not answer the locator records of $($r.domain)" }
            }
        }
    )
}
# ---------------------------------------------------------------------------------------
# Phase 5: the DHCP window. Tenko holds the adopted leases before Windows is silent, and its
# scopes go on in the step after; Windows is made silent by stopping the DHCP Server service
# on both servers and removing both authorizations, read back on each controller.
# ---------------------------------------------------------------------------------------

function Show-TkRestoreLine {
    param([System.Collections.IDictionary]$Readings)
    Write-TkNote 'To bring a Windows DHCP server back by hand, run on it (or for it):'
    foreach ($server in $Readings.dhcp) {
        Write-TkNote "  Add-DhcpServerInDC -DnsName $($server.name) -IPAddress $($server.address)"
        Write-TkNote "  Set-Service DHCPServer -StartupType Automatic; Start-Service DHCPServer    # on $($server.name)"
    }
}

function Get-TkLaggingController {
    # The controllers whose own replica does not list exactly the given servers as authorized
    # (or none of them): the name field of each dhcpServers value, compared whole.
    param([System.Collections.IDictionary]$Readings, [string[]]$Servers, [bool]$Authorized)
    foreach ($controller in $Readings.controllers) {
        $names = @(Invoke-TkRemote -Server $controller.name -Name ReadAuthorization -Arguments @($Readings.configuration) |
                ForEach-Object { ([string]$_).Split('$') } | Where-Object { $_.Length -gt 1 -and $_[0] -eq 's' } | ForEach-Object { $_.Substring(1).ToLowerInvariant() })
        if (@($Servers | Where-Object { ($names -contains $_) -ne $Authorized }).Count -gt 0) { $controller.name }
    }
}

function Test-TkAuthorization {
    param([System.Collections.IDictionary]$Readings, [string[]]$Servers, [bool]$Authorized)
    return @(Get-TkLaggingController -Readings $Readings -Servers $Servers -Authorized $Authorized).Count -eq 0
}

function Write-TkAuthorization {
    # The authorization of the given servers added or removed, replicated, and read back on
    # every controller's own replica until all show it, for at most five minutes; the last
    # read decides. With -Lenient the controllers still behind are returned, not thrown.
    param([System.Collections.IDictionary]$Readings, [string[]]$Servers, [bool]$Authorized, [switch]$Lenient)
    foreach ($server in $Readings.dhcp | Where-Object { $Servers -contains $_.name }) { [void](Invoke-TkRemote -Server $Readings.pdc -Name SetAuthorization -Arguments @($server.name, $server.address, $Authorized)) }
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        [void](Invoke-TkRemote -Server $Readings.pdc -Name Replicate)
        $lagging = @(Get-TkLaggingController -Readings $Readings -Servers $Servers -Authorized $Authorized)
        if ($lagging.Count -eq 0) { return }
        if ($watch.Elapsed.TotalSeconds -ge $script:TkReplicaWaitSec) {
            if ($Lenient) { return $lagging }
            throw "a controller's replica ($($lagging -join ', ')) does not show the DHCP servers as $(if ($Authorized) { 'authorized' } else { 'not authorized' }) within $($script:TkReplicaWaitSec / 60) minutes of the change; run the script again once it has replicated"
        }
        Start-Sleep -Seconds $script:TkPollSec
    }
}

function Sync-TkBarrier {
    # The DHCP window's second barrier: both authorizations removed and read back on every
    # controller's own replica. A controller that has not caught up within five minutes
    # leaves the barrier pending, with a warning; the check step and every later sitting read
    # it again until it holds. With -Remove the removal is made first.
    param([hashtable]$State, [switch]$Remove)
    $r = $State.Data.readings
    $names = @($r.dhcp | ForEach-Object { $_.name })
    if ($Remove) { $lagging = @(Write-TkAuthorization -Readings $r -Servers $names -Authorized $false -Lenient) }
    else {
        if (@(@(Get-TkField $State.Data.values 'barrier_pending') | Where-Object { $_ }).Count -eq 0) { return }
        [void](Invoke-TkRemote -Server $r.pdc -Name Replicate)
        $lagging = @(Get-TkLaggingController -Readings $r -Servers $names -Authorized $false)
    }
    $State.Data.values.barrier_pending = $lagging
    Save-TkState $State
    [void](Invoke-TkRemote -Server $r.pdc -Name WriteMarkerPending -Arguments @($script:TkMarkerKey, $(if ($lagging.Count -gt 0) { $names -join ',' } else { '' })))
    if ($lagging.Count -gt 0) {
        Write-Warning "the removal of the DHCP servers' authorization has not reached $($lagging -join ', ') yet. Tenko serves and the DHCP Server services are stopped and disabled, so no Windows server answers unless someone starts that service; the check step and every later sitting read it again."
    } elseif (-not $Remove) { Write-TkNote 'The removal of the DHCP servers'' authorization has now reached every controller.' }
}

function Complete-TkMarkedBarrier {
    # A sitting without that run's state file finds another run's pending barrier beside its
    # marker on the PDC emulator: it says so, and on y reads the replicas again for it.
    param([System.Collections.IDictionary]$Readings, [string]$Pending)
    $servers = @($Pending.Split(',') | Where-Object { $_ -cmatch '^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}$' })
    Write-TkNote "The run recorded on $($Readings.pdc) has a pending step: the removal of the DHCP authorization of $($servers -join ', ') has not been read back on every controller."
    if ($servers.Count -eq 0 -or 'y', 'yes' -notcontains (Read-TkAnswer 'Read the controllers again for it now? [y/N]').Trim().ToLowerInvariant()) { return }
    [void](Invoke-TkRemote -Server $Readings.pdc -Name Replicate)
    $lagging = @(Get-TkLaggingController -Readings $Readings -Servers $servers -Authorized $false)
    if ($lagging.Count -gt 0) { Write-Warning "the removal has still not reached $($lagging -join ', ')"; return }
    [void](Invoke-TkRemote -Server $Readings.pdc -Name WriteMarkerPending -Arguments @($script:TkMarkerKey, ''))
    Write-TkNote 'The removal has reached every controller; the pending step is done.'
}

function Find-TkMarkedBarrier {
    # A sitting with no readings of its own reads the PDC emulator's marker first, before any
    # DHCP server: a pending barrier there is offered at once (Complete-TkMarkedBarrier).
    param([string]$Domain)
    $pdc = Get-TkPdcName $Domain
    $script:TkKnownHosts = @($pdc)
    $marker = Invoke-TkRemote -Server $pdc -Name ReadMarker -Arguments @($script:TkMarkerKey) | Select-Object -Last 1
    if ($null -eq $marker -or -not [string]$marker.Pending) { return }
    $rows = @(Invoke-TkRemote -Server $pdc -Name ReadDomain)
    $info = $rows | Where-Object { $_.Kind -eq 'domain' } | Select-Object -First 1
    $controllers = @($rows | Where-Object { $_.Kind -eq 'controller' } | ForEach-Object { [ordered]@{ name = $_.Name } })
    $script:TkKnownHosts = @($controllers | ForEach-Object { $_.name })
    Complete-TkMarkedBarrier -Readings ([ordered]@{ pdc = $pdc; controllers = $controllers; configuration = [string]$info.Configuration }) -Pending ([string]$marker.Pending)
}

function Read-TkChoice {
    # The host's choice prompt: a dialog where the host has one, a two-way question in a
    # console. A host that cannot ask answers the default.
    param([string]$Caption, [string]$Message, [string[]]$Choices, [int]$Default)
    $options = [System.Collections.ObjectModel.Collection[System.Management.Automation.Host.ChoiceDescription]]::new()
    foreach ($choice in $Choices) { $options.Add([System.Management.Automation.Host.ChoiceDescription]::new($choice)) }
    try { return $Choices[$Host.UI.PromptForChoice($Caption, $Message, $options, $Default)] } catch { return $Choices[$Default] }
}

function Get-TkSilenceText {
    # The DHCP window's warning, the same at the DNS window's confirmation and at its own.
    param([System.Collections.IDictionary]$Readings)
    $servers = @($Readings.dhcp | ForEach-Object { $_.name })
    $scopes = @($Readings.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.cidr } | Select-Object -Unique)
    return (@(
            'The DHCP window makes these changes:'
            "  1. The DHCP Server service is stopped and disabled on $($servers -join ' and ')."
            "  2. Tenko starts answering $($scopes -join ', ') at once."
            "  3. The servers' authorization in the directory is removed right after; it may take some minutes to reach every controller."
            'To go back later, before the finish, run Tenko-Takeover.ps1 -Reverse: Tenko keeps answering until Windows answers again.'
        ) -join "`n")
}

function Confirm-TkSilence {
    # The DHCP window's confirmation, right before anything is stopped: the DNS window's typed
    # confirmation of this process stands for it within 15 minutes (a monotonic stopwatch,
    # never a clock or a time from the state file); otherwise Abort, the default, or Continue.
    param([System.Collections.IDictionary]$Readings)
    if ($null -ne $script:TkWindowWatch -and $script:TkWindowWatch.Elapsed.TotalSeconds -le $script:TkWindowHoldSec) {
        Write-TkNote "The DNS window's confirmation $([int]$script:TkWindowWatch.Elapsed.TotalMinutes) minutes ago stands for the DHCP window."
        return $true
    }
    $message = (Get-TkSilenceText -Readings $Readings) + "`nAbort changes nothing."
    return ((Read-TkChoice -Caption 'The DHCP window' -Message $message -Choices @('&Abort', '&Continue') -Default 0) -replace '&', '') -eq 'Continue'
}

function Restore-TkWindowsSide {
    # Tenko's side failed after the silence, while the Windows servers are stopped but still
    # authorized: Tenko's completed takeovers reverted first, then Windows started again as it
    # was, which answers at once; no replica is waited for. The last lines say which side
    # answers each scope and what to run next.
    param([hashtable]$State, [string]$Why)
    $r = $State.Data.readings
    $scopes = @($r.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.cidr } | Select-Object -Unique)
    $completed = @($State.Data.values.Keys | Where-Object { $_ -like 'completed.*' })
    if ($completed.Count -gt 0) {
        try { Undo-TkTakeoverJob -State $State; Complete-TkRevert -State $State } catch {
            throw "${Why}; Tenko's revert failed too ($($_.Exception.Message)): Tenko may still answer $(@($completed | ForEach-Object { $_.Substring(19) }) -join ', '), the Windows DHCP servers are stopped; run Tenko-Takeover.ps1 -Reverse once Tenko answers"
        }
    }
    Resume-TkWindowsDhcp -State $State
    foreach ($key in @($State.Data.values.Keys | Where-Object { $_ -like 'completed.*' -or $_ -eq 'silenced' })) { $State.Data.values.Remove($key) }
    Save-TkState $State
    foreach ($scope in $scopes) { Write-TkNote "  ${scope}: Windows answers ($(@($r.dhcp | ForEach-Object { $_.name }) -join ', ')); Tenko is off" }
    $next = $(if ($completed.Count -gt 0) { "run Tenko-Takeover.ps1 -Reverse, which undoes the window's takeover in Tenko, before the DHCP window again" } else { 'run Tenko-Takeover.ps1 again to retry the DHCP window, or -Reverse' })
    throw "${Why}: Windows answers every scope again and Tenko is off; $next"
}

function Resume-TkWindowsDhcp {
    # The Windows DHCP servers this run stopped, started again as the discovery read them,
    # still authorized: they serve, and Tenko stays off.
    param([hashtable]$State)
    $r = $State.Data.readings
    foreach ($server in $r.dhcp | Where-Object { @(Get-TkField $State.Data.values 'stopped') -contains $_.name }) {
        Assert-TkRestoreValue -Readings $r -Value $server.service_start -Class discovered
        $now = $null
        try { $now = Invoke-TkRemote -Server $server.name -Name StartDhcp -Arguments @($server.service_start, $false) | Select-Object -Last 1 } catch { Write-Warning "the start of $($server.name) failed: $($_.Exception.Message)" }
        if ($null -eq $now -or $now.Status -ne 'Running') { Write-Warning "$($server.name)'s DHCP Server service is not running again; start it there (Set-Service DHCPServer -StartupType $($server.service_start); Start-Service DHCPServer)" }
    }
    $State.Data.values.stopped = @()
    Save-TkState $State
}

function Get-TkPhase5 {
    param([hashtable]$State)
    $r = $State.Data.readings
    $names = @($r.dhcp | ForEach-Object { $_.name })
    return , @(
        @{ Name = 'refusals'
            Do = {
                if (@($r.window_refusals).Count -gt 0) { Exit-TkTakeover 1 "the DHCP window is refused: $(@($r.window_refusals) -join '; ')" }
            }
        }
        @{ Name = 'takeover'
            Do = {
                foreach ($server in $r.dhcp) {
                    foreach ($scope in $server.scopes) {
                        $key = "takeover.$($scope.cidr)"
                        if (Get-TkField $State.Data.jobs $key) { continue }
                        $job = Invoke-Tenko -Method POST -Path "/migrate/mirrors/$($State.Data.mirrors[$server.name])/scopes/$($scope.cidr -replace '/', '%2F')/takeover"
                        $id = [string](Get-TkField $job 'id')
                        $same = @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' -and [string]$State.Data.jobs[$_] -ceq $id })
                        if ($same.Count -gt 0) { Exit-TkTakeover 4 "Tenko named the job $id for the takeover of $($scope.cidr) and of $($same[0].Substring(9)), so the script cannot prove each scope on its own. Windows still serves. Tenko may hold a takeover job for $($scope.cidr) that this run did not record, waiting at its manual step: cancel it in Tenko before you run the script again, since completing it would turn Tenko on beside Windows" }
                        $State.Data.jobs[$key] = $id
                        Save-TkState $State
                    }
                }
                foreach ($server in $r.dhcp) { [void](Invoke-TkRemote -Server $r.mirror_host.name -Name StartExporter -Arguments @("Tenko DHCP mirror $($server.name.Split('.')[0])")) }
            }
            # Windows still serves here unless the silence ran, whose reverse comes first.
            Undo = { Undo-TkTakeoverJob -State $State; Complete-TkRevert -State $State }
        }
        @{ Name = 'silence'
            Do = {
                # The confirmation; the silence read back; Tenko's scopes on at once; then the
                # authorizations removed, whose read-back may stay pending. Each part recorded,
                # so a resume goes on where the last sitting stopped and asks nothing twice.
                $waits = @{}
                foreach ($key in @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' })) {
                    if ((Get-TkField $State.Data.values "completed.$key") -eq $true) { continue }
                    $waits[$key] = Wait-TkJob -Id $State.Data.jobs[$key] -ManualKind 'migrate.takeover.silence'
                    # A sitting that ended between a completion and its record: that job is done.
                    if ($waits[$key].Step -lt 0 -and $waits[$key].State -eq 'succeeded' -and (Get-TkField $State.Data.values 'silenced') -eq $true) {
                        $State.Data.values["completed.$key"] = $true
                        Save-TkState $State
                        $waits.Remove($key)
                        continue
                    }
                    if ($waits[$key].Step -lt 0) { throw "the takeover job of $($key.Substring(9)) ended $($waits[$key].State) before Windows was made silent" }
                }
                $State.Data.values.method = 'stop'
                # The pairs Windows holds, read once: all reads first, saved only when every
                # one succeeded, never read again on a resume.
                if (-not $State.Data.values.Contains('leases')) {
                    $pairs = [ordered]@{}
                    foreach ($server in $r.dhcp) {
                        foreach ($scope in $server.scopes) {
                            $pairs["$($server.name)|$($scope.id)"] = @(Invoke-TkRemote -Server $server.name -Name ReadLeases -Arguments @($scope.id) | ForEach-Object { [ordered]@{ ip = $_.Ip; client = $_.Client } })
                        }
                    }
                    $State.Data.values.leases = $pairs
                    Save-TkState $State
                }
                # Tenko never goes on while a Windows server of the pair may still answer: both
                # silences read back first, or both servers started again and Tenko left off.
                if ((Get-TkField $State.Data.values 'silenced') -eq $true -and $waits.Count -gt 0) {
                    # A resume reads each service again before Tenko goes on: one that answers
                    # again (a policy, a console) is stopped and disabled again.
                    try {
                        foreach ($server in $r.dhcp) {
                            $now = Invoke-TkRemote -Server $server.name -Name ReadDhcpService | Select-Object -Last 1
                            if ($now.Status -ne 'Stopped' -or $now.Start -ne 'Disabled' -or $now.Listening -ne 0) { $now = Invoke-TkRemote -Server $server.name -Name StopDhcp | Select-Object -Last 1 }
                            if ($now.Status -ne 'Stopped' -or $now.Start -ne 'Disabled' -or $now.Listening -ne 0) { throw "$($server.name) is not silent: the service is $($now.Status), start $($now.Start), $($now.Listening) listeners on UDP 67" }
                        }
                    } catch {
                        $why = $_.Exception.Message
                        Resume-TkWindowsDhcp -State $State
                        $State.Data.values.Remove('silenced')
                        Save-TkState $State
                        throw "the silence of the Windows DHCP servers was not read back again ($why): they are started again as they were and answer, and Tenko's scopes stay off"
                    }
                }
                if ((Get-TkField $State.Data.values 'silenced') -ne $true) {
                    # The proof of the window's last step, asked before any question or stop.
                    Assert-TkTakeoverList -Code 2
                    if (-not (Confirm-TkSilence -Readings $r)) { Exit-TkTakeover 3 'the DHCP window was aborted at the console; nothing of it was changed, Windows answers as before' }
                    Show-TkRestoreLine $r
                    try {
                        foreach ($server in $r.dhcp) {
                            # Recorded before the stop: a later sitting does not read a server that may be stopped.
                            if (@(Get-TkField $State.Data.values 'stopped') -notcontains $server.name) { $State.Data.values.stopped = @(@(Get-TkField $State.Data.values 'stopped') | Where-Object { $_ }) + $server.name; Save-TkState $State }
                            $now = Invoke-TkRemote -Server $server.name -Name StopDhcp | Select-Object -Last 1
                            if ($now.Status -ne 'Stopped' -or $now.Start -ne 'Disabled' -or $now.Listening -ne 0) { throw "$($server.name) is not silent: the service is $($now.Status), start $($now.Start), $($now.Listening) listeners on UDP 67" }
                        }
                    } catch {
                        $why = $_.Exception.Message
                        Resume-TkWindowsDhcp -State $State
                        throw "the silence of the Windows DHCP servers was not read back ($why): they are started again as they were and answer, and Tenko's scopes stay off"
                    }
                    $State.Data.values.silenced = $true
                    Save-TkState $State
                }
                # Tenko's side failing after the silence leaves no server: Windows is started
                # again (still authorized), Tenko's completed takeovers reverted first.
                foreach ($key in @($waits.Keys)) {
                    for ($try = 1; ; $try++) {
                        try {
                            [void](Invoke-Tenko -Method POST -Path "/jobs/$($State.Data.jobs[$key])/steps/$($waits[$key].Step)/complete" -Body ([ordered]@{ note = "Windows silent: DHCPServer stopped and disabled on $($names -join ', '), read back; the authorizations are removed next" }))
                            break
                        } catch {
                            $why = $_.Exception.Message
                            # Only Tenko's answer, or its absence, is Tenko's side failing.
                            if ($why -notmatch '^(Tenko refused |the connection to Tenko failed|TLS to |Tenko at |Tenko''s answer)') { throw }
                            # A completion already made (a sitting that ended before its record) is one.
                            if ($why -match '^Tenko refused \S+ \S+ with 409') { break }
                            if ($try -ge $script:TkResumeTries) { Restore-TkWindowsSide -State $State -Why "Tenko did not complete the takeover of $($key.Substring(9)) ($why)" }
                            Start-Sleep -Seconds $script:TkPollSec
                        }
                    }
                    $State.Data.values["completed.$key"] = $true
                    Save-TkState $State
                }
                foreach ($key in @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' })) {
                    $done = Wait-TkJob -Id $State.Data.jobs[$key]
                    if ($done.State -ne 'succeeded') { Restore-TkWindowsSide -State $State -Why "the takeover of $($key.Substring(9)) ended $($done.State) after its task was completed" }
                }
                $State.Data.values.deauthorized = $names
                Save-TkState $State
                Sync-TkBarrier -State $State -Remove
            }
            Undo = {
                # Tenko serves until Windows is ready: each stopped service started while its
                # server is not authorized (it serves nobody, its cmdlets answer), the leases
                # written and read back, the authorization added and read back on each
                # controller; only then Tenko silent and Windows restarted to serve. A failure
                # after Tenko went silent leaves one side for every scope: the Windows servers
                # stopped and disabled again and read back, then Tenko's scopes on again.
                $stopped = @(@(Get-TkField $State.Data.values 'stopped') | Where-Object { $_ })
                $down = @(@($stopped) + @(Get-TkField $State.Data.values 'deauthorized') | Where-Object { $_ } | Select-Object -Unique)
                # An earlier sitting that stopped after Tenko went silent: that state first.
                if (@(Get-TkResumable -State $State).Count -gt 0) {
                    Suspend-TkWindowsDhcp -State $State -Servers $down -Why 'an earlier sitting stopped after Tenko went silent'
                    Resume-TkTakeoverJob -State $State
                }
                # Each server starts unauthorized: its authorization read first, removed if there.
                if ($stopped.Count -gt 0 -and -not (Test-TkAuthorization -Readings $r -Servers $stopped -Authorized $false)) {
                    $State.Data.values.deauthorized = $down
                    Save-TkState $State
                    Write-TkAuthorization -Readings $r -Servers $stopped -Authorized $false
                }
                foreach ($server in $r.dhcp | Where-Object { $stopped -contains $_.name }) {
                    Assert-TkRestoreValue -Readings $r -Value $server.service_start -Class discovered
                    $now = Invoke-TkRemote -Server $server.name -Name StartDhcp -Arguments @($server.service_start, $false) | Select-Object -Last 1
                    if ($now.Status -ne 'Running') { throw "$($server.name)'s DHCP Server service is $($now.Status) after the start; Tenko still serves" }
                }
                Write-TkLeaseBack -State $State
                if ($down.Count -gt 0) { Write-TkAuthorization -Readings $r -Servers $down -Authorized $true }
                # A revert that fails puts back what was reverted: Windows is not restarted then,
                # so a silent scope would have no server.
                try { Undo-TkTakeoverJob -State $State } catch { Restore-TkTenkoSide -State $State -Servers $down -Why "Tenko's revert failed ($($_.Exception.Message))" }
                foreach ($server in $r.dhcp | Where-Object { $down -contains $_.name }) {
                    $now = $null
                    try { $now = Invoke-TkRemote -Server $server.name -Name StartDhcp -Arguments @($server.service_start, $true) | Select-Object -Last 1 } catch { Write-Warning "the restart of $($server.name) failed: $($_.Exception.Message)" }
                    if ($null -eq $now -or $now.Status -ne 'Running' -or -not $now.Authorized) {
                        Restore-TkTenkoSide -State $State -Servers $down -Why "$($server.name) did not serve after its restart (service $(if ($null -ne $now) { $now.Status } else { 'unknown' }), event 1044 $(if ($null -ne $now -and $now.Authorized) { 'read' } else { 'not read' }))"
                    }
                }
                $State.Data.values.stopped = @()
                $State.Data.values.deauthorized = @()
                foreach ($key in @($State.Data.values.Keys | Where-Object { $_ -like 'completed.*' -or $_ -eq 'silenced' -or $_ -eq 'barrier_pending' -or $_ -eq 'unproven' })) { $State.Data.values.Remove($key) }
                Complete-TkRevert -State $State
            }
        }
        @{ Name = 'check'
            Do = {
                Sync-TkBarrier -State $State
                # Tenko's ACK counters: a client answered within five minutes of its scopes on. A
                # quiet network may show none yet: the takeover is then done and unproven.
                $watch = [System.Diagnostics.Stopwatch]::StartNew()
                $unproven = @(Get-TkUnproven -State $State)
                while ($unproven.Count -gt 0) {
                    if ($watch.Elapsed.TotalSeconds -gt $script:TkAckWaitSec) {
                        Write-Warning "$($script:TkQuietText) Not answered yet: $($unproven -join ', ')."
                        $State.Data.values.unproven = $unproven
                        Save-TkState $State
                        break
                    }
                    Start-Sleep -Seconds $script:TkPollSec
                    $unproven = @(Get-TkUnproven -State $State)
                }
                if ($unproven.Count -gt 0) { Write-TkNote "Tenko's scopes are on; not yet proven by an answered client: $($unproven -join ', '). The parallel period starts: the exporter's tasks keep running and read nothing; a push from them now is the alarm." }
                else { Write-TkNote 'Tenko serves the scopes. The parallel period starts: the exporter''s tasks keep running and read nothing; a push from them now is the alarm.' }
            }
        }
    )
}

$script:TkQuietText = 'Tenko has not answered a client yet. That is normal in a quiet network: a client that holds a lease asks its old server directly until 87.5 percent of the lease time has passed, and only new, restarted or reconnecting clients ask openly. To prove it now, run ipconfig /renew on any client of the scope and look at the lease it gets. If a client that asks gets no answer, check the relay or the listener, or run -Reverse.'

function Get-TkUnproven {
    # The scopes whose takeover Tenko reports no answered client for yet: only the item whose
    # job is that scope's own counts, and anything but an ACK counter greater than zero, a
    # missing item or a scope without a job counts as not answered. An item without a counter
    # is a node that does not report answered clients, and two items of one job are refused.
    param([hashtable]$State)
    foreach ($cidr in @($State.Data.readings.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.cidr } | Select-Object -Unique)) {
        $job = [string](Get-TkField $State.Data.jobs "takeover.$cidr")
        if (-not $job) { $cidr; continue }
        $items = @(@(Get-TkField (Invoke-Tenko -Method GET -Path "/migrate/takeovers?job=$job") 'items') | Where-Object { [string](Get-TkField $_ 'job') -ceq $job })
        if ($items.Count -gt 1) { Exit-TkTakeover 4 "Tenko lists the job $job of $cidr $($items.Count) times in its takeover list, so the script cannot tell which ACK counter is the scope's" }
        if ($items.Count -eq 0) { $cidr; continue }
        $value = Get-TkField $items[0] 'acks'
        # Read only once Windows is silent: the check step and the sittings after it.
        if ($null -eq $value) { throw "Tenko's node does not report answered clients for $cidr (its takeover has no ACK counter), so the script cannot tell a quiet network from a scope that no server answers. Tenko's scopes are on and the Windows DHCP services are stopped: update the node, then run the script again, or run it with -Reverse" }
        $acks = [long]0
        if (-not [long]::TryParse([string]$value, [ref]$acks) -or $acks -le 0) { $cidr }
    }
}

function Assert-TkTakeoverList {
    # Windows is made silent only on a node that can report answered clients: its takeover
    # list answers, and every item carries a job and an ACK counter. Anything else refuses.
    param([int]$Code)
    $why = ''
    try {
        $answer = Invoke-TkCall -Method GET -Path '/migrate/takeovers' -Expect @(200)
        $items = @(Get-TkField $answer 'items')
        if (-not ($answer -is [System.Collections.IDictionary]) -or -not $answer.Contains('items')) { $why = 'its takeover list is not a list of items' }
        elseif (@($items | Where-Object { -not ($_ -is [System.Collections.IDictionary]) -or -not [string](Get-TkField $_ 'job') -or $null -eq (Get-TkField $_ 'acks') }).Count -gt 0) { $why = 'its takeover list has an item without a job or an ACK counter' }
    } catch { $why = ConvertTo-TkSafeText $_.Exception.Message }
    if ($why) {
        Exit-TkTakeover $Code "this node's version of Tenko cannot report answered clients per takeover ($why), so the DHCP window is not started and Windows answers as before: $(if ($Code -eq 1) { 'no DNS or DHCP setting was changed; this run''s marker on the PDC emulator stays, so run the script again from this machine once the node serves the takeover list' } else { 'update the node, then run the script again to resume, or run it with -Reverse' })"
    }
}

function Undo-TkTakeoverJob {
    # Tenko's revert of each takeover: its scopes silent. Recorded as reverting; final only
    # once Windows serves (Complete-TkRevert).
    param([hashtable]$State)
    $r = $State.Data.readings
    foreach ($key in @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' })) {
        if ((Get-TkField $State.Data.values "reverted.$key") -eq $true -or (Get-TkField $State.Data.values "reverting.$key") -eq $true) { continue }
        if ($script:TkOffline) { $script:TkPending += "revert $($key.Substring(9))"; continue }
        $cidr = $key.Substring(9)
        $server = $r.dhcp | Where-Object { @($_.scopes | ForEach-Object { $_.cidr }) -contains $cidr } | Select-Object -First 1
        $job = Invoke-Tenko -Method POST -Path "/migrate/mirrors/$($State.Data.mirrors[$server.name])/scopes/$($cidr -replace '/', '%2F')/revert"
        $done = Wait-TkJob -Id ([string](Get-TkField $job 'id'))
        if ($done.State -ne 'succeeded') { throw "the revert of $cidr ended $($done.State): Tenko's scopes may still answer, so Windows is not restarted" }
        $State.Data.values["reverting.$key"] = $true
        Save-TkState $State
    }
}

function Get-TkResumable {
    # The takeovers Tenko reverted for a reverse that has not finished, and has not refused
    # to turn on again.
    param([hashtable]$State)
    return @($State.Data.jobs.Keys | Where-Object { (Get-TkField $State.Data.values "reverting.$_") -eq $true -and (Get-TkField $State.Data.values "refused.$_") -ne $true })
}

function Suspend-TkWindowsDhcp {
    # The Windows DHCP servers a reverse started, stopped and disabled again and read back.
    param([hashtable]$State, [string[]]$Servers, [string]$Why)
    foreach ($server in $State.Data.readings.dhcp | Where-Object { $Servers -contains $_.name }) {
        $now = $null
        try { $now = Invoke-TkRemote -Server $server.name -Name StopDhcp | Select-Object -Last 1 } catch { Write-Warning "the stop of $($server.name) failed: $($_.Exception.Message)" }
        if ($null -eq $now -or $now.Status -ne 'Stopped' -or $now.Start -ne 'Disabled' -or $now.Listening -ne 0) {
            throw "${Why}; $($server.name) is not read back as stopped, so Tenko's scopes stay off while it may serve: stop it there (Stop-Service DHCPServer; Set-Service DHCPServer -StartupType Disabled), then run Tenko-Takeover.ps1 -Reverse again"
        }
    }
}

function Resume-TkTakeoverJob {
    # Tenko's scopes on again for a reverse that cannot finish, the Windows servers stopped.
    # An unanswered call is tried again; a refusal is Tenko's decision and stands.
    param([hashtable]$State)
    foreach ($key in @(Get-TkResumable -State $State)) {
        $cidr = $key.Substring(9)
        if ($script:TkOffline) { $script:TkPending += "resume $cidr"; continue }
        for ($try = 1; ; $try++) {
            try {
                foreach ($item in @(Get-TkField (Invoke-Tenko -Method GET -Path "/migrate/takeovers?job=$($State.Data.jobs[$key])") 'items')) {
                    $id = [string](Get-TkField $item 'id')
                    if ($id -cmatch $script:TkUuidPattern) { [void](Invoke-Tenko -Method POST -Path "/migrate/takeovers/$id/resume") }
                }
                break
            } catch {
                $why = $_.Exception.Message
                # Only a refusal that names the takeover is Tenko's decision about it; a session
                # that ended or a route this session may not call is not.
                if ($why -match '^Tenko refused \S+ \S+ with 401') {
                    throw "the session with Tenko ended before it turned $cidr on again ($why): no server answers $cidr now, the Windows servers are stopped; run Tenko-Takeover.ps1 -Reverse again, which asks for a new approval and then turns Tenko's scopes on first"
                }
                if ($why -match '^Tenko refused \S+ \S+ with 4\d\d migrate\.takeover\.') {
                    $State.Data.values["refused.$key"] = $true
                    Save-TkState $State
                    throw "Tenko refused to turn $cidr on again ($why): no server answers $cidr now; make the Windows DHCP servers start again, then run Tenko-Takeover.ps1 -Reverse, which brings Windows back without asking Tenko again"
                }
                if ($why -match '^Tenko refused \S+ \S+ with 4\d\d') {
                    throw "Tenko did not take the call that turns $cidr on again ($why): no server answers $cidr now, the Windows servers are stopped; run Tenko-Takeover.ps1 -Reverse again once the node takes it, it turns Tenko's scopes on first"
                }
                if ($try -ge $script:TkResumeTries) { throw "Tenko did not answer the call that turns $cidr on again ($why): no server answers $cidr now, the Windows servers are stopped; run Tenko-Takeover.ps1 -Reverse again once Tenko answers, it turns Tenko's scopes on first" }
                Start-Sleep -Seconds $script:TkPollSec
            }
        }
        $State.Data.values.Remove("reverting.$key")
        Save-TkState $State
    }
}

function Restore-TkTenkoSide {
    # A reverse that cannot finish leaves one side for every scope: the Windows servers it
    # started stopped and disabled again, read back, then Tenko's scopes on again, then their
    # authorizations removed again (the second barrier; the next reverse checks it first).
    # Where Tenko refused before to turn on again, Windows is the only side and stays.
    param([hashtable]$State, [string[]]$Servers, [string]$Why)
    $reverting = @($State.Data.jobs.Keys | Where-Object { (Get-TkField $State.Data.values "reverting.$_") -eq $true })
    if ($reverting.Count -gt 0 -and @(Get-TkResumable -State $State).Count -eq 0) {
        throw "${Why}: Tenko refused earlier to turn its scopes on again, so the Windows servers are left as they are; make them serve, then run Tenko-Takeover.ps1 -Reverse again"
    }
    Suspend-TkWindowsDhcp -State $State -Servers $Servers -Why $Why
    Resume-TkTakeoverJob -State $State
    try { Write-TkAuthorization -Readings $State.Data.readings -Servers $Servers -Authorized $false } catch { Write-Warning "the authorizations of $($Servers -join ', ') are not read back as removed yet ($($_.Exception.Message)); the services are stopped and disabled, and the next reverse removes them first" }
    throw "${Why}: the Windows DHCP servers are stopped and disabled again and Tenko's scopes are on again; run Tenko-Takeover.ps1 -Reverse again once the cause is fixed"
}

function Complete-TkRevert {
    param([hashtable]$State)
    foreach ($key in @($State.Data.jobs.Keys | Where-Object { (Get-TkField $State.Data.values "reverting.$_") -eq $true })) {
        $State.Data.values.Remove("reverting.$key")
        $State.Data.values.Remove("refused.$key")
        $State.Data.values["reverted.$key"] = $true
    }
    Save-TkState $State
}

function Write-TkLeaseBack {
    # Only addresses, client identifiers and ends, inside the pool, outside the exclusions and
    # others' reservations, the end bounded by the scope's lease time, the count by the pool.
    # The pairs read before the stop come first; nothing from Tenko but these three values.
    # Each written address is read back.
    param([hashtable]$State)
    $r = $State.Data.readings
    $ids = @($r.dhcp | ForEach-Object { $_.scopes } | ForEach-Object { $_.id } | Select-Object -Unique)
    foreach ($id in $ids) {
        $holders = @($r.dhcp | Where-Object { @($_.scopes | ForEach-Object { $_.id }) -contains $id })
        $server = $holders[0]
        $scope = @($server.scopes | Where-Object { $_.id -eq $id })[0]
        $start = ConvertTo-TkUInt32 $scope.start
        $end = ConvertTo-TkUInt32 $scope.end
        $excluded = @($scope.exclusions | ForEach-Object { $a, $b = $_.Split('-'); , @((ConvertTo-TkUInt32 $a), (ConvertTo-TkUInt32 $b)) })
        $reserved = @{}
        foreach ($reservation in $scope.reservations) { $reserved[$reservation.ip] = $reservation.client }
        $leases = [ordered]@{}
        foreach ($holder in $holders) {
            foreach ($pair in @(Get-TkField (Get-TkField $State.Data.values 'leases') "$($holder.name)|$id")) { if ($pair -and -not $leases.Contains($pair.ip)) { $leases[$pair.ip] = [ordered]@{ client = $pair.client; seconds = $scope.lease_secs } } }
        }
        $mirror = $State.Data.mirrors[$server.name]
        $tenko = $null
        try { $tenko = Invoke-Tenko -Method GET -Path "/dhcp/leases?scope=$($scope.cidr -replace '/', '%2F')&mirror=$mirror" } catch { Write-Warning "Tenko's leases of $($scope.cidr) could not be read: $($_.Exception.Message); only the pairs read before the stop are written" }
        $items = @(Get-TkField $tenko 'items')
        if ($items.Count -gt ($end - $start + 1)) { Exit-TkTakeover 4 "Tenko names $($items.Count) leases for $($scope.cidr), more than its pool of $($end - $start + 1) addresses holds" }
        foreach ($item in $items) {
            $ip = [string](Get-TkField $item 'ip')
            $client = ([string](Get-TkField $item 'client_id')).ToLowerInvariant()
            $seconds = [long](Get-TkField $item 'remaining_secs')
            if ($leases.Contains($ip)) { continue }
            # The canonical dotted form only, so that every comparison below is exact.
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed) -or $parsed.AddressFamily -ne 'InterNetwork' -or $ip -cne $parsed.ToString() -or $client -notmatch '^([0-9a-f]{2}-){1,31}[0-9a-f]{2}$') { continue }
            $leases[$ip] = [ordered]@{ client = $client; seconds = [math]::Min([math]::Max($seconds, 0), $scope.lease_secs) }
        }
        $write = @()
        foreach ($ip in $leases.Keys) {
            $value = ConvertTo-TkUInt32 $ip
            if ($value -lt $start -or $value -gt $end) { continue }
            if (@($excluded | Where-Object { $value -ge $_[0] -and $value -le $_[1] }).Count -gt 0) { continue }
            if ($reserved.ContainsKey($ip) -and $reserved[$ip] -ne $leases[$ip].client) { continue }
            $write += [pscustomobject]@{ Ip = $ip; Client = $leases[$ip].client; Seconds = [int]$leases[$ip].seconds }
        }
        # Windows accepts a written lease and does not replicate it: each server on its own.
        foreach ($holder in $holders) {
            $conflict = [math]::Max(1, [int](Get-TkField $holder 'conflict'))
            $present = @(Invoke-TkRemote -Server $holder.name -Name WriteLeases -Arguments @($id, $write, $conflict))
            $missing = @($write | Where-Object { $present -notcontains $_.Ip })
            if ($missing.Count -gt 0) { throw "$($holder.name) does not list $($missing.Count) of the leases written (first $($missing[0].Ip)); Tenko still serves" }
        }
    }
}

# ---------------------------------------------------------------------------------------
# Phase 6: the finish, after the parallel period. The DHCP Server service is never started,
# no role is removed or installed and no server restarted; the finish has no reverse.
# ---------------------------------------------------------------------------------------

function Test-TkFinishAdmitted {
    # Before the finish records anything: Tenko admits what its steps ask, read without a
    # change (each zone's release as a dry run, each mirror read), or the finish does not start.
    param([hashtable]$State)
    try {
        foreach ($zone in $State.Data.readings.zones) {
            $id = Get-TkZoneId $zone.name
            if ($id) { [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/release" -Body ([ordered]@{ dry_run = $true })) }
        }
        foreach ($id in @($State.Data.mirrors.Values)) { [void](Invoke-Tenko -Method GET -Path "/migrate/mirrors/$id" -Expect @(200, 404)) }
    } catch {
        Exit-TkTakeover 1 "the finish did not start, nothing was changed and -Reverse still works: $(ConvertTo-TkSafeText $_.Exception.Message)"
    }
}

function Get-TkDhcpEndText {
    # The DHCP servers as read now: each service, and whether the directory lists the server.
    param([System.Collections.IDictionary]$Readings)
    $listed = @(Invoke-TkRemote -Server $Readings.pdc -Name ReadDhcpInDirectory | ForEach-Object { [string]$_.Name })
    $read = foreach ($server in $Readings.dhcp) {
        $service = Invoke-TkRemote -Server $server.name -Name ReadDhcpService | Select-Object -Last 1
        "$($server.name) $(ConvertTo-TkSafeText $service.Status) and $(ConvertTo-TkSafeText $service.Start), $(if ($listed -contains $server.name) { 'authorized' } else { 'not authorized' })"
    }
    return "The DHCP Server service and authorization read now: $($read -join '; ')."
}

function Get-TkPhase6 {
    param([hashtable]$State, [hashtable]$Payloads)
    $r = $State.Data.readings
    $pdc = $r.pdc
    $phase2 = . Get-TkPhase2 -State $State -Payloads $Payloads
    return , @(
        @{ Name = 'tenko'
            Do = {
                foreach ($zone in $r.zones) {
                    $id = Get-TkZoneId $zone.name
                    if (-not $id) { continue }
                    [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/release" -Body ([ordered]@{ dry_run = $true }))
                    [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/release" -Body ([ordered]@{ dry_run = $false }))
                }
            }
        }
        ($phase2 | Where-Object { $_.Name -eq 'exporter' } | ForEach-Object { @{ Name = 'exporter'; Do = $_.Undo } })
        ($phase2 | Where-Object { $_.Name -eq 'mirror-account' } | ForEach-Object { @{ Name = 'mirror-account'; Do = $_.Undo } })
        @{ Name = 'dns-credential'; Do = { Clear-TkRunAccount -State $State -Key 'dns_user_sid' } }
        @{ Name = 'zone-objects'
            Do = {
                $names = @($r.zones | ForEach-Object { $_.name })
                foreach ($object in @(Invoke-TkRemote -Server $pdc -Name ReadDirectoryZones -Arguments @($r.domain_dn, ('DC=' + ($r.forest_root -replace '\.', ',DC='))))) {
                    if ($names -contains $object.Name) { [void](Invoke-TkRemote -Server $pdc -Name RemoveZoneObject -Arguments @($object.Dn)) }
                }
            }
        }
        @{ Name = 'mirrors'; Do = { foreach ($id in @($State.Data.mirrors.Values)) { [void](Invoke-Tenko -Method DELETE -Path "/migrate/mirrors/$id" -Expect @(200, 204, 404)) } } }
        # Last: the run marker gives way to the run's finished mark, which refuses any reverse.
        @{ Name = 'marker'; Do = { [void](Invoke-TkRemote -Server $pdc -Name WriteMarker -Arguments @($script:TkMarkerKey, '', '', $true, $State.Data.id)) } }
    )
}

# ---------------------------------------------------------------------------------------
# One sitting
# ---------------------------------------------------------------------------------------

function Get-TkNextPhase {
    param([System.Collections.IDictionary]$Phases)
    foreach ($phase in '2', '3', '4', '5', '6') {
        $value = Get-TkField $Phases $phase
        if ($value -ne 'done') { return $phase }
    }
    return ''
}

function Get-TkLatestPhase {
    # The latest phase done or failed, which -Reverse undoes.
    param([System.Collections.IDictionary]$Phases)
    foreach ($phase in '6', '5', '4', '3', '2') {
        $value = Get-TkField $Phases $phase
        if ($value -eq 'done' -or $value -eq 'failed') { return $phase }
    }
    return ''
}

function Test-TkLocator {
    # A later sitting signs in only to the controllers it knew.
    param([System.Collections.IDictionary]$Readings)
    $now = Get-TkDomainLocator $Readings.domain
    $known = @($Readings.controllers | ForEach-Object { $_.name })
    $addresses = @($Readings.controllers | ForEach-Object { $_.addresses } | ForEach-Object { $_ })
    if ($known -notcontains $now.name -or $addresses -notcontains $now.address) { Exit-TkTakeover 4 "the DC locator now answers $($now.name) at $($now.address), which the discovery did not record; no session was opened" }
    foreach ($controller in $Readings.controllers) {
        foreach ($address in @(Get-TkHostAddress $controller.name | ForEach-Object { [string]$_ })) {
            if (@($controller.addresses) -notcontains $address) { Exit-TkTakeover 4 "$($controller.name) now resolves to $address, which the discovery did not record; no session was opened" }
        }
    }
}

function Invoke-TkPhase {
    param([hashtable]$State, [string]$Phase, [hashtable]$Payloads, [switch]$Undo)
    # The phase's definition is dot-sourced: its variables ($r, $pdc, ...) then live in this
    # scope, where the step blocks, run below, read them. A closure would rebind $script:.
    $steps = switch ($Phase) {
        '2' { . Get-TkPhase2 -State $State -Payloads $Payloads }
        '3' { , @(@{ Name = 'review'; Do = { [void](Confirm-TkWindow -State $State) } }) }
        '4' { . Get-TkPhase4 -State $State -Payloads $Payloads }
        '5' { . Get-TkPhase5 -State $State }
        '6' { . Get-TkPhase6 -State $State -Payloads $Payloads }
    }
    if ($Undo) { Undo-TkStepList -State $State -Phase $Phase -Steps $steps; return }
    Invoke-TkStepList -State $State -Phase $Phase -Steps $steps
}

function Assert-TkStateShape {
    # The values of the state file that reach a command are of their exact form.
    param([System.Collections.IDictionary]$Data)
    if ($null -eq $Data.readings) { return }
    $fqdn = '^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}$'
    $hosts = @($Data.readings.controllers | ForEach-Object { $_.name }) + @($Data.readings.dhcp | ForEach-Object { $_.name }) + @($Data.readings.mirror_host.name)
    if ($Data.tenko.node -cnotmatch $script:TkLabelPattern -or @($hosts | Where-Object { [string]$_ -cnotmatch $fqdn }).Count -gt 0) { Exit-TkTakeover 4 'the state file holds a name that is not of its exact form; nothing was run' }
}

function Invoke-Takeover {
    param([switch]$DryRun, [switch]$Reverse, [string]$Directory)
    # No confirmation of an earlier run in this process stands for this one.
    $script:TkWindowWatch = $null
    Assert-TkHost
    if ($Directory -and -not (Test-TkTrustedPath (Get-TkPathSecurity $Directory))) { Write-Warning "the folder $Directory is writable by accounts other than Administrators: a file there can be swapped between its check and its start" }
    $joined = ''
    try { $joined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name.ToLowerInvariant() } catch { $joined = '' }
    $existing = @()
    $base = Join-Path (Join-Path $script:TkDataRoot 'Tenko') 'takeover'
    if (Test-Path -LiteralPath $base) { $existing = @(Get-ChildItem -LiteralPath $base -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'state.json') } | ForEach-Object { $_.Name }) }
    $domain = $(if ($existing.Count -eq 1) { $existing[0] } else { '' })
    if (-not $domain) {
        $typed = (Read-TkAnswer "The domain to take over [$joined]").Trim().ToLowerInvariant().TrimEnd('.')
        $domain = $(if ($typed) { $typed } else { $joined })
    }
    if ($domain -notmatch '^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}$') { Exit-TkTakeover 1 "$domain is not a domain name" }

    if ($DryRun) {
        # The dry run shows everything it can, the policy's stop among the refusals.
        $policy = ''
        try { Assert-TkDirectAnswer -Domain $domain } catch { if (-not $_.Exception.Data.Contains('tk.exit')) { throw }; $policy = $_.Exception.Message }
        $readings = Get-TkDiscovery -Domain $domain
        Select-TkMirrorHost -Readings $readings
        Show-TkChangeList -Readings $readings -NodeName '<the node>'
        foreach ($refusal in @($readings.refusals) + @($readings.window_refusals) + @($policy | Where-Object { $_ })) { Write-Warning $refusal }
        Write-TkNote 'Dry run: nothing was changed and Tenko was not contacted.'
        return $(if (@($readings.refusals).Count -gt 0 -or $policy) { 1 } else { 0 })
    }

    $state = Open-TkState -Domain $domain
    try {
        $data = $state.Data
        Assert-TkStateShape $data
        $phase = Get-TkNextPhase $data.phases
        $latest = Get-TkLatestPhase $data.phases
        # The finish has started once any of its steps is recorded: from then on a run only goes
        # forward, and a resume asks nothing again.
        $finishing = @($data.steps.Keys | Where-Object { $_ -like '6.*' }).Count -gt 0
        $noWayBack = 'the finish (phase 6) has started: there is no scripted way back, going back is manual work (README.md, after the finish); nothing was changed'
        if ($finishing -and $Reverse) { Exit-TkTakeover 1 $noWayBack }
        if ($finishing -and -not $phase) { Write-TkNote "The takeover of $domain is finished; nothing is left to run."; return 0 }
        if (-not $Reverse -and $latest) {
            Write-TkNote "A run of $domain against Tenko at $($data.tenko.host):$($data.tenko.port) exists; the next phase is $phase, the latest done or failed ${latest}."
            $pending = @(@(Get-TkField $data.values 'barrier_pending') | Where-Object { $_ })
            if ($pending.Count -gt 0) { Write-TkNote "Pending: the removal of the DHCP servers' authorization has not reached $($pending -join ', '); this sitting reads it again." }
            if (-not $finishing -and (Read-TkAnswer "Continue with phase $phase, or reverse phase ${latest}? [C/r]").Trim().ToLowerInvariant() -eq 'r') { $Reverse = $true }
        }
        # A precondition of the DNS window's check, with the others: before any change.
        $checked = Get-TkField $data.steps '4.check'
        if (-not $Reverse -and ($null -eq $checked -or $checked.state -ne 'done')) { Assert-TkDirectAnswer -Domain $domain }
        if ($null -ne $data.readings -and ((Get-TkField $data.phases '4') -eq 'done' -or (Get-TkField $data.phases '4') -eq 'failed')) { Test-TkLocator $data.readings }

        # Discovery: always fresh, its controller addresses the class the reverse checks
        # against; the recorded readings stay what the reverse restores from.
        if ($null -eq $data.readings) { Find-TkMarkedBarrier -Domain $domain }
        $recorded = $(if ($null -ne $data.readings) { @($data.readings.dhcp) } else { @() })
        $readings = Get-TkDiscovery -Domain $domain -Stopped @(@(Get-TkField $data.values 'stopped') | Where-Object { $_ }) -Recorded $recorded -KnownDhcp @($recorded | ForEach-Object { $_.name })
        $script:TkFresh = $readings
        if ($null -eq $data.readings) {
            Select-TkMirrorHost -Readings $readings
            if (@($readings.refusals).Count -gt 0 -and -not $Reverse) {
                foreach ($refusal in $readings.refusals) { Write-TkNote $refusal }
                Exit-TkTakeover 1 'the discovery refuses this domain; nothing was changed'
            }
        } else {
            Select-TkMirrorHost -Readings $readings -Chosen $data.readings.mirror_host.name
            $script:TkKnownHosts = @($script:TkKnownHosts + @($data.readings.controllers | ForEach-Object { $_.name }) + @($data.readings.dhcp | ForEach-Object { $_.name }) + $data.readings.mirror_host.name | Select-Object -Unique)
            if (-not $Reverse) { Sync-TkBarrier -State $state }
        }
        $payloads = @{
            exporter  = Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $Directory -OutDir (Join-Path $state.Dir 'payload')
            installer = Get-TkPayload -Name 'Install-TenkoDhcpMirror.ps1' -Directory $Directory -OutDir (Join-Path $state.Dir 'payload')
        }
        $installed = Get-TkField $data.steps '2.exporter'
        if (-not $Reverse -and $phase -eq '2' -and ($null -eq $installed -or $installed.state -ne 'done')) { Assert-TkInstallerContract -Path $payloads.installer.Path }

        # A copy of the state file from before the finish: the domain names this run finished.
        if ($Reverse -and $null -ne $data.readings -and [string](Invoke-TkRemote -Server $data.readings.pdc -Name ReadMarker -Arguments @($script:TkMarkerKey) | Select-Object -Last 1 | ForEach-Object { $_.Finished }) -eq $data.id) { Exit-TkTakeover 1 $noWayBack }
        $address = $(if ($data.tenko.Contains('host')) { "$($data.tenko.host):$($data.tenko.port)" } else { Read-TkAnswer "Tenko's address (host name, port $($script:TkPort) unless host:port)" })
        if ($Reverse -and $latest -and -not (Test-TkReachable $address)) {
            Write-Warning 'Tenko cannot be reached. A node whose API is unreachable may still serve DHCP, so a Windows server made to answer again would answer beside it (conflict detection, which the reverse turns on, limits the damage).'
            if (-not (Confirm-TkTyped 'Type the domain''s name to reverse the Windows half alone' $domain)) { Exit-TkTakeover 1 'the reverse was declined; nothing was changed' }
            $script:TkOffline = $true
            Invoke-TkPhase -State $state -Phase $latest -Payloads $payloads -Undo
            $data.values["pending.$latest"] = @($script:TkPending)
            Save-TkState $state
            Write-TkNote "Phase $latest is reversed on Windows. Tenko's half is pending: $(@($script:TkPending).Count) operations, recorded in the state file; reverse them in Tenko's UI or run -Reverse again once Tenko answers."
            return 5
        }
        Connect-TkNode -Address $address
        if ($null -eq $data.readings) {
            $data.readings = $readings
            $data.tenko = [ordered]@{ host = $script:TkConn.Host; port = $script:TkConn.Port; address = [string]$script:TkConn.Address; node = (Get-TkNodeName -HostName $script:TkConn.Host -Domain $domain -Pdc $readings.pdc -Address ([string]$script:TkConn.Address)); fingerprint = '' }
            Show-TkChangeList -Readings $readings -NodeName $data.tenko.node
            if (-not (Confirm-TkTyped "Type the domain's name ($domain) to approve this change list" $domain)) { Exit-TkTakeover 1 'the change list was declined; nothing was changed' }
            $data.plan = Get-TkPlan -Readings $readings -NodeName $data.tenko.node
        } else {
            $script:TkConn.Pinned = [string]$data.tenko.fingerprint
            Write-TkNote "Domain $domain, Tenko at $($data.tenko.host):$($data.tenko.port) (from the state file)."
        }
        # The run marker before the approval, read back: two machines never both pass it.
        $marker = Invoke-TkRemote -Server $data.readings.pdc -Name ReadMarker -Arguments @($script:TkMarkerKey) | Select-Object -Last 1
        if ($null -ne $marker -and $marker.Run -and $marker.Run -ne $data.id -and [string]$marker.Pending) { Complete-TkMarkedBarrier -Readings $readings -Pending ([string]$marker.Pending) }
        if ($null -ne $marker -and $marker.Run -and $marker.Run -ne $data.id) { Exit-TkTakeover 1 "another run ($($marker.Run) from $($marker.Host) at $($marker.Time)) is recorded on $($data.readings.pdc); it must end first, or be reversed before its finish" }
        [void](Invoke-TkRemote -Server $data.readings.pdc -Name WriteMarker -Arguments @($script:TkMarkerKey, $data.id, [System.Environment]::MachineName, $false))
        $marker = Invoke-TkRemote -Server $data.readings.pdc -Name ReadMarker -Arguments @($script:TkMarkerKey) | Select-Object -Last 1
        if ($null -eq $marker -or $marker.Run -ne $data.id) { Exit-TkTakeover 1 "another run wrote its marker on $($data.readings.pdc) at the same time; let one of them go on" }

        # Phase 1: the approval, every sitting.
        $pinned = $script:TkConn.Pinned
        $run = Request-TkApproval -Plan $data.plan -Domain $domain
        if ($pinned -and $pinned -ne $script:TkConn.Pinned) { Exit-TkTakeover 4 'the new approval binds another TLS root than the run pinned' }
        if ($data.run -and $data.run -ne $run) { Write-TkNote "Tenko names the run $run for this sitting." }
        $data.run = $run
        $data.tenko.fingerprint = $script:TkConn.Pinned
        Save-TkState $state
        Test-TkServedRoot
        # A precondition of the first sitting: the node can report answered clients.
        if (-not $Reverse -and $null -eq (Get-TkField $data.phases '2')) { Assert-TkTakeoverList -Code 1 }
        if (-not $Reverse -and @(@(Get-TkField $data.values 'unproven') | Where-Object { $_ }).Count -gt 0) {
            # A sitting with no failed step only reports here: a node without counters is a warning.
            $unproven = $null
            try { $unproven = @(Get-TkUnproven -State $state) } catch { if ($_.Exception.Data.Contains('tk.exit')) { throw }; Write-Warning "$($_.Exception.Message). The scopes stay recorded as unproven." }
            if ($null -eq $unproven) { Write-Verbose 'the record stays as it was' }
            elseif ($unproven.Count -eq 0) { $data.values.Remove('unproven'); Write-TkNote 'Tenko reports that it has answered a client of every scope since the DHCP window.' }
            else { $data.values.unproven = $unproven; Write-TkNote "Tenko reports no answered client yet for $($unproven -join ', '): a quiet network, or a client that asks gets no answer (README.md, the quiet network)." }
            Save-TkState $state
        }

        if ($Reverse) {
            if (-not $latest) { Exit-TkTakeover 1 'nothing to reverse' }
            Invoke-TkPhase -State $state -Phase $latest -Payloads $payloads -Undo
            [void](Invoke-Tenko -Method PUT -Path "/migrate/runs/$run/phases/$latest" -Body ([ordered]@{ state = 'reversed' }) -Expect @(200, 204, 404))
            if (-not (Get-TkLatestPhase $data.phases)) { [void](Invoke-TkRemote -Server $data.readings.pdc -Name WriteMarker -Arguments @($script:TkMarkerKey, '', '', $true)) }
            Write-TkNote "Phase $latest is reversed."
            return 5
        }
        while ($phase) {
            $dnsNote = $(if ($data.readings.dns_credential -eq 'create') { " The DHCP servers' DNS credential names $($script:TkDnsCredentialUser), an account the finish deletes: to serve again, a server needs another, set with Set-DhcpServerDnsCredential after its service is started unauthorized and before it is authorized." })
            if ($phase -eq '6' -and -not $finishing) {
                Test-TkFinishAdmitted -State $state
                $open = @(@(Get-TkField $data.values 'unproven') | Where-Object { $_ })
                $note = $(if ($open.Count -gt 0) { " Tenko reports no answered client yet for $($open -join ', ')." } else { '' })
                $text = "The parallel period is over. The finish (phase 6) releases the frozen names in Tenko's zones and removes the exporter and its account, the zones' objects in the directory partitions and Tenko's mirrors. After it there is no scripted way back: -Reverse is refused and going back is manual work. " +
                "Each DHCP server keeps the DHCP Server role and its database; the finish neither starts nor authorizes its service. $(Get-TkDhcpEndText $data.readings) Removing the role is yours to do later (README.md). " +
                "The export of phase 2 stays in Program Files\Tenko\takeover\backup on each DHCP server and in $(Join-Path $state.Dir 'backup') here.$dnsNote$note Type the domain's name to go on"
                if (-not (Confirm-TkTyped $text $domain)) { Exit-TkTakeover 3 'waiting for the parallel period' }
            }
            # The DNS window is confirmed at the console in every sitting that starts it; the
            # DHCP window by its own one confirmation, right before the silence.
            if ($phase -eq '4' -and $null -eq $script:TkWindowWatch) { [void](Confirm-TkWindow -State $state) }
            Write-TkNote "Phase $phase"
            Invoke-TkPhase -State $state -Phase $phase -Payloads $payloads
            [void](Invoke-Tenko -Method PUT -Path "/migrate/runs/$run/phases/$phase" -Body ([ordered]@{ state = 'done' }) -Expect @(200, 204, 404))
            if ($phase -eq '5') { Write-TkNote 'The parallel period runs now. After it, run the script again for the finish.'; return 3 }
            if ($phase -eq '6') { Write-TkNote "The takeover is finished. The DHCP Server role stays installed on each DHCP server. $(Get-TkDhcpEndText $data.readings) README.md says how to remove the role yourself.$dnsNote"; return 0 }
            $phase = Get-TkNextPhase $data.phases
        }
        return 0
    } finally {
        Close-TkSession
        Close-TkState $state
    }
}

function Test-TkReachable {
    param([string]$Address)
    try { Connect-TkNode -Address $Address; return $true } catch { return $false }
}

# Dot-sourced by the tests: define the functions and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

$code = 1
try {
    $code = Invoke-Takeover -DryRun:$DryRun -Reverse:$Reverse -Directory $PSScriptRoot
} catch {
    $code = $(if ($_.Exception.Data.Contains('tk.exit')) { [int]$_.Exception.Data['tk.exit'] } else { 2 })
    [Console]::Error.WriteLine("Tenko-Takeover: $(ConvertTo-TkSafeText $_.Exception.Message)")
}
exit $code
