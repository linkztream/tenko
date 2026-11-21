<#
.SYNOPSIS
  Moves an Active Directory domain's DNS zones and DHCP scopes from its Windows servers to
  Tenko DDI, phase by phase, each phase reversible (MIG-17, MIG-08; ADR 0038).

.DESCRIPTION
  Run elevated, as a member of the domain's Domain Admins, on a domain controller or a
  privileged access workstation of the domain. The script uses the logon it runs under and
  asks for no credential. It reads Windows, shows what it will change, and signs in to Tenko
  through an approval that a signed-in administrator gives in Tenko's UI by typing the code
  the script shows. It never runs text that Tenko sends: every value from Tenko is checked
  against what Windows reports and used in fixed commands.

  Phases: 0 discover (read only), 1 approval, 2 prepare (nothing served), 3 review (the
  window is started in Tenko's UI), 4 the DNS window, 5 the DHCP window, then the parallel
  period; 6 the finish, in a later sitting. Started without a parameter it runs or resumes
  the next phase; when a run exists it offers to reverse the latest phase instead.

  Exit codes: 0 the phase is done; 1 refused before any change; 2 stopped at a failed step
  (named in the state file); 3 waiting for the review or the parallel period; 4 a value from
  Tenko disagreed with Windows, and nothing further was changed; 5 reversed.

  The file must be the release's: check it with the start line of the release notes (or of
  the intake's check command) before it runs. See README.md beside it.

.PARAMETER DryRun
  Discover and print the change list. Changes nothing on Windows and contacts no Tenko.

.PARAMETER Reverse
  Undo the latest phase done, both halves. Run again to walk one more phase back.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Reverse
)

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
$script:TkMirrorWindowSec = 300            # Tenko creates mirrors within 5 minutes of the approval
$script:TkPasswordChangeSec = 600          # Tenko changes its account's password within 10 minutes
$script:TkReconfirmSec = 900               # the console asks again before the silence after 15 minutes
$script:TkMinLeaseSec = 3600               # a scope under an hour refuses the DHCP window
$script:TkPollSec = 5
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

# The connection to Tenko for this process: the host the person typed, the pinned root and
# the delegated session's secret, which never leaves this table but into the socket.
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

$script:TkConn = @{ Host = ''; Port = 0; Address = $null; Local = $null; Pinned = ''; Session = $null; LastTls = $null }
$script:TkTokens = @{}
$script:TkOffline = $false
$script:TkWindowWatch = $null
$script:TkMirrorPassword = $null
$script:TkPending = @()

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

function Use-TkSystemModulePath {
    # Modules load from the system's directories only, which only administrators write.
    $system = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'
    $programs = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
    $env:PSModulePath = "$system;$programs"
}

function Test-TkForeignWriter {
    # Whether anyone but SYSTEM, Administrators and TrustedInstaller may write the folder.
    param([string]$Path)
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $write = [System.Security.AccessControl.FileSystemRights]'Write, Modify, FullControl, CreateFiles, AppendData, ChangePermissions, TakeOwnership'
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        if (($rule.FileSystemRights -band $write) -eq 0) { continue }
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $sid -and $sid -ne 'S-1-3-0') { return $true }
    }
    return $false
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
    if ([string]::IsNullOrEmpty($script:TkVersion)) { Exit-TkTakeover 1 'this copy is not a release build; take Tenko-Takeover.ps1 from the release and check it with the start line' }
    if (-not (Test-TkElevated)) { Exit-TkTakeover 1 'run the script elevated (Run as administrator)' }
    if (-not (Test-TkDomainAdmin -Sids (Get-TkTokenSid))) { Exit-TkTakeover 1 'the logon this runs under is not a member of Domain Admins' }
    Use-TkSystemModulePath
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
        $object = [ordered]@{}
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
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
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
        $presented = @()
        if ($null -ne $chain) {
            if ($chain.ChainPolicy.ExtraStore.Count -gt 0) {
                $presented = @($chain.ChainPolicy.ExtraStore)
            } else {
                $presented = @($chain.ChainElements | ForEach-Object { $_.Certificate })
            }
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
        $ssl = [System.Net.Security.SslStream]::new($network, $false, (Get-TkTlsCallback))
        try {
            $ssl.AuthenticateAsClient($script:TkConn.Host)
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
        throw "Tenko refused $Method $Path with $($answer.Status) $($answer.Code): $($answer.Detail)"
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

function Get-TkApprovalCode {
    param([string]$Domain, [byte[]]$RootSha256, [byte[]]$RequestSha256, [byte[]]$Key, [string]$Id)
    $domainBytes = [System.Text.Encoding]::ASCII.GetBytes($Domain.ToLowerInvariant().TrimEnd('.'))
    $preimage = Join-TkByte @($script:TkCodeContext, ([byte[]]@(0, $domainBytes.Length)), $domainBytes, $RootSha256, $RequestSha256, $Key, (ConvertTo-TkUuidByte $Id))
    $digest = Get-TkSha256 $preimage
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
            $answer = Invoke-TkHttp -Method POST -Path "/api/v1/auth/approvals/$id/collect" -Body $collect -NoSession
            if ($answer.Status -eq 200) { break }
            if ($answer.Status -eq 409 -and $answer.Code -eq 'auth.approval.pending') { Start-Sleep -Seconds $script:TkPollSec; continue }
            Exit-TkTakeover 1 "the approval was not given: $($answer.Status) $($answer.Code) $($answer.Detail)"
        }
        $secret = Get-TkField $answer.Json 'secret'
        $run = [string](Get-TkField $answer.Json 'delegation')
        if (-not ($secret -is [securestring]) -or -not (Test-TkSecurePattern $secret $script:TkSessionPattern) -or $run -cnotmatch $script:TkUuidPattern) {
            Exit-TkTakeover 4 'Tenko answered the collect with a session that is not of the exact form'
        }
        $script:TkConn.Session = $secret
        $script:TkConn.Pinned = $tls.RootSha256
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
    if ([System.Net.IPAddress]::TryParse($hostName, [ref]$ip)) {
        $script:TkConn.Address = $ip
    } else {
        $all = @(Get-TkHostAddress $hostName)
        if ($all.Count -eq 0) { Exit-TkTakeover 1 "$hostName does not resolve" }
        $script:TkConn.Address = $all[0]
    }
    $script:TkConn.Host = $hostName
    $script:TkConn.Port = $port
    $health = Invoke-TkHttp -Method GET -Path '/api/v1/health' -NoSession
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
        Invoke-Command -Session $session -ScriptBlock $script:TkRemote.NewDirectory -ArgumentList $Directory -ErrorAction Stop
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

$script:TkRemote = @{
    NewDirectory          = {
        param([string]$Path)
        if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -ItemType Directory -Path $Path }
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
        Get-ADComputer -Filter 'Enabled -eq $true' -Properties DNSHostName, OperatingSystem, IPv4Address | ForEach-Object {
            $name = ([string]$_.DNSHostName).ToLowerInvariant()
            if ($name -and $Controllers -notcontains $name) {
                @{ Name = $name; Server = ([string]$_.OperatingSystem -like '*Server*'); IPv4 = [string]$_.IPv4Address; Sid = [string]$_.SID }
            }
        }
    }
    ReadHardening         = {
        param([string]$Configuration, [string]$DomainDn)
        $ntds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
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
            $template = $_
            $rights = @((Get-Acl -Path ("AD:\" + $template.DistinguishedName)).Access | ForEach-Object {
                    @{ Who = [string]$_.IdentityReference; Rights = [string]$_.ActiveDirectoryRights; Object = [string]$_.ObjectType; Allow = ([string]$_.AccessControlType -eq 'Allow') }
                })
            @{ Kind = 'template'; Name = [string]$template.Name; NameFlag = [int]$template.'msPKI-Certificate-Name-Flag'; Usages = @($template.pKIExtendedKeyUsage | ForEach-Object { [string]$_ }); Rights = $rights }
        }
        Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties 'msDS-SupportedEncryptionTypes' | ForEach-Object {
            $types = $_.'msDS-SupportedEncryptionTypes'
            if ($null -eq $types -or ([int]$types -band 4) -ne 0 -or ([int]$types -band 24) -eq 0) { @{ Kind = 'rc4'; Name = [string]$_.SamAccountName } }
        }
        $null = $DomainDn
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
        param([string]$Key, [string]$Run, [string]$Machine, [bool]$Remove)
        if ($Remove) { if (Test-Path -LiteralPath $Key) { Remove-Item -LiteralPath $Key -Recurse -Force }; return }
        if (-not (Test-Path -LiteralPath $Key)) { $null = New-Item -Path $Key -Force }
        $null = New-ItemProperty -Path $Key -Name Run -Value $Run -PropertyType String -Force
        $null = New-ItemProperty -Path $Key -Name Host -Value $Machine -PropertyType String -Force
        $null = New-ItemProperty -Path $Key -Name Time -Value ((Get-Date).ToUniversalTime().ToString('s') + 'Z') -PropertyType String -Force
    }
    ReadMarker            = {
        param([string]$Key)
        if (Test-Path -LiteralPath $Key) {
            $values = Get-ItemProperty -LiteralPath $Key
            @{ Run = [string]$values.Run; Host = [string]$values.Host; Time = [string]$values.Time }
        }
    }
    ExportDhcp            = {
        param([string]$Path)
        $dir = Split-Path -Path $Path -Parent
        if (-not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir }
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
        $zone = Get-DnsServerZone -Name $Zone
        @{ Transfer = [string]$zone.SecureSecondaries; Notify = [string]$zone.Notify; Secondaries = @($zone.SecondaryServers | ForEach-Object { [string]$_ }); NotifyServers = @($zone.NotifyServers | ForEach-Object { [string]$_ }) }
    }
    NewMirrorAccount      = {
        param([string]$Name, [bool]$Gmsa, [string]$Domain, [string]$MirrorHost, [securestring]$Password)
        if ($Gmsa) {
            if ($null -eq (Get-ADServiceAccount -Filter "Name -eq '$Name'")) {
                New-ADServiceAccount -Name $Name -DNSHostName "$Name.$Domain" -PrincipalsAllowedToRetrieveManagedPassword $MirrorHost -KerberosEncryptionType AES128, AES256
            }
            $account = Get-ADServiceAccount -Identity $Name
        } else {
            if ($null -eq (Get-ADUser -Filter "SamAccountName -eq '$Name'")) {
                New-ADUser -Name $Name -SamAccountName $Name -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -KerberosEncryptionType AES128, AES256
            }
            $account = Get-ADUser -Identity $Name
        }
        Add-ADGroupMember -Identity 'DHCP Users' -Members $account
        [string]$account.SID
    }
    RemoveMirrorAccount   = {
        param([string]$Name, [bool]$Gmsa)
        if ($Gmsa) { Get-ADServiceAccount -Filter "Name -eq '$Name'" | Remove-ADServiceAccount -Confirm:$false }
        else { Get-ADUser -Filter "SamAccountName -eq '$Name'" | Remove-ADUser -Confirm:$false }
    }
    InstallExporter       = {
        param([string]$Directory, [string]$Url, [string]$Mirror, [string]$Fingerprint, [string]$Account, [pscredential]$Credential, [securestring]$Token, [string]$TaskName, [string]$DataDir, [string]$Server)
        $installer = Join-Path $Directory 'Install-TenkoDhcpMirror.ps1'
        $arguments = @{ Url = $Url; MirrorId = $Mirror; Fingerprint = $Fingerprint; Account = $Account; Token = $Token; TaskName = $TaskName; DataDir = $DataDir; ComputerName = $Server; SkipDryRun = $true }
        if ($null -ne $Credential) { $arguments.Credential = $Credential }
        & $installer @arguments
        @{ Pending = (Test-Path -LiteralPath (Join-Path $DataDir 'state\token.pending')); Stored = (Test-Path -LiteralPath (Join-Path $DataDir 'state\token.dpapi')) }
    }
    RemoveExporter        = {
        param([string]$Directory, [string]$TaskName, [string]$DataDir)
        $installer = Join-Path $Directory 'Install-TenkoDhcpMirror.ps1'
        if (Test-Path -LiteralPath $installer) { & $installer -Remove -TaskName $TaskName -DataDir $DataDir -Confirm:$false }
        @{ Pending = (Test-Path -LiteralPath (Join-Path $DataDir 'state\token.pending')); Task = ($null -ne (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) }
    }
    StartExporter         = {
        param([string]$TaskName)
        Start-ScheduledTask -TaskPath '\Tenko\' -TaskName $TaskName
    }
    RemoveBatchRight      = {
        # The right to log on as a batch job that the task's registration granted the account.
        param([string]$Sid)
        $work = Join-Path $env:SystemRoot 'Temp\tenko-takeover-rights'
        if (-not (Test-Path -LiteralPath $work)) { $null = New-Item -ItemType Directory -Path $work }
        $inf = Join-Path $work 'rights.inf'
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
            $null = secedit /configure /db (Join-Path $work 'rights.sdb') /cfg $inf /areas USER_RIGHTS
        }
        $null = secedit /export /cfg $inf /areas USER_RIGHTS
        $still = @(Get-Content -LiteralPath $inf | Where-Object { $_ -like 'SeBatchLogonRight*' -and $_ -like "*$Sid*" }).Count -gt 0
        Remove-Item -LiteralPath $work -Recurse -Force
        -not $still
    }
    SetDnsCredential      = {
        param([pscredential]$Credential, [bool]$Remove)
        if ($Remove) { Remove-DhcpServerDnsCredential -Force } else { Set-DhcpServerDnsCredential -Credential $Credential }
        $now = Get-DhcpServerDnsCredential -ErrorAction SilentlyContinue
        $(if ($null -ne $now -and $now.UserName) { [string]$now.DomainName + '\' + [string]$now.UserName } else { '' })
    }
    NewDnsUser            = {
        param([string]$Name, [securestring]$Password, [bool]$Remove)
        if ($Remove) { Get-ADUser -Filter "SamAccountName -eq '$Name'" | Remove-ADUser -Confirm:$false; return }
        if ($null -eq (Get-ADUser -Filter "SamAccountName -eq '$Name'")) {
            New-ADUser -Name $Name -SamAccountName $Name -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -KerberosEncryptionType AES128, AES256
        }
    }
    NewTenkoAccount       = {
        # Tenko's computer account: no privileged group, no delegation, AES only, one SPN.
        param([string]$Name, [string]$Path, [string]$Spn, [securestring]$Password)
        if ($null -eq (Get-ADComputer -Filter "SamAccountName -eq '$Name$'")) {
            New-ADComputer -Name $Name -SAMAccountName "$Name$" -Path $Path -AccountPassword $Password -Enabled $true -KerberosEncryptionType AES128, AES256 -ServicePrincipalNames $Spn -TrustedForDelegation $false
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
            Rights      = @((Get-Acl -Path ("AD:\" + $account.DistinguishedName)).Access | ForEach-Object {
                    @{ Who = [string]$_.IdentityReference; Rights = [string]$_.ActiveDirectoryRights; Object = [string]$_.ObjectType; Allow = ([string]$_.AccessControlType -eq 'Allow') }
                })
            AccountOps  = @(Get-ADGroupMember -Identity 'S-1-5-32-548' -ErrorAction SilentlyContinue).Count
        }
    }
    ReadPwdLastSet        = {
        param([string]$Name)
        [string](Get-ADComputer -Identity "$Name$" -Properties pwdLastSet).pwdLastSet
    }
    SetAccountState       = {
        param([string]$Name, [bool]$Remove)
        if ($Remove) { Get-ADComputer -Filter "SamAccountName -eq '$Name$'" | Remove-ADComputer -Confirm:$false }
        else { Disable-ADAccount -Identity "$Name$"; [bool](Get-ADComputer -Identity "$Name$").Enabled }
    }
    NewGpo                = {
        param([string]$Name, [string]$DomainDn, [string[]]$Members)
        $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $gpo) { $gpo = New-GPO -Name $Name }
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
                default { 'unread' }
            }
            @{ Name = ([string]$_.HostName).ToLowerInvariant(); Type = [string]$_.RecordType; Data = $text }
        }
    }
    ConvertToSecondary    = {
        param([string]$Zone, [string]$Master, [string]$File, [bool]$Convert)
        $zone = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($Convert) {
            if ($null -ne $zone -and [string]$zone.ZoneType -ne 'Secondary') { ConvertTo-DnsServerSecondaryZone -Name $Zone -MasterServers $Master -ZoneFile $File -Force }
        } elseif ($null -eq $zone) {
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
    ConvertToPrimary      = {
        # The way back on the PDC emulator: a file-backed primary, then directory-integrated,
        # then the update setting and the transfer lists of the discovery.
        param([string]$Zone, [string]$File, [string]$Scope, [string]$Update)
        $zone = Get-DnsServerZone -Name $Zone
        if ([string]$zone.ZoneType -eq 'Secondary') { ConvertTo-DnsServerPrimaryZone -Name $Zone -ZoneFile $File -Force }
        if (-not (Get-DnsServerZone -Name $Zone).IsDsIntegrated) { ConvertTo-DnsServerPrimaryZone -Name $Zone -ReplicationScope $Scope -Force }
        Set-DnsServerPrimaryZone -Name $Zone -DynamicUpdate $Update
        $zone = Get-DnsServerZone -Name $Zone
        @{ Type = [string]$zone.ZoneType; Ds = [bool]$zone.IsDsIntegrated; Update = [string]$zone.DynamicUpdate }
    }
    RemoveSecondary       = {
        param([string]$Zone)
        $zone = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($null -ne $zone -and [string]$zone.ZoneType -eq 'Secondary') { Remove-DnsServerZone -Name $Zone -Force }
    }
    ReadZone              = {
        param([string]$Zone)
        $zone = Get-DnsServerZone -Name $Zone -ErrorAction SilentlyContinue
        if ($null -ne $zone) { @{ Type = [string]$zone.ZoneType; Ds = [bool]$zone.IsDsIntegrated; Update = [string]$zone.DynamicUpdate } }
    }
    StopDhcp              = {
        # DHCPServer, never Dhcp (the DHCP client a controller needs for its own registration).
        Stop-Service -Name DHCPServer -Force
        Set-Service -Name DHCPServer -StartupType Disabled
        $service = Get-Service -Name DHCPServer
        @{ Status = [string]$service.Status; Start = [string]$service.StartType; Listening = @(Get-NetUDPEndpoint -LocalPort 67 -ErrorAction SilentlyContinue).Count }
    }
    StartDhcp             = {
        param([string]$Start)
        Set-Service -Name DHCPServer -StartupType $Start
        Start-Service -Name DHCPServer
        $service = Get-Service -Name DHCPServer
        @{ Status = [string]$service.Status; Start = [string]$service.StartType }
    }
    SetAuthorization      = {
        param([string]$Name, [string]$Address, [bool]$Authorized)
        if ($Authorized) { Add-DhcpServerInDC -DnsName $Name -IPAddress $Address } else { Remove-DhcpServerInDC -DnsName $Name -IPAddress $Address -Confirm:$false }
    }
    ReadAuthorization     = {
        # The controller's own replica of the authorized DHCP servers.
        param([string]$Configuration)
        Get-ADObject -Server $env:COMPUTERNAME -SearchBase "CN=NetServices,CN=Services,$Configuration" -Filter 'objectClass -eq "dHCPClass"' -Properties dhcpServers |
            ForEach-Object { @($_.dhcpServers | ForEach-Object { [string]$_ }) }
    }
    WriteLeases           = {
        # The narrow write-back: address, client identifier and end; the state active.
        param([string]$ScopeId, [object[]]$Leases)
        $written = 0
        $known = @(Get-DhcpServerv4Lease -ScopeId $ScopeId -AllLeases | ForEach-Object { [string]$_.IPAddress })
        foreach ($lease in $Leases) {
            if ($known -contains [string]$lease.Ip) { continue }
            Add-DhcpServerv4Lease -ScopeId $ScopeId -IPAddress $lease.Ip -ClientId $lease.Client -AddressState Active -LeaseExpiryTime ((Get-Date).AddSeconds([int]$lease.Seconds))
            $written++
        }
        Set-DhcpServerSetting -ConflictDetectionAttempts 2
        $written
    }
    RemoveDhcpRole        = {
        param([string]$Backup)
        if ([string](Get-Service -Name DHCPServer -ErrorAction SilentlyContinue).Status -eq 'Running') { throw 'the DHCP Server service runs; the finish never removes a running server' }
        $null = Uninstall-WindowsFeature -Name DHCP
        $database = Join-Path $env:SystemRoot 'System32\dhcp'
        if (Test-Path -LiteralPath $database) {
            if (-not (Test-Path -LiteralPath $Backup)) { $null = New-Item -ItemType Directory -Path $Backup }
            Move-Item -LiteralPath $database -Destination (Join-Path $Backup 'dhcp') -Force
        }
        [bool](Get-WindowsFeature -Name DHCP).Installed
    }
    RestoreDhcpRole       = {
        param([string]$Backup, [string]$Export, [bool]$Import, [string]$Group)
        $null = Install-WindowsFeature -Name DHCP -IncludeManagementTools
        if ($Group) { Add-DhcpServerSecurityGroup }
        if ($Import) { Import-DhcpServer -File $Export -BackupPath (Join-Path $Backup 'import') -Leases -Force }
        Set-Service -Name DHCPServer -StartupType Disabled
        [bool](Get-WindowsFeature -Name DHCP).Installed
    }
    AddFailover           = {
        param([string]$Name, [string]$Partner, [string[]]$Scopes)
        if (-not (Get-DhcpServerv4Failover -Name $Name -ErrorAction SilentlyContinue)) {
            Add-DhcpServerv4Failover -Name $Name -PartnerServer $Partner -ScopeId $Scopes -LoadBalancePercent 50 -MaxClientLeadTime (New-TimeSpan -Hours 1) -Force
        }
    }
    RemoveZoneObject      = {
        param([string]$Dn)
        Remove-ADObject -Identity $Dn -Recursive -Confirm:$false
    }
    ReadGroups            = {
        param([string[]]$Names)
        foreach ($name in $Names) { @{ Name = $name; Count = @(Get-ADGroup -Filter "sAMAccountName -eq '$name'").Count; Conflicts = @(Get-ADGroup -Filter "Name -like '$name*CNF:*'").Count } }
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
    return Join-Path (Join-Path (Join-Path $env:ProgramData 'Tenko') 'takeover') $Domain
}

function Protect-TkDirectory {
    param([string]$Path)
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', $inherit, 'None', 'Allow'))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Open-TkState {
    # Creates or reads the run's state and holds its lock. A second process stops with exit 1.
    param([string]$Domain)
    $dir = Get-TkStateDir $Domain
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    if ($env:OS -eq 'Windows_NT') { Protect-TkDirectory $dir }
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
    # A value the reverse writes to Windows: a controller address Active Directory reported,
    # or a value present at discovery. Anything else stops the reverse with exit 4.
    param([System.Collections.IDictionary]$Readings, [string]$Value, [ValidateSet('address', 'discovered')][string]$Class)
    $allowed = $(if ($Class -eq 'address') { @($Readings.controllers | ForEach-Object { $_.addresses }) } else { @($Readings.values) })
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

function Find-TkHardeningWarning {
    param([object[]]$Rows, [string]$DomainSid, [string]$Quota, [string]$Pdc)
    $warnings = @()
    $enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $lowSids = @('S-1-1-0', 'S-1-5-11', "$DomainSid-513", "$DomainSid-515")
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
                foreach ($right in @($row.Rights)) {
                    if (-not $right.Allow) { continue }
                    $low = $false
                    foreach ($name in 'Everyone', 'Authenticated Users', 'Domain Users', 'Domain Computers') { if ($right.Who -like "*\$name" -or $right.Who -eq $name) { $low = $true } }
                    if ($lowSids -contains $right.Who) { $low = $true }
                    if (-not $low) { continue }
                    $write = $right.Rights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty'
                    $enrolls = $right.Rights -match 'ExtendedRight|GenericAll' -and ($right.Object -eq $enroll -or $right.Object -eq '00000000-0000-0000-0000-000000000000')
                    if ($write -or ($risky -and $enrolls)) { $warnings += "certificate template $($row.Name): $($right.Who) may $(if ($write) { 'write' } else { 'enroll in' }) it$(if ($risky) { ' and it lets the enrollee supply the subject or allows any purpose' })"; break }
                }
            }
            'rc4' { $warnings += "account $($row.Name) has a service principal name and allows RC4" }
        }
    }
    if ($Quota -and $Quota -ne '0') { $warnings += "ms-DS-MachineAccountQuota is ${Quota}: any domain user may create computer accounts" }
    return , $warnings
}

function Find-TkGppPassword {
    param([string]$Domain)
    $root = "\\$Domain\SYSVOL\$Domain\Policies"
    $hits = @()
    if (Test-Path -LiteralPath $root) {
        $hits = @(Get-ChildItem -LiteralPath $root -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue |
                Select-String -Pattern 'cpassword="[^"]+"' -List -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
    }
    return , $hits
}

function Find-TkDhcpStartPolicy {
    # Policies whose security template sets the start mode of DHCPServer.
    param([string]$Domain)
    $root = "\\$Domain\SYSVOL\$Domain\Policies"
    $hits = @()
    if (Test-Path -LiteralPath $root) {
        $hits = @(Get-ChildItem -LiteralPath $root -Recurse -Filter 'GptTmpl.inf' -ErrorAction SilentlyContinue |
                Select-String -Pattern '^\s*"?DHCPServer"?\s*,' -List -ErrorAction SilentlyContinue | ForEach-Object { $_.Path })
    }
    return , $hits
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
    # Reads everything the plan, the change list and the warnings need.
    param([string]$Domain)
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
            if (-not $zoneSet.Contains($row.Name)) { $zoneSet[$row.Name] = [ordered]@{ name = $row.Name; type = $row.Type; ds = $row.Ds; scope = $row.Scope; update = $row.Update; reverse = $row.Reverse; aging = $row.Aging; servers = [ordered]@{} } }
            $zoneSet[$row.Name].servers[$controller] = [ordered]@{ transfer = $row.Transfer; notify = $row.Notify; secondaries = @($row.Secondaries); notify_servers = @($row.NotifyServers); serial = $row.Serial; type = $row.Type }
            $r.values += @($row.Secondaries) + @($row.NotifyServers) + @($row.Transfer, $row.Notify, $row.Update, $row.Scope)
        }
    }
    foreach ($controller in $controllers) { if (-not (@($zoneSet.Values) | Where-Object { $_.servers.Contains($controller.name) })) { $r.warnings += "$($controller.name) serves no zone (it was never enlisted in the DNS application partitions)" } }
    $r.directory_zones = @(Invoke-TkRemote -Server $pdc -Name ReadDirectoryZones -Arguments @($r.domain_dn, ('DC=' + ($r.forest_root -replace '\.', ',DC='))) | ForEach-Object { [ordered]@{ name = $_.Name; dn = $_.Dn } })
    foreach ($object in $r.directory_zones) {
        if (-not $zoneSet.Contains($object.name) -and $object.name -notmatch '^\.\.') { $r.warnings += "the directory holds the zone object $($object.name), which no server loads: a DNS Server role installed later serves it at once with its old data" }
    }

    # DHCP: the servers the directory authorizes, each read in its own session.
    $authorized = @(Invoke-TkRemote -Server $pdc -Name ReadDhcpInDirectory)
    $script:TkKnownHosts = @($names) + @($authorized | ForEach-Object { $_.Name })
    foreach ($server in $authorized) {
        $read = Invoke-TkRemote -Server $server.Name -Name ReadDhcpServer | Select-Object -First 1
        $scopes = @($read.Scopes | ForEach-Object {
                [ordered]@{ id = $_.Id; cidr = (ConvertTo-TkCidr $_.Id $_.Mask); start = $_.Start; end = $_.End; state = $_.State; lease_secs = $_.LeaseSeconds; exclusions = @($_.Exclusions); reservations = @($_.Reservations | ForEach-Object { [ordered]@{ ip = $_.Ip; client = $_.Client } }); hosts = @($_.Hosts) }
            })
        $r.dhcp += , [ordered]@{ name = $server.Name; address = $server.Address; scopes = $scopes; bindings = @($read.Bindings); failover = @($read.Failover | ForEach-Object { [ordered]@{ name = $_.Name; partner = $_.Partner; mode = $_.Mode; scopes = @($_.Scopes) } }); dns_user = $read.DnsUser; v6 = @($read.V6Scopes); multicast = @($read.Multicast); allow_list = $read.AllowList; service_start = $read.Service; policies = @($read.Policies); superscopes = @($read.Superscope) }
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
    foreach ($policy in (Find-TkDhcpStartPolicy $Domain)) { $r.window_refusals += "the group policy $policy sets the start mode of DHCPServer: its owner must remove that setting before the DHCP window" }

    # The member servers the exporter may run on, and the members that are DHCP clients.
    $computers = @(Invoke-TkRemote -Server $pdc -Name ReadComputers -Arguments (, [string[]]$names))
    $r.servers = @($computers | Where-Object { $_.Server -and $_.IPv4 } | ForEach-Object { [ordered]@{ name = $_.Name; address = $_.IPv4 } })
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
    }

    # What a compromised DNS authority with a domain computer account could use.
    $hardening = @()
    foreach ($controller in $names) {
        foreach ($row in (Invoke-TkRemote -Server $controller -Name ReadHardening -Arguments @($r.configuration, $r.domain_dn))) {
            if ($row.Kind -eq 'server') { $row.Server = $controller; $hardening += $row }
            elseif ($controller -eq $pdc) { $hardening += $row }
        }
    }
    $r.warnings += Find-TkHardeningWarning -Rows $hardening -DomainSid $r.domain_sid -Quota $info.Quota -Pdc $pdc
    foreach ($path in (Find-TkGppPassword $Domain)) { $r.warnings += "a password is left in Group Policy Preferences: $path" }
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
    # The node's name: the label of the typed host name under the domain, else the label of
    # the certificate's name under the domain; checked against the deny list and the domain.
    param([string]$HostName, [string]$Domain)
    $candidate = ''
    if ($HostName.ToLowerInvariant().EndsWith(".$Domain")) { $candidate = $HostName.ToLowerInvariant().Substring(0, $HostName.Length - $Domain.Length - 1) }
    if ($candidate -notmatch $script:TkLabelPattern) { $candidate = '' }
    if (-not $candidate) { Exit-TkTakeover 1 "type Tenko's address as its host name under $Domain (for example tenko.$Domain), so that its name in the zones is known" }
    if ($script:TkDeniedNodeNames -contains $candidate) { Exit-TkTakeover 1 "the node's name $candidate is on the deny list (wpad, isatap, localhost)" }
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
            Write-TkNote "The step $key failed. Run the script again to resume at this step after reading the actual state, or run it with -Reverse to undo the phase's done steps."
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
        if ($null -ne $step.Undo) { & $step.Undo }
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

function Get-TkPhase2 {
    param([hashtable]$State, [hashtable]$Payloads)
    $r = $State.Data.readings
    $pdc = $r.pdc
    $mirrorHost = $r.mirror_host.name
    $tenkoIp = [string]$State.Data.tenko.address
    $gmsa = [bool]$r.kds
    $url = "https://$($State.Data.tenko.host):$($State.Data.tenko.port)"
    $remoteDir = 'C:\Program Files\Tenko\takeover-payload'
    $payloadFiles = @($Payloads.exporter, $Payloads.installer)
    $steps = @(
        @{ Name = 'mirrors'
            Do = {
                # First, within five minutes of the approval: the creation mints the tokens.
                foreach ($server in $r.dhcp) {
                    if ($script:TkTokens.ContainsKey($server.name)) { continue }
                    # A mirror of an earlier, failed attempt whose token is gone is made anew.
                    $old = Get-TkField $State.Data.mirrors $server.name
                    if ($old) { [void](Invoke-Tenko -Method DELETE -Path "/migrate/mirrors/$old" -Expect @(200, 204, 404)) }
                    $created = Invoke-Tenko -Method POST -Path '/migrate/mirrors' -Body ([ordered]@{ name = $server.name; kind = 'windows-dhcp'; source_prefixes = @("$($r.mirror_host.address)/32") })
                    $mirror = Get-TkField $created 'mirror'
                    $id = [string](Get-TkField $mirror 'id')
                    $token = Get-TkField $created 'token'
                    $fingerprint = ([string](Get-TkField $created 'ca_fingerprint') -replace '[:\s]', '').ToLowerInvariant()
                    if ($id -cnotmatch $script:TkUuidPattern -or -not ($token -is [securestring]) -or -not (Test-TkSecurePattern $token $script:TkTokenPattern)) { Exit-TkTakeover 4 "Tenko answered a mirror id or token for $($server.name) that is not of the exact form" }
                    if ($fingerprint -and $fingerprint -ne $State.Data.tenko.fingerprint) { Exit-TkTakeover 4 'the fingerprint Tenko names for the mirror is not the pinned root' }
                    $State.Data.mirrors[$server.name] = $id
                    $script:TkTokens[$server.name] = $token
                    Save-TkState $State
                }
            }
            Undo = { foreach ($id in @($State.Data.mirrors.Values)) { [void](Invoke-Tenko -Method DELETE -Path "/migrate/mirrors/$id" -Expect @(200, 204, 404)) }; $State.Data.mirrors = [ordered]@{} }
        }
        @{ Name = 'backups'
            Do = {
                $backup = Join-Path $State.Dir 'backup'
                if (-not (Test-Path -LiteralPath $backup)) { [void](New-Item -ItemType Directory -Path $backup) }
                foreach ($server in $r.dhcp) {
                    $remote = 'C:\ProgramData\Tenko\takeover-backup\dhcp-export.xml'
                    [void](Invoke-TkRemote -Server $server.name -Name ExportDhcp -Arguments @($remote))
                    Copy-TkFromServer -Server $server.name -RemotePath $remote -LocalPath (Join-Path $backup "dhcp-$($server.name).xml")
                }
                foreach ($zone in $r.zones) {
                    $file = "tenko-backup-$($zone.name).dns"
                    $remote = [string](Invoke-TkRemote -Server $pdc -Name ExportZone -Arguments @($zone.name, $file) | Select-Object -Last 1)
                    Copy-TkFromServer -Server $pdc -RemotePath $remote -LocalPath (Join-Path $backup $file)
                }
            }
            Undo = $null
        }
        @{ Name = 'mirror-account'
            Do = {
                $password = $(if ($gmsa) { $null } else { Get-TkRandomSecret })
                $script:TkMirrorPassword = $password
                $sid = [string](Invoke-TkRemote -Server $pdc -Name NewMirrorAccount -Arguments @($script:TkMirrorAccount, $gmsa, $r.domain, ($mirrorHost.Split('.')[0] + '$'), $password) | Select-Object -Last 1)
                $State.Data.values.mirror_account_sid = $sid
            }
            Undo = { [void](Invoke-TkRemote -Server $pdc -Name RemoveMirrorAccount -Arguments @($script:TkMirrorAccount, $gmsa)) }
        }
        @{ Name = 'mirror-tools'
            Do = { if (-not $r.mirror_host.tools) { [void](Invoke-TkRemote -Server $mirrorHost -Name SetFeature -Arguments @('RSAT-DHCP', $true)) } }
            Undo = { if (-not $r.mirror_host.tools) { [void](Invoke-TkRemote -Server $mirrorHost -Name SetFeature -Arguments @('RSAT-DHCP', $false)) } }
        }
        @{ Name = 'exporter'
            Do = {
                Copy-TkToServer -Server $mirrorHost -Files @($Payloads.exporter, $Payloads.installer) -Directory $remoteDir
                $account = $(if ($gmsa) { "$($r.netbios)\$($script:TkMirrorAccount)$" } else { "$($r.netbios)\$($script:TkMirrorAccount)" })
                $credential = $null
                if (-not $gmsa) {
                    if ($null -eq $script:TkMirrorPassword) { Exit-TkTakeover 2 'the exporter account''s password is no longer in memory; reverse the phase and run it again' }
                    $credential = [pscredential]::new($account, $script:TkMirrorPassword)
                }
                foreach ($server in $r.dhcp) {
                    $short = $server.name.Split('.')[0]
                    if (-not $script:TkTokens.ContainsKey($server.name)) { Exit-TkTakeover 2 "the token of the mirror of $($server.name) is no longer in memory; reverse the phase and run it again within five minutes of a new approval" }
                    $result = Invoke-TkRemote -Server $mirrorHost -Name InstallExporter -Arguments @($remoteDir, $url, $State.Data.mirrors[$server.name], $State.Data.tenko.fingerprint, $account, $credential, $script:TkTokens[$server.name], "Tenko DHCP mirror $short", "C:\ProgramData\Tenko\mirror\$short", $server.name) | Select-Object -Last 1
                    if ($result.Pending -or -not $result.Stored) { throw "the exporter's first run for $($server.name) did not store its token (token.pending left or no token.dpapi)" }
                }
            }
            Undo = {
                foreach ($server in $r.dhcp) {
                    $short = $server.name.Split('.')[0]
                    $result = Invoke-TkRemote -Server $mirrorHost -Name RemoveExporter -Arguments @($remoteDir, "Tenko DHCP mirror $short", "C:\ProgramData\Tenko\mirror\$short") | Select-Object -Last 1
                    if ($result.Pending -or $result.Task) { throw "the exporter of $($server.name) is not fully removed from $mirrorHost" }
                }
                if ($State.Data.values.Contains('mirror_account_sid')) {
                    if (-not (Invoke-TkRemote -Server $mirrorHost -Name RemoveBatchRight -Arguments @($State.Data.values.mirror_account_sid) | Select-Object -Last 1)) { throw "the batch logon right of the exporter's account is still granted on $mirrorHost" }
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
            Undo = {
                foreach ($zone in $r.zones) {
                    $before = $zone.servers[$pdc]
                    foreach ($value in @($before.secondaries) + @($before.notify_servers) + @($before.transfer, $before.notify)) { if ($value) { Assert-TkRestoreValue -Readings $r -Value $value -Class discovered } }
                    [void](Invoke-TkRemote -Server $pdc -Name SetZoneLists -Arguments @($zone.name, [string[]]@($before.secondaries), $before.transfer, $before.notify, [string[]]@($before.notify_servers)))
                }
            }
        }
        @{ Name = 'dns-credential'
            Do = {
                if ($r.dns_credential -ne 'create') { return }
                $password = Get-TkRandomSecret
                [void](Invoke-TkRemote -Server $pdc -Name NewDnsUser -Arguments @($script:TkDnsCredentialUser, $password, $false))
                $credential = [pscredential]::new("$($r.netbios)\$($script:TkDnsCredentialUser)", $password)
                foreach ($server in $r.dhcp) { [void](Invoke-TkRemote -Server $server.name -Name SetDnsCredential -Arguments @($credential, $false)) }
            }
            Undo = {
                if ($r.dns_credential -ne 'create') { return }
                foreach ($server in $r.dhcp) {
                    if ($server.dns_user) { Write-Warning "$($server.name) had the DNS credential $($server.dns_user) before; set it again there with Set-DhcpServerDnsCredential (its password was never read)" }
                    [void](Invoke-TkRemote -Server $server.name -Name SetDnsCredential -Arguments @($null, $true))
                }
                [void](Invoke-TkRemote -Server $pdc -Name NewDnsUser -Arguments @($script:TkDnsCredentialUser, $null, $true))
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
                if ($State.Data.values.Contains('tenko_account')) { [void](Invoke-TkRemote -Server $pdc -Name SetAccountState -Arguments @($State.Data.tenko.node, $true)) }
            }
        }
        @{ Name = 'gpo'
            Do = {
                $members = @($r.members | Where-Object { $_ } | ForEach-Object { $_.Split('.')[0] })
                $State.Data.values.gpo = [string](Invoke-TkRemote -Server $pdc -Name NewGpo -Arguments @($script:TkGpoName, $r.domain_dn, [string[]]$members) | Select-Object -Last 1)
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
            Undo = $null
        }
    )
    return , $steps
}

function Invoke-TkTenkoAccount {
    # Tenko's computer account for zones that took secure updates, with a one-time password
    # made here; disabled when Tenko has not changed it within ten minutes of the adoption.
    param([hashtable]$State)
    $r = $State.Data.readings
    if (@($r.zones | Where-Object { $_.update -eq 'Secure' }).Count -eq 0) { return }
    $node = $State.Data.tenko.node
    $password = Get-TkRandomSecret
    $account = Invoke-TkRemote -Server $r.pdc -Name NewTenkoAccount -Arguments @($node, $r.computers, "DNS/$node.$($r.domain)", $password) | Select-Object -Last 1
    $State.Data.values.tenko_account = [ordered]@{ dn = $account.Dn; sid = $account.Sid }
    Save-TkState $State
    if (@($account.Groups).Count -gt 0) { throw "Tenko's account is a member of $(@($account.Groups) -join ', ')" }
    if (($account.Uac -band 0x1080000) -ne 0 -or @($account.DelegateTo).Count -gt 0) { throw "Tenko's account allows delegation" }
    if ($account.Encryption -ne 24) { throw "Tenko's account's encryption types are $($account.Encryption), not AES only (24)" }
    if (@($account.Spns).Count -ne 1 -or $account.Spns[0] -ne "DNS/$node.$($r.domain)") { throw "Tenko's account carries the names $(@($account.Spns) -join ', ')" }
    foreach ($right in @($account.Rights)) {
        if ($right.Allow -and $right.Rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight' -and $right.Who -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|SELF|Cert Publishers|Key Admins|Enterprise Key Admins') {
            Write-Warning "$($right.Who) holds $($right.Rights) on Tenko's account"
        }
    }
    if ($account.AccountOps -gt 0) { Write-Warning "Account Operators is not empty: its members may reset Tenko's account" }
    $before = $account.PwdLastSet
    [void](Invoke-Tenko -Method POST -Path '/dns/kerberos/adopt' -Body ([ordered]@{ realm = $r.domain.ToUpperInvariant(); name = "$node$"; password = $password; spns = @("DNS/$node.$($r.domain)") }))
    $password.Dispose()
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $script:TkPasswordChangeSec) {
        if ([string](Invoke-TkRemote -Server $r.pdc -Name ReadPwdLastSet -Arguments @($node) | Select-Object -Last 1) -ne $before) { return }
        Start-Sleep -Seconds $script:TkPollSec
    }
    [void](Invoke-TkRemote -Server $r.pdc -Name SetAccountState -Arguments @($node, $false))
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
    Write-TkNote "The window was started by $by at $at, according to Tenko; next the DNS window (phase 4) and the DHCP window (phase 5)."
    if (-not (Confirm-TkTyped 'Type the domain''s name to go on' $State.Data.domain)) { Exit-TkTakeover 3 'the window was not confirmed at the console; nothing was changed' }
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
    # The exporter's mapping of one server's configuration, on this host: the verified copy
    # of the exporter is dot-sourced here, in this function's scope only.
    param([object]$Raw, [string]$Server, [string]$ExporterPath)
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

function Compare-TkZoneCopy {
    # Tenko's copy of a zone against every controller's records, type by type.
    param([System.Collections.IDictionary]$Readings, [string]$Zone, [string]$ZoneId)
    $page = Invoke-Tenko -Method GET -Path "/dns/zones/$ZoneId/records"
    $theirs = @(@(Get-TkField $page 'items') | Where-Object { [string](Get-TkField $_ 'type') -ne 'SOA' } | ForEach-Object {
            "$(([string]$_.name).ToLowerInvariant().TrimEnd('.'))|$([string]$_.type)|$(([string]$_.data).TrimEnd('.').ToLowerInvariant())"
        } | Sort-Object -Unique)
    foreach ($controller in $Readings.controllers) {
        $mine = @(Invoke-TkRemote -Server $controller.name -Name ReadRecords -Arguments @($Zone) | ForEach-Object {
                $name = $(if ($_.Name -eq '@') { $Zone } else { "$($_.Name).$Zone" })
                "$name|$($_.Type)|$(([string]$_.Data).ToLowerInvariant())"
            } | Sort-Object -Unique)
        $diff = @(Compare-Object -ReferenceObject $mine -DifferenceObject $theirs)
        if ($diff.Count -gt 0) { Exit-TkTakeover 4 "Tenko's copy of $Zone differs from $($controller.name) in $($diff.Count) records (first: $(ConvertTo-TkSafeText $diff[0].InputObject)); the flip is refused" }
    }
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
        @{ Name = 'configuration'; Do = { Test-TkConfiguration -State $State -ExporterPath $Payloads.exporter.Path }; Undo = $null }
        @{ Name = 'replicate'; Do = { $out = Invoke-TkRemote -Server $pdc -Name Replicate | Select-Object -Last 1; if ($out.Exit -ne 0) { throw "repadmin /syncall failed: $(ConvertTo-TkSafeText $out.Text)" } }; Undo = $null }
        @{ Name = 'tenko-flip'
            Do = {
                foreach ($zone in $ordered) {
                    $id = Get-TkZoneId $zone.name
                    if (-not $id) { Exit-TkTakeover 4 "Tenko holds no zone $($zone.name)" }
                    $view = Invoke-Tenko -Method GET -Path "/dns/zones/$id"
                    if ([string](Get-TkField $view 'kind') -eq 'primary') { continue }
                    [void](Invoke-Tenko -Method POST -Path "/dns/zones/$id/transfer")
                    Compare-TkZoneCopy -Readings $r -Zone $zone.name -ZoneId $id
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
                # The PDC emulator first while the others answer from their secondaries; then
                # each other controller in turn loads the directory copy by its own polling.
                foreach ($zone in $ordered) {
                    $scope = $(if ($zone.name.StartsWith('_msdcs.')) { 'Forest' } else { 'Domain' })
                    Assert-TkRestoreValue -Readings $r -Value $zone.update -Class discovered
                    $now = Invoke-TkRemote -Server $pdc -Name ConvertToPrimary -Arguments @($zone.name, "$($zone.name).dns", $scope, $zone.update) | Select-Object -Last 1
                    if (-not $now.Ds -or $now.Update -ne $zone.update) { Exit-TkTakeover 2 "$($zone.name) on $pdc is $($now.Type), update $($now.Update) after the way back, not directory-integrated with $($zone.update): a zone left open to unsigned updates fails the reverse" }
                    $before = $zone.servers[$pdc]
                    [void](Invoke-TkRemote -Server $pdc -Name SetZoneLists -Arguments @($zone.name, [string[]]@($before.secondaries), $before.transfer, $before.notify, [string[]]@($before.notify_servers)))
                }
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
        @{ Name = 'register'; Do = { foreach ($controller in $r.controllers) { [void](Invoke-TkRemote -Server $controller.name -Name RegisterDns) } }; Undo = $null }
        @{ Name = 'check'
            Do = {
                $answer = @(Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$($r.domain)" -Type SRV -Server $tenkoIp -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'SRV' })
                $names = @($r.controllers | ForEach-Object { $_.name })
                if (@($answer | Where-Object { $names -contains ([string]$_.NameTarget).ToLowerInvariant().TrimEnd('.') }).Count -eq 0) { throw "Tenko does not answer the locator records of $($r.domain)" }
            }
            Undo = $null
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

function Test-TkAuthorizationRemoved {
    # Each controller's own replica no longer lists the servers.
    param([System.Collections.IDictionary]$Readings, [bool]$Authorized)
    foreach ($controller in $Readings.controllers) {
        $listed = @(Invoke-TkRemote -Server $controller.name -Name ReadAuthorization -Arguments @($Readings.configuration)) -join "`n"
        foreach ($server in $Readings.dhcp) {
            $present = $listed -match [regex]::Escape($server.name)
            if ($present -ne $Authorized) { return $false }
        }
    }
    return $true
}

function Get-TkPhase5 {
    param([hashtable]$State)
    $r = $State.Data.readings
    $pdc = $r.pdc
    return , @(
        @{ Name = 'refusals'
            Do = {
                if (@($r.window_refusals).Count -gt 0) { Exit-TkTakeover 1 "the DHCP window is refused: $(@($r.window_refusals) -join '; ')" }
                if ($null -ne $script:TkWindowWatch -and $script:TkWindowWatch.Elapsed.TotalSeconds -gt $script:TkReconfirmSec) {
                    if (-not (Confirm-TkTyped 'More than fifteen minutes have passed since the window''s confirmation. Type the domain''s name to make Windows silent' $r.domain)) { Exit-TkTakeover 3 'the silence was not confirmed at the console' }
                }
            }
            Undo = $null
        }
        @{ Name = 'takeover'
            Do = {
                foreach ($server in $r.dhcp) {
                    foreach ($scope in $server.scopes) {
                        $key = "takeover.$($scope.cidr)"
                        if (Get-TkField $State.Data.jobs $key) { continue }
                        $job = Invoke-Tenko -Method POST -Path "/migrate/mirrors/$($State.Data.mirrors[$server.name])/scopes/$($scope.cidr -replace '/', '%2F')/takeover"
                        $State.Data.jobs[$key] = [string](Get-TkField $job 'id')
                        Save-TkState $State
                    }
                }
                foreach ($server in $r.dhcp) { [void](Invoke-TkRemote -Server $r.mirror_host.name -Name StartExporter -Arguments @("Tenko DHCP mirror $($server.name.Split('.')[0])")) }
            }
            Undo = { Undo-TkTakeoverJob -State $State }
        }
        @{ Name = 'silence'
            Do = {
                $waits = @{}
                foreach ($key in @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' })) {
                    $waits[$key] = Wait-TkJob -Id $State.Data.jobs[$key] -ManualKind 'migrate.takeover.silence'
                    if ($waits[$key].Step -lt 0) { throw "the takeover job of $($key.Substring(9)) ended $($waits[$key].State) before Windows was made silent" }
                }
                $State.Data.values.method = 'stop'
                $State.Data.values.leases = [ordered]@{}
                foreach ($server in $r.dhcp) {
                    foreach ($scope in $server.scopes) {
                        $State.Data.values.leases["$($server.name)|$($scope.id)"] = @(Invoke-TkRemote -Server $server.name -Name ReadLeases -Arguments @($scope.id) | ForEach-Object { [ordered]@{ ip = $_.Ip; client = $_.Client } })
                    }
                }
                Save-TkState $State
                Show-TkRestoreLine $r
                foreach ($server in $r.dhcp) {
                    $now = Invoke-TkRemote -Server $server.name -Name StopDhcp | Select-Object -Last 1
                    if ($now.Status -ne 'Stopped' -or $now.Start -ne 'Disabled' -or $now.Listening -ne 0) { throw "$($server.name) is not silent: the service is $($now.Status), start $($now.Start), $($now.Listening) listeners on UDP 67" }
                }
                foreach ($server in $r.dhcp) { [void](Invoke-TkRemote -Server $pdc -Name SetAuthorization -Arguments @($server.name, $server.address, $false)) }
                [void](Invoke-TkRemote -Server $pdc -Name Replicate)
                if (-not (Test-TkAuthorizationRemoved $r $false)) { throw 'a controller''s replica still lists a DHCP server as authorized after the replication' }
                foreach ($key in $waits.Keys) {
                    [void](Invoke-Tenko -Method POST -Path "/jobs/$($State.Data.jobs[$key])/steps/$($waits[$key].Step)/complete" -Body ([ordered]@{ note = "Windows silent: DHCPServer stopped and disabled on $(@($r.dhcp | ForEach-Object { $_.name }) -join ', '), authorizations removed and read back" }))
                }
                foreach ($key in $waits.Keys) {
                    $done = Wait-TkJob -Id $State.Data.jobs[$key]
                    if ($done.State -ne 'succeeded') { throw "the takeover of $($key.Substring(9)) ended $($done.State) after the silence; run -Reverse to make Windows answer again" }
                }
            }
            Undo = {
                # Tenko silent first; then the narrow write-back, the authorization, conflict
                # detection and the service.
                Undo-TkTakeoverJob -State $State
                Write-TkLeaseBack -State $State
                foreach ($server in $r.dhcp) { [void](Invoke-TkRemote -Server $pdc -Name SetAuthorization -Arguments @($server.name, $server.address, $true)) }
                [void](Invoke-TkRemote -Server $pdc -Name Replicate)
                if (-not (Test-TkAuthorizationRemoved $r $true)) { throw 'a controller''s replica does not list the DHCP servers as authorized yet; run -Reverse again after replication' }
                foreach ($server in $r.dhcp) {
                    Assert-TkRestoreValue -Readings $r -Value $server.service_start -Class discovered
                    $now = Invoke-TkRemote -Server $server.name -Name StartDhcp -Arguments @($server.service_start) | Select-Object -Last 1
                    if ($now.Status -ne 'Running') { throw "$($server.name)'s DHCP Server service is $($now.Status) after the start" }
                }
            }
        }
        @{ Name = 'check'
            Do = {
                foreach ($key in @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' })) {
                    $takeovers = Invoke-Tenko -Method GET -Path "/migrate/takeovers?job=$($State.Data.jobs[$key])"
                    $item = @(Get-TkField $takeovers 'items') | Select-Object -First 1
                    if ($null -eq $item -or [long](Get-TkField $item 'acks') -lt 0) { throw "Tenko reports no takeover record for $($key.Substring(9))" }
                }
                Write-TkNote 'Tenko serves the scopes. The parallel period starts: the exporter''s tasks keep running and read nothing; a push from them now is the alarm.'
            }
            Undo = $null
        }
    )
}

function Undo-TkTakeoverJob {
    # Tenko's revert of each takeover, its scopes silent first; each once.
    param([hashtable]$State)
    $r = $State.Data.readings
    foreach ($key in @($State.Data.jobs.Keys | Where-Object { $_ -like 'takeover.*' })) {
        if ((Get-TkField $State.Data.values "reverted.$key") -eq $true) { continue }
        if ($script:TkOffline) { $script:TkPending += "revert $($key.Substring(9))"; continue }
        $cidr = $key.Substring(9)
        $server = $r.dhcp | Where-Object { @($_.scopes | ForEach-Object { $_.cidr }) -contains $cidr } | Select-Object -First 1
        $job = Invoke-Tenko -Method POST -Path "/migrate/mirrors/$($State.Data.mirrors[$server.name])/scopes/$($cidr -replace '/', '%2F')/revert"
        $done = Wait-TkJob -Id ([string](Get-TkField $job 'id'))
        if ($done.State -ne 'succeeded') { throw "the revert of $cidr ended $($done.State): Tenko's scopes may still answer, so Windows stays silent" }
        $State.Data.values["reverted.$key"] = $true
        Save-TkState $State
    }
}

function Write-TkLeaseBack {
    # Only addresses, client identifiers and ends, inside the pool, outside the exclusions and
    # others' reservations, the end bounded by the scope's lease time, the count by the pool.
    # The pairs read before the stop come first; nothing from Tenko but these three values.
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
            foreach ($pair in @(Get-TkField $State.Data.values.leases "$($holder.name)|$id")) { if ($pair -and -not $leases.Contains($pair.ip)) { $leases[$pair.ip] = [ordered]@{ client = $pair.client; seconds = $scope.lease_secs } } }
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
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$parsed) -or $parsed.AddressFamily -ne 'InterNetwork' -or $client -notmatch '^([0-9a-f]{2}-){1,31}[0-9a-f]{2}$') { continue }
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
        foreach ($holder in $holders) { [void](Invoke-TkRemote -Server $holder.name -Name WriteLeases -Arguments @($id, $write)) }
    }
}

# ---------------------------------------------------------------------------------------
# Phase 6: the finish, after the parallel period. The DHCP Server service is never started.
# ---------------------------------------------------------------------------------------

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
            Undo = $null
        }
        @{ Name = 'dhcp-role'
            Do = {
                foreach ($server in $r.dhcp) {
                    if (Invoke-TkRemote -Server $server.name -Name RemoveDhcpRole -Arguments @('C:\ProgramData\Tenko\takeover-backup') | Select-Object -Last 1) { throw "the DHCP role is still installed on $($server.name)" }
                }
            }
            Undo = {
                # The way back: the role, its groups on one server, replication, then the other;
                # the backup imported on the first; the relationship; the authorization stays removed.
                $first = $r.dhcp[0]
                $backup = 'C:\ProgramData\Tenko\takeover-backup'
                [void](Invoke-TkRemote -Server $first.name -Name RestoreDhcpRole -Arguments @($backup, "$backup\dhcp-export.xml", $true, 'yes'))
                [void](Invoke-TkRemote -Server $pdc -Name Replicate)
                foreach ($controller in $r.controllers) {
                    $groups = @(Invoke-TkRemote -Server $controller.name -Name ReadGroups -Arguments (, [string[]]@('DHCP Users', 'DHCP Administrators')))
                    if (@($groups | Where-Object { $_.Count -ne 1 -or $_.Conflicts -gt 0 }).Count -gt 0) { throw "the DHCP groups have not replicated to $($controller.name) cleanly yet; run -Reverse again" }
                }
                foreach ($server in @($r.dhcp | Select-Object -Skip 1)) { [void](Invoke-TkRemote -Server $server.name -Name RestoreDhcpRole -Arguments @($backup, '', $false, '')) }
                foreach ($relationship in $first.failover) {
                    [void](Invoke-TkRemote -Server $first.name -Name AddFailover -Arguments @($relationship.name, $relationship.partner, [string[]]@($relationship.scopes)))
                }
            }
        }
        ($phase2 | Where-Object { $_.Name -eq 'exporter' } | ForEach-Object { @{ Name = 'exporter'; Do = $_.Undo; Undo = $null } })
        ($phase2 | Where-Object { $_.Name -eq 'mirror-account' } | ForEach-Object { @{ Name = 'mirror-account'; Do = $_.Undo; Undo = $null } })
        ($phase2 | Where-Object { $_.Name -eq 'dns-credential' } | ForEach-Object { @{ Name = 'dns-credential'; Do = { if ($r.dns_credential -eq 'create') { [void](Invoke-TkRemote -Server $pdc -Name NewDnsUser -Arguments @($script:TkDnsCredentialUser, $null, $true)) } }; Undo = $null } })
        @{ Name = 'zone-objects'
            Do = {
                $names = @($r.zones | ForEach-Object { $_.name })
                foreach ($object in @(Invoke-TkRemote -Server $pdc -Name ReadDirectoryZones -Arguments @($r.domain_dn, ('DC=' + ($r.forest_root -replace '\.', ',DC='))))) {
                    if ($names -contains $object.Name) { [void](Invoke-TkRemote -Server $pdc -Name RemoveZoneObject -Arguments @($object.Dn)) }
                }
            }
            Undo = $null
        }
        @{ Name = 'mirrors'
            Do = { foreach ($id in @($State.Data.mirrors.Values)) { [void](Invoke-Tenko -Method DELETE -Path "/migrate/mirrors/$id" -Expect @(200, 204, 404)) } }
            Undo = $null
        }
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
        '3' { , @(@{ Name = 'review'; Do = { [void](Confirm-TkWindow -State $State) }; Undo = $null }) }
        '4' { . Get-TkPhase4 -State $State -Payloads $Payloads }
        '5' { . Get-TkPhase5 -State $State }
        '6' { . Get-TkPhase6 -State $State -Payloads $Payloads }
    }
    if ($Undo) { Undo-TkStepList -State $State -Phase $Phase -Steps $steps; return }
    Invoke-TkStepList -State $State -Phase $Phase -Steps $steps
}

function Invoke-Takeover {
    param([switch]$DryRun, [switch]$Reverse, [string]$Directory)
    Assert-TkHost
    if ($Directory -and (Test-TkForeignWriter $Directory)) { Write-Warning "the folder $Directory is writable by accounts other than Administrators: a file there can be swapped between its check and its start" }
    $joined = ''
    try { $joined = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name.ToLowerInvariant() } catch { $joined = '' }
    $existing = @()
    $base = Join-Path (Join-Path $env:ProgramData 'Tenko') 'takeover'
    if (Test-Path -LiteralPath $base) { $existing = @(Get-ChildItem -LiteralPath $base -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'state.json') } | ForEach-Object { $_.Name }) }
    $domain = $(if ($existing.Count -eq 1) { $existing[0] } else { '' })
    if (-not $domain) {
        $typed = (Read-TkAnswer "The domain to take over [$joined]").Trim().ToLowerInvariant().TrimEnd('.')
        $domain = $(if ($typed) { $typed } else { $joined })
    }
    if ($domain -notmatch '^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{1,63}$') { Exit-TkTakeover 1 "$domain is not a domain name" }

    if ($DryRun) {
        $readings = Get-TkDiscovery -Domain $domain
        Select-TkMirrorHost -Readings $readings
        Show-TkChangeList -Readings $readings -NodeName '<the node>'
        foreach ($refusal in @($readings.refusals) + @($readings.window_refusals)) { Write-Warning $refusal }
        Write-TkNote 'Dry run: nothing was changed and Tenko was not contacted.'
        return $(if (@($readings.refusals).Count -gt 0) { 1 } else { 0 })
    }

    $state = Open-TkState -Domain $domain
    try {
        $data = $state.Data
        $phase = Get-TkNextPhase $data.phases
        $latest = Get-TkLatestPhase $data.phases
        if (-not $Reverse -and $latest) {
            Write-TkNote "A run of $domain against Tenko at $($data.tenko.host):$($data.tenko.port) exists; the next phase is $phase, the latest done or failed ${latest}."
            $choice = (Read-TkAnswer "Continue with phase $phase, or reverse phase ${latest}? [C/r]").Trim().ToLowerInvariant()
            if ($choice -eq 'r') { $Reverse = $true }
        }
        if ($null -ne $data.readings -and ((Get-TkField $data.phases '4') -eq 'done' -or (Get-TkField $data.phases '4') -eq 'failed')) { Test-TkLocator $data.readings }

        # Discovery: always fresh; the recorded readings stay what the reverse restores from.
        $readings = Get-TkDiscovery -Domain $domain
        if ($null -eq $data.readings) {
            Select-TkMirrorHost -Readings $readings
            if (@($readings.refusals).Count -gt 0 -and -not $Reverse) {
                foreach ($refusal in $readings.refusals) { Write-TkNote $refusal }
                Exit-TkTakeover 1 'the discovery refuses this domain; nothing was changed'
            }
        } else {
            Select-TkMirrorHost -Readings $readings -Chosen $data.readings.mirror_host.name
            $script:TkKnownHosts = @($script:TkKnownHosts + @($data.readings.controllers | ForEach-Object { $_.name }) + @($data.readings.dhcp | ForEach-Object { $_.name }) + $data.readings.mirror_host.name | Select-Object -Unique)
        }

        $address = $(if ($data.tenko.Contains('host')) { "$($data.tenko.host):$($data.tenko.port)" } else { Read-TkAnswer "Tenko's address (host name, port $($script:TkPort) unless host:port)" })
        if ($Reverse -and $latest -and -not (Test-TkReachable $address)) {
            Write-Warning 'Tenko cannot be reached. A node whose API is unreachable may still serve DHCP, so a Windows server made to answer again would answer beside it (conflict detection, which the reverse turns on, limits the damage).'
            if (-not (Confirm-TkTyped 'Type the domain''s name to reverse the Windows half alone' $domain)) { Exit-TkTakeover 1 'the reverse was declined; nothing was changed' }
            $script:TkOffline = $true
            $payloads = @{
                exporter  = Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $Directory -OutDir (Join-Path $state.Dir 'payload')
                installer = Get-TkPayload -Name 'Install-TenkoDhcpMirror.ps1' -Directory $Directory -OutDir (Join-Path $state.Dir 'payload')
            }
            Invoke-TkPhase -State $state -Phase $latest -Payloads $payloads -Undo
            $data.values["pending.$latest"] = @($script:TkPending)
            Save-TkState $state
            Write-TkNote "Phase $latest is reversed on Windows. Tenko's half is pending: $(@($script:TkPending).Count) operations, recorded in the state file; reverse them in Tenko's UI or run -Reverse again once Tenko answers."
            return 5
        }
        Connect-TkNode -Address $address
        if ($null -eq $data.readings) {
            $data.readings = $readings
            $data.tenko = [ordered]@{ host = $script:TkConn.Host; port = $script:TkConn.Port; address = [string]$script:TkConn.Address; node = (Get-TkNodeName -HostName $script:TkConn.Host -Domain $domain); fingerprint = '' }
            Show-TkChangeList -Readings $readings -NodeName $data.tenko.node
            if (-not (Confirm-TkTyped "Type the domain's name ($domain) to approve this change list" $domain)) { Exit-TkTakeover 1 'the change list was declined; nothing was changed' }
            $data.plan = Get-TkPlan -Readings $readings -NodeName $data.tenko.node
        } else {
            $script:TkConn.Pinned = [string]$data.tenko.fingerprint
            Write-TkNote "Domain $domain, Tenko at $($data.tenko.host):$($data.tenko.port) (from the state file)."
        }
        $marker = Invoke-TkRemote -Server $data.readings.pdc -Name ReadMarker -Arguments @($script:TkMarkerKey) | Select-Object -Last 1
        if ($null -ne $marker -and $marker.Run -and $marker.Run -ne $data.id) { Exit-TkTakeover 1 "another run ($($marker.Run) from $($marker.Host) at $($marker.Time)) is recorded on $($data.readings.pdc); it must end or be reversed first" }

        # Phase 1: the approval, every sitting.
        $pinned = $script:TkConn.Pinned
        $run = Request-TkApproval -Plan $data.plan -Domain $domain
        if ($pinned -and $pinned -ne $script:TkConn.Pinned) { Exit-TkTakeover 4 'the new approval binds another TLS root than the run pinned' }
        if ($data.run -and $data.run -ne $run) { Write-TkNote "Tenko names the run $run for this sitting." }
        $data.run = $run
        $data.tenko.fingerprint = $script:TkConn.Pinned
        Save-TkState $state
        Test-TkServedRoot
        [void](Invoke-TkRemote -Server $data.readings.pdc -Name WriteMarker -Arguments @($script:TkMarkerKey, $data.id, [System.Environment]::MachineName, $false))

        $payloads = @{
            exporter  = Get-TkPayload -Name 'Tenko-DhcpMirror.ps1' -Directory $Directory -OutDir (Join-Path $state.Dir 'payload')
            installer = Get-TkPayload -Name 'Install-TenkoDhcpMirror.ps1' -Directory $Directory -OutDir (Join-Path $state.Dir 'payload')
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
            if ($phase -eq '6' -and (Get-TkField $data.values 'finish_confirmed') -ne $true) {
                if (-not (Confirm-TkTyped 'The parallel period is over and the finish (phase 6) removes the DHCP role from both servers. Type the domain''s name to go on' $domain)) { Exit-TkTakeover 3 'waiting for the parallel period' }
                $data.values.finish_confirmed = $true
            }
            # The window is confirmed at the console in every sitting that starts phase 4 or 5.
            if (('4', '5' -contains $phase) -and $null -eq $script:TkWindowWatch) { [void](Confirm-TkWindow -State $state) }
            Write-TkNote "Phase $phase"
            Invoke-TkPhase -State $state -Phase $phase -Payloads $payloads
            [void](Invoke-Tenko -Method PUT -Path "/migrate/runs/$run/phases/$phase" -Body ([ordered]@{ state = 'done' }) -Expect @(200, 204, 404))
            if ($phase -eq '5') { Write-TkNote 'The parallel period runs now. After it, run the script again for the finish.'; return 3 }
            if ($phase -eq '6') { [void](Invoke-TkRemote -Server $data.readings.pdc -Name WriteMarker -Arguments @($script:TkMarkerKey, '', '', $true)); Write-TkNote 'The takeover is finished.'; return 0 }
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
