<#
.SYNOPSIS
  The Windows DHCP mirror exporter of Tenko DDI (MIG-01, MIG-08).

.DESCRIPTION
  Reads the DHCPv4 configuration and the active leases of the Windows DHCP server it runs
  on with the DhcpServer module, maps them onto Tenko's migration IR (the MirrorSnapshot
  envelope of docs/plans/windows-takeover-plan.md section 3.1) with a loss report of what
  Tenko does not take over, and pushes the snapshot with PUT to
  https://<controller>/api/v1/migrate/mirrors/<id>/snapshot. The token can write one mirror
  and nothing else; the controller's certificate chain must end in the pinned certificate
  authority; Tenko never connects back and the script acts on nothing but the HTTP answer.

  Install-TenkoDhcpMirror.ps1 registers it as a scheduled task every minute under an
  account that is a member of DHCP Users and of no privileged group. The script refuses to
  push when its account is a member of Domain Admins, Enterprise Admins, Administrators,
  DHCP Administrators or DnsAdmins, or is SYSTEM.

  PowerShell 5.1 and 7, the DhcpServer module only, nothing downloaded.

.PARAMETER Once
  Dry run: read, map and print the snapshot (the IR and the loss report) as JSON on
  standard output. Nothing is pushed, no token is needed, and a privileged account gets a
  warning instead of a refusal, because nothing leaves the server.

.PARAMETER ConfigPath
  The configuration file the install script writes: url, mirror and fingerprint.
  Default: %ProgramData%\Tenko\mirror\config.json.

.PARAMETER StateDir
  Where the stored token, the sequence state and the log live.
  Default: %ProgramData%\Tenko\mirror\state.

.PARAMETER Url
  The controller, for example https://tenko1.corp.example.test:8443. Overrides the file.

.PARAMETER MirrorId
  The mirror's id, from the mirror card. Overrides the file.

.PARAMETER Fingerprint
  The SHA-256 fingerprint of Tenko's certificate authority, from the mirror card, as
  64 hexadecimal digits with or without colons. Overrides the file.

.PARAMETER ServerName
  The name reported as the source server. Default: this computer's name.

.PARAMETER AllowPlainHttp
  Test only: allow http:// to a loopback address, with no certificate check. Any other
  address is refused even with this switch. The run says loudly that it is insecure.

.EXAMPLE
  .\Tenko-DhcpMirror.ps1 -Once | Out-File snapshot.json

.EXAMPLE
  .\Tenko-DhcpMirror.ps1 -Once -Url https://tenko1.corp.example.test:8443 -MirrorId 01J...
#>
[CmdletBinding()]
param(
    [switch]$Once,
    [string]$ConfigPath,
    [string]$StateDir,
    [string]$Url,
    [string]$MirrorId,
    [string]$Fingerprint,
    [string]$ServerName,
    [switch]$AllowPlainHttp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------------------

# Versioned with Tenko: the release that ships this file (crates/tenko/Cargo.toml).
$script:AdapterVersion = '0.0.12'
$script:AdapterName = 'Tenko-DhcpMirror.ps1'
$script:SourceKind = 'windows-dhcp'
$script:SnapshotFormat = 1
$script:LogDays = 7
$script:GzipAbove = 1MB
$script:HttpTimeoutMs = 30000

# Plan section 2.1, point 6: the controller refuses more; the log says so before it does.
$script:MaxScopes = 1000
$script:MaxReservations = 10000
$script:MaxLeases = 100000

# Plan section 2.1, point 4: a member of one of these does not push.
$script:PrivilegedSids = @(
    'S-1-5-18',      # SYSTEM
    'S-1-5-32-544'   # Administrators
)
$script:PrivilegedRids = @(512, 519)   # Domain Admins, Enterprise Admins
$script:PrivilegedNames = @('DHCP Administrators', 'DnsAdmins')

# ---------------------------------------------------------------------------------------
# Small helpers: values as the cmdlets give them on Windows and as ConvertTo-Json wrote
# them in the recorded fixtures (an IPAddress becomes an object with IPAddressToString, a
# TimeSpan one with TotalSeconds, a DateTime a string).
# ---------------------------------------------------------------------------------------

function Get-Prop {
    param([object]$Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-Blank {
    param([object]$Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace($Value) }
    return $false
}

function ConvertTo-IpText {
    param([object]$Value)
    if (Test-Blank $Value) { return $null }
    if ($Value -is [System.Net.IPAddress]) { return $Value.ToString() }
    if ($Value -is [string]) { return $Value.Trim() }
    $text = Get-Prop $Value 'IPAddressToString'
    if (-not (Test-Blank $text)) { return ([string]$text).Trim() }
    # An IPAddress recorded without its text form: the address as .NET stores it.
    $address = Get-Prop $Value 'Address'
    if ($null -ne $address -and [int](Get-Prop $Value 'AddressFamily') -eq 2) {
        return [System.Net.IPAddress]::new([int64]$address).ToString()
    }
    return ([string]$Value).Trim()
}

function ConvertTo-IpList {
    param([object]$Value)
    $list = @()
    if ($null -eq $Value) { return , $list }
    if ($Value -is [string] -or $Value -is [System.Net.IPAddress] -or -not ($Value -is [System.Collections.IEnumerable])) {
        $text = ConvertTo-IpText $Value
        if ($null -ne $text) { $list += $text }
        return , $list
    }
    foreach ($item in $Value) {
        $text = ConvertTo-IpText $item
        if ($null -ne $text) { $list += $text }
    }
    return , $list
}

function ConvertTo-SecondCount {
    param([object]$Value)
    if (Test-Blank $Value) { return $null }
    if ($Value -is [timespan]) { return [uint32][math]::Floor($Value.TotalSeconds) }
    if ($Value -is [string]) {
        $parsed = [timespan]::Zero
        if ([timespan]::TryParse($Value, [ref]$parsed)) { return [uint32][math]::Floor($parsed.TotalSeconds) }
        return $null
    }
    $total = Get-Prop $Value 'TotalSeconds'
    if ($null -ne $total) { return [uint32][math]::Floor([double]$total) }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) { return [uint32]$Value }
    return $null
}

function ConvertTo-UtcText {
    param([object]$Value)
    if (Test-Blank $Value) { return $null }
    $time = $null
    if ($Value -is [datetime]) {
        $time = $Value
    } elseif ($Value -is [string]) {
        $text = $Value.Trim()
        if ($text -match '^/Date\((-?\d+)\)/$') {
            $time = [datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).AddMilliseconds([double]$Matches[1])
        } else {
            $parsed = [datetime]::MinValue
            $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeLocal
            if (-not [datetime]::TryParse($text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { return $null }
            $time = $parsed
        }
    } else {
        $inner = Get-Prop $Value 'DateTime'
        if ($null -eq $inner) { return $null }
        return ConvertTo-UtcText $inner
    }
    if ($time.Kind -eq [System.DateTimeKind]::Unspecified) {
        $time = [datetime]::SpecifyKind($time, [System.DateTimeKind]::Local)
    }
    return $time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-PrefixLength {
    param([string]$Mask)
    $address = [System.Net.IPAddress]::Parse($Mask)
    $bits = 0
    $seenZero = $false
    foreach ($octet in $address.GetAddressBytes()) {
        for ($i = 7; $i -ge 0; $i--) {
            if (($octet -band (1 -shl $i)) -ne 0) {
                if ($seenZero) { throw "subnet mask $Mask is not contiguous" }
                $bits++
            } else {
                $seenZero = $true
            }
        }
    }
    return $bits
}

function ConvertTo-HexText {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $digits = ($Value -replace '[:\-\.\s]', '').ToLowerInvariant()
        if ($digits.Length -eq 0) { return $null }
        if ($digits -notmatch '^([0-9a-f]{2})+$') { return $null }
        return $digits
    }
    $bytes = @()
    foreach ($item in $Value) { $bytes += [byte]$item }
    if ($bytes.Count -eq 0) { return $null }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertFrom-ClientId {
    # Windows writes a MAC address and any other option 61 identifier the same way, as
    # dash-separated octets. Six octets are a MAC address, anything else client_id octets.
    param([object]$Value)
    $client = [ordered]@{}
    $hex = ConvertTo-HexText $Value
    if ($null -eq $hex) { return $client }
    if ($hex.Length -eq 12) {
        $client.mac = ($hex -split '(?<=\G.{2})(?!$)') -join ':'
    } else {
        $client.client_id = $hex
    }
    return $client
}

function ConvertTo-HostNameOrNull {
    # The rule of tenko_core::net::HostName: lowercase, no trailing dot, labels of 1 to 63
    # characters from a-z, 0-9, hyphen and underscore, no label starting or ending with a
    # hyphen, at most 253 characters. Anything else is reported, never tidied (WT-Q10).
    param([object]$Value)
    if (Test-Blank $Value) { return $null }
    $name = ([string]$Value).Trim()
    if ($name.EndsWith('.')) { $name = $name.Substring(0, $name.Length - 1) }
    $name = $name.ToLowerInvariant()
    if ($name.Length -eq 0 -or $name.Length -gt 253) { return $null }
    foreach ($label in $name.Split('.')) {
        if ($label.Length -eq 0 -or $label.Length -gt 63) { return $null }
        if ($label.StartsWith('-') -or $label.EndsWith('-')) { return $null }
        if ($label -notmatch '^[a-z0-9_\-]+$') { return $null }
    }
    return $name
}

function ConvertTo-StringList {
    param([object]$Value)
    $list = @()
    if ($null -eq $Value) { return , $list }
    if ($Value -is [string] -or -not ($Value -is [System.Collections.IEnumerable])) {
        $list += [string]$Value
        return , $list
    }
    foreach ($item in $Value) {
        if ($null -ne $item) { $list += [string]$item }
    }
    return , $list
}

# ---------------------------------------------------------------------------------------
# A canonical JSON writer: the same bytes on PowerShell 5.1 and 7 (ConvertTo-Json differs
# between the editions in escaping and spacing), compact, keys in the order the IR declares
# them, so that the pushed body and its hash are stable.
# ---------------------------------------------------------------------------------------

function Write-JsonValue {
    param([System.Text.StringBuilder]$Builder, [object]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { [void]$Builder.Append('null'); return }
    if ($Value -is [bool]) { [void]$Builder.Append($(if ($Value) { 'true' } else { 'false' })); return }
    if ($Value -is [string]) { Write-JsonString $Builder $Value; return }
    if ($Value -is [datetime]) { Write-JsonString $Builder (ConvertTo-UtcText $Value); return }
    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int] -or $Value -is [long] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or $Value -is [sbyte] -or
        $Value -is [System.Numerics.BigInteger]) {
        [void]$Builder.Append($Value.ToString([System.Globalization.CultureInfo]::InvariantCulture)); return
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        [void]$Builder.Append(([double]$Value).ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)); return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        [void]$Builder.Append('{')
        $first = $true
        foreach ($key in $Value.Keys) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Write-JsonString $Builder ([string]$key)
            [void]$Builder.Append(':')
            Write-JsonValue $Builder $Value[$key]
        }
        [void]$Builder.Append('}')
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        [void]$Builder.Append('[')
        $first = $true
        foreach ($item in $Value) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Write-JsonValue $Builder $item
        }
        [void]$Builder.Append(']')
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        [void]$Builder.Append('{')
        $first = $true
        foreach ($property in $Value.PSObject.Properties) {
            if (-not $first) { [void]$Builder.Append(',') }
            $first = $false
            Write-JsonString $Builder $property.Name
            [void]$Builder.Append(':')
            Write-JsonValue $Builder $property.Value
        }
        [void]$Builder.Append('}')
        return
    }
    Write-JsonString $Builder ([string]$Value)
}

function Write-JsonString {
    param([System.Text.StringBuilder]$Builder, [string]$Text)
    [void]$Builder.Append('"')
    foreach ($char in $Text.ToCharArray()) {
        switch ($char) {
            '"' { [void]$Builder.Append('\"') }
            '\' { [void]$Builder.Append('\\') }
            "`n" { [void]$Builder.Append('\n') }
            "`r" { [void]$Builder.Append('\r') }
            "`t" { [void]$Builder.Append('\t') }
            "`b" { [void]$Builder.Append('\b') }
            "`f" { [void]$Builder.Append('\f') }
            default {
                if ([int]$char -lt 0x20) {
                    [void]$Builder.Append('\u' + ([int]$char).ToString('x4'))
                } else {
                    [void]$Builder.Append($char)
                }
            }
        }
    }
    [void]$Builder.Append('"')
}

function ConvertTo-CanonicalJson {
    param([object]$Value)
    $builder = [System.Text.StringBuilder]::new()
    Write-JsonValue $builder $Value
    return $builder.ToString()
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

# ---------------------------------------------------------------------------------------
# The loss report (MIG-01): nothing is dropped silently. Every entry carries where it came
# from as {sheet: <cmdlet>, column: <object key>}.
# ---------------------------------------------------------------------------------------

function ConvertTo-Location {
    param([string]$Sheet, [string]$Column)
    return [ordered]@{ sheet = $Sheet; row = $null; column = $Column }
}

function Add-Loss {
    param([System.Collections.ArrayList]$Entries, [string]$Sheet, [string]$Column, [string]$Code, [string]$Detail)
    [void]$Entries.Add([ordered]@{
            location = (ConvertTo-Location $Sheet $Column)
            code     = $Code
            detail   = $Detail
        })
}

# ---------------------------------------------------------------------------------------
# The reads. One run reads every cmdlet once per level; the tests replace the cmdlets with
# recorded output. The DNS credential is never read (Get-DhcpServerDnsCredential is not
# called), and nothing is written.
# ---------------------------------------------------------------------------------------

function Import-DhcpServerModule {
    if (Get-Command -Name 'Get-DhcpServerv4Scope' -ErrorAction SilentlyContinue) { return }
    Import-Module -Name DhcpServer -ErrorAction Stop
}

function Read-DhcpServer {
    Import-DhcpServerModule
    $raw = [ordered]@{
        scopes         = @(Get-DhcpServerv4Scope)
        server_options = @(Get-DhcpServerv4OptionValue -All)
        option_defs    = @(Get-DhcpServerv4OptionDefinition -All)
        classes        = @(Get-DhcpServerv4Class)
        exclusions     = @{}
        reservations   = @{}
        scope_options  = @{}
        reservation_options = @{}
        dns            = @{}
        leases         = @{}
        policies       = @(Get-DhcpServerv4Policy)
        filters        = @(Get-DhcpServerv4Filter)
        superscopes    = @(Get-DhcpServerv4Superscope)
        failover       = @(Get-DhcpServerv4Failover)
    }
    foreach ($scope in $raw.scopes) {
        $scopeId = ConvertTo-IpText (Get-Prop $scope 'ScopeId')
        $raw.exclusions[$scopeId] = @(Get-DhcpServerv4ExclusionRange -ScopeId $scopeId)
        $raw.reservations[$scopeId] = @(Get-DhcpServerv4Reservation -ScopeId $scopeId)
        $raw.scope_options[$scopeId] = @(Get-DhcpServerv4OptionValue -ScopeId $scopeId -All)
        $raw.dns[$scopeId] = @(Get-DhcpServerv4DnsSetting -ScopeId $scopeId)
        $raw.leases[$scopeId] = @(Get-DhcpServerv4Lease -ScopeId $scopeId)
        $raw.policies += @(Get-DhcpServerv4Policy -ScopeId $scopeId)
        foreach ($reservation in $raw.reservations[$scopeId]) {
            $ip = ConvertTo-IpText (Get-Prop $reservation 'IPAddress')
            $raw.reservation_options[$ip] = @(Get-DhcpServerv4OptionValue -ReservedIP $ip -All)
        }
    }
    return $raw
}

# ---------------------------------------------------------------------------------------
# The mapping onto the IR (docs/dhcp-contracts.md section 11; the cmdlets' property names
# are the XML element names there).
# ---------------------------------------------------------------------------------------

$script:ManagedOptionCodes = @(58, 59)   # T1 and T2: Tenko computes them from the lease time
$script:LeaseTimeOptionCode = 51          # carried as lease_secs, not as an option

function ConvertTo-IrOption {
    param([object]$Value, [string]$Sheet, [string]$Scope, [System.Collections.ArrayList]$Losses)
    $code = [int](Get-Prop $Value 'OptionId')
    $column = $(if ($Scope) { "${Scope}:$code" } else { "$code" })
    $policy = Get-Prop $Value 'PolicyName'
    if (-not (Test-Blank $policy)) {
        Add-Loss -Entries $Losses -Sheet $Sheet -Column $column -Code 'mirror.option.policy' -Detail "option $code is set by the policy ``$policy``; policies are not taken over (WT-Q2)"
        return $null
    }
    if ($code -eq $script:LeaseTimeOptionCode) { return $null }
    if ($script:ManagedOptionCodes -contains $code) {
        $values = ConvertTo-StringList (Get-Prop $Value 'Value')
        Add-Loss -Entries $Losses -Sheet $Sheet -Column $column -Code 'mirror.option.managed' -Detail "option $code (``$($values -join ', ')``) is computed by Tenko from the lease time and is not carried"
        return $null
    }
    $option = [ordered]@{ code = $code }
    $vendor = Get-Prop $Value 'VendorClass'
    if (-not (Test-Blank $vendor)) { $option.vendor_class = [string]$vendor }
    $user = Get-Prop $Value 'UserClass'
    if (-not (Test-Blank $user)) { $option.user_class = [string]$user }
    $option.values = ConvertTo-StringList (Get-Prop $Value 'Value')
    $option.origin = ConvertTo-Location $Sheet $column
    return $option
}

function ConvertTo-IrOptionList {
    param([object[]]$Values, [string]$Sheet, [string]$Scope, [System.Collections.ArrayList]$Losses)
    $list = @()
    foreach ($value in $Values) {
        $option = ConvertTo-IrOption -Value $value -Sheet $Sheet -Scope $Scope -Losses $Losses
        if ($null -ne $option) { $list += , $option }
    }
    return , $list
}

$script:OptionKinds = @{
    'Byte' = 'u8'; 'Word' = 'u16'; 'DWord' = 'u32'; 'DWordDword' = 'binary'
    'IPv4Address' = 'ipv4_address'; 'String' = 'string'; 'BinaryData' = 'binary'
    'EncapsulatedData' = 'binary'; 'IPv6Address' = 'ipv6_address'
}

function Test-CustomOptionDefinition {
    # Windows ships the standard definitions (codes 1 to 127 without a vendor class) and
    # its own vendor classes; Tenko's catalog holds the standard ones. The mirror carries
    # the definitions an operator added.
    param([object]$Definition)
    $code = [int](Get-Prop $Definition 'OptionId')
    $vendor = Get-Prop $Definition 'VendorClass'
    if (-not (Test-Blank $vendor)) { return -not ([string]$vendor).StartsWith('Microsoft ') }
    return $code -ge 128
}

function ConvertTo-IrOptionDef {
    param([object]$Definition, [System.Collections.ArrayList]$Losses)
    $sheet = 'Get-DhcpServerv4OptionDefinition'
    $code = [int](Get-Prop $Definition 'OptionId')
    $vendor = Get-Prop $Definition 'VendorClass'
    $column = $(if (Test-Blank $vendor) { "$code" } else { "${code}@$vendor" })
    $type = [string](Get-Prop $Definition 'Type')
    if (-not $script:OptionKinds.ContainsKey($type)) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $column -Code 'mirror.option_def.type' -Detail "option definition $code has the type ``$type``, which Tenko has no kind for"
        return $null
    }
    $def = [ordered]@{
        code = $code
        name = [string](Get-Prop $Definition 'Name')
        kind = $script:OptionKinds[$type]
        array = [bool](Get-Prop $Definition 'MultiValued')
    }
    if (-not (Test-Blank $vendor)) { $def.vendor_class = [string]$vendor }
    $description = Get-Prop $Definition 'Description'
    if (-not (Test-Blank $description)) { $def.description = [string]$description }
    $def.origin = ConvertTo-Location $sheet $column
    $default = ConvertTo-StringList (Get-Prop $Definition 'DefaultValue')
    if ($default.Count -gt 0) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $column -Code 'mirror.option_def.default' -Detail "the default value ``$($default -join ', ')`` of option definition $code is not carried; Tenko has no option defaults"
    }
    return $def
}

function ConvertTo-IrClass {
    param([object]$Class)
    $name = [string](Get-Prop $Class 'Name')
    $kind = $(if ([string](Get-Prop $Class 'Type') -eq 'Vendor') { 'vendor' } else { 'user' })
    $data = ConvertTo-HexText (Get-Prop $Class 'Data')
    if ($null -eq $data) {
        $ascii = Get-Prop $Class 'AsciiData'
        if (-not (Test-Blank $ascii)) {
            $data = (([System.Text.Encoding]::UTF8.GetBytes([string]$ascii)) | ForEach-Object { $_.ToString('x2') }) -join ''
        } else {
            $data = ''
        }
    }
    $item = [ordered]@{
        name = $name
        kind = $kind
        data = $data
        builtin = ($name.StartsWith('Microsoft ') -or $name.StartsWith('Default '))
    }
    $description = Get-Prop $Class 'Description'
    if (-not (Test-Blank $description)) { $item.description = [string]$description }
    $item.origin = ConvertTo-Location 'Get-DhcpServerv4Class' $name
    return $item
}

function ConvertTo-DdnsPolicy {
    # The table of docs/active-directory.md step 10.
    param([object]$Setting, [string]$Scope, [System.Collections.ArrayList]$Losses)
    $sheet = 'Get-DhcpServerv4DnsSetting'
    $updates = [string](Get-Prop $Setting 'DynamicUpdates')
    $protection = [bool](Get-Prop $Setting 'NameProtection')
    $policy = [ordered]@{
        enabled = ($updates -ne 'Never')
        reverse = -not [bool](Get-Prop $Setting 'DisableDnsPtrRRUpdate')
        conflict = $(if ($protection) { 'protect' } else { 'replace' })
        client_may_update_a = ($updates -eq 'OnClientRequest')
        legacy_clients = [bool](Get-Prop $Setting 'UpdateDnsRRForOlderClients')
        refuse_foreign = $false
    }
    $deleteOnExpiry = Get-Prop $Setting 'DeleteDnsRROnLeaseExpiry'
    if ($null -ne $deleteOnExpiry -and -not [bool]$deleteOnExpiry) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $Scope -Code 'mirror.ddns.keep_on_expiry' -Detail "scope $Scope keeps DNS records when a lease expires (DeleteDnsRROnLeaseExpiry false); Tenko removes the records it wrote when the lease ends (ADR 0020)"
    }
    $suffix = Get-Prop $Setting 'DnsSuffix'
    if (-not (Test-Blank $suffix)) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $Scope -Code 'mirror.ddns.suffix' -Detail "scope $Scope registers names under the DNS suffix ``$suffix`` instead of option 15; the IR carries no suffix, so set the scope's forward zone in Tenko"
    }
    return $policy
}

function ConvertTo-IrReservation {
    param([object]$Reservation, [object[]]$Options, [System.Collections.ArrayList]$Losses)
    $sheet = 'Get-DhcpServerv4Reservation'
    $ip = ConvertTo-IpText (Get-Prop $Reservation 'IPAddress')
    $item = [ordered]@{
        ip = $ip
        client = (ConvertFrom-ClientId (Get-Prop $Reservation 'ClientId'))
    }
    $rawName = Get-Prop $Reservation 'Name'
    $name = ConvertTo-HostNameOrNull $rawName
    if ($null -ne $name) {
        $item.name = $name
    } elseif (-not (Test-Blank $rawName)) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $ip -Code 'mirror.reservation.name' -Detail "the name ``$rawName`` of reservation $ip is not a host name and is not tidied (WT-Q10); the reservation is carried without a name"
    }
    $description = Get-Prop $Reservation 'Description'
    if (-not (Test-Blank $description)) { $item.description = [string]$description }
    $type = [string](Get-Prop $Reservation 'Type')
    $item.bootp = ($type -eq 'Bootp' -or $type -eq 'Both')
    if ($type -eq 'Bootp') {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $ip -Code 'mirror.reservation.bootp' -Detail "reservation $ip answers BOOTP only; Tenko serves it as a DHCP reservation"
    }
    $item.options = ConvertTo-IrOptionList -Values $Options -Sheet 'Get-DhcpServerv4OptionValue' -Scope $ip -Losses $Losses
    $item.origin = ConvertTo-Location $sheet $ip
    return $item
}

function ConvertTo-IrRange {
    param([object]$Value)
    return [ordered]@{
        first = ConvertTo-IpText (Get-Prop $Value 'StartRange')
        last  = ConvertTo-IpText (Get-Prop $Value 'EndRange')
    }
}

function ConvertTo-IrScope {
    param([object]$Scope, [hashtable]$Raw, [System.Collections.ArrayList]$Losses)
    $sheet = 'Get-DhcpServerv4Scope'
    $scopeId = ConvertTo-IpText (Get-Prop $Scope 'ScopeId')
    $mask = ConvertTo-IpText (Get-Prop $Scope 'SubnetMask')
    $cidr = "$scopeId/$(ConvertTo-PrefixLength $mask)"
    $item = [ordered]@{ cidr = $cidr }
    $name = Get-Prop $Scope 'Name'
    if (-not (Test-Blank $name)) { $item.name = [string]$name }
    $description = Get-Prop $Scope 'Description'
    if (-not (Test-Blank $description)) { $item.description = [string]$description }
    $item.active = ([string](Get-Prop $Scope 'State') -eq 'Active')
    $lease = ConvertTo-SecondCount (Get-Prop $Scope 'LeaseDuration')
    if ($null -ne $lease) { $item.lease_secs = $lease }
    $item.ranges = @(, [ordered]@{
            first = ConvertTo-IpText (Get-Prop $Scope 'StartRange')
            last  = ConvertTo-IpText (Get-Prop $Scope 'EndRange')
        })
    $exclusions = @()
    foreach ($exclusion in $Raw.exclusions[$scopeId]) { $exclusions += , (ConvertTo-IrRange $exclusion) }
    $item.exclusions = $exclusions
    $reservations = @()
    foreach ($reservation in $Raw.reservations[$scopeId]) {
        $ip = ConvertTo-IpText (Get-Prop $reservation 'IPAddress')
        $options = @()
        if ($Raw.reservation_options.ContainsKey($ip)) { $options = $Raw.reservation_options[$ip] }
        $reservations += , (ConvertTo-IrReservation -Reservation $reservation -Options $options -Losses $Losses)
    }
    $item.reservations = $reservations
    $item.options = ConvertTo-IrOptionList -Values $Raw.scope_options[$scopeId] -Sheet 'Get-DhcpServerv4OptionValue' -Scope $scopeId -Losses $Losses
    $dns = $Raw.dns[$scopeId]
    if ($null -ne $dns -and $dns.Count -gt 0) {
        $item.ddns = ConvertTo-DdnsPolicy -Setting $dns[0] -Scope $scopeId -Losses $Losses
    }
    # Superscopes and filters go to the loss report (WT-Q2): no shared network, no
    # restriction is derived from them.
    $item.restricted = $false
    $delay = Get-Prop $Scope 'Delay'
    $item.delay_ms = $(if (Test-Blank $delay) { 0 } else { [uint32]$delay })
    if ($item.delay_ms -ne 0) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $scopeId -Code 'mirror.scope.delay' -Detail "scope $scopeId delays its offers by $($item.delay_ms) ms; Tenko has no offer delay and the runbook does not use split scopes"
    }
    $type = [string](Get-Prop $Scope 'Type')
    if ($type -eq 'Bootp') {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $scopeId -Code 'mirror.scope.bootp' -Detail "scope $scopeId serves BOOTP only; Tenko serves it as a DHCP scope"
    }
    $item.origin = ConvertTo-Location $sheet $scopeId
    return $item
}

$script:LeaseStates = @{ 'Active' = 'active'; 'ActiveReservation' = 'active_reservation'; 'Declined' = 'declined' }
# A reservation without a client holds no lease, and an expired lease is not carried
# (plan section 2.3); neither is a loss, the reservation is in `reservations`.
$script:SilentLeaseStates = @('Expired', 'InactiveReservation')

function ConvertTo-IrLease {
    param([object]$Lease, [string]$Cidr, [System.Collections.ArrayList]$Losses)
    $sheet = 'Get-DhcpServerv4Lease'
    $ip = ConvertTo-IpText (Get-Prop $Lease 'IPAddress')
    $state = [string](Get-Prop $Lease 'AddressState')
    if ($script:SilentLeaseStates -contains $state) { return $null }
    if (-not $script:LeaseStates.ContainsKey($state)) {
        Add-Loss -Entries $Losses -Sheet $sheet -Column $ip -Code 'mirror.lease.state' -Detail "lease $ip is in the state ``$state``, which the mirror does not carry"
        return $null
    }
    $item = [ordered]@{
        ip = $ip
        scope = $Cidr
        client = (ConvertFrom-ClientId (Get-Prop $Lease 'ClientId'))
    }
    $hostname = Get-Prop $Lease 'HostName'
    if (-not (Test-Blank $hostname)) { $item.hostname = ([string]$hostname).Trim() }
    $expires = ConvertTo-UtcText (Get-Prop $Lease 'LeaseExpiryTime')
    if ($null -ne $expires) { $item.expires = $expires }
    $item.state = $script:LeaseStates[$state]
    $item.origin = ConvertTo-Location $sheet $ip
    return $item
}

function Add-PolicyLoss {
    param([object]$Policy, [System.Collections.ArrayList]$Losses)
    $name = [string](Get-Prop $Policy 'Name')
    $scope = ConvertTo-IpText (Get-Prop $Policy 'ScopeId')
    $where = $(if (Test-Blank $scope) { 'the server' } else { "scope $scope" })
    $enabled = $(if ([bool](Get-Prop $Policy 'Enabled')) { 'enabled' } else { 'disabled' })
    $criteria = @()
    foreach ($criterion in 'VendorClass', 'UserClass', 'MacAddress', 'ClientId', 'RelayAgent', 'CircuitId', 'RemoteId', 'SubscriberId', 'Fqdn') {
        $values = ConvertTo-StringList (Get-Prop $Policy $criterion)
        if ($values.Count -gt 0) { $criteria += "$criterion $($values -join ' ')" }
    }
    $condition = [string](Get-Prop $Policy 'Condition')
    $detail = "policy ``$name`` on $where ($enabled, order $(Get-Prop $Policy 'ProcessingOrder'))"
    if ($criteria.Count -gt 0) { $detail += ": $($criteria -join " $($condition.ToUpperInvariant()) ")" }
    $detail += '; policies are not taken over (WT-Q2)'
    Add-Loss -Entries $Losses -Sheet 'Get-DhcpServerv4Policy' -Column $name -Code 'mirror.policy' -Detail $detail
}

function Add-FilterLoss {
    param([object]$Filter, [System.Collections.ArrayList]$Losses)
    $mac = [string](Get-Prop $Filter 'MacAddress')
    $list = [string](Get-Prop $Filter 'List')
    $detail = "$($list.ToLowerInvariant()) filter entry ``$mac``"
    $description = Get-Prop $Filter 'Description'
    if (-not (Test-Blank $description)) { $detail += " ($description)" }
    $detail += '; filters are not taken over (WT-Q2)'
    Add-Loss -Entries $Losses -Sheet 'Get-DhcpServerv4Filter' -Column $mac -Code 'mirror.filter' -Detail $detail
}

function Add-SuperscopeLoss {
    param([object]$Superscope, [System.Collections.ArrayList]$Losses)
    $name = [string](Get-Prop $Superscope 'SuperscopeName')
    $scopes = ConvertTo-IpList (Get-Prop $Superscope 'ScopeId')
    Add-Loss -Entries $Losses -Sheet 'Get-DhcpServerv4Superscope' -Column $name -Code 'mirror.superscope' -Detail "superscope ``$name`` joins the scopes $($scopes -join ', '); superscopes are not taken over (WT-Q2), each scope is prepared alone"
}

function Add-FailoverLoss {
    param([object]$Failover, [System.Collections.ArrayList]$Losses)
    $name = [string](Get-Prop $Failover 'Name')
    $partner = [string](Get-Prop $Failover 'PartnerServer')
    $mode = [string](Get-Prop $Failover 'Mode')
    $scopes = ConvertTo-IpList (Get-Prop $Failover 'ScopeId')
    Add-Loss -Entries $Losses -Sheet 'Get-DhcpServerv4Failover' -Column $name -Code 'mirror.failover' -Detail "failover relationship ``$name`` with $partner ($mode) over the scopes $($scopes -join ', '); Windows failover is not interoperable (CON-05) and the shared secret is never read"
}

function ConvertTo-MirrorSnapshot {
    param(
        [Parameter(Mandatory)][hashtable]$Raw,
        [Parameter(Mandatory)][uint64]$Sequence,
        [Parameter(Mandatory)][string]$TakenAt,
        [Parameter(Mandatory)][string]$ServerName
    )
    $losses = [System.Collections.ArrayList]::new()
    $dhcp = [ordered]@{}
    $dhcp.server_options = ConvertTo-IrOptionList -Values $Raw.server_options -Sheet 'Get-DhcpServerv4OptionValue' -Scope '' -Losses $losses
    $defs = @()
    foreach ($definition in $Raw.option_defs) {
        if (-not (Test-CustomOptionDefinition $definition)) { continue }
        $def = ConvertTo-IrOptionDef -Definition $definition -Losses $losses
        if ($null -ne $def) { $defs += , $def }
    }
    $dhcp.option_defs = $defs
    $classes = @()
    foreach ($class in $Raw.classes) { $classes += , (ConvertTo-IrClass $class) }
    $dhcp.classes = $classes
    $scopes = @()
    $leases = @()
    foreach ($scope in $Raw.scopes) {
        $irScope = ConvertTo-IrScope -Scope $scope -Raw $Raw -Losses $losses
        $scopes += , $irScope
        $scopeId = ConvertTo-IpText (Get-Prop $scope 'ScopeId')
        foreach ($lease in $Raw.leases[$scopeId]) {
            $irLease = ConvertTo-IrLease -Lease $lease -Cidr $irScope.cidr -Losses $losses
            if ($null -ne $irLease) { $leases += , $irLease }
        }
    }
    $dhcp.scopes = $scopes
    $dhcp.superscopes = @()
    $dhcp.policies = @()
    $dhcp.filters = @()
    $dhcp.failover = @()
    $dhcp.leases = $leases
    foreach ($policy in $Raw.policies) { Add-PolicyLoss -Policy $policy -Losses $losses }
    foreach ($filter in $Raw.filters) { Add-FilterLoss -Filter $filter -Losses $losses }
    foreach ($superscope in $Raw.superscopes) { Add-SuperscopeLoss -Superscope $superscope -Losses $losses }
    foreach ($failover in $Raw.failover) { Add-FailoverLoss -Failover $failover -Losses $losses }

    return [ordered]@{
        format = $script:SnapshotFormat
        sequence = $Sequence
        taken_at = $TakenAt
        source = [ordered]@{
            kind = $script:SourceKind
            server = $ServerName
            adapter = $script:AdapterName
            adapter_version = $script:AdapterVersion
        }
        dhcp = $dhcp
        losses = [ordered]@{ entries = @($losses.ToArray()) }
    }
}

# ---------------------------------------------------------------------------------------
# The account check (plan section 2.1, point 4).
# ---------------------------------------------------------------------------------------

function Test-WindowsHost {
    return ($env:OS -eq 'Windows_NT')
}

function Get-IdentityGroup {
    # The groups of the running token as {Sid, Name}; Name is empty when the SID does not
    # translate (a group of a domain that is not reachable).
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $groups = @()
    $all = @($identity.User) + @($identity.Groups)
    foreach ($sid in $all) {
        if ($null -eq $sid) { continue }
        $name = ''
        try { $name = $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = '' }
        $groups += [pscustomobject]@{ Sid = $sid.Value; Name = $name }
    }
    return , $groups
}

function Get-PrivilegedMembership {
    # The names of the privileged groups among the given ones; empty when none.
    param([object[]]$Groups)
    $found = @()
    foreach ($group in $Groups) {
        $sid = [string](Get-Prop $group 'Sid')
        $name = [string](Get-Prop $group 'Name')
        $short = $name
        if ($name.Contains('\')) { $short = $name.Substring($name.LastIndexOf('\') + 1) }
        $hit = $false
        if ($script:PrivilegedSids -contains $sid) { $hit = $true }
        if ($sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$' -and $script:PrivilegedRids -contains [int]$Matches[1]) { $hit = $true }
        foreach ($privileged in $script:PrivilegedNames) {
            if ($short -and $short.Equals($privileged, [System.StringComparison]::OrdinalIgnoreCase)) { $hit = $true }
        }
        if ($hit) {
            $found += $(if ($name) { $name } else { $sid })
        }
    }
    return , $found
}

# ---------------------------------------------------------------------------------------
# The certificate pin (plan section 2.1, point 5). The check is C# compiled at start, so
# that it runs as a delegate on both editions and on whichever thread the TLS handshake
# uses; a PowerShell script block cannot run there on PowerShell 7. It accepts a chain
# only when the chain the server presents builds and ends in the certificate whose SHA-256
# is the pin; nothing is added to the trust store, and the host name must match.
# ---------------------------------------------------------------------------------------

$script:PinSource = @'
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tenko.Mirror
{
    public static class Pin
    {
        public static string Fingerprint = "";
        public static string LastFailure = "";

        public static RemoteCertificateValidationCallback Callback
        {
            get { return new RemoteCertificateValidationCallback(Validate); }
        }

        public static string Sha256Hex(byte[] raw)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(raw);
                char[] text = new char[hash.Length * 2];
                const string digits = "0123456789abcdef";
                for (int i = 0; i < hash.Length; i++)
                {
                    text[i * 2] = digits[hash[i] >> 4];
                    text[i * 2 + 1] = digits[hash[i] & 0x0f];
                }
                return new string(text);
            }
        }

        public static bool Validate(object sender, X509Certificate certificate, X509Chain presented, SslPolicyErrors errors)
        {
            LastFailure = "";
            if (certificate == null)
            {
                LastFailure = "the server presented no certificate";
                return false;
            }
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                LastFailure = "the server certificate does not match the host name";
                return false;
            }
            if (string.IsNullOrEmpty(Fingerprint))
            {
                LastFailure = "no fingerprint is pinned";
                return false;
            }
            X509Certificate2 leaf = new X509Certificate2(certificate);
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            if (presented != null)
            {
                foreach (X509ChainElement element in presented.ChainElements)
                {
                    chain.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }
            return Accepts(chain, leaf);
        }

        public static bool Accepts(X509Chain chain, X509Certificate2 leaf)
        {
            bool built = chain.Build(leaf);
            if (!built)
            {
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.NoError && status.Status != X509ChainStatusFlags.UntrustedRoot)
                    {
                        LastFailure = "the certificate chain does not verify: " + status.Status;
                        return false;
                    }
                }
            }
            if (chain.ChainElements.Count == 0)
            {
                LastFailure = "the certificate chain is empty";
                return false;
            }
            X509Certificate2 root = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            string actual = Sha256Hex(root.RawData);
            if (!string.Equals(actual, Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                LastFailure = "the chain ends in a certificate with the SHA-256 fingerprint " + actual + ", not the pinned one";
                return false;
            }
            return true;
        }
    }
}
'@

function Initialize-Pin {
    param([string]$Fingerprint)
    if (-not ('Tenko.Mirror.Pin' -as [type])) {
        Add-Type -TypeDefinition $script:PinSource -ErrorAction Stop
    }
    [Tenko.Mirror.Pin]::Fingerprint = ConvertTo-FingerprintHex $Fingerprint
}

function ConvertTo-FingerprintHex {
    param([string]$Fingerprint)
    if (Test-Blank $Fingerprint) { throw 'the fingerprint of the certificate authority is empty' }
    $hex = ($Fingerprint -replace '[:\s\-]', '').ToLowerInvariant()
    if ($hex -notmatch '^[0-9a-f]{64}$') { throw 'the fingerprint must be the SHA-256 of the certificate authority, 64 hexadecimal digits' }
    return $hex
}

function Test-LoopbackUrl {
    param([uri]$Uri)
    if ($Uri.IsLoopback) { return $true }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($Uri.Host, [ref]$address)) {
        return [System.Net.IPAddress]::IsLoopback($address)
    }
    return $false
}

# ---------------------------------------------------------------------------------------
# The push.
# ---------------------------------------------------------------------------------------

function ConvertFrom-SecureToken {
    param([securestring]$Token)
    $pointer = [System.IntPtr]::Zero
    try {
        $pointer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        if ($pointer -ne [System.IntPtr]::Zero) { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    }
}

function Get-SnapshotUri {
    param([string]$Url, [string]$MirrorId)
    if (Test-Blank $Url) { throw 'the controller URL is not set' }
    if (Test-Blank $MirrorId) { throw 'the mirror id is not set' }
    if ($MirrorId -notmatch '^[A-Za-z0-9_\-]{1,64}$') { throw 'the mirror id must be letters, digits, hyphens and underscores' }
    $base = [uri]$Url.TrimEnd('/')
    if ($base.Scheme -ne 'https' -and $base.Scheme -ne 'http') { throw "the controller URL must be https://, not $($base.Scheme)://" }
    if (-not (Test-Blank $base.PathAndQuery) -and $base.PathAndQuery -ne '/') {
        throw 'the controller URL names the host and the port only; the path is fixed'
    }
    return [uri]"$($base.Scheme)://$($base.Authority)/api/v1/migrate/mirrors/$MirrorId/snapshot"
}

function Read-ResponseBody {
    param([System.Net.WebResponse]$Response)
    if ($null -eq $Response) { return '' }
    $stream = $Response.GetResponseStream()
    if ($null -eq $stream) { return '' }
    $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function ConvertFrom-ProblemBody {
    # RFC 9457 problem details with Tenko's `code`; the body may also be empty or not JSON.
    param([string]$Body)
    $result = [ordered]@{ code = ''; detail = ''; sequence = $null }
    if (Test-Blank $Body) { return $result }
    try {
        $json = $Body | ConvertFrom-Json
    } catch {
        $result.detail = $Body.Trim()
        if ($result.detail.Length -gt 200) { $result.detail = $result.detail.Substring(0, 200) }
        return $result
    }
    $code = Get-Prop $json 'code'
    if (-not (Test-Blank $code)) { $result.code = [string]$code }
    $detail = Get-Prop $json 'detail'
    if (-not (Test-Blank $detail)) { $result.detail = [string]$detail }
    $sequence = Get-Prop $json 'sequence'
    if ($null -ne $sequence) { $result.sequence = [uint64]$sequence }
    return $result
}

function Invoke-MirrorPush {
    <#
    .SYNOPSIS
      PUTs the snapshot bytes and returns @{status; sequence; changed; code; detail}.
      Nothing is thrown for an HTTP refusal; a transport failure throws.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$MirrorId,
        [Parameter(Mandatory)][securestring]$Token,
        [Parameter(Mandatory)][byte[]]$Body,
        [string]$Fingerprint,
        [switch]$AllowPlainHttp
    )
    $uri = Get-SnapshotUri -Url $Url -MirrorId $MirrorId
    $plain = ($uri.Scheme -eq 'http')
    if ($plain) {
        if (-not $AllowPlainHttp) { throw "the controller URL must be https://; $($uri.Scheme):// carries the token in the clear" }
        if (-not (Test-LoopbackUrl $uri)) { throw 'plain HTTP is allowed to a loopback address only' }
        Write-Warning "INSECURE: pushing over plain HTTP to $($uri.Authority); for tests only"
    } else {
        Initialize-Pin -Fingerprint $Fingerprint
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $protocols = [System.Net.SecurityProtocolType]::Tls12
        if ([enum]::GetNames([System.Net.SecurityProtocolType]) -contains 'Tls13') {
            $protocols = $protocols -bor [System.Net.SecurityProtocolType]::Tls13
        }
        [System.Net.ServicePointManager]::SecurityProtocol = $protocols
    }

    $payload = $Body
    $gzip = $false
    if ($Body.Length -gt $script:GzipAbove) {
        $buffer = [System.IO.MemoryStream]::new()
        $zip = [System.IO.Compression.GZipStream]::new($buffer, [System.IO.Compression.CompressionMode]::Compress, $true)
        $zip.Write($Body, 0, $Body.Length)
        $zip.Dispose()
        $payload = $buffer.ToArray()
        $buffer.Dispose()
        $gzip = $true
    }

    $request = [System.Net.HttpWebRequest]::Create($uri)
    $request.Method = 'PUT'
    $request.ContentType = 'application/json'
    $request.Accept = 'application/json, application/problem+json'
    $request.UserAgent = "$script:AdapterName/$script:AdapterVersion"
    $request.Timeout = $script:HttpTimeoutMs
    $request.ReadWriteTimeout = $script:HttpTimeoutMs
    $request.AllowAutoRedirect = $false
    $request.KeepAlive = $false
    if ($gzip) { $request.Headers.Add('Content-Encoding', 'gzip') }
    if (-not $plain) { $request.ServerCertificateValidationCallback = [Tenko.Mirror.Pin]::Callback }
    $secret = ConvertFrom-SecureToken $Token
    try {
        $request.Headers.Add('Authorization', "Bearer $secret")
    } finally {
        $secret = $null
    }
    $request.ContentLength = $payload.Length

    $result = [ordered]@{ status = 0; sequence = $null; changed = $null; code = ''; detail = '' }
    $response = $null
    try {
        $stream = $request.GetRequestStream()
        try { $stream.Write($payload, 0, $payload.Length) } finally { $stream.Dispose() }
        $response = $request.GetResponse()
        $result.status = [int]$response.StatusCode
        $text = Read-ResponseBody $response
        if (-not (Test-Blank $text)) {
            $json = $text | ConvertFrom-Json
            $sequence = Get-Prop $json 'sequence'
            if ($null -ne $sequence) { $result.sequence = [uint64]$sequence }
            $changed = Get-Prop $json 'changed'
            if ($null -ne $changed) { $result.changed = [bool]$changed }
        }
    } catch [System.Net.WebException] {
        $failure = $_.Exception
        if ($null -eq $failure.Response) {
            $reason = $failure.Message
            if ($failure.Status -eq [System.Net.WebExceptionStatus]::TrustFailure -or $failure.Status -eq [System.Net.WebExceptionStatus]::SecureChannelFailure) {
                $pinned = [Tenko.Mirror.Pin]::LastFailure
                if (-not (Test-Blank $pinned)) { $reason = "TLS: $pinned" }
            }
            throw "the push to $($uri.Authority) failed: $reason"
        }
        $response = $failure.Response
        $result.status = [int]$response.StatusCode
        $problem = ConvertFrom-ProblemBody (Read-ResponseBody $response)
        $result.code = $problem.code
        $result.detail = $problem.detail
        $result.sequence = $problem.sequence
    } finally {
        if ($null -ne $response) { $response.Close() }
    }
    return $result
}

# ---------------------------------------------------------------------------------------
# The state directory: the token (DPAPI, this account only), the sequence state, the log.
# ---------------------------------------------------------------------------------------

function Get-DefaultStateDir {
    return (Join-Path (Join-Path $env:ProgramData 'Tenko') (Join-Path 'mirror' 'state'))
}

function Get-DefaultConfigPath {
    return (Join-Path (Join-Path $env:ProgramData 'Tenko') (Join-Path 'mirror' 'config.json'))
}

function Read-MirrorConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "the configuration file $Path does not exist; run Install-TenkoDhcpMirror.ps1" }
    $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    return [ordered]@{
        url = [string](Get-Prop $json 'url')
        mirror = [string](Get-Prop $json 'mirror')
        fingerprint = [string](Get-Prop $json 'fingerprint')
    }
}

function Save-PendingToken {
    # The install script leaves the token as token.pending with an access list for this
    # account; the first run under the account stores it with DPAPI (user scope, no key)
    # and deletes the plain file.
    param([string]$Dir)
    $pending = Join-Path $Dir 'token.pending'
    if (-not (Test-Path -LiteralPath $pending)) { return $false }
    $plain = (Get-Content -LiteralPath $pending -Raw -Encoding UTF8).Trim()
    if ($plain.Length -eq 0) { throw 'token.pending is empty' }
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $plain = $null
    $protected = ConvertFrom-SecureString -SecureString $secure
    Set-Content -LiteralPath (Join-Path $Dir 'token.dpapi') -Value $protected -Encoding ASCII
    Remove-Item -LiteralPath $pending -Force
    return $true
}

function Read-MirrorToken {
    param([string]$Dir)
    $path = Join-Path $Dir 'token.dpapi'
    if (-not (Test-Path -LiteralPath $path)) { throw "no token is stored in $Dir; run Install-TenkoDhcpMirror.ps1 with -Token" }
    $protected = (Get-Content -LiteralPath $path -Raw -Encoding ASCII).Trim()
    return (ConvertTo-SecureString -String $protected)
}

function Read-MirrorState {
    param([string]$Dir)
    $path = Join-Path $Dir 'state.json'
    $state = [ordered]@{ last_sequence = [uint64]0 }
    if (Test-Path -LiteralPath $path) {
        try {
            $json = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
            $last = Get-Prop $json 'last_sequence'
            if ($null -ne $last) { $state.last_sequence = [uint64]$last }
        } catch {
            Write-Warning "state.json could not be read and is replaced: $($_.Exception.Message)"
        }
    }
    return $state
}

function Write-MirrorState {
    param([string]$Dir, [uint64]$LastSequence)
    $path = Join-Path $Dir 'state.json'
    Set-Content -LiteralPath $path -Value (ConvertTo-CanonicalJson ([ordered]@{ last_sequence = $LastSequence })) -Encoding ASCII
}

function Get-NextSequence {
    # Strictly increasing per mirror: the Unix time of the run, or one more than the last
    # push when the clock went back.
    param([uint64]$LastSequence, [datetime]$Now)
    $unix = [uint64][math]::Floor(($Now.ToUniversalTime() - [datetime]::new(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).TotalSeconds)
    if ($unix -gt $LastSequence) { return $unix }
    return $LastSequence + 1
}

function Write-MirrorLog {
    param([string]$Dir, [string]$Line)
    $stamp = [datetime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    $text = "$stamp $Line"
    Write-Verbose $text
    if (Test-Blank $Dir) { return }
    $path = Join-Path $Dir ('mirror-' + [datetime]::UtcNow.ToString('yyyyMMdd') + '.log')
    Add-Content -LiteralPath $path -Value $text -Encoding UTF8
    Get-ChildItem -LiteralPath $Dir -Filter 'mirror-*.log' -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -lt [datetime]::UtcNow.AddDays(-$script:LogDays) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

function Get-LocalServerName {
    $name = [System.Net.Dns]::GetHostName()
    if ($env:USERDNSDOMAIN -and -not $name.Contains('.')) { $name = "$name.$($env:USERDNSDOMAIN)" }
    return $name.ToLowerInvariant()
}

# ---------------------------------------------------------------------------------------
# One run.
# ---------------------------------------------------------------------------------------

function Invoke-MirrorRun {
    param(
        [switch]$Once,
        [string]$ConfigPath,
        [string]$StateDir,
        [string]$Url,
        [string]$MirrorId,
        [string]$Fingerprint,
        [string]$ServerName,
        [switch]$AllowPlainHttp
    )
    $started = [datetime]::UtcNow
    $script:ExitCode = 1
    if (Test-Blank $StateDir) { $StateDir = Get-DefaultStateDir }
    if (Test-Blank $ConfigPath) { $ConfigPath = Get-DefaultConfigPath }
    $logDir = $(if ($Once) { '' } else { $StateDir })

    # 1. The account. A privileged account never pushes; -Once reads only and warns.
    if (Test-WindowsHost) {
        $privileged = Get-PrivilegedMembership -Groups (Get-IdentityGroup)
        if ($privileged.Count -gt 0) {
            $message = "this account is a member of $($privileged -join ', '); the mirror runs as a member of DHCP Users and of no privileged group"
            if ($Once) {
                Write-Warning $message
            } else {
                Write-MirrorLog $logDir "refused: $message"
                throw $message
            }
        }
    } elseif (-not $Once) {
        Write-Warning 'not Windows: the account check is skipped'
    }

    # 2. The configuration.
    $config = [ordered]@{ url = $Url; mirror = $MirrorId; fingerprint = $Fingerprint }
    if (-not $Once -or (Test-Blank $Url)) {
        if (Test-Path -LiteralPath $ConfigPath) {
            $file = Read-MirrorConfig $ConfigPath
            foreach ($key in 'url', 'mirror', 'fingerprint') {
                if (Test-Blank $config[$key]) { $config[$key] = $file[$key] }
            }
        } elseif (-not $Once) {
            throw "the configuration file $ConfigPath does not exist; run Install-TenkoDhcpMirror.ps1"
        }
    }

    # 3. A token left by the install script is stored under this account.
    if (-not $Once) {
        if (-not (Test-Path -LiteralPath $StateDir)) { throw "the state directory $StateDir does not exist; run Install-TenkoDhcpMirror.ps1" }
        if (Save-PendingToken -Dir $StateDir) { Write-MirrorLog $logDir 'token stored with DPAPI for this account' }
    }

    # 4. The reads and the mapping.
    if (Test-Blank $ServerName) { $ServerName = Get-LocalServerName }
    try {
        $raw = Read-DhcpServer
    } catch {
        Write-MirrorLog $logDir "read failed: $($_.Exception.Message)"
        throw "reading the DHCP server failed: $($_.Exception.Message)"
    }
    $state = Read-MirrorState -Dir $StateDir
    $sequence = Get-NextSequence -LastSequence $state.last_sequence -Now $started
    $takenAt = $started.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    $snapshot = ConvertTo-MirrorSnapshot -Raw $raw -Sequence $sequence -TakenAt $takenAt -ServerName $ServerName
    $json = ConvertTo-CanonicalJson $snapshot
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $hash = Get-Sha256Hex $bytes
    $reservationCount = 0
    foreach ($scope in $snapshot.dhcp.scopes) { $reservationCount += $scope.reservations.Count }
    $counts = "scopes=$($snapshot.dhcp.scopes.Count) reservations=$reservationCount leases=$($snapshot.dhcp.leases.Count) losses=$($snapshot.losses.entries.Count)"
    if ($snapshot.dhcp.scopes.Count -gt $script:MaxScopes -or $reservationCount -gt $script:MaxReservations -or $snapshot.dhcp.leases.Count -gt $script:MaxLeases) {
        Write-Warning "the snapshot is above the controller's bounds ($counts); the push will be refused with 413"
    }

    # 5. The dry run prints and stops.
    if ($Once) {
        $script:ExitCode = 0
        Write-Output ($snapshot | ConvertTo-Json -Depth 20)
        return
    }

    # 6. The push.
    $token = Read-MirrorToken -Dir $StateDir
    try {
        $answer = Invoke-MirrorPush -Url $config.url -MirrorId $config.mirror -Token $token -Body $bytes -Fingerprint $config.fingerprint -AllowPlainHttp:$AllowPlainHttp
    } catch {
        $duration = [int]([datetime]::UtcNow - $started).TotalMilliseconds
        Write-MirrorLog $logDir "seq=$sequence $counts hash=$($hash.Substring(0, 16)) answer=none error=$($_.Exception.Message) duration_ms=$duration"
        $script:ExitCode = 6
        throw
    }
    $duration = [int]([datetime]::UtcNow - $started).TotalMilliseconds
    $line = "seq=$sequence $counts hash=$($hash.Substring(0, 16)) answer=$($answer.status)"
    switch ($answer.status) {
        200 {
            Write-MirrorState -Dir $StateDir -LastSequence $sequence
            $changed = $(if ($null -eq $answer.changed) { 'unknown' } else { $answer.changed.ToString().ToLowerInvariant() })
            Write-MirrorLog $logDir "$line changed=$changed duration_ms=$duration"
            $script:ExitCode = 0
        }
        409 {
            # A replay: the controller is ahead of our state. Next run continues above it.
            $ahead = $sequence
            if ($null -ne $answer.sequence -and $answer.sequence -gt $ahead) { $ahead = $answer.sequence }
            Write-MirrorState -Dir $StateDir -LastSequence $ahead
            Write-MirrorLog $logDir "$line code=$($answer.code) detail=$($answer.detail) duration_ms=$duration"
            $script:ExitCode = 5
        }
        default {
            Write-MirrorLog $logDir "$line code=$($answer.code) detail=$($answer.detail) duration_ms=$duration"
            $script:ExitCode = $(if ($answer.status -ge 500) { 6 } else { 5 })
        }
    }
}

# Dot-sourced by the tests: define the functions and stop here.
if ($MyInvocation.InvocationName -eq '.') { return }

# Exit codes: 0 pushed or printed; 1 a failure before the push (configuration, the account,
# the reads); 5 the controller refused the push (4xx); 6 the push did not complete (transport,
# TLS, 5xx).
$script:ExitCode = 1
try {
    Invoke-MirrorRun -Once:$Once -ConfigPath $ConfigPath -StateDir $StateDir -Url $Url -MirrorId $MirrorId `
        -Fingerprint $Fingerprint -ServerName $ServerName -AllowPlainHttp:$AllowPlainHttp
    exit $script:ExitCode
} catch {
    [Console]::Error.WriteLine("Tenko-DhcpMirror: $($_.Exception.Message)")
    exit $script:ExitCode
}
