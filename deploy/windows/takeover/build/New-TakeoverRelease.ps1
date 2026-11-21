<#
.SYNOPSIS
  Builds the Windows takeover files of a release (run by .github/workflows/release.yml).

.DESCRIPTION
  Checks that the three scripts are ASCII with CRLF line ends, fills the release data of
  Tenko-Takeover.ps1 (the version, and the exporter and its installer as base64 with the
  SHA-256 of their text), and writes to -OutDir the single file Tenko-Takeover.ps1, the loose
  Tenko-DhcpMirror.ps1 and Install-TenkoDhcpMirror.ps1, and tenko-takeover-<version>.zip
  with the three and README.md. It prints the names of the files it wrote, one per line.

  With -Notes it writes instead the release notes' section with the start line and its
  fetching form for the Tenko-Takeover.ps1 given by -Script, its digest built in.

  The exporter and its installer are stored with LF line ends in the repository today: a
  file with LF line ends only is written with CRLF; a file with mixed line ends, or with a
  byte outside ASCII, stops the build.
#>
[CmdletBinding(DefaultParameterSetName = 'Build')]
param(
    [Parameter(ParameterSetName = 'Build', Mandatory)][string]$Version,
    [Parameter(ParameterSetName = 'Build', Mandatory)][string]$OutDir,
    [Parameter(ParameterSetName = 'Notes', Mandatory)][switch]$Notes,
    [Parameter(ParameterSetName = 'Notes', Mandatory)][string]$Tag,
    [Parameter(ParameterSetName = 'Notes', Mandatory)][string]$Script
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $PSScriptRoot
$mirror = Join-Path (Split-Path -Parent $here) 'mirror'

function Get-ReleaseText {
    # The file's bytes as ASCII with CRLF line ends, or a refusal.
    param([string]$Path, [switch]$MayConvert)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $name = Split-Path -Leaf $Path
    foreach ($byte in $bytes) { if ($byte -gt 0x7e -or ($byte -lt 0x20 -and $byte -ne 9 -and $byte -ne 10 -and $byte -ne 13)) { throw "$name holds a byte outside printable ASCII ($byte)" } }
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $lf = ([regex]::Matches($text, "(?<!`r)`n")).Count
    $cr = ([regex]::Matches($text, "`r(?!`n)")).Count
    $crlf = ([regex]::Matches($text, "`r`n")).Count
    if ($cr -gt 0) { throw "$name holds a CR without LF" }
    if ($lf -gt 0 -and $crlf -gt 0) { throw "$name mixes LF and CRLF line ends" }
    if ($lf -gt 0) {
        if (-not $MayConvert) { throw "$name has LF line ends; the released scripts are CRLF" }
        $text = $text.Replace("`n", "`r`n")
    }
    if (-not $text.EndsWith("`r`n")) { throw "$name does not end with a line end" }
    return $text
}

function Get-TextDigest {
    # The same digest as Get-TkTextDigest of Tenko-Takeover.ps1: the text before a signature
    # block, trailing line ends removed.
    param([string]$Text)
    $body = $Text
    $at = $Text.IndexOf("`r`n# SIG # Begin signature block`r`n", [System.StringComparison]::Ordinal)
    if ($at -ge 0) { $body = $Text.Substring(0, $at) }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($body.TrimEnd("`r", "`n")))) -replace '-', '').ToLowerInvariant() } finally { $sha.Dispose() }
}

function Get-FileDigest {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StartLine {
    # The one line that checks the file's digest and only then starts it: the folder and
    # PowerShell as the platform names them, never by an environment variable a user sets.
    param([string]$Digest)
    return '$f=[Environment]::GetFolderPath(''ProgramFiles'')+''\Tenko\takeover\Tenko-Takeover.ps1''; if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -eq ''' + $Digest.ToUpperInvariant() + ''') { Unblock-File -LiteralPath $f; & "$PSHOME\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File $f } else { Write-Error (''Tenko-Takeover.ps1 does not match the release digest; nothing was run. Its SHA-256 is '' + (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash) }'
}

function Get-FetchLine {
    param([string]$Digest, [string]$Tag)
    return '$d=[Environment]::GetFolderPath(''ProgramFiles'')+''\Tenko\takeover''; $null = New-Item -ItemType Directory -Force $d; curl.exe -fsSL -o "$d\Tenko-Takeover.ps1" https://github.com/linkztream/tenko/releases/download/' + $Tag + '/Tenko-Takeover.ps1; ' + (Get-StartLine $Digest)
}

if ($Notes) {
    if ($Tag -notmatch '^v\d+\.\d+\.\d+(-rc\.\d+)?$') { throw "the tag $Tag is not vX.Y.Z or vX.Y.Z-rc.N" }
    $digest = Get-FileDigest $Script
    $lines = @(
        '', '## Windows takeover', '',
        "Tenko-Takeover.ps1 of this release has the SHA-256 ``$digest``. Bring it in with ``tenko-takeover-*.zip`` and ``SHA256SUMS`` through your intake (README.md of the archive, ""Intake""), copy it to ``%ProgramFiles%\Tenko\takeover`` and paste this line in an elevated PowerShell:", '',
        '```powershell', (Get-StartLine $digest), '```', '',
        'On a host that reaches this page, the fetching form:', '',
        '```powershell', (Get-FetchLine $digest $Tag), '```'
    )
    Write-Output ($lines -join "`n")
    return
}

if ($Version -notmatch '^\d+\.\d+\.\d+(-rc\.\d+)?$') { throw "the version $Version is not X.Y.Z or X.Y.Z-rc.N" }
$takeover = Get-ReleaseText (Join-Path $here 'Tenko-Takeover.ps1')
$payloads = [ordered]@{}
foreach ($name in 'Tenko-DhcpMirror.ps1', 'Install-TenkoDhcpMirror.ps1') { $payloads[$name] = Get-ReleaseText (Join-Path $mirror $name) -MayConvert }

$begin = "# BEGIN RELEASE DATA`r`n"
$end = "# END RELEASE DATA`r`n"
$from = $takeover.IndexOf($begin, [System.StringComparison]::Ordinal)
$to = $takeover.IndexOf($end, [System.StringComparison]::Ordinal)
if ($from -lt 0 -or $to -lt $from -or $takeover.IndexOf($begin, $from + 1, [System.StringComparison]::Ordinal) -ge 0) { throw 'Tenko-Takeover.ps1 does not hold one release data block' }
$block = [System.Text.StringBuilder]::new()
[void]$block.Append($begin)
[void]$block.Append("# Filled by build/New-TakeoverRelease.ps1 for this release.`r`n")
[void]$block.Append("`$script:TkVersion = '$Version'`r`n")
[void]$block.Append("`$script:TkPayloadDigest = @{`r`n")
foreach ($name in $payloads.Keys) { [void]$block.Append("    '$name' = '$(Get-TextDigest $payloads[$name])'`r`n") }
[void]$block.Append("}`r`n`$script:TkPayloadText = @{`r`n")
foreach ($name in $payloads.Keys) {
    $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($payloads[$name]))
    [void]$block.Append("    '$name' = @'`r`n")
    for ($i = 0; $i -lt $base64.Length; $i += 76) { [void]$block.Append($base64.Substring($i, [math]::Min(76, $base64.Length - $i)) + "`r`n") }
    [void]$block.Append("'@`r`n")
}
[void]$block.Append("}`r`n")
$filled = $takeover.Substring(0, $from) + $block.ToString() + $takeover.Substring($to)

if (-not (Test-Path -LiteralPath $OutDir)) { [void](New-Item -ItemType Directory -Path $OutDir) }
$out = (Resolve-Path -LiteralPath $OutDir).Path
$files = [ordered]@{ 'Tenko-Takeover.ps1' = $filled }
foreach ($name in $payloads.Keys) { $files[$name] = $payloads[$name] }
foreach ($name in $files.Keys) { [System.IO.File]::WriteAllBytes((Join-Path $out $name), [System.Text.Encoding]::ASCII.GetBytes($files[$name])) }

$zip = Join-Path $out "tenko-takeover-$Version.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip }
# Windows PowerShell loads the archive classes only when asked (a library of the platform).
if ($PSVersionTable.PSEdition -eq 'Desktop') { Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem }
$stream = [System.IO.File]::Open($zip, 'CreateNew')
try {
    $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        $entries = [ordered]@{}
        foreach ($name in $files.Keys) { $entries[$name] = [System.Text.Encoding]::ASCII.GetBytes($files[$name]) }
        $entries['README.md'] = [System.IO.File]::ReadAllBytes((Join-Path $here 'README.md'))
        foreach ($name in $entries.Keys) {
            $entry = $archive.CreateEntry("tenko-takeover/$name", [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [datetimeoffset]::new(2000, 1, 1, 0, 0, 0, [timespan]::Zero)
            $writer = $entry.Open()
            try { $writer.Write($entries[$name], 0, $entries[$name].Length) } finally { $writer.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $stream.Dispose() }

foreach ($name in @($files.Keys) + "tenko-takeover-$Version.zip") { Write-Output $name }
