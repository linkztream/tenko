<#
.SYNOPSIS
Builds the Tenko DDI MSI from a release binary with the WiX toolset v5.

.DESCRIPTION
Uses the WiX version pinned in .config/dotnet-tools.json (a .NET local tool; needs the .NET
SDK 8 or newer) and the WiX extensions of the same version. Writes
<Out>\tenko-<Version>-windows-x86_64.msi and validates it with WiX's ICE validation.

  pwsh -File deploy\windows\build-msi.ps1 -Binary .\tenko.exe -Version 0.2.0 -Out dist

The binary must report -Version (`tenko --version`). The MSI's own version is the numeric
part of -Version (0.2.0-rc.1 becomes 0.2.0); -MsiVersion overrides it, which the smoke test
uses to build a second, newer package from the same binary.

.PARAMETER Binary
The tenko.exe to package.

.PARAMETER Version
The release version, as the workflow's VERSION (0.2.0 or 0.2.0-rc.1).

.PARAMETER Out
The output directory; created when missing.

.PARAMETER MsiVersion
The MSI ProductVersion, major.minor.build with major and minor up to 255 and build up to
65535. Default: the numeric part of -Version.

.PARAMETER NoValidate
Skip the ICE validation (it needs the Windows Installer service).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Binary,
    [Parameter(Mandatory)] [string] $Version,
    [Parameter(Mandatory)] [string] $Out,
    [string] $MsiVersion,
    [switch] $NoValidate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The extensions must match the toolset in .config/dotnet-tools.json.
$WixVersion = '5.0.2'
$Extensions = @('WixToolset.UI.wixext', 'WixToolset.Util.wixext', 'WixToolset.Firewall.wixext')

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$wixDir = Join-Path $PSScriptRoot 'wix'

function Invoke-Checked {
    param([string] $What, [scriptblock] $Command)
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$What failed with exit status $LASTEXITCODE" }
}

# --- Inputs ------------------------------------------------------------------------------
$Binary = (Resolve-Path $Binary).Path
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$') {
    throw "-Version '$Version' is not a version like 0.2.0 or 0.2.0-rc.1"
}
if (-not $MsiVersion) { $MsiVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])" }
if ($MsiVersion -notmatch '^(\d+)\.(\d+)\.(\d+)$' -or [int]$Matches[1] -gt 255 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 65535) {
    throw "the MSI version '$MsiVersion' must be major.minor.build with major and minor up to 255 and build up to 65535"
}

$reported = (& $Binary --version) -join ' '
if ($LASTEXITCODE -ne 0) { throw "$Binary --version failed with exit status $LASTEXITCODE" }
if (-not $reported.Contains($Version)) {
    throw "$Binary reports '$reported', expected version $Version"
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$msi = Join-Path $Out "tenko-$Version-windows-x86_64.msi"
$obj = Join-Path $Out "obj-msi-$MsiVersion"
New-Item -ItemType Directory -Force -Path $obj | Out-Null

# --- The licence page: the repository's LICENSE.md as RTF -----------------------------------
$rtfLines = foreach ($line in Get-Content -LiteralPath (Join-Path $repo 'LICENSE.md') -Encoding utf8) {
    $escaped = $line.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
    $sb = [System.Text.StringBuilder]::new()
    foreach ($c in $escaped.ToCharArray()) {
        if ([int]$c -gt 127) { [void]$sb.Append("\u$([int]$c)?") } else { [void]$sb.Append($c) }
    }
    "$($sb.ToString())\par"
}
$rtf = Join-Path $obj 'License.rtf'
$rtfText = "{\rtf1\ansi\deff0{\fonttbl{\f0 Tahoma;}}\fs16`r`n" + ($rtfLines -join "`r`n") + "`r`n}`r`n"
[System.IO.File]::WriteAllText($rtf, $rtfText, [System.Text.Encoding]::ASCII)

# --- The toolset -------------------------------------------------------------------------
Push-Location $repo
try {
    Invoke-Checked 'dotnet tool restore' { dotnet tool restore }
    $have = (dotnet tool run wix extension list -g) -join "`n"
    foreach ($ext in $Extensions) {
        if ($have -notmatch [regex]::Escape("$ext $WixVersion")) {
            Invoke-Checked "wix extension add $ext" { dotnet tool run wix extension add -g "$ext/$WixVersion" }
        }
    }

    # --- Build ---------------------------------------------------------------------------
    $build = @(
        'build', '-arch', 'x64', '-culture', 'en-US',
        '-d', "Version=$Version", '-d', "ProductVersion=$MsiVersion",
        '-d', "Binary=$Binary", '-d', "LicenseRtf=$rtf",
        '-intermediatefolder', $obj, '-o', $msi
    )
    foreach ($ext in $Extensions) { $build += @('-ext', "$ext/$WixVersion") }
    $build += @((Join-Path $wixDir 'Package.wxs'), (Join-Path $wixDir 'TenkoUI.wxs'))
    Invoke-Checked 'wix build' { dotnet tool run wix @build }

    if (-not $NoValidate) {
        # Suppressed: ICE38, ICE43 and ICE57 expect a per-user key path for Start menu
        # shortcuts, which a per-machine package has no use for; ICE61 flags the same-version
        # upgrades that MajorUpgrade allows on purpose.
        $validate = @('msi', 'validate', '-intermediatefolder', $obj)
        foreach ($ice in 'ICE38', 'ICE43', 'ICE57', 'ICE61') { $validate += @('-sice', $ice) }
        Invoke-Checked 'wix msi validate' { dotnet tool run wix @validate $msi }
    }
}
finally {
    Pop-Location
}

# wix build leaves the debug symbols next to the package; the release ships the MSI only.
Remove-Item -LiteralPath ([System.IO.Path]::ChangeExtension($msi, '.wixpdb')) -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $obj -Recurse -Force -ErrorAction SilentlyContinue

$hash = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "built $msi (MSI version $MsiVersion)"
Write-Host "sha256 $hash"
