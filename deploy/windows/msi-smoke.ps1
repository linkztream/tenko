<#
.SYNOPSIS
  Smoke test of the Tenko DDI MSI: silent install, upgrade, uninstall and purge.

.DESCRIPTION
  Installs the MSI unattended with the controller and dns roles (DNS on a high loopback
  port), checks the running service, the health probe, the setup token, the layout and the
  firewall rules, upgrades to a second package of a higher version (or reinstalls the same
  package when -UpgradeMsi is not given), checks that the service runs again with the data
  kept, uninstalls and checks that the configuration and the data stay, installs once more
  over the kept data and finally uninstalls with TENKO_PURGE=1.

  It changes the machine: it installs the product for real, under its real name, with
  the configuration at %ProgramData%\Tenko\tenko.toml. Run it on a throw-away machine or a
  CI runner, in an elevated PowerShell 7:

    pwsh -File deploy\windows\msi-smoke.ps1 -Msi dist\tenko-0.2.0-windows-x86_64.msi `
        -UpgradeMsi upgrade\tenko-0.2.0-windows-x86_64.msi

  It refuses to start when Tenko is installed already, when a service named tenko exists or
  when %ProgramData%\Tenko\tenko.toml exists. Each step prints a line that starts with
  `==>`; a failure prints the tail of the installer log and of tenko.log, removes what the
  script installed (unless -Keep) and exits with status 1.

.PARAMETER Msi
  The package under test.

.PARAMETER UpgradeMsi
  A package of the same product with a higher MSI version (build-msi.ps1 -MsiVersion).
  Without it the upgrade step is a reinstall of -Msi (REINSTALL=ALL REINSTALLMODE=vomus).

.PARAMETER DataDir
  The data directory to install with. Default: a fresh directory under %ProgramData%.

.PARAMETER DnsPort
  The DNS port of the dns role. Default: 15353.

.PARAMETER LogDir
  Where the installer logs go. Default: the temporary directory.

.PARAMETER Keep
  Leave the product installed after a failure, to look at it.
#>
param(
    [Parameter(Mandatory)][string]$Msi,
    [string]$UpgradeMsi,
    [string]$DataDir = (Join-Path $env:ProgramData ("TenkoMsiSmoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))),
    [int]$DnsPort = 15353,
    [string]$LogDir = [System.IO.Path]::GetTempPath(),
    [switch]$Keep
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$PSNativeCommandUseErrorActionPreference = $false

$ServiceName = 'tenko'
$ProductName = 'Tenko DDI'
$ConfigFile = Join-Path $env:ProgramData 'Tenko\tenko.toml'
$InstallDir = Join-Path $env:ProgramFiles 'Tenko'
$Exe = Join-Path $InstallDir 'tenko.exe'
$BaseUrl = 'https://localhost:8443'
$CaFile = Join-Path $DataDir 'tls\ca-root.pem'
$Marker = Join-Path $DataDir 'msi-smoke.marker'
$script:LastLog = $null
$script:Installed = $false

function Write-Step([string]$Text) { Write-Host "==> $Text" }

function Assert-That($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Wait-Until([scriptblock]$Test, [int]$TimeoutSec, [string]$What) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ($true) {
        $result = & $Test
        if ($result) { return $result }
        if ([DateTime]::UtcNow -gt $deadline) { throw "timed out after $TimeoutSec s waiting for: $What" }
        Start-Sleep -Seconds 1
    }
}

# Runs msiexec with a verbose log and returns its exit status (0, or 3010 for a reboot that
# a service install never needs, count as success).
function Invoke-Msiexec([string]$Name, [string[]]$Arguments) {
    $log = Join-Path $LogDir "msi-smoke-$Name.log"
    $script:LastLog = $log
    $all = $Arguments + @('/qn', '/norestart', '/l*v', "`"$log`"")
    Write-Host "msiexec $($all -join ' ')"
    $process = Start-Process -FilePath msiexec.exe -ArgumentList $all -Wait -PassThru
    return $process.ExitCode
}

function Invoke-MsiexecOk([string]$Name, [string[]]$Arguments) {
    $code = Invoke-Msiexec $Name $Arguments
    Assert-That ($code -eq 0 -or $code -eq 3010) "msiexec ($Name) exited with status $code; log: $script:LastLog"
}

function Invoke-Tenko([string[]]$Arguments) {
    $output = & $Exe @Arguments 2>&1 | Out-String
    [pscustomobject]@{ Code = $LASTEXITCODE; Output = $output.TrimEnd() }
}

# The installed products named Tenko DDI, from the uninstall registry.
function Get-TenkoProducts {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq $ProductName })
}

function Get-ServiceState {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) { return $null }
    return [string]$service.Status
}

function Get-FirewallPorts([string]$DisplayName) {
    $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($null -eq $rule) { return $null }
    return (($rule | Get-NetFirewallPortFilter).LocalPort -join ',')
}

# The service runs, answers the liveness probe and runs from the version layout.
function Assert-Running([string]$When) {
    Wait-Until -TimeoutSec 120 -What "service $ServiceName running ($When)" -Test { (Get-ServiceState) -eq 'Running' } | Out-Null
    $health = Wait-Until -TimeoutSec 120 -What "tenko health --live ($When)" -Test {
        if (-not (Test-Path -LiteralPath $CaFile)) { return $null }
        $result = Invoke-Tenko @('health', '--live', '--url', $BaseUrl, '--ca-file', $CaFile)
        if ($result.Code -eq 0) { return $result.Output }
        return $null
    }
    Write-Host $health
    $image = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'").PathName
    Assert-That ($image -like "*$DataDir\updates\current\tenko.exe*") "the service runs '$image', not the version layout of $DataDir"
    $listening = Get-NetTCPConnection -LocalPort $DnsPort -State Listen -ErrorAction SilentlyContinue
    Assert-That ($null -ne $listening) "nothing listens on TCP $DnsPort (the dns role)"
}

function Show-Diagnostics {
    Write-Host '---- diagnostics'
    Write-Host "service: $(Get-ServiceState)"
    if ($script:LastLog -and (Test-Path -LiteralPath $script:LastLog)) {
        Write-Host "---- last 80 lines of $script:LastLog"
        Get-Content -LiteralPath $script:LastLog -Tail 80 | ForEach-Object { Write-Host $_ }
    }
    $serviceLog = Join-Path $DataDir 'logs\tenko.log'
    if (Test-Path -LiteralPath $serviceLog) {
        Write-Host "---- last 80 lines of $serviceLog"
        Get-Content -LiteralPath $serviceLog -Tail 80 | ForEach-Object { Write-Host $_ }
    }
}

# ---------------------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------------------
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('msi-smoke: run this script in an elevated prompt (Run as administrator)')
    exit 1
}
$Msi = (Resolve-Path -LiteralPath $Msi).Path
if ($UpgradeMsi) { $UpgradeMsi = (Resolve-Path -LiteralPath $UpgradeMsi).Path }
if (@(Get-TenkoProducts).Count -gt 0) {
    [Console]::Error.WriteLine("msi-smoke: $ProductName is installed on this machine; the smoke test needs a machine without it")
    exit 1
}
if ($null -ne (Get-ServiceState)) {
    [Console]::Error.WriteLine("msi-smoke: a service named $ServiceName exists; the smoke test needs a machine without it")
    exit 1
}
if (Test-Path -LiteralPath $ConfigFile) {
    [Console]::Error.WriteLine("msi-smoke: $ConfigFile exists; the smoke test needs a machine without it")
    exit 1
}
if (Test-Path -LiteralPath $DataDir) {
    [Console]::Error.WriteLine("msi-smoke: $DataDir exists; name a new directory with -DataDir")
    exit 1
}

$installArgs = @(
    'TENKO_ROLES=controller,dns',
    "TENKO_DATA_DIR=`"$DataDir`"",
    'TENKO_DNS_ADDRESS=127.0.0.1',
    "TENKO_DNS_PORT=$DnsPort",
    'TENKO_PROFILE=home',
    'TENKO_HOSTNAME=msi-smoke.example.test'
)

$failed = $false
try {
    # -----------------------------------------------------------------------------------
    Write-Step '1/7 silent install'
    $script:Installed = $true
    Invoke-MsiexecOk 'install' (@('/i', "`"$Msi`"") + $installArgs)
    Assert-That (Test-Path -LiteralPath $Exe) "$Exe is missing"
    Assert-That (Test-Path -LiteralPath (Join-Path $InstallDir 'setup-token.cmd')) 'setup-token.cmd is missing'
    $config = Get-Content -LiteralPath $ConfigFile -Raw
    Write-Host $config
    Assert-That ($config -match [regex]::Escape("$DataDir")) "tenko.toml does not name $DataDir"
    Assert-That ($config -match "127\.0\.0\.1:$DnsPort") "tenko.toml does not listen on 127.0.0.1:$DnsPort"
    Assert-That ((Get-FirewallPorts 'Tenko DDI web UI and API (TCP 8443)') -eq '8443') 'the firewall rule for TCP 8443 is missing'
    Assert-That ((Get-FirewallPorts 'Tenko DDI DNS (UDP)') -eq "$DnsPort") "the firewall rule for UDP $DnsPort is missing"
    Assert-That ((Get-FirewallPorts 'Tenko DDI DNS (TCP)') -eq "$DnsPort") "the firewall rule for TCP $DnsPort is missing"
    # WP7.5: the dhcp rule (UDP 67) belongs to the dhcp role, which this install does not
    # name, so the rule must not exist. (A role list with dhcp would start a DHCP server on
    # the runner's port 67, which a smoke test must not do.)
    Assert-That ($null -eq (Get-FirewallPorts 'Tenko DDI DHCP (UDP)')) 'the firewall rule for UDP 67 exists without the dhcp role'

    # -----------------------------------------------------------------------------------
    Write-Step '2/7 service running, health, setup token'
    Assert-Running 'after the install'
    $token = Invoke-Tenko @('setup', 'token', '--config', $ConfigFile)
    Assert-That ($token.Code -eq 0 -and $token.Output.Trim().Length -gt 0) "tenko setup token failed (status $($token.Code)): $($token.Output)"
    Write-Host 'setup token: readable'
    Set-Content -LiteralPath $Marker -Value 'kept across upgrade and uninstall'
    $configHash = (Get-FileHash -LiteralPath $ConfigFile).Hash

    # -----------------------------------------------------------------------------------
    if ($UpgradeMsi) {
        Write-Step '3/7 silent upgrade to the second package'
        Invoke-MsiexecOk 'upgrade' @('/i', "`"$UpgradeMsi`"")
        Assert-That (@(Get-TenkoProducts).Count -eq 1) "after the upgrade $(@(Get-TenkoProducts).Count) products named $ProductName are installed"
        $current = $UpgradeMsi
    } else {
        Write-Step '3/7 silent reinstall of the same package'
        Invoke-MsiexecOk 'reinstall' @('/i', "`"$Msi`"", 'REINSTALL=ALL', 'REINSTALLMODE=vomus')
        $current = $Msi
    }
    Assert-Running 'after the upgrade'
    Assert-That (Test-Path -LiteralPath $Marker) 'the data directory lost its marker file in the upgrade'
    Assert-That ((Get-FileHash -LiteralPath $ConfigFile).Hash -eq $configHash) 'the upgrade changed tenko.toml'
    Assert-That ((Get-FirewallPorts 'Tenko DDI DNS (UDP)') -eq "$DnsPort") 'the upgrade lost the DNS firewall rule'

    # -----------------------------------------------------------------------------------
    Write-Step '4/7 silent uninstall keeps the configuration and the data'
    Invoke-MsiexecOk 'uninstall' @('/x', "`"$current`"")
    $script:Installed = $false
    Assert-That ($null -eq (Get-ServiceState)) 'the service is still registered after the uninstall'
    Assert-That (-not (Test-Path -LiteralPath $Exe)) "$Exe is still there after the uninstall"
    Assert-That ($null -eq (Get-FirewallPorts 'Tenko DDI web UI and API (TCP 8443)')) 'the firewall rule is still there after the uninstall'
    Assert-That (Test-Path -LiteralPath $Marker) 'the uninstall removed the data directory'
    Assert-That (Test-Path -LiteralPath (Join-Path $DataDir 'store')) 'the uninstall removed the store'
    Assert-That ((Get-FileHash -LiteralPath $ConfigFile).Hash -eq $configHash) 'the uninstall changed or removed tenko.toml'
    Assert-That (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Tenko\Installer') 'the uninstall removed the remembered properties'

    # -----------------------------------------------------------------------------------
    # No properties: the remembered ones apply, the data directory among them.
    Write-Step '5/7 install again over the kept configuration and data'
    $script:Installed = $true
    Invoke-MsiexecOk 'reinstall-kept' @('/i', "`"$current`"")
    Assert-Running 'over the kept data'
    Assert-That ((Get-FileHash -LiteralPath $ConfigFile).Hash -eq $configHash) 'the install replaced the kept tenko.toml'

    # -----------------------------------------------------------------------------------
    Write-Step '6/7 silent uninstall with TENKO_PURGE=1'
    Invoke-MsiexecOk 'purge' @('/x', "`"$current`"", 'TENKO_PURGE=1')
    $script:Installed = $false
    Assert-That ($null -eq (Get-ServiceState)) 'the service is still registered after the purge'
    Assert-That (-not (Test-Path -LiteralPath $DataDir)) "$DataDir is still there after the purge"
    Assert-That (-not (Test-Path -LiteralPath $ConfigFile)) "$ConfigFile is still there after the purge"

    # -----------------------------------------------------------------------------------
    Write-Step '7/7 nothing left'
    Assert-That (@(Get-TenkoProducts).Count -eq 0) "$ProductName is still registered as installed"
    Assert-That (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Tenko\Installer')) 'the remembered properties are still in the registry'
    Write-Host 'msi-smoke: all steps passed'
}
catch {
    $failed = $true
    [Console]::Error.WriteLine("FAILED: $($_.Exception.Message)")
    Show-Diagnostics
}
finally {
    if ($failed -and -not $Keep -and $script:Installed) {
        Write-Host '==> cleanup: uninstall with TENKO_PURGE=1'
        $product = Get-TenkoProducts | Select-Object -First 1
        if ($null -ne $product) {
            Invoke-Msiexec 'cleanup' @('/x', $product.PSChildName, 'TENKO_PURGE=1') | Out-Null
        }
    }
}
if ($failed) { exit 1 }
exit 0
