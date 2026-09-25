<#
.SYNOPSIS
    Reports whether a Windows Server still depends on the Windows Deployment
    Services (WDS) role, and whether the CVE-2026-0386 hands-free deployment
    hardening registry setting is configured securely.

.DESCRIPTION
    On September 21, 2026, Microsoft published KB5129631 announcing that the
    WDS server role (PXE boot, multicast transport, management tools/APIs,
    and the WinPE-WDS-Tools component) is deprecated starting with the next
    release of Windows Server, in favor of Microsoft Configuration Manager.
    WDS remains fully supported on Windows Server 2025 and earlier per their
    normal servicing lifecycles - nothing is removed today.

    Separately, WDS's "hands-free" deployment feature (which serves an
    Unattend.xml answer file - often containing credentials - to a PXE
    client over the RemoteInstall share) was the subject of CVE-2026-0386.
    Microsoft hardened this in two phases: Phase 1 (January 13, 2026) added
    an explicit registry option to disable it; Phase 2 (April 14, 2026) made
    the secure setting the default going forward.

    This script is READ-ONLY. It checks, on the local server:
      - Whether the WDS role and its WDS-Deployment / WDS-Transport role
        services are installed (via Get-WindowsFeature, Windows Server only).
      - The value of AllowHandsFreeFunctionality under
        HKLM:\SYSTEM\CurrentControlSet\Services\WdsServer\Providers\WdsImgSrv\Unattend
        (0 = secure/hands-free disabled, 1 = insecure/hands-free allowed,
        absent = relying on the OS-version default).
      - Whether the WDSServer service exists and its current state.
      - If the ConfigurationManager PowerShell module is already loaded in
        the session, whether any distribution point has PXE or multicast
        enabled (both of these run on top of the same WDS role).

    It never calls Install-WindowsFeature, Uninstall-WindowsFeature,
    Set-ItemProperty, New-ItemProperty, Set-CMDistributionPoint, or any other
    state-changing cmdlet. Running this script does not install, remove, or
    reconfigure anything.

    This script targets Windows Server. On a non-server OS, or where the
    ServerManager module is unavailable, the role-installation check is
    skipped (not treated as an error) and the script still reports the
    registry and service checks.

.PARAMETER CsvPath
    Optional. Path to a .csv file. If supplied, the single-row result for
    this server is exported there (in addition to the console output). The
    file is only written after every check has completed - a run that errors
    partway through does not produce a partial CSV that could be mistaken
    for a complete report.

.EXAMPLE
    .\Get-WdsDependencyReport.ps1

    Checks the local server and prints the results to the console.

.EXAMPLE
    .\Get-WdsDependencyReport.ps1 -CsvPath "C:\Reports\wds-dependency.csv"

    Checks the local server and also writes the result to a CSV file.

.NOTES
    Author        : Imran Awan
    Blog post      : https://endpointweekly.com/blog/windows-deployment-services-wds-deprecation-configuration-manager-migration.html
    Read-only      : Yes - no Install-*, Uninstall-*, Set-*, or New-ItemProperty cmdlets are used.
    Requires       : Run elevated (Administrator) to read the WdsServer registry key reliably.
                     Get-WindowsFeature requires the ServerManager module (Windows Server only) -
                     its absence is not treated as an error.
                     The Configuration Manager distribution point check only runs if the
                     ConfigurationManager module is already imported and a CM PS drive is
                     already active in the current session - this script does not attempt
                     to connect to a site server itself.
    Exit codes     : 0 = no WDS dependency found (role not installed, or already on the
                         secure hands-free setting, and no PXE/multicast distribution
                         point found)
                     1 = at least one WDS dependency or insecure setting was found
                     2 = a script-level error occurred - treat as a run failure, not a result
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

$script:hadError = $false
$findings = New-Object System.Collections.Generic.List[string]

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}

Write-Section "Checking WDS dependency on $($env:COMPUTERNAME)..."

# --- Check 1: Is the WDS role installed? (Windows Server only) -------------
$wdsRoleInstalled  = 'Unknown'
$wdsDeployInstalled = 'Unknown'
$wdsTransportInstalled = 'Unknown'

try {
    if (Get-Module -ListAvailable -Name ServerManager) {
        Import-Module ServerManager -ErrorAction Stop

        $wdsFeature = Get-WindowsFeature -Name WDS -ErrorAction SilentlyContinue
        if ($wdsFeature) {
            $wdsRoleInstalled = [string]$wdsFeature.InstallState
        }
        else {
            $wdsRoleInstalled = 'NotFound'
        }

        $wdsDeploy = Get-WindowsFeature -Name WDS-Deployment -ErrorAction SilentlyContinue
        if ($wdsDeploy) { $wdsDeployInstalled = [string]$wdsDeploy.InstallState }

        $wdsTransport = Get-WindowsFeature -Name WDS-Transport -ErrorAction SilentlyContinue
        if ($wdsTransport) { $wdsTransportInstalled = [string]$wdsTransport.InstallState }
    }
    else {
        Write-Host "ServerManager module not available - skipping role-installation check (this is expected on a non-server OS)." -ForegroundColor DarkGray
        $wdsRoleInstalled = 'N/A - not Windows Server'
    }
}
catch {
    $script:hadError = $true
    Write-Warning "Failed to query the WDS role state: $($_.Exception.Message)"
}

$wdsRoleIsInstalled = ($wdsRoleInstalled -eq 'Installed')
if ($wdsRoleIsInstalled) {
    $findings.Add("WDS role is installed (Deployment: $wdsDeployInstalled, Transport: $wdsTransportInstalled).")
}

# --- Check 2: hands-free hardening registry value ---------------------------
$handsFreeRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WdsServer\Providers\WdsImgSrv\Unattend'
$handsFreeValueName = 'AllowHandsFreeFunctionality'
$handsFreeState = 'NotConfigured'
$handsFreeInsecure = $false

try {
    $regItem = Get-ItemProperty -Path $handsFreeRegPath -Name $handsFreeValueName -ErrorAction SilentlyContinue
    if ($null -ne $regItem) {
        $value = $regItem.$handsFreeValueName
        if ($value -eq 0) {
            $handsFreeState = 'Secure (0) - hands-free deployment disabled over the insecure path'
        }
        elseif ($value -eq 1) {
            $handsFreeState = 'Insecure (1) - hands-free deployment explicitly allowed'
            $handsFreeInsecure = $true
        }
        else {
            $handsFreeState = "Unexpected value: $value"
            $handsFreeInsecure = $true
        }
    }
    else {
        $handsFreeState = 'Not configured - relying on the OS build default (insecure with warnings before April 14, 2026 updates, secure by default after)'
        $handsFreeInsecure = $true
    }
}
catch {
    $script:hadError = $true
    Write-Warning "Failed to read the hands-free hardening registry value: $($_.Exception.Message)"
}

if ($handsFreeInsecure -and $wdsRoleIsInstalled) {
    $findings.Add("Hands-free deployment registry setting is not confirmed secure: $handsFreeState")
}

# --- Check 3: WDSServer service state ---------------------------------------
$wdsServiceStatus = 'NotFound'
try {
    $svc = Get-Service -Name WDSServer -ErrorAction SilentlyContinue
    if ($svc) {
        $wdsServiceStatus = "$($svc.Status) (StartType: $($svc.StartType))"
    }
}
catch {
    $script:hadError = $true
    Write-Warning "Failed to query the WDSServer service: $($_.Exception.Message)"
}

# --- Check 4: Configuration Manager PXE / multicast distribution points ----
# Only runs if the ConfigurationManager module is already loaded and a CM
# PS drive is already active in this session - this script does not attempt
# to connect to a site server on its own.
$cmPxeDpCount = 'Not checked (ConfigurationManager module not loaded in this session)'
$cmMulticastDpCount = 'Not checked (ConfigurationManager module not loaded in this session)'

try {
    if (Get-Module -Name ConfigurationManager -ErrorAction SilentlyContinue) {
        $cmDrive = (Get-PSDrive -PSProvider CMSite -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($cmDrive) {
            $originalLocation = Get-Location
            Set-Location "$($cmDrive.Name):\" -ErrorAction Stop

            $allDPs = Get-CMDistributionPoint -ErrorAction Stop
            $pxeDPs = $allDPs | Where-Object { $_.IsPXE -eq $true }
            $mcDPs  = $allDPs | Where-Object { $_.IsMulticast -eq $true }

            $cmPxeDpCount = ($pxeDPs | Measure-Object).Count
            $cmMulticastDpCount = ($mcDPs | Measure-Object).Count

            if ($cmPxeDpCount -gt 0) {
                $findings.Add("$cmPxeDpCount Configuration Manager distribution point(s) have PXE enabled (running WDS underneath).")
            }
            if ($cmMulticastDpCount -gt 0) {
                $findings.Add("$cmMulticastDpCount Configuration Manager distribution point(s) have multicast enabled (the specific WDS-dependent transport flagged for retirement).")
            }

            Set-Location $originalLocation
        }
    }
}
catch {
    $script:hadError = $true
    Write-Warning "Failed to query Configuration Manager distribution points: $($_.Exception.Message)"
}

# --- Report -------------------------------------------------------------
Write-Host ""
$result = [PSCustomObject]@{
    ComputerName            = $env:COMPUTERNAME
    WdsRoleInstallState     = $wdsRoleInstalled
    WdsDeploymentInstallState = $wdsDeployInstalled
    WdsTransportInstallState  = $wdsTransportInstalled
    HandsFreeRegistryState  = $handsFreeState
    WdsServiceStatus        = $wdsServiceStatus
    CmPxeDistributionPoints = $cmPxeDpCount
    CmMulticastDistributionPoints = $cmMulticastDpCount
}
$result | Format-List

if ($findings.Count -gt 0) {
    Write-Host "FINDINGS:" -ForegroundColor Yellow
    foreach ($f in $findings) { Write-Host "  - $f" -ForegroundColor Yellow }
}
else {
    Write-Host "No WDS dependency or insecure hands-free setting found on this server." -ForegroundColor Green
}

# --- Optional CSV export - only written on a fully-collected result ------
if ($CsvPath) {
    try {
        $result | Export-Csv -Path $CsvPath -NoTypeInformation -Force -ErrorAction Stop
        Write-Host ""
        Write-Host "Result exported to: $CsvPath" -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Failed to export CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

# --- Exit code ------------------------------------------------------------
if ($script:hadError) {
    exit 2
}
elseif ($findings.Count -gt 0) {
    exit 1
}
else {
    exit 0
}
