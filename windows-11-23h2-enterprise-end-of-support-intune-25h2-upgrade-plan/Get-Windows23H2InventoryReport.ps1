<#
.SYNOPSIS
    Reports how many Intune-managed Windows devices are still on Windows 11
    version 23H2, versus 24H2 or 25H2, ahead of 23H2 Enterprise/Education's
    end of servicing on November 11, 2026.

.DESCRIPTION
    On September 15, 2026, Microsoft posted the 60-day end-of-servicing
    notice for Windows 11, version 23H2 Enterprise and Education editions:
    the November 2026 security update (released November 10, 2026) is the
    last update those editions receive. The recommended replacement is
    Windows 11, version 25H2, supported until October 11, 2028.

    This script is READ-ONLY. It connects to Microsoft Graph and queries
    every Intune-managed Windows device's reported OS version, then buckets
    each device by build number:
      - 23H2  = OS version starting with 10.0.22631
      - 24H2  = OS version starting with 10.0.26100
      - 25H2  = OS version starting with 10.0.26200
      - Other = anything else (older builds, Windows 10, non-Windows-11)

    It only ever calls Get-MgDeviceManagementManagedDevice (an HTTP GET
    against Microsoft Graph). It never calls Update-MgDeviceManagement*,
    Remove-MgDeviceManagement*, or any other state-changing cmdlet, and it
    does not create, modify, or delete anything in Intune or Entra ID.

.PARAMETER TenantId
    Optional. The Entra tenant ID for app-only (certificate-based) auth. If
    supplied together with -ClientId and -CertificateThumbprint, the script
    authenticates non-interactively. If omitted, the script falls back to
    an interactive device-code sign-in.

.PARAMETER ClientId
    Optional. The application (client) ID of the Entra app registration used
    for app-only authentication. Requires DeviceManagementManagedDevices.Read.All
    as an application permission, admin-consented.

.PARAMETER CertificateThumbprint
    Optional. Thumbprint of the certificate (in the local machine or current
    user certificate store) associated with the app registration above, used
    for app-only authentication.

.PARAMETER UseDeviceCode
    Optional switch. Forces interactive device-code sign-in even if
    TenantId/ClientId/CertificateThumbprint are supplied. Useful for a quick
    one-off run from an admin's own workstation.

.PARAMETER CsvPath
    Optional. Path to a .csv file. If supplied, the full per-device list
    (DeviceName, OsVersion, OsBucket, UserPrincipalName) is exported there,
    in addition to the console summary. The file is only written after every
    device has been retrieved and classified - a run that errors partway
    through does not produce a partial CSV that could be mistaken for a
    complete inventory.

.EXAMPLE
    .\Get-Windows23H2InventoryReport.ps1 -UseDeviceCode

    Signs in interactively and prints a summary of how many managed Windows
    devices are on 23H2, 24H2, 25H2, or another version.

.EXAMPLE
    .\Get-Windows23H2InventoryReport.ps1 -TenantId "<tenant-guid>" -ClientId "<app-guid>" -CertificateThumbprint "<thumbprint>" -CsvPath "C:\Reports\23h2-inventory.csv"

    Signs in non-interactively using an app registration certificate and
    also exports the full per-device breakdown to CSV.

.NOTES
    Author        : Imran Awan
    Blog post      : https://endpointweekly.com/blog/windows-11-23h2-enterprise-end-of-support-intune-25h2-upgrade-plan.html
    Read-only      : Yes - only Get-MgDeviceManagementManagedDevice is called. No Update-* or Remove-* cmdlets are used.
    Requires       : Microsoft.Graph.DeviceManagement module; an account or app registration with
                     DeviceManagementManagedDevices.Read.All (delegated or application) permission.
    Exit codes     : 0 = no devices found still on 23H2
                     1 = at least one managed device is still on 23H2
                     2 = a script-level error occurred - treat as a run failure, not a result
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory = $false)]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath
)

$script:hadError = $false

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}

function Get-OsBucket {
    param([string]$OsVersion)
    if ([string]::IsNullOrWhiteSpace($OsVersion)) { return 'Unknown' }
    if ($OsVersion -like '10.0.22631*') { return '23H2' }
    if ($OsVersion -like '10.0.26100*') { return '24H2' }
    if ($OsVersion -like '10.0.26200*') { return '25H2' }
    return 'Other'
}

# --- Confirm the required module is present ---------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement)) {
    Write-Error "Required module 'Microsoft.Graph.DeviceManagement' is not installed. Install it with: Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser"
    exit 2
}

# --- Connect to Microsoft Graph (read-only scope only) ----------------------
try {
    $requiredScope = 'DeviceManagementManagedDevices.Read.All'

    if (-not $UseDeviceCode -and $TenantId -and $ClientId -and $CertificateThumbprint) {
        Write-Host "Connecting to Microsoft Graph using app-only certificate authentication..." -ForegroundColor DarkGray
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Host "Connecting to Microsoft Graph using interactive device-code sign-in..." -ForegroundColor DarkGray
        Connect-MgGraph -Scopes $requiredScope -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
    }
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 2
}

Write-Section "Retrieving Intune-managed Windows devices from Microsoft Graph..."

# --- Retrieve every managed Windows device (read-only GET, paged) ----------
$devices = $null
try {
    $devices = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'Windows'" -All -ErrorAction Stop
}
catch {
    $script:hadError = $true
    Write-Error "Failed to retrieve managed devices: $($_.Exception.Message)"
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    exit 2
}

if (-not $devices -or $devices.Count -eq 0) {
    Write-Warning "No Windows devices were returned. Nothing to report."
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    exit 2
}

# --- Classify each device by OS bucket --------------------------------------
$results = foreach ($d in $devices) {
    [PSCustomObject]@{
        DeviceName        = $d.DeviceName
        OsVersion         = $d.OsVersion
        OsBucket          = Get-OsBucket -OsVersion $d.OsVersion
        UserPrincipalName = $d.UserPrincipalName
    }
}

$summary = $results | Group-Object OsBucket | Sort-Object Name
$stillOn23H2 = $results | Where-Object { $_.OsBucket -eq '23H2' }

# --- Report -------------------------------------------------------------
Write-Host ""
Write-Host "SUMMARY - $($results.Count) managed Windows device(s) checked:" -ForegroundColor Cyan
$summary | ForEach-Object {
    $color = if ($_.Name -eq '23H2') { 'Yellow' } else { 'Green' }
    Write-Host ("  {0,-10} {1,6}" -f $_.Name, $_.Count) -ForegroundColor $color
}

if ($stillOn23H2.Count -gt 0) {
    Write-Host ""
    Write-Host "$($stillOn23H2.Count) device(s) are still on 23H2 and will stop receiving security updates on November 11, 2026:" -ForegroundColor Yellow
    $stillOn23H2 | Select-Object DeviceName, OsVersion, UserPrincipalName | Format-Table -AutoSize
}
else {
    Write-Host ""
    Write-Host "No managed devices remain on 23H2." -ForegroundColor Green
}

# --- Optional CSV export - only written on a fully-collected result set -----
if ($CsvPath) {
    try {
        $results | Export-Csv -Path $CsvPath -NoTypeInformation -Force -ErrorAction Stop
        Write-Host ""
        Write-Host "Full device list exported to: $CsvPath" -ForegroundColor DarkGray
    }
    catch {
        Write-Warning "Failed to export CSV to '$CsvPath': $($_.Exception.Message)"
        $script:hadError = $true
    }
}

Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

# --- Exit code ---------------------------------------------------------------
if ($script:hadError) {
    exit 2
}
elseif ($stillOn23H2.Count -gt 0) {
    exit 1
}
else {
    exit 0
}
