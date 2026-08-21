<#
.SYNOPSIS
    Audits every Intune-managed Windows device for its Windows servicing channel,
    flagging any device running Windows Enterprise LTSC or Windows IoT Enterprise LTSC.

.DESCRIPTION
    Queries Microsoft Graph for all Intune-managed Windows devices and inspects the
    OS description/version metadata Intune already collects. Any device whose edition
    string contains "LTSC" is flagged and classified into one of two lifecycle buckets:

      - Windows Enterprise LTSC        -> 5-year Fixed Lifecycle Policy
      - Windows IoT Enterprise LTSC    -> 10-year lifecycle

    This does not tell you definitively which SKU was licensed for a device - it tells
    you what the device is currently reporting, which is the starting point for
    confirming whether a long-life special-purpose device (kiosk, POS, medical cart,
    industrial HMI) is actually running the SKU its intended service life requires.

    This script is entirely READ-ONLY. It makes no configuration changes and does not
    write anything back to Intune, Entra ID, or the devices themselves.

.PARAMETER ExportCsv
    If specified, exports the full list of LTSC devices found to a timestamped CSV
    file in the current directory.

.PARAMETER TenantId
    Tenant ID for app-only certificate authentication. Omit for interactive/device-code sign-in.

.PARAMETER ClientId
    App registration client ID for app-only certificate authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only authentication. Requires the app registration
    to have DeviceManagementManagedDevices.Read.All granted as an APPLICATION permission
    (not delegated), with admin consent, and the certificate's private key installed in
    the local certificate store.

.NOTES
    Requires the Microsoft.Graph.DeviceManagement PowerShell module.
    Permission required (read-only): DeviceManagementManagedDevices.Read.All

    Blog post: https://endpointweekly.com/blog/windows-11-ltsc-2024-lifecycle-explained.html
    Author:    Imran Awan
    Version:   1.0

    This script has NOT been validated against a live tenant. Please test it against
    your own environment (or a non-production tenant) before relying on its output.

.EXAMPLE
    .\Get-FleetServicingChannelReport.ps1
    Runs an interactive audit, prompting for device-code sign-in.

.EXAMPLE
    .\Get-FleetServicingChannelReport.ps1 -ExportCsv
    Runs the audit and exports the full list of LTSC devices found to a CSV file.

.EXAMPLE
    .\Get-FleetServicingChannelReport.ps1 -TenantId "xxxx" -ClientId "xxxx" -CertificateThumbprint "xxxx"
    Runs the audit using app-only certificate authentication, skipping interactive sign-in.
#>

[CmdletBinding()]
param (
    [switch]$ExportCsv,

    [string]$TenantId,
    [string]$ClientId,
    [string]$CertificateThumbprint
)

#region Prerequisites
$requiredModule = 'Microsoft.Graph.DeviceManagement'
if (-not (Get-Module -ListAvailable -Name $requiredModule)) {
    Write-Host "Installing $requiredModule module..." -ForegroundColor Yellow
    Install-Module -Name $requiredModule -Scope CurrentUser -Force
}
Import-Module $requiredModule -ErrorAction Stop

$useAppOnlyAuth = $TenantId -and $ClientId -and $CertificateThumbprint

try {
    if ($useAppOnlyAuth) {
        Write-Host "Connecting to Microsoft Graph using app-only certificate auth..." -ForegroundColor Cyan
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
    } else {
        Write-Host "Connecting to Microsoft Graph (read-only scope)..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -UseDeviceCode -ErrorAction Stop
    }
} catch {
    Write-Host "`nFailed to connect to Microsoft Graph: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Aborting - a '0 found' report after a failed connection would be misleading, not a real result." -ForegroundColor Red
    exit 1
}
#endregion

Write-Host "Fetching all Intune-managed Windows devices..." -ForegroundColor Cyan
try {
    $devices = Get-MgDeviceManagementManagedDevice -All -Filter "operatingSystem eq 'Windows'" -ErrorAction Stop
} catch {
    Write-Host "`nFailed to fetch managed devices: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Aborting - a '0 found' report after a failed query would be misleading, not a real result." -ForegroundColor Red
    exit 1
}
Write-Host "  Found $($devices.Count) managed Windows devices" -ForegroundColor Gray

# OSDescription typically carries the edition string (e.g. "Windows 11 IoT Enterprise LTSC").
# Some tenants only populate this on OSVersion instead, so check both fields.
$ltscDevices = $devices | Where-Object {
    ($_.OSDescription -and $_.OSDescription -match 'LTSC') -or
    ($_.OSVersion -and $_.OSVersion -match 'LTSC')
}

Write-Host "  Found $($ltscDevices.Count) device(s) reporting an LTSC servicing channel`n" -ForegroundColor Gray

$results = @()

foreach ($d in $ltscDevices) {
    $osLabel = if ($d.OSDescription) { $d.OSDescription } else { $d.OSVersion }
    $isIoT   = $osLabel -match 'IoT'
    $lifecycleYears = if ($isIoT) { 10 } else { 5 }
    $severity = if ($isIoT) { 'AMBER' } else { 'RED' }

    $results += [PSCustomObject]@{
        DeviceName       = $d.DeviceName
        SerialNumber     = $d.SerialNumber
        OSDescription    = $osLabel
        IsIoTEnterprise  = $isIoT
        LifecycleYears   = $lifecycleYears
        EnrolledDateTime = $d.EnrolledDateTime
        LastSyncDateTime = $d.LastSyncDateTime
        ComplianceState  = $d.ComplianceState
        Severity         = $severity
    }
}

#region Report
Write-Host "============================================================" -ForegroundColor White
Write-Host " LTSC DEVICES FOUND ($($results.Count))" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

foreach ($r in ($results | Sort-Object Severity, DeviceName)) {
    $colour = if ($r.Severity -eq 'RED') { 'Red' } else { 'Yellow' }
    $label  = if ($r.IsIoTEnterprise) { 'IoT Enterprise LTSC' } else { 'Enterprise LTSC' }
    Write-Host "[$($r.Severity)] $($r.DeviceName)  $label  Lifecycle: $($r.LifecycleYears)yr" -ForegroundColor $colour
}

if ($results.Count -eq 0) {
    Write-Host "None found - no devices in this fleet are reporting an LTSC servicing channel." -ForegroundColor Green
}

$redCount   = ($results | Where-Object { $_.Severity -eq 'RED' }).Count
$amberCount = ($results | Where-Object { $_.Severity -eq 'AMBER' }).Count

Write-Host "`n--- Summary ---" -ForegroundColor White
Write-Host "Total managed Windows devices scanned : $($devices.Count)" -ForegroundColor Gray
Write-Host "LTSC devices found                     : $($results.Count)" -ForegroundColor Gray
Write-Host "RED   (Enterprise LTSC - 5yr lifecycle) : $redCount" -ForegroundColor $(if ($redCount -gt 0) { 'Red' } else { 'Green' })
Write-Host "AMBER (IoT Enterprise LTSC - 10yr)      : $amberCount" -ForegroundColor $(if ($amberCount -gt 0) { 'Yellow' } else { 'Green' })
#endregion

if ($ExportCsv -and $results.Count -gt 0) {
    $outPath = Join-Path $PSScriptRoot "FleetServicingChannel-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
    $results | Export-Csv -Path $outPath -NoTypeInformation
    Write-Host "`nReport exported to: $outPath" -ForegroundColor Green
}

Write-Host "`nAudit complete." -ForegroundColor Cyan
