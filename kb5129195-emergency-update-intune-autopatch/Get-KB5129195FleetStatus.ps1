<#
.SYNOPSIS
    Reports which managed Windows 11 devices have or have not installed KB5129195.
    Uses Microsoft Graph to query Intune device OS version data.

.DESCRIPTION
    Connects to Microsoft Graph via app-only certificate auth, queries all managed
    Windows 11 devices, and compares the reported OS version against the KB5129195
    minimum UBR (9457 for both 24H2/26100 and 25H2/26200). Exports a CSV with
    per-device patch status. Read-only - makes no changes.

    Reports:
    - Installed: build UBR >= 9457
    - Not installed: build UBR < 9457
    - Unknown: OS version not parsable or device not reporting

.NOTES
    Blog post: https://endpointweekly.com/blog/kb5129195-emergency-update-intune-autopatch-rds-fix.html
    Repo: https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/kb5129195-emergency-update-intune-autopatch
    Author: Imran Awan
    Version: 1.0
    Requires: Microsoft.Graph.Authentication module or app-only cert auth

.PARAMETER TenantId
    Entra tenant ID.

.PARAMETER ClientId
    App registration client ID with DeviceManagementManagedDevices.Read.All permission.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth.

.PARAMETER ExportPath
    Path for CSV output. Defaults to C:\ProgramData\EndpointWeekly\KB5129195-FleetStatus.csv

.PARAMETER UseDeviceCode
    Switch. Use device code flow instead of certificate auth (interactive, for testing).

.EXAMPLE
    .\Get-KB5129195FleetStatus.ps1 -TenantId "..." -ClientId "..." -CertificateThumbprint "..."
    Runs with app-only cert auth and exports CSV.

.EXAMPLE
    .\Get-KB5129195FleetStatus.ps1 -UseDeviceCode
    Runs with interactive device code flow (for manual testing).
#>

[CmdletBinding(DefaultParameterSetName = 'Certificate')]
param(
    [Parameter(ParameterSetName = 'Certificate', Mandatory)]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Certificate', Mandatory)]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Certificate', Mandatory)]
    [string]$CertificateThumbprint,

    [Parameter(ParameterSetName = 'DeviceCode')]
    [switch]$UseDeviceCode,

    [string]$ExportPath = "$env:ProgramData\EndpointWeekly\KB5129195-FleetStatus.csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:hadError = $false

$RequiredUBR     = 9457
$RequiredBuilds  = @(26100, 26200)  # 24H2 and 25H2

# Connect to Graph
try {
    if ($UseDeviceCode) {
        Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -UseDeviceAuthentication
    } else {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint
    }
    Write-Host "Connected to Microsoft Graph." -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

try {
    Write-Host "Querying managed Windows 11 devices..." -ForegroundColor Cyan

    $Devices = @()
    $Uri     = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=deviceName,osVersion,lastSyncDateTime,complianceState,id"

    do {
        $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri
        $Devices += $Response.value
        $Uri      = $Response.'@odata.nextLink'
    } while ($Uri)

    Write-Host "Total Windows managed devices: $($Devices.Count)" -ForegroundColor Cyan

    $Results = foreach ($Device in $Devices) {
        $OsVersion = $Device.osVersion  # e.g. "10.0.26100.9457"
        $Status    = 'Unknown'
        $UBR       = $null
        $Build     = $null

        if ($OsVersion -match '10\.0\.(\d+)\.(\d+)') {
            $Build = [int]$Matches[1]
            $UBR   = [int]$Matches[2]

            if ($Build -in $RequiredBuilds) {
                $Status = if ($UBR -ge $RequiredUBR) { 'Installed' } else { 'Not installed' }
            } else {
                $Status = 'Not applicable (not 24H2/25H2)'
            }
        }

        [PSCustomObject]@{
            DeviceName     = $Device.deviceName
            OsVersion      = $OsVersion
            Build          = $Build
            UBR            = $UBR
            KB5129195      = $Status
            ComplianceState = $Device.complianceState
            LastSync       = $Device.lastSyncDateTime
        }
    }

    # Summary
    $Installed    = ($Results | Where-Object { $_.KB5129195 -eq 'Installed' }).Count
    $NotInstalled = ($Results | Where-Object { $_.KB5129195 -eq 'Not installed' }).Count
    $NA           = ($Results | Where-Object { $_.KB5129195 -eq 'Not applicable (not 24H2/25H2)' }).Count
    $Unknown      = ($Results | Where-Object { $_.KB5129195 -eq 'Unknown' }).Count

    Write-Host "`n--- KB5129195 Fleet Status ---" -ForegroundColor Cyan
    Write-Host "  Installed:      $Installed" -ForegroundColor Green
    Write-Host "  Not installed:  $NotInstalled" -ForegroundColor Yellow
    Write-Host "  Not applicable: $NA" -ForegroundColor Gray
    Write-Host "  Unknown:        $Unknown" -ForegroundColor DarkYellow

    # Export
    $Dir = Split-Path $ExportPath
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    $Results | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nCSV exported: $ExportPath" -ForegroundColor Cyan

} catch {
    $script:hadError = $true
    Write-Error "Query failed: $_"
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}

if ($script:hadError) { exit 1 }
exit 0
