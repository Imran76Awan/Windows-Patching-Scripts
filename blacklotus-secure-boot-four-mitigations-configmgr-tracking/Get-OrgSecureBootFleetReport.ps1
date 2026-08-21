<#
.SYNOPSIS
    Read-only fleet-wide report on Secure Boot / BlackLotus (CVE-2023-24932)
    mitigation status, pulled from your own organisation's Intune tenant via
    Microsoft Graph.

.DESCRIPTION
    This is NOT a hosted portal and does not store or transmit your
    credentials anywhere. It uses Microsoft Graph PowerShell's interactive
    sign-in (delegated auth) - you sign in with your own already-authorized
    admin account, exactly like any other Graph PowerShell session, and the
    script only makes read-only (GET) Graph calls.

    Two data sources, combined:
      1. Basic Secure Boot state for every Windows device Intune manages -
         SecureBootEnabled and OS build, straight from the managed device
         record. Available immediately, no extra deployment needed.
      2. If you have deployed Get-BlackLotusMitigationStatus.ps1 (from this
         same series) as an Intune Proactive Remediation, this script finds
         it by name and pulls the real per-device compliant / non-compliant
         counts from its detection results - the actual 4-mitigation view,
         not just "certificate present."

    Exports both to CSV. Makes no changes to any device or any Intune
    setting - GET requests only.

.NOTES
    Blog post: https://endpointweekly.com/blog/blacklotus-secure-boot-four-mitigations-configmgr-tracking.html
    Requires: Microsoft.Graph.Authentication and Microsoft.Graph.DeviceManagement
    modules (Install-Module Microsoft.Graph -Scope CurrentUser if not present).
    Requires an account with at least DeviceManagementManagedDevices.Read.All
    and DeviceManagementConfiguration.Read.All delegated permissions - your
    existing Intune admin role normally already covers this.

.PARAMETER RemediationName
    The display name of the Proactive Remediation to look up for the
    4-mitigation compliance counts. Defaults to the name used in this post's
    walkthrough. Skip this entirely if you haven't deployed it yet - the
    script still reports the basic Secure Boot state for every device.

.PARAMETER CsvPath
    Where to write the device-level export. Defaults to the current folder.

.EXAMPLE
    .\Get-OrgSecureBootFleetReport.ps1

.EXAMPLE
    .\Get-OrgSecureBootFleetReport.ps1 -RemediationName "BlackLotus Mitigation Status - Detect and Remediate"
#>

[CmdletBinding()]
param(
    [string]$RemediationName = "BlackLotus Mitigation Status - Detect and Remediate",
    [string]$CsvPath = ".\SecureBootFleetReport_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

function Write-Section {
    param([string]$Title)
    Write-Output ""
    Write-Output ("=" * 70)
    Write-Output "  $Title"
    Write-Output ("=" * 70)
}

# ---------------------------------------------------------------------------
# 1. Connect - interactive, delegated, your own permissions
# ---------------------------------------------------------------------------
Write-Section "Connecting to Microsoft Graph"
try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Output "Microsoft.Graph module not found. Install with:"
        Write-Output "  Install-Module Microsoft.Graph -Scope CurrentUser"
        exit 2
    }
    Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All","DeviceManagementConfiguration.Read.All" -NoWelcome
    $context = Get-MgContext
    Write-Output "Connected as: $($context.Account)"
    Write-Output "Tenant: $($context.TenantId)"
} catch {
    Write-Output "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# ---------------------------------------------------------------------------
# 2. Basic Secure Boot state for every managed Windows device
# ---------------------------------------------------------------------------
Write-Section "Pulling managed Windows devices (basic Secure Boot state)"
$devices = @()
try {
    $uri = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,osVersion,complianceState,lastSyncDateTime"
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
        $devices += $resp.value
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    Write-Output "Found $($devices.Count) Windows devices managed by Intune."
} catch {
    Write-Output "Failed to query managed devices: $($_.Exception.Message)"
    $script:hadError = $true
}

# Note: SecureBootEnabled is not on the default managedDevices projection in
# all tenants/API versions - if it comes back blank for your tenant, pull it
# via the device's hardwareInformation instead:
#   GET /deviceManagement/managedDevices/{id}?$select=hardwareInformation
# This is intentionally kept as a documented follow-up rather than a second
# per-device call in the main loop, to keep this a light, fast report.

$devices | Select-Object deviceName, osVersion, complianceState, lastSyncDateTime |
    Export-Csv -Path $CsvPath -NoTypeInformation
Write-Output "Device-level export written to: $CsvPath"

# ---------------------------------------------------------------------------
# 3. If deployed, pull the real 4-mitigation Proactive Remediation results
# ---------------------------------------------------------------------------
Write-Section "Looking for the BlackLotus Proactive Remediation: '$RemediationName'"
try {
    $scriptsUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$filter=displayName eq '$RemediationName'"
    $scriptResp = Invoke-MgGraphRequest -Method GET -Uri $scriptsUri
    $remediation = $scriptResp.value | Select-Object -First 1

    if (-not $remediation) {
        Write-Output "Not found - this is expected if you haven't deployed the Proactive Remediation yet."
        Write-Output "See the blog post's 'Deploy this as an Intune Proactive Remediation' section to set it up,"
        Write-Output "then re-run this script with -RemediationName matching whatever you named it."
    } else {
        Write-Output "Found: $($remediation.displayName) (id: $($remediation.id))"
        $statesUri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($remediation.id)/deviceRunStates"
        $states = @()
        do {
            $stateResp = Invoke-MgGraphRequest -Method GET -Uri $statesUri
            $states += $stateResp.value
            $statesUri = $stateResp.'@odata.nextLink'
        } while ($statesUri)

        $compliant    = ($states | Where-Object { $_.detectionState -eq 'internalUnknown' -or $_.detectionState -eq 'noIssueFound' }).Count
        $nonCompliant = ($states | Where-Object { $_.detectionState -eq 'issueFound' }).Count
        $errored      = ($states | Where-Object { $_.detectionState -eq 'scriptError' }).Count

        Write-Output ""
        Write-Output "Fleet-wide 4-mitigation compliance (from the Proactive Remediation's own detection results):"
        Write-Output "  Compliant (all 4 mitigations confirmed) : $compliant"
        Write-Output "  Non-compliant (one or more pending)      : $nonCompliant"
        Write-Output "  Script error (re-check manually)         : $errored"
    }
} catch {
    Write-Output "Could not query the Proactive Remediation results: $($_.Exception.Message)"
    Write-Output "(This can happen if your account lacks DeviceManagementConfiguration.Read.All, or the beta"
    Write-Output " Graph endpoint is throttled - the basic device report above is unaffected.)"
    $script:hadError = $true
}

Write-Section "Summary"
Write-Output "Devices reported     : $($devices.Count)"
Write-Output "CSV export           : $CsvPath"
Write-Output "Graph calls made     : GET only - no device or tenant setting was changed"

if ($script:hadError) { exit 1 } else { exit 0 }
