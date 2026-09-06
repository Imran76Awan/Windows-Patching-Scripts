<#
.SYNOPSIS
    Audits every Windows Autopatch quality update policy in a tenant for its approval
    method and deferral period, per update category, including Quick Machine Recovery (QMR).

.DESCRIPTION
    Windows Autopatch quality update policies now govern Windows OS quality updates,
    supported .NET Framework updates, and Quick Machine Recovery updates in a single
    policy object. Microsoft documents that the approval method chosen for any update
    type in a quality update policy CANNOT be edited after creation - if it is wrong,
    a brand new policy must be created instead. This script is a read-only audit that
    helps you catch that mistake before it becomes permanent, or simply confirm your
    current approval posture across every policy in the tenant.

    The script queries the Microsoft Graph beta resource windowsQualityUpdatePolicy
    (GET /deviceManagement/windowsQualityUpdatePolicies) using Invoke-MgGraphRequest
    with GET only. It never creates, updates, or deletes anything. For each policy it
    reports:
      - displayName and hotpatchEnabled
      - every approval setting entry: cadence (monthly / outOfBand), category
        (all / security / nonSecurity / quickMachineRecovery), approval method
        (manual / automatic), and deferral in days

    It also flags two specific situations worth a second look, without ever
    fabricating a "clean" result if a query genuinely fails:
      - A policy where Quick Machine Recovery is set to automatic with a 0-day
        deferral while monthly security updates on the same policy are still manual
        (QMR deploying faster than your own security patches is unusual and worth
        reviewing).
      - A policy with zero approval settings configured (may indicate an incomplete
        or placeholder policy).

    Requires the Microsoft.Graph.Authentication module. Uses app-only certificate
    authentication by default (-TenantId, -ClientId, -CertificateThumbprint), with an
    interactive device-code fallback (-UseDeviceCode) for ad hoc runs. The only Graph
    permission required is DeviceManagementConfiguration.Read.All (least privilege -
    read only, no write scope is ever requested).

.PARAMETER TenantId
    Entra ID (Azure AD) tenant ID or verified domain name. Required unless -UseDeviceCode
    is specified and you intend to select the tenant interactively.

.PARAMETER ClientId
    Application (client) ID of the app registration used for certificate authentication.
    Required for app-only auth; not required with -UseDeviceCode.

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate (installed in the local certificate store) associated
    with the app registration, used for app-only authentication. Required for app-only
    auth; not required with -UseDeviceCode.

.PARAMETER UseDeviceCode
    Switch. Falls back to interactive device-code sign-in (Connect-MgGraph -UseDeviceCode)
    instead of certificate-based app-only authentication. Useful for a one-off manual
    audit run without provisioning an app registration.

.PARAMETER CsvPath
    Optional path to a CSV file. When specified, writes one row per policy per approval
    setting (so a policy with four categories configured produces four rows) for easy
    tracking of approval-method configuration over time.

.NOTES
    Author:      Imran Awan
    Blog post:   https://endpointweekly.com/blog/windows-autopatch-quality-net-qmr-update-governance.html
    Repo:        https://github.com/Imran76Awan/Windows-Patching-Scripts
    Read-only:   Yes. Calls Graph with GET only. Never modifies any policy.
    Graph scope: DeviceManagementConfiguration.Read.All
    Exit codes:  0 = ran successfully, no policy flagged for review
                 1 = ran successfully, at least one policy flagged for review
                 2 = script error (auth failure, Graph query failure, or unexpected exception)

.EXAMPLE
    .\Get-AutopatchQualityUpdatePolicyAudit.ps1 -TenantId "contoso.onmicrosoft.com" -ClientId "11111111-1111-1111-1111-111111111111" -CertificateThumbprint "AABBCCDDEEFF00112233445566778899AABBCCDD"

    Runs the audit using app-only certificate authentication and prints the results to
    the console.

.EXAMPLE
    .\Get-AutopatchQualityUpdatePolicyAudit.ps1 -UseDeviceCode -CsvPath "C:\Reports\autopatch-quality-policy-audit.csv"

    Runs the audit using interactive device-code sign-in and also exports one row per
    policy per approval setting to a CSV file.
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

$ErrorActionPreference = 'Stop'
$script:hadError = $false
$script:flaggedCount = 0
$script:auditRows = New-Object System.Collections.Generic.List[object]

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host $Text -ForegroundColor Cyan
}

function Connect-ToGraph {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "The Microsoft.Graph.Authentication module is not installed. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    if ($UseDeviceCode) {
        Write-Section "Connecting to Microsoft Graph interactively (device code)..."
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -UseDeviceCode -ErrorAction Stop | Out-Null
    }
    else {
        if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
            throw "App-only authentication requires -TenantId, -ClientId, and -CertificateThumbprint. Use -UseDeviceCode instead for interactive sign-in."
        }
        Write-Section "Connecting to Microsoft Graph as an application..."
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop | Out-Null
    }

    Write-Host "Connected." -ForegroundColor Green
}

function Get-AutopatchQualityUpdatePolicies {
    $uri = "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdatePolicies"
    $allPolicies = New-Object System.Collections.Generic.List[object]
    $nextLink = $uri

    while ($nextLink) {
        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
        }
        catch {
            $script:hadError = $true
            throw "Graph query failed against '$nextLink'. $($_.Exception.Message)"
        }

        if ($response.value) {
            foreach ($item in $response.value) {
                $allPolicies.Add($item)
            }
        }

        $nextLink = $response.'@odata.nextLink'
    }

    return $allPolicies
}

function Format-ApprovalSetting {
    param($setting)

    $method = $setting.approvalMethodType
    if ($method -eq 'automatic') {
        $deferDays = $setting.deferredDeploymentInDay
        if ($null -eq $deferDays) { $deferDays = 0 }
        return "automatic, defer $deferDays day(s)"
    }
    else {
        return "manual"
    }
}

try {
    Connect-ToGraph

    Write-Section "Querying /deviceManagement/windowsQualityUpdatePolicies"
    $policies = Get-AutopatchQualityUpdatePolicies

    if ($policies.Count -eq 0) {
        Write-Host ""
        Write-Host "No Windows quality update policies were found in this tenant." -ForegroundColor Yellow
        Write-Host "This is not necessarily an error - it may mean Windows Autopatch quality" -ForegroundColor Yellow
        Write-Host "update policies have not been configured yet." -ForegroundColor Yellow
    }
    else {
        Write-Host ""
        Write-Host "Found $($policies.Count) Windows quality update policy(ies)." -ForegroundColor Green
    }

    foreach ($policy in $policies) {
        $flaggedThisPolicy = $false
        $reasons = New-Object System.Collections.Generic.List[string]

        Write-Host ""
        Write-Host "Policy: $($policy.displayName)" -ForegroundColor White
        Write-Host "  Hotpatch enabled       : $($policy.hotpatchEnabled)"

        $settings = $policy.approvalSettings
        if (-not $settings -or $settings.Count -eq 0) {
            Write-Host "  (no approval settings configured on this policy)" -ForegroundColor Yellow
            $flaggedThisPolicy = $true
            $reasons.Add("no approval settings configured")
        }

        $qmrSetting = $null
        $securityMonthlySetting = $null

        foreach ($setting in $settings) {
            $label = "$($setting.windowsQualityUpdateCategory) / $($setting.windowsQualityUpdateCadence)"
            $formatted = Format-ApprovalSetting -setting $setting
            Write-Host "  $label : $formatted"

            $script:auditRows.Add([pscustomobject]@{
                PolicyDisplayName   = $policy.displayName
                PolicyId            = $policy.id
                HotpatchEnabled     = $policy.hotpatchEnabled
                UpdateCategory      = $setting.windowsQualityUpdateCategory
                UpdateCadence       = $setting.windowsQualityUpdateCadence
                ApprovalMethod      = $setting.approvalMethodType
                DeferredDeploymentInDay = $setting.deferredDeploymentInDay
                LastModifiedDateTime = $policy.lastModifiedDateTime
            })

            if ($setting.windowsQualityUpdateCategory -eq 'quickMachineRecovery') {
                $qmrSetting = $setting
            }
            if ($setting.windowsQualityUpdateCategory -eq 'security' -and $setting.windowsQualityUpdateCadence -eq 'monthly') {
                $securityMonthlySetting = $setting
            }
        }

        if ($qmrSetting -and $securityMonthlySetting) {
            $qmrAuto = ($qmrSetting.approvalMethodType -eq 'automatic')
            $qmrZeroDefer = ($qmrSetting.deferredDeploymentInDay -eq 0)
            $securityManual = ($securityMonthlySetting.approvalMethodType -eq 'manual')

            if ($qmrAuto -and $qmrZeroDefer -and $securityManual) {
                $flaggedThisPolicy = $true
                $reasons.Add("Quick Machine Recovery is automatic with 0-day deferral while monthly security updates are still manual on the same policy")
            }
        }

        if ($flaggedThisPolicy) {
            $script:flaggedCount++
            Write-Host ""
            Write-Host "WARNING: Policy '$($policy.displayName)' flagged for review:" -ForegroundColor Yellow
            foreach ($reason in $reasons) {
                Write-Host "  - $reason" -ForegroundColor Yellow
            }
            Write-Host "  Remember: the approval method itself cannot be edited on an existing policy." -ForegroundColor Yellow
            Write-Host "  If this configuration was not intentional, plan a replacement policy." -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "Summary: $($policies.Count) policies audited, $script:flaggedCount flagged for review." -ForegroundColor Cyan

    if ($CsvPath) {
        $script:auditRows | Export-Csv -Path $CsvPath -NoTypeInformation -Force
        Write-Host "CSV written to: $CsvPath" -ForegroundColor Green
    }

    if ($script:flaggedCount -gt 0) {
        exit 1
    }
    else {
        exit 0
    }
}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 2
}
