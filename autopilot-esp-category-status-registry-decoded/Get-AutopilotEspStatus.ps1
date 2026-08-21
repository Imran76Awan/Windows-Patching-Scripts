<#
.SYNOPSIS
    Reads the Enrollment Status Page (ESP) progress that Windows actually
    records on disk, broken down by phase and subcategory, so you can tell
    exactly which step an ESP is stuck on.

.DESCRIPTION
    Read-only. The ESP writes its own progress into three REG_SZ values under
    HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings, each holding a
    JSON blob:

      DevicePreparationCategory.Status   - TPM attestation, Entra join, MDM enrollment
      DeviceSetupCategory.Status         - security policies, certificates, network, apps
      AccountSetupCategory.Status        - the same set again, in user context

    Each blob contains a categoryState plus one entry per subcategory, with its
    own state and the exact status text the user sees on screen. That means you
    can determine which specific subcategory hung, after the fact, without
    trawling MDM diagnostic logs.

    Makes no changes. Exits 1 if any category or subcategory is in a failed
    state, 0 otherwise, so it can be used as an Intune Proactive Remediation
    detection script.

.NOTES
    Blog post: https://endpointweekly.com/blog/autopilot-esp-category-status-registry-decoded.html
    Run elevated - the Provisioning registry hive requires administrator rights.

.EXAMPLE
    .\Get-AutopilotEspStatus.ps1
#>

[CmdletBinding()]
param()

$key = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'

Write-Output "Autopilot / ESP Category Status"
Write-Output ("-" * 62)

if (-not (Test-Path $key)) {
    Write-Output "AutopilotSettings key not present - this device was very likely not"
    Write-Output "provisioned by Autopilot, or predates the refactored ESP."
    exit 2
}

$settings = Get-ItemProperty $key
$anyFailed = $false

$categories = [ordered]@{
    'DevicePreparationCategory.Status' = 'Device Preparation  (TPM attestation, Entra join, MDM enrollment)'
    'DeviceSetupCategory.Status'       = 'Device Setup        (security policies, certs, network, apps)'
    'AccountSetupCategory.Status'      = 'Account Setup       (same set again, in user context)'
}

foreach ($valueName in $categories.Keys) {
    Write-Output ""
    Write-Output $categories[$valueName]
    $raw = $settings.$valueName
    if (-not $raw) {
        Write-Output "  (not recorded)"
        continue
    }
    try {
        $obj = $raw | ConvertFrom-Json
    } catch {
        Write-Output "  (present but not parseable as JSON)"
        continue
    }

    $catState = $obj.categoryState
    Write-Output ("  categoryState : {0}" -f $catState)
    if ($obj.categoryStatusText) {
        Write-Output ("  statusText    : {0}" -f $obj.categoryStatusText)
    }
    if ($catState -match 'fail|error') { $anyFailed = $true }

    # Every property that is itself an object with a subcategoryState is a subcategory.
    foreach ($prop in $obj.PSObject.Properties) {
        if ($prop.Value -is [System.Management.Automation.PSCustomObject] -and
            $null -ne $prop.Value.subcategoryState) {
            $state = $prop.Value.subcategoryState
            $text  = $prop.Value.subcategoryStatusText
            if ($state -match 'fail|error') { $anyFailed = $true }
            $shortName = $prop.Name -replace '^(DevicePreparation|DeviceSetup|AccountSetup)\.', ''
            if ($text -and $text -ne $state) {
                Write-Output ("    {0,-34} {1,-12} {2}" -f $shortName, $state, $text)
            } else {
                Write-Output ("    {0,-34} {1}" -f $shortName, $state)
            }
        }
    }
}

Write-Output ""
Write-Output "How to read this:"
Write-Output "  A category stuck at 'inProgress' with one subcategory also 'inProgress' is"
Write-Output "  your hang point - that subcategory name tells you which phase to chase."
Write-Output "  'notStarted' on Account Setup is normal on a device where the ESP's user"
Write-Output "  phase was skipped or has not run for this user yet."

if ($anyFailed) {
    Write-Output ""
    Write-Output "Result: FAILURE STATE DETECTED in at least one category/subcategory."
    exit 1
}
exit 0
