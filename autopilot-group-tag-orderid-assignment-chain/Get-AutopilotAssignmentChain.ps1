<#
.SYNOPSIS
    Reports how this device's Autopilot profile was assigned - explicitly, or
    inherited through a dynamic group - plus the ZTD registration ID that
    dynamic group membership rules actually match on.

.DESCRIPTION
    Read-only. A group tag in Intune is not a device-side setting. It is
    written to the Microsoft Entra device object as the OrderID attribute, and
    dynamic group rules match on it. That indirection is why changing a group
    tag does not take effect immediately - the change has to propagate through
    Entra dynamic group evaluation and then through Autopilot profile
    assignment, and each stage adds its own delay.

    What this script can tell you locally:
      - The ZTD registration ID this device presents (matched by
        devicePhysicalIds rules using the [ZTDid] prefix)
      - Whether the cached profile was assigned explicitly or not
        (IsExplicitProfileAssignment)
      - Which profile is actually cached, and when it was cached

    What it deliberately does NOT claim: the current group tag. That lives on
    the Entra device object, not on the device, and this script does not call
    Graph. Read the group tag from the Intune admin center or via Graph.

    Privacy: the ZTD registration ID is a device identifier. This script
    prints only a truncated form by default.

.NOTES
    Blog post: https://endpointweekly.com/blog/autopilot-group-tag-orderid-assignment-chain.html
    Run elevated - the Provisioning registry hive requires administrator rights.

.EXAMPLE
    .\Get-AutopilotAssignmentChain.ps1

.EXAMPLE
    .\Get-AutopilotAssignmentChain.ps1 -ShowFullZtdId
    Print the full ZTD registration ID (device identifier - handle with care).
#>

[CmdletBinding()]
param(
    [switch]$ShowFullZtdId
)

Write-Output "Autopilot Assignment Chain (device side)"
Write-Output ("-" * 62)

$cacheKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache'
if (-not (Test-Path $cacheKey)) {
    Write-Output "No Autopilot profile cache on this device - it was very likely not"
    Write-Output "provisioned by Autopilot."
    exit 2
}

$cache = Get-ItemProperty $cacheKey
if (-not $cache.PolicyJsonCache) {
    Write-Output "PolicyJsonCache is empty - no profile was cached."
    exit 2
}

try {
    $p = $cache.PolicyJsonCache | ConvertFrom-Json
} catch {
    Write-Output "PolicyJsonCache present but not parseable as JSON."
    exit 1
}

Write-Output "Cached profile name       : $($p.DeploymentProfileName)"
Write-Output "Cached on                 : $($p.PolicyDownloadDate)"

$ztd = $p.ZtdRegistrationId
if ($ztd) {
    if ($ShowFullZtdId) {
        Write-Output "ZtdRegistrationId         : $ztd"
    } else {
        $short = if ($ztd.Length -gt 8) { $ztd.Substring(0,8) + '-...' } else { $ztd }
        Write-Output "ZtdRegistrationId         : $short   (truncated - use -ShowFullZtdId to see it all)"
    }
    Write-Output "  This is the value an Entra dynamic group rule matches when you write:"
    Write-Output '    (device.devicePhysicalIDs -any (_ -startsWith "[ZTDid]"))'
} else {
    Write-Output "ZtdRegistrationId         : not present in the cached profile"
}

Write-Output ""
$explicit = $p.IsExplicitProfileAssignment
Write-Output "IsExplicitProfileAssignment: $explicit"
if ($explicit -eq $true) {
    Write-Output "  -> This profile was assigned DIRECTLY to the device, not inherited via a"
    Write-Output "     dynamic group. Group tag changes will NOT redirect this device to a"
    Write-Output "     different profile, because no group membership rule is deciding it."
} else {
    Write-Output "  -> This profile was not flagged as an explicit assignment, so group"
    Write-Output "     membership (and therefore the group tag / OrderID) is what selected it."
    Write-Output "     Expect dynamic group evaluation plus assignment propagation delay after"
    Write-Output "     any group tag change."
}

Write-Output ""
Write-Output "Where the group tag actually lives:"
Write-Output "  Intune 'group tag'  ->  Entra device attribute 'OrderID'"
Write-Output "  Dynamic group rule for one tag:"
Write-Output '    (device.devicePhysicalIds -any (_ -eq "[OrderID]:YourTagValue"))'
Write-Output ""
Write-Output "This script does not read the current group tag - it is not stored on the"
Write-Output "device. Read it from Intune (Devices > Enrollment > Windows Autopilot devices)"
Write-Output "or via Microsoft Graph."

exit 0
