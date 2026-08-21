<#
.SYNOPSIS
    Reports the Autopilot profile that is actually cached on this device - in
    the registry AND on disk - and when it was downloaded, so you can tell
    whether a profile edit in Intune has really reached the device.

.DESCRIPTION
    Read-only. An Autopilot deployment profile is downloaded once, during
    provisioning, and then cached in two places:

      1. Registry : HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache
                    value PolicyJsonCache (the whole profile as JSON)
      2. On disk  : C:\Windows\ServiceState\wmansvc\AutopilotDDSZTDFile.json

    Editing the profile in Intune does NOT rewrite either copy on an
    already-provisioned device. This script surfaces the cached values and the
    PolicyDownloadDate so you can prove what the device is actually holding.

    Privacy: this script deliberately reports only the metadata and the
    non-identifying fields of the cached profile. It does NOT print the
    hardware hash (CachedHash.txt) or the TPM endorsement key
    (CachedTpmEkPub.txt) - those are device identifiers. It reports only that
    those files exist, their size, and their timestamp.

.NOTES
    Blog post: https://endpointweekly.com/blog/autopilot-profile-cache-why-edits-dont-apply.html
    Run elevated - the Provisioning registry hive and the ServiceState folder
    require administrator rights to read.

.EXAMPLE
    .\Get-AutopilotProfileCacheReport.ps1
#>

[CmdletBinding()]
param()

Write-Output "Autopilot Profile Cache Report"
Write-Output ("-" * 62)

$diagKey  = 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot'
$cacheKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache'

# --- 1. Is this even an Autopilot device? -----------------------------------
if (-not (Test-Path $diagKey)) {
    Write-Output "No Autopilot diagnostics key found - this device was very likely not"
    Write-Output "provisioned by Autopilot. Nothing further to report."
    exit 2
}

$diag = Get-ItemProperty $diagKey
Write-Output "Deployment profile name  : $($diag.DeploymentProfileName)"
Write-Output "Autopilot disabled flag  : $($diag.IsAutoPilotDisabled)"
Write-Output "Forced enrollment        : $($diag.CloudAssignedForcedEnrollment)"
Write-Output "OOBE config (bitmask)    : $($diag.CloudAssignedOobeConfig)"
Write-Output ""

# --- 2. The cached profile JSON in the registry -----------------------------
Write-Output "Registry cache ($cacheKey):"
if (Test-Path $cacheKey) {
    $cache = Get-ItemProperty $cacheKey
    Write-Output "  ProfileAvailable       : $($cache.ProfileAvailable)"
    if ($cache.PolicyJsonCache) {
        try {
            $profileJson = $cache.PolicyJsonCache | ConvertFrom-Json
            # Report only the non-identifying, operationally useful fields.
            Write-Output "  PolicyDownloadDate     : $($profileJson.PolicyDownloadDate)   <-- when the profile was cached"
            Write-Output "  AutopilotCreationDate  : $($profileJson.AutopilotCreationDate)"
            Write-Output "  DeploymentProfileName  : $($profileJson.DeploymentProfileName)"
            $djm = $profileJson.CloudAssignedDomainJoinMethod
            $djmText = if ($djm -eq 1) { '1 (Microsoft Entra hybrid join)' }
                       elseif ($djm -eq 0) { '0 (Microsoft Entra join)' }
                       else { "$djm (unrecognised)" }
            Write-Output "  DomainJoinMethod       : $djmText"
            Write-Output "  ExplicitProfileAssign  : $($profileJson.IsExplicitProfileAssignment)"
            Write-Output "  AutopilotUpdateDisabled: $($profileJson.CloudAssignedAutopilotUpdateDisabled)"
        } catch {
            Write-Output "  PolicyJsonCache present but could not be parsed as JSON."
        }
    } else {
        Write-Output "  PolicyJsonCache        : not present"
    }
} else {
    Write-Output "  key not present"
}
Write-Output ""

# --- 3. The on-disk cache ---------------------------------------------------
Write-Output "On-disk cache (C:\Windows\ServiceState\wmansvc):"
$wman = 'C:\Windows\ServiceState\wmansvc'
if (Test-Path $wman) {
    foreach ($name in 'AutopilotDDSZTDFile.json','CachedHash.txt','CachedTpmEkPub.txt') {
        $f = Join-Path $wman $name
        if (Test-Path $f) {
            $item = Get-Item $f
            $note = switch ($name) {
                'CachedHash.txt'     { '  (hardware hash - contents deliberately NOT read)' }
                'CachedTpmEkPub.txt' { '  (TPM endorsement key - contents deliberately NOT read)' }
                default              { '' }
            }
            Write-Output ("  {0,-26} {1,7:N0} bytes  {2}{3}" -f $name, $item.Length, $item.LastWriteTime, $note)
        } else {
            Write-Output ("  {0,-26} not present" -f $name)
        }
    }
} else {
    Write-Output "  wmansvc folder not present"
}

Write-Output ""
Write-Output "How to read this:"
Write-Output "  PolicyDownloadDate is when this device last actually pulled its profile."
Write-Output "  If you edited the Autopilot profile in Intune AFTER that date, this device"
Write-Output "  is still running the old cached copy. Profile edits apply at the NEXT"
Write-Output "  provisioning cycle (Autopilot Reset / reimage), not on a running device."

exit 0
