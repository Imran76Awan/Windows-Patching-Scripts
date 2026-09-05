<#
.SYNOPSIS
    Detects whether Microsoft Edge on this device is on the required version and
    whether the EdgeUpdate service/task are healthy, for use as the detection
    half of an Intune Proactive Remediation.

.DESCRIPTION
    Matches exactly the checks described in the blog post's "How to verify"
    section: installed version (the "pv" registry value), running msedge.exe
    version, the edgeupdate service state, the update scheduled task state, and
    whether a policy override (TargetChannel/TargetVersionPrefix) is pinning the
    device away from Stable/Extended.

    Read-only. Makes no changes to the device. Pair with
    Remediate-EdgeUpdateCompliance.ps1 for the remediation half.

.PARAMETER CompliantVersion
    The minimum Microsoft Edge version that counts as compliant. Update this
    each time a new security build ships - it is not read automatically from
    anywhere, since Intune has no built-in "latest Edge version" value to
    reference.

.NOTES
    Blog post: https://endpointweekly.com/blog/edge-152-security-updates-force-latest-build-intune.html
    Companion script: Get-EdgeUpdateComplianceReport.ps1 (same folder) - a
    standalone version of this same logic for ad-hoc single-device checks with
    CSV export, not tied to Intune's exit-code contract.

    Exit 0 = Compliant
    Exit 1 = Not compliant (remediation required)

.EXAMPLE
    .\Detect-EdgeUpdateCompliance.ps1
    Run standalone to check a single device, or deploy as the detection script
    in an Intune Proactive Remediation, with -CompliantVersion updated in the
    param block below to match the current required build before each deploy.
#>

param(
    [string]$CompliantVersion = "152.0.4191.66"
)

$EdgeStableGuid = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"

function Compare-EdgeVersion {
    param([string]$Left, [string]$Right)
    try {
        return ([version]$Left) -ge ([version]$Right)
    } catch {
        return $false
    }
}

try {
    $Issues = New-Object System.Collections.Generic.List[string]

    ## --- Installed version (pv registry value) ---
    $ClientKeyPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$EdgeStableGuid"
    if (-not (Test-Path $ClientKeyPath)) {
        Write-Output "Not compliant: EdgeUpdate client key not found - Edge does not appear to be installed via EdgeUpdate"
        exit 1
    }
    $InstalledVersion = (Get-ItemProperty -Path $ClientKeyPath -Name "pv" -ErrorAction Stop).pv

    ## --- Running version (msedge.exe file version) ---
    $MsEdgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    if (-not (Test-Path $MsEdgePath)) {
        Write-Output "Not compliant: msedge.exe not found at $MsEdgePath"
        exit 1
    }
    $RunningVersion = (Get-Item -Path $MsEdgePath -ErrorAction Stop).VersionInfo.ProductVersion

    if (-not (Compare-EdgeVersion -Left $InstalledVersion -Right $CompliantVersion)) {
        $Issues.Add("Installed version $InstalledVersion is behind the required $CompliantVersion")
    }
    if (-not (Compare-EdgeVersion -Left $RunningVersion -Right $CompliantVersion)) {
        $Issues.Add("Running version $RunningVersion is behind the required $CompliantVersion (relaunch may be pending)")
    }

    ## --- EdgeUpdate service state ---
    $svc = Get-Service -Name "edgeupdate" -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne "Running") {
        $status = if ($svc) { $svc.Status } else { "NotFound" }
        $Issues.Add("edgeupdate service is '$status', expected 'Running'")
    }

    ## --- Update scheduled task state ---
    $task = Get-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA" -ErrorAction SilentlyContinue
    if (-not $task -or $task.State -eq "Disabled") {
        $state = if ($task) { $task.State } else { "NotFound" }
        $Issues.Add("MicrosoftEdgeUpdateTaskMachineUA scheduled task is '$state', expected 'Ready' or 'Running'")
    }

    ## --- Policy overrides that pin the device away from Stable/Extended ---
    $PolicyKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
    if (Test-Path $PolicyKeyPath) {
        $PolicyKey = Get-ItemProperty -Path $PolicyKeyPath -ErrorAction SilentlyContinue
        $TargetChannelValue = $PolicyKey."TargetChannel$EdgeStableGuid"
        $TargetVersionPrefixValue = $PolicyKey."TargetVersionPrefix$EdgeStableGuid"

        if ($TargetChannelValue -and $TargetChannelValue -ne "stable" -and $TargetChannelValue -ne "extended") {
            $Issues.Add("TargetChannel is set to '$TargetChannelValue', not stable or extended - confirm this is intentional")
        }
        if ($TargetVersionPrefixValue) {
            $Issues.Add("TargetVersionPrefix is pinning this device to '$TargetVersionPrefixValue'")
        }
        if ($PolicyKey.UpdateDefault -eq 0) {
            $Issues.Add("UpdateDefault is 0 (Updates disabled)")
        }
    }

    if ($Issues.Count -eq 0) {
        Write-Output "Compliant: Edge $InstalledVersion running, EdgeUpdate healthy"
        exit 0
    } else {
        Write-Output ("Not compliant: " + ($Issues -join " | "))
        exit 1
    }
}
catch {
    Write-Output "Error during detection: $_"
    exit 1
}
