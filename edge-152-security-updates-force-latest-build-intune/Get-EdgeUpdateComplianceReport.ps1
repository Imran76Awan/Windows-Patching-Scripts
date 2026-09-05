<#
.SYNOPSIS
    Read-only audit of a device's Microsoft Edge patch state - installed version,
    running version, EdgeUpdate service/task health, and update policy overrides.

.DESCRIPTION
    Microsoft Edge updates itself using its own background service (EdgeUpdate),
    completely separate from Windows Update and from how Intune deploys Win32 apps.
    "Edge should be current" is not the same claim as "Edge is current" - this script
    checks the actual evidence instead of assuming the updater did its job.

    Checks performed, all read-only, nothing on the device is changed:
        1. InstalledVersion  - the "pv" registry value under Edge Update's own
           client key. This is the version the updater believes it has installed.
        2. RunningVersion    - the actual file version of msedge.exe currently on
           disk. If this differs from InstalledVersion, an update downloaded
           successfully but the browser has not been relaunched yet.
        3. EdgeUpdateService - state of the "edgeupdate" service (should be
           Running) and the "edgeupdatem" service (Stopped is normal - it only
           runs briefly during an update).
        4. UpdateTaskState   - state of the MicrosoftEdgeUpdateTaskMachineUA
           scheduled task, the one that actually performs the update check
           (should be Ready, not Disabled).
        5. PolicyOverrides   - UpdateDefault, TargetChannel, and
           TargetVersionPrefix under the EdgeUpdate policy key. A leftover
           TargetChannel or TargetVersionPrefix from a pilot can silently pin a
           device to an old build or the wrong channel forever.
        6. RelaunchPolicy    - RelaunchNotification / RelaunchNotificationPeriod
           under the separate Microsoft Edge browser policy key.

    Compliance verdict:
        - Compliant    : InstalledVersion and RunningVersion both meet
                         -CompliantVersion, and no stale TargetVersionPrefix
                         is pinning an older build.
        - NeedsRelaunch: InstalledVersion meets -CompliantVersion but
                         RunningVersion does not - the fix is a relaunch, not
                         a policy change.
        - NonCompliant : InstalledVersion itself is behind -CompliantVersion,
                         or the EdgeUpdate service/task is not healthy, or a
                         policy override is pinning an old channel/version.

.NOTES
    Blog post: https://endpointweekly.com/blog/edge-152-security-updates-force-latest-build-intune.html
    Read-only. Makes no changes to the device, the registry, or any service state.

    Exit 0 = Compliant
    Exit 1 = NeedsRelaunch or NonCompliant (see Verdict/Reasons in the output)
    Exit 2 = Script error (e.g. Edge is not installed on this device)

.EXAMPLE
    .\Get-EdgeUpdateComplianceReport.ps1
    Run standalone against the current build, using the default compliant
    version of 152.0.4191.66.

.EXAMPLE
    .\Get-EdgeUpdateComplianceReport.ps1 -CompliantVersion "152.0.4191.66" -ExportCsv -CsvPath "C:\Temp\edge-report.csv"
    Check against a specific version and append the result as one row to a CSV,
    for scheduling as an Intune platform script across a fleet.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$CompliantVersion = "152.0.4191.66",

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath = "C:\Windows\Logs\Scripts\EdgeUpdateComplianceReport.csv"
)

$script:hadError = $false
$EdgeStableGuid  = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
$Reasons         = New-Object System.Collections.Generic.List[string]

function Compare-EdgeVersion {
    param([string]$Left, [string]$Right)
    try {
        return ([version]$Left) -ge ([version]$Right)
    } catch {
        return $false
    }
}

## --- 1. Installed version (pv registry value) ---
$InstalledVersion = $null
try {
    $ClientKeyPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$EdgeStableGuid"
    if (Test-Path $ClientKeyPath) {
        $InstalledVersion = (Get-ItemProperty -Path $ClientKeyPath -Name "pv" -ErrorAction Stop).pv
    } else {
        $script:hadError = $true
        $Reasons.Add("EdgeUpdate client key not found - Microsoft Edge does not appear to be installed via EdgeUpdate on this device")
    }
} catch {
    $script:hadError = $true
    $Reasons.Add("Could not read installed version (pv) from the registry: $_")
}

## --- 2. Running version (msedge.exe file version) ---
$RunningVersion = $null
try {
    $MsEdgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    if (Test-Path $MsEdgePath) {
        $RunningVersion = (Get-Item -Path $MsEdgePath -ErrorAction Stop).VersionInfo.ProductVersion
    } else {
        $script:hadError = $true
        $Reasons.Add("msedge.exe not found at the expected path: $MsEdgePath")
    }
} catch {
    $script:hadError = $true
    $Reasons.Add("Could not read msedge.exe file version: $_")
}

## --- 3. EdgeUpdate service state ---
$EdgeUpdateServiceStatus  = $null
$EdgeUpdateMServiceStatus = $null
try {
    $svc = Get-Service -Name "edgeupdate" -ErrorAction SilentlyContinue
    $EdgeUpdateServiceStatus = if ($svc) { $svc.Status.ToString() } else { "NotFound" }

    $svcM = Get-Service -Name "edgeupdatem" -ErrorAction SilentlyContinue
    $EdgeUpdateMServiceStatus = if ($svcM) { $svcM.Status.ToString() } else { "NotFound" }

    if ($EdgeUpdateServiceStatus -ne "Running") {
        $Reasons.Add("edgeupdate service is '$EdgeUpdateServiceStatus', expected 'Running' - the device will not check for new Edge versions")
    }
} catch {
    $Reasons.Add("Could not query the edgeupdate/edgeupdatem services: $_")
}

## --- 4. Update scheduled task state ---
$UpdateTaskState = $null
try {
    $task = Get-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA" -ErrorAction SilentlyContinue
    $UpdateTaskState = if ($task) { $task.State.ToString() } else { "NotFound" }

    if ($UpdateTaskState -eq "Disabled" -or $UpdateTaskState -eq "NotFound") {
        $Reasons.Add("MicrosoftEdgeUpdateTaskMachineUA scheduled task is '$UpdateTaskState', expected 'Ready' or 'Running'")
    }
} catch {
    $Reasons.Add("Could not query the MicrosoftEdgeUpdateTaskMachineUA scheduled task: $_")
}

## --- 5. Policy overrides that can pin a device to an old channel/version ---
$UpdateDefaultValue        = $null
$TargetChannelValue        = $null
$TargetVersionPrefixValue  = $null
try {
    $PolicyKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
    if (Test-Path $PolicyKeyPath) {
        $PolicyKey = Get-ItemProperty -Path $PolicyKeyPath -ErrorAction SilentlyContinue

        $UpdateDefaultValue = $PolicyKey.UpdateDefault
        $TargetChannelValue = $PolicyKey."TargetChannel$EdgeStableGuid"
        $TargetVersionPrefixValue = $PolicyKey."TargetVersionPrefix$EdgeStableGuid"

        if ($TargetChannelValue -and $TargetChannelValue -ne "stable" -and $TargetChannelValue -ne "extended") {
            $Reasons.Add("TargetChannel is set to '$TargetChannelValue' - not stable or extended. Confirm this is intentional and not a leftover pilot policy")
        }
        if ($TargetVersionPrefixValue) {
            $Reasons.Add("TargetVersionPrefix is pinning this device to version '$TargetVersionPrefixValue' - it will not update past this version while the policy remains")
        }
        if ($UpdateDefaultValue -eq 0) {
            $Reasons.Add("UpdateDefault is set to 0 (Updates disabled) - this device will never update automatically")
        }
    }
    ## Not having this key at all is normal - it means no override policy is configured.
} catch {
    $Reasons.Add("Could not read EdgeUpdate policy overrides: $_")
}

## --- 6. Relaunch policy (separate key from EdgeUpdate) ---
$RelaunchNotificationValue = $null
$RelaunchNotificationPeriodValue = $null
try {
    $RelaunchKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (Test-Path $RelaunchKeyPath) {
        $RelaunchKey = Get-ItemProperty -Path $RelaunchKeyPath -ErrorAction SilentlyContinue
        $RelaunchNotificationValue = $RelaunchKey.RelaunchNotification
        $RelaunchNotificationPeriodValue = $RelaunchKey.RelaunchNotificationPeriod
    }
} catch {
    $Reasons.Add("Could not read the RelaunchNotification policy: $_")
}

## --- Verdict ---
$Verdict = "Unknown"
if ($script:hadError) {
    $Verdict = "Error"
} elseif ($InstalledVersion -and $RunningVersion) {
    $InstalledIsCompliant = Compare-EdgeVersion -Left $InstalledVersion -Right $CompliantVersion
    $RunningIsCompliant   = Compare-EdgeVersion -Left $RunningVersion -Right $CompliantVersion

    if (-not $InstalledIsCompliant) {
        $Verdict = "NonCompliant"
        $Reasons.Add("Installed version $InstalledVersion is behind the required $CompliantVersion")
    } elseif (-not $RunningIsCompliant) {
        $Verdict = "NeedsRelaunch"
        $Reasons.Add("Update to $InstalledVersion is installed but the running browser is still on $RunningVersion - relaunch required")
    } elseif ($Reasons.Count -gt 0) {
        $Verdict = "NonCompliant"
    } else {
        $Verdict = "Compliant"
    }
} else {
    $Verdict = "Error"
}

$Result = [PSCustomObject]@{
    ComputerName                = $env:COMPUTERNAME
    CheckedAt                   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    InstalledVersion             = $InstalledVersion
    RunningVersion               = $RunningVersion
    CompliantVersion             = $CompliantVersion
    Verdict                      = $Verdict
    EdgeUpdateServiceStatus      = $EdgeUpdateServiceStatus
    EdgeUpdateMServiceStatus     = $EdgeUpdateMServiceStatus
    UpdateTaskState              = $UpdateTaskState
    UpdateDefault                = $UpdateDefaultValue
    TargetChannel                = $TargetChannelValue
    TargetVersionPrefix          = $TargetVersionPrefixValue
    RelaunchNotification         = $RelaunchNotificationValue
    RelaunchNotificationPeriod   = $RelaunchNotificationPeriodValue
    Reasons                      = ($Reasons -join " | ")
}

$Result | Format-List

if ($ExportCsv) {
    $CsvDir = Split-Path -Path $CsvPath -Parent
    if (-not (Test-Path $CsvDir)) {
        New-Item -ItemType Directory -Path $CsvDir -Force | Out-Null
    }
    $WriteHeader = -not (Test-Path $CsvPath)
    $Result | Export-Csv -Path $CsvPath -NoTypeInformation -Append:(!$WriteHeader) -Force
    Write-Host "Result appended to $CsvPath"
}

switch ($Verdict) {
    "Compliant"     { exit 0 }
    "NeedsRelaunch" { exit 1 }
    "NonCompliant"  { exit 1 }
    default         { exit 2 }
}
