<#
.SYNOPSIS
    Remediates the most common cause of Edge falling behind - the EdgeUpdate
    service or its scheduled task not running - and triggers an on-demand
    update check, for use as the remediation half of an Intune Proactive
    Remediation.

.DESCRIPTION
    Pairs with Detect-EdgeUpdateCompliance.ps1. Performs, in order:
        1. Sets the "edgeupdate" service to Automatic startup and starts it if
           it is not already running.
        2. Enables the MicrosoftEdgeUpdateTaskMachineUA scheduled task if it
           was disabled.
        3. Triggers an on-demand update check via MicrosoftEdgeUpdate.exe, the
           same binary the scheduled task itself calls.
        4. Waits briefly, then re-checks the installed version.

    What this script deliberately does NOT do: it does not touch
    TargetChannel, TargetVersionPrefix, or UpdateDefault policy values. Those
    are set by Intune/GPO policy (see the blog post's "The fix" section) and
    a per-device script silently rewriting them would fight with whatever set
    them in the first place, and get reverted on the next policy refresh
    regardless. If Detect still reports a policy-related issue after this
    script runs, that is a signal for an admin to fix the Intune/GPO
    assignment, not something this script should paper over.

.NOTES
    Blog post: https://endpointweekly.com/blog/edge-152-security-updates-force-latest-build-intune.html

    Exit 0 = Remediation actions completed (service/task are now healthy and
             an update check was triggered - this does not guarantee the
             device is immediately compliant, since a download can take a
             few minutes and a relaunch may still be required)
    Exit 1 = Remediation failed (e.g. could not start the service)

.EXAMPLE
    .\Remediate-EdgeUpdateCompliance.ps1
    Deploy as the remediation script in an Intune Proactive Remediation,
    paired with Detect-EdgeUpdateCompliance.ps1.
#>

$LogDir = "C:\Windows\Logs\Scripts"
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
Start-Transcript -Path "$LogDir\EdgeUpdateRemediation.log" -Append -Force

try {
    $HadError = $false

    ## --- Ensure the edgeupdate service is set to auto-start and running ---
    Write-Host "Checking edgeupdate service..."
    try {
        $svc = Get-Service -Name "edgeupdate" -ErrorAction Stop

        if ($svc.StartType -ne "Automatic") {
            Set-Service -Name "edgeupdate" -StartupType Automatic -ErrorAction Stop
            Write-Host "  Set edgeupdate startup type to Automatic (was $($svc.StartType))"
        }

        if ($svc.Status -ne "Running") {
            Start-Service -Name "edgeupdate" -ErrorAction Stop
            Write-Host "  Started edgeupdate service (was $($svc.Status))"
        } else {
            Write-Host "  edgeupdate already Running"
        }
    } catch {
        Write-Host "  ERROR: could not check/start edgeupdate service: $_"
        $HadError = $true
    }

    ## --- Ensure the update scheduled task is enabled ---
    Write-Host "Checking MicrosoftEdgeUpdateTaskMachineUA scheduled task..."
    try {
        $task = Get-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA" -ErrorAction Stop
        if ($task.State -eq "Disabled") {
            Enable-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineUA" -ErrorAction Stop | Out-Null
            Write-Host "  Enabled MicrosoftEdgeUpdateTaskMachineUA (was Disabled)"
        } else {
            Write-Host "  Task state: $($task.State)"
        }
    } catch {
        Write-Host "  ERROR: could not check/enable the scheduled task: $_"
        $HadError = $true
    }

    ## --- Trigger an on-demand update check ---
    Write-Host "Triggering on-demand update check..."
    try {
        $UpdaterPath = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
        if (Test-Path $UpdaterPath) {
            Start-Process -FilePath $UpdaterPath -ArgumentList "/ua /installsource ondemandcheckforupdate" -Wait -ErrorAction Stop
            Write-Host "  Update check triggered"
        } else {
            Write-Host "  ERROR: MicrosoftEdgeUpdate.exe not found at $UpdaterPath"
            $HadError = $true
        }
    } catch {
        Write-Host "  ERROR: could not trigger the update check: $_"
        $HadError = $true
    }

    ## --- Report the version after remediation (informational only) ---
    Start-Sleep -Seconds 15
    try {
        $EdgeStableGuid = "{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}"
        $ClientKeyPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$EdgeStableGuid"
        if (Test-Path $ClientKeyPath) {
            $InstalledVersion = (Get-ItemProperty -Path $ClientKeyPath -Name "pv" -ErrorAction SilentlyContinue).pv
            Write-Host "Installed version after remediation: $InstalledVersion"
            Write-Host "(A download can take a few minutes, and a relaunch may still be required for the running process to match - re-run Detect on the next scheduled cycle to confirm.)"
        }
    } catch {
        Write-Host "  Could not re-read the installed version: $_"
    }

    if ($HadError) {
        Write-Host "FAILED: one or more remediation steps did not complete."
        Stop-Transcript
        exit 1
    }

    Write-Host "SUCCESS: EdgeUpdate service/task are healthy and an update check was triggered."
    Stop-Transcript
    exit 0
}
catch {
    Write-Host "Unhandled error: $_"
    Stop-Transcript
    exit 1
}
