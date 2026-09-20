<#
.SYNOPSIS
    Intune Proactive Remediation — REMEDIATION script for KB5124008 File History crash.

.DESCRIPTION
    Temporary workaround only. There is no production fix for this issue as of 2026-09-20.
    This script restarts the fhsvc (Windows File History Service), which may allow one backup
    cycle to complete before the next crash. It does not resolve the underlying regression.

    Replace this script with a real fix script once Microsoft releases the production update.
    Monitor the KB5124008 support article for status updates.

    DO NOT uninstall KB5124008 — it is the September 2026 security update and contains
    patches for multiple CVEs. Removing it to restore File History is not an acceptable trade.

    Deploy as the Remediation Script in an Intune Proactive Remediation pair alongside
    Detect-FileHistoryKB5124008.ps1. Run as: SYSTEM, 64-bit PowerShell.

.NOTES
    Blog:   https://endpointweekly.com/blog/kb5124008-file-history-reconnect-drive-error-windows-11.html
    Repo:   https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/kb5124008-file-history-reconnect-drive-error-windows-11
#>

try {
    Restart-Service -Name fhsvc -Force -ErrorAction Stop
    $svc = Get-Service -Name fhsvc
    Write-Output "fhsvc restarted. Current state: $($svc.Status). File History may complete one backup cycle before the next crash. Monitor Event ID 1000 in the Application log to confirm."
    exit 0
} catch {
    Write-Output "Failed to restart fhsvc: $_"
    exit 1
}
