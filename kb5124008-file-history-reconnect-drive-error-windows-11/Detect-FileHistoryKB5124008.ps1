<#
.SYNOPSIS
    Intune Proactive Remediation — DETECTION script for KB5124008 File History crash.

.DESCRIPTION
    Exits 1 (non-compliant / issue found) when the device has KB5124008 installed,
    File History is enabled, and FileHistory.exe crash events appear in the last 7 days.
    Exits 0 (compliant / no issue) in all other cases.

    Deploy as the Detection Script in an Intune Proactive Remediation pair.
    Run as: SYSTEM, 64-bit PowerShell.

.NOTES
    Blog:   https://endpointweekly.com/blog/kb5124008-file-history-reconnect-drive-error-windows-11.html
    Repo:   https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/kb5124008-file-history-reconnect-drive-error-windows-11
#>

# 1. Is KB5124008 installed?
$kb = Get-HotFix -Id KB5124008 -ErrorAction SilentlyContinue
if (-not $kb) {
    Write-Output 'KB5124008 not installed - not affected'
    exit 0
}

# 2. Is File History enabled? (Check HKCU for the currently logged-on user)
$fhReg = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory' -ErrorAction SilentlyContinue
if (-not $fhReg -or $fhReg.Enabled -ne 1) {
    Write-Output 'File History not enabled for current user - not affected'
    exit 0
}

# 3. Any FileHistory.exe crash events in the last 7 days?
$since = (Get-Date).AddDays(-7)
$crashes = Get-WinEvent -LogName Application -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -eq 1000 -and $_.Message -like '*FileHistory.exe*' -and $_.TimeCreated -gt $since }

if ($crashes.Count -gt 0) {
    Write-Output "AFFECTED: $($crashes.Count) FileHistory.exe crash event(s) in the last 7 days. Most recent: $($crashes[0].TimeCreated)"
    exit 1
}

Write-Output 'No recent FileHistory.exe crashes - not currently symptomatic'
exit 0
