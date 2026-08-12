<#
.SYNOPSIS
    Report-only remediation companion to Get-PatchTuesdayBuildCompliance.ps1.

.DESCRIPTION
    Deliberately does NOT force an update, trigger a reboot, or call
    UsoClient/Start-Scan on a device that may be under its own change-control
    process. Forcing a scan or install from a remediation script risks
    colliding with a managed patch schedule (WUfB deferral rings, ConfigMgr
    maintenance windows, etc.) that the fleet is already governed by.

    Instead this script logs the non-compliant finding - build number,
    branch, expected vs actual - to a local CSV and the Application event
    log, so it shows up in your existing patch-compliance reporting without
    fighting your real update-management tooling for control of the device.

.NOTES
    Blog post: https://endpointweekly.com/blog/kb5121003-kb5120240-august-2026-patch-tuesday-whats-new.html
    Pair with Get-PatchTuesdayBuildCompliance.ps1 as the detection script in
    an Intune Proactive Remediation. Always exits 0 - it reports, it does not fix.

.EXAMPLE
    .\Remediate-PatchTuesdayBuildComplianceReport.ps1
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$env:ProgramData\EndpointWeekly\PatchCompliance\build-compliance-log.csv"
)

$expected = @{
    '25H2' = @{ Build = '26200.9168'; KB = 'KB5121003' }
    '24H2' = @{ Build = '26100.9168'; KB = 'KB5121003' }
    '23H2' = @{ Build = '22631.7517'; KB = 'KB5120240' }
}

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$actualBuild = "$($cv.CurrentBuild).$($cv.UBR)"
$branch = $cv.DisplayVersion
$target = $expected[$branch]
$compliant = ($target -and $actualBuild -eq $target.Build)

$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }

$row = [pscustomobject]@{
    Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    ComputerName  = $env:COMPUTERNAME
    Branch        = $branch
    ActualBuild   = $actualBuild
    ExpectedBuild = if ($target) { $target.Build } else { 'unknown branch' }
    Compliant     = $compliant
}
$row | Export-Csv -Path $LogPath -Append -NoTypeInformation

$sourceName = 'EndpointWeekly-PatchCompliance'
if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
    New-EventLog -LogName Application -Source $sourceName
}
$message = "Patch Tuesday build compliance check: branch=$branch actual=$actualBuild expected=$($row.ExpectedBuild) compliant=$compliant. This script does not force an update - reported for existing patch-management tooling to act on."
Write-EventLog -LogName Application -Source $sourceName -EventId 7701 -EntryType ([System.Diagnostics.EventLogEntryType]::($(if ($compliant) { 'Information' } else { 'Warning' }))) -Message $message

Write-Output $message
exit 0
