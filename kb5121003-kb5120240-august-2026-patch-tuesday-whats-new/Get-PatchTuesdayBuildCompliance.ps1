<#
.SYNOPSIS
    Confirms a device actually landed on the expected build after August 2026
    Patch Tuesday (KB5121003 / KB5120240), rather than trusting Windows Update's
    "installed" status alone.

.DESCRIPTION
    Read-only compliance check. Reads the real OS build (CurrentBuildNumber +
    UBR) and DisplayVersion from the registry, compares it against the expected
    build for each Windows 11 servicing branch this month, and reports whether
    the matching KB shows up in the hotfix history.

    Expected builds (August 2026 Patch Tuesday):
      25H2  -> 26200.9168  (KB5121003)
      24H2  -> 26100.9168  (KB5121003)
      23H2  -> 22631.7517  (KB5120240)

    Makes no changes to the system. Exits non-zero if the device has not yet
    reached the expected build for its branch, so this can be dropped straight
    into an Intune Proactive Remediation detection script.

.NOTES
    Blog post: https://endpointweekly.com/blog/kb5121003-kb5120240-august-2026-patch-tuesday-whats-new.html
    Run as any user; registry reads and Get-HotFix do not require elevation.

.EXAMPLE
    .\Get-PatchTuesdayBuildCompliance.ps1
#>

[CmdletBinding()]
param()

$expected = @{
    '25H2' = @{ Build = '26200.9168'; KB = 'KB5121003' }
    '24H2' = @{ Build = '26100.9168'; KB = 'KB5121003' }
    '23H2' = @{ Build = '22631.7517'; KB = 'KB5120240' }
}

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$actualBuild = "$($cv.CurrentBuild).$($cv.UBR)"
$branch = $cv.DisplayVersion

Write-Output "Patch Tuesday Build Compliance - August 2026"
Write-Output ("-" * 60)
Write-Output "DisplayVersion (branch) : $branch"
Write-Output "Actual build            : $actualBuild"

if (-not $expected.ContainsKey($branch)) {
    Write-Output "Result                  : UNKNOWN branch - not one of 23H2/24H2/25H2, cannot compare"
    exit 2
}

$target = $expected[$branch]
Write-Output "Expected build          : $($target.Build)  ($($target.KB))"

if ($actualBuild -eq $target.Build) {
    Write-Output "Result                  : COMPLIANT - device is on the expected build"
} else {
    Write-Output "Result                  : NOT YET COMPLIANT - update has not landed (or has not rebooted to apply)"
}

Write-Output ""
Write-Output "Hotfix history check ($($target.KB)):"
$hotfix = Get-HotFix -Id $target.KB -ErrorAction SilentlyContinue
if ($hotfix) {
    Write-Output "  Found in Get-HotFix, installed $($hotfix.InstalledOn)"
} else {
    Write-Output "  Not found via Get-HotFix - this is normal even on a compliant build; cumulative"
    Write-Output "  updates for 24H2/25H2 often do not enumerate via the legacy Get-HotFix API."
    Write-Output "  The build number comparison above is the authoritative check."
}

if ($actualBuild -eq $target.Build) { exit 0 } else { exit 1 }
