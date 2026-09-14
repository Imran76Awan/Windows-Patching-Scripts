<#
.SYNOPSIS
    Detects whether the OSLicense PowerShell module is available on this device.
    For use as an Intune Proactive Remediation detection script.

.DESCRIPTION
    Checks the device OS build number against the minimum build that ships the OSLicense module
    (26100.9278 / 26200.9278, included in the September 2026 servicing update KB5124008 and
    the August 27, 2026 Preview KB5120998 or later).

    Exit 0 = OSLicense module is available (healthy)
    Exit 1 = OSLicense module not yet available (device needs September 2026 patch)

.NOTES
    Blog post: https://endpointweekly.com/blog/vbscript-deprecation-slmgr-oslicense-powershell-replacement.html
    Repo: https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/vbscript-deprecation-slmgr-oslicense
    Author: Imran Awan
    Version: 1.0
    Pair: Remediate-OSLicenseModuleAvailable.ps1
#>

$ErrorActionPreference = 'Stop'

try {
    $UBR = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    $BuildNumber = [System.Environment]::OSVersion.Version.Build

    # OSLicense ships from UBR 9278 onwards on both 26100 (23H2/24H2) and 26200 (25H2) tracks
    $MinUBR = 9278

    if ($UBR -ge $MinUBR) {
        # Also confirm the module actually loads
        $ModuleCheck = Get-Command -Name 'Get-OSLicenseInfo' -ErrorAction SilentlyContinue
        if ($ModuleCheck) {
            Write-Output "OSLicense module available. Build: $BuildNumber.$UBR. Get-OSLicenseInfo found."
            exit 0
        } else {
            Write-Output "Build meets threshold ($BuildNumber.$UBR >= $BuildNumber.$MinUBR) but Get-OSLicenseInfo not found - may need reboot or reimport."
            exit 1
        }
    } else {
        Write-Output "Build $BuildNumber.$UBR does not meet minimum $BuildNumber.$MinUBR for OSLicense support. Apply September 2026 patch."
        exit 1
    }
} catch {
    Write-Output "Detection error: $_"
    exit 1
}
