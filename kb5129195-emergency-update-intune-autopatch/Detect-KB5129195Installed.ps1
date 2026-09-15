<#
.SYNOPSIS
    Detects whether KB5129195 (September 2026 OOB emergency update) is installed.
    For use as an Intune Proactive Remediation detection script.

.DESCRIPTION
    Checks for KB5129195 presence and verifies the device OS build meets the minimum
    required level: 26100.9457 (Windows 11 24H2) or 26200.9457 (Windows 11 25H2).

    KB5129195 fixes three regressions introduced by the September 2026 Patch Tuesday CU:
    - Remote Desktop Services (RDS) instability and RDP connection failures
    - HCS/Plan9 WSL folder sharing failures in Hyper-V-managed VMs
    - USB Audio Class 1.0 multichannel (8-channel / 3D audio) failure

    Also adds CVE-2026-62721 (Windows User-Mode Power Service EoP) protection.

    Exit 0 = KB5129195 is installed (no remediation needed)
    Exit 1 = KB5129195 is NOT installed (trigger remediation)

.NOTES
    Blog post: https://endpointweekly.com/blog/kb5129195-emergency-update-intune-autopatch-rds-fix.html
    Repo: https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/kb5129195-emergency-update-intune-autopatch
    Author: Imran Awan
    Version: 1.0
    Pair: Remediate-KB5129195Install.ps1
#>

$ErrorActionPreference = 'Stop'

try {
    $UBR         = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    $BuildNumber = [System.Environment]::OSVersion.Version.Build
    $FullBuild   = "$BuildNumber.$UBR"

    # KB5129195 target UBR is 9457 for both 24H2 (26100) and 25H2 (26200)
    $RequiredUBR = 9457

    # Check by build number (covers both Windows Update and Catalog installation)
    if ($UBR -ge $RequiredUBR) {
        Write-Output "KB5129195 installed. Build: $FullBuild (>= $BuildNumber.$RequiredUBR)"
        exit 0
    }

    # Double-check via Get-HotFix in case build number reporting lags
    $HotFix = Get-HotFix -Id KB5129195 -ErrorAction SilentlyContinue
    if ($HotFix) {
        Write-Output "KB5129195 found via HotFix list. Build: $FullBuild"
        exit 0
    }

    Write-Output "KB5129195 NOT installed. Current build: $FullBuild. Required UBR: $RequiredUBR."
    exit 1

} catch {
    Write-Output "Detection error: $_"
    exit 1
}
