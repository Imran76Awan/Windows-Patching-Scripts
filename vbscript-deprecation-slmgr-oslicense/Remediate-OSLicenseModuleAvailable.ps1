<#
.SYNOPSIS
    Remediation script: triggers Windows Update to ensure the device has the minimum build
    for OSLicense PowerShell module availability.
    For use as an Intune Proactive Remediation remediation script.

.DESCRIPTION
    If the detect script exits 1 (OSLicense not available), this remediation initiates a Windows
    Update scan via the Update Session COM object and logs the result. It does NOT force-install
    any specific update - it triggers the standard Windows Update client to find and queue the
    applicable September 2026 servicing update for the device's Windows 11 channel.

    Exit 0 = Scan triggered successfully
    Exit 1 = Could not trigger update scan

.NOTES
    Blog post: https://endpointweekly.com/blog/vbscript-deprecation-slmgr-oslicense-powershell-replacement.html
    Repo: https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/vbscript-deprecation-slmgr-oslicense
    Author: Imran Awan
    Version: 1.0
    Pair: Detect-OSLicenseModuleAvailable.ps1
#>

$ErrorActionPreference = 'Stop'
$LogFile = "$env:ProgramData\EndpointWeekly\Remediate-OSLicense.log"

function Write-Log {
    param([string]$Message)
    $Entry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Output $Entry
    try {
        $Dir = Split-Path $LogFile
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $Entry -Encoding UTF8
    } catch {}
}

try {
    Write-Log "Starting remediation: triggering Windows Update scan for OSLicense prerequisite patch."

    $UpdateSession    = New-Object -ComObject "Microsoft.Update.Session"
    $UpdateSearcher   = $UpdateSession.CreateUpdateSearcher()
    Write-Log "Searching for applicable Windows updates..."
    $SearchResult     = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $UpdateCount      = $SearchResult.Updates.Count
    Write-Log "Windows Update search complete. $UpdateCount update(s) available."

    if ($UpdateCount -gt 0) {
        $UpdateTitles = ($SearchResult.Updates | ForEach-Object { $_.Title }) -join '; '
        Write-Log "Available: $UpdateTitles"
    }

    # Trigger UsoClient scan to queue updates via Intune/WUfB
    $UsoResult = & "$env:SystemRoot\System32\UsoClient.exe" StartScan 2>&1
    Write-Log "UsoClient StartScan result: $UsoResult"

    Write-Log "Remediation complete. Device will install pending updates on next maintenance window."
    exit 0
} catch {
    Write-Log "Remediation failed: $_"
    exit 1
}
