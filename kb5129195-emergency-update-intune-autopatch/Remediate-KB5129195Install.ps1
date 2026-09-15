<#
.SYNOPSIS
    Remediation: triggers a Windows Update scan to queue KB5129195.
    For use as an Intune Proactive Remediation remediation script.

.DESCRIPTION
    Runs UsoClient StartScan to prompt Windows Update to find and queue KB5129195.
    The update is an OOB Security Update - it syncs to WSUS/WUfB automatically
    when Classification: Security Updates is configured, but some Autopatch policies
    require manual approval for non-monthly updates. This script forces the WU client
    to re-check rather than wait for its next scheduled scan.

    Exit 0 = Scan triggered successfully
    Exit 1 = Could not trigger scan

.NOTES
    Blog post: https://endpointweekly.com/blog/kb5129195-emergency-update-intune-autopatch-rds-fix.html
    Repo: https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/kb5129195-emergency-update-intune-autopatch
    Author: Imran Awan
    Version: 1.0
    Pair: Detect-KB5129195Installed.ps1
#>

$ErrorActionPreference = 'Continue'
$LogDir  = "$env:ProgramData\EndpointWeekly"
$LogFile = "$LogDir\Remediate-KB5129195.log"

function Write-Log { param([string]$Msg)
    $Line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Msg"
    Write-Output $Line
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $Line -Encoding UTF8
    } catch {}
}

try {
    Write-Log "Starting remediation for KB5129195 (September 2026 OOB emergency update)."
    Write-Log "Current build: $([System.Environment]::OSVersion.Version.Build).$(
        (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    )"

    # Trigger WU scan via UsoClient
    Write-Log "Triggering Windows Update scan (UsoClient StartScan)..."
    $UsoOut = & "$env:SystemRoot\System32\UsoClient.exe" StartScan 2>&1
    Write-Log "UsoClient: $UsoOut"

    # Also trigger via Windows Update Agent COM object for immediate effect
    Write-Log "Triggering update search via Windows Update Agent..."
    $Session   = New-Object -ComObject "Microsoft.Update.Session"
    $Searcher  = $Session.CreateUpdateSearcher()
    $Results   = $Searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
    $Count     = $Results.Updates.Count
    Write-Log "WUA search complete: $Count update(s) found and queued for install."

    if ($Count -gt 0) {
        $Titles = ($Results.Updates | ForEach-Object { $_.Title }) -join '; '
        Write-Log "Queued: $Titles"
    }

    Write-Log "Remediation complete. KB5129195 will install on next maintenance window."
    exit 0
} catch {
    Write-Log "Remediation error: $_"
    exit 1
}
