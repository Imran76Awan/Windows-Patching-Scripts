<#
.SYNOPSIS
    Audits a Windows device for slmgr.vbs and VBScript-based activation dependencies.

.DESCRIPTION
    Searches common script locations (Intune remediations, task sequences, MDT share references,
    scheduled tasks, PowerShell scripts, batch files) for references to slmgr.vbs, cscript,
    wscript, and .vbs activation patterns. Reports findings to console and optionally exports
    a CSV for fleet-level review.

    This script is READ-ONLY. It makes no changes to the device.

.NOTES
    Blog post: https://endpointweekly.com/blog/vbscript-deprecation-slmgr-oslicense-powershell-replacement.html
    Repo: https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/vbscript-deprecation-slmgr-oslicense
    Author: Imran Awan
    Version: 1.0

.PARAMETER SearchPaths
    Additional directories to scan beyond the defaults. Accepts an array of paths.

.PARAMETER ExportCsv
    Switch. When set, exports findings to CSV at C:\ProgramData\EndpointWeekly\VBScriptAudit.csv

.EXAMPLE
    .\Find-VBScriptActivationDependencies.ps1 -ExportCsv
    Scans default locations and exports findings to CSV.

.EXAMPLE
    .\Find-VBScriptActivationDependencies.ps1 -SearchPaths "D:\Scripts","C:\MDT\Scripts"
    Scans default locations plus two additional paths.
#>

[CmdletBinding()]
param(
    [string[]]$SearchPaths = @(),
    [switch]$ExportCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$script:hadError = $false

# Default search roots
$DefaultRoots = @(
    "$env:ProgramData\Microsoft\IntuneManagementExtension\Scripts",
    "$env:ProgramData\Microsoft\IntuneManagementExtension\Tasks",
    "$env:SystemRoot\System32\GroupPolicy",
    "$env:SystemRoot\System32\GroupPolicyUsers",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ALLUSERSPROFILE\Application Data\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\Windows\SYSVOL",
    "C:\Scripts",
    "C:\IT",
    "C:\Deploy"
)

$AllRoots = $DefaultRoots + $SearchPaths | Where-Object { Test-Path $_ } | Sort-Object -Unique

# Patterns that indicate VBScript-based activation
$DependencyPatterns = @(
    'slmgr',
    'slmgr\.vbs',
    'cscript.*\.vbs',
    'wscript.*\.vbs',
    '//E:vbscript',
    'SoftwareLicensingProduct.*GetValue.*LicenseStatus'
)

$FileExtensions = @('*.ps1', '*.bat', '*.cmd', '*.xml', '*.json', '*.ini', '*.txt', '*.vbs', '*.wsf')

$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "`n[VBScript Activation Dependency Audit]" -ForegroundColor Cyan
Write-Host "Scanning $($AllRoots.Count) root path(s)..." -ForegroundColor Gray

foreach ($Root in $AllRoots) {
    Write-Host "  Scanning: $Root" -ForegroundColor DarkGray
    try {
        $Files = Get-ChildItem -Path $Root -Recurse -Include $FileExtensions -ErrorAction SilentlyContinue
        foreach ($File in $Files) {
            try {
                $Content = Get-Content -Path $File.FullName -Raw -ErrorAction Stop
                foreach ($Pattern in $DependencyPatterns) {
                    if ($Content -imatch $Pattern) {
                        $MatchedLine = ($Content -split "`n" | Where-Object { $_ -imatch $Pattern } | Select-Object -First 1).Trim()
                        $Results.Add([PSCustomObject]@{
                            Computer    = $env:COMPUTERNAME
                            FilePath    = $File.FullName
                            FileName    = $File.Name
                            Extension   = $File.Extension
                            Pattern     = $Pattern
                            MatchedLine = $MatchedLine -replace '\s+', ' '
                            SizeKB      = [math]::Round($File.Length / 1KB, 1)
                            LastModified = $File.LastWriteTime.ToString('yyyy-MM-dd')
                        })
                        break
                    }
                }
            } catch {
                $script:hadError = $true
                Write-Warning "Could not read: $($File.FullName) - $_"
            }
        }
    } catch {
        Write-Warning "Could not scan root: $Root - $_"
    }
}

# Check scheduled tasks for VBScript activation patterns
Write-Host "  Scanning: Scheduled Tasks" -ForegroundColor DarkGray
try {
    $Tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
    foreach ($Task in $Tasks) {
        $Actions = $Task.Actions | Where-Object { $_.Execute -imatch 'wscript|cscript' -or ($_.Arguments -imatch 'slmgr|\.vbs') }
        foreach ($Action in $Actions) {
            $Results.Add([PSCustomObject]@{
                Computer    = $env:COMPUTERNAME
                FilePath    = "ScheduledTask:\$($Task.TaskPath)$($Task.TaskName)"
                FileName    = $Task.TaskName
                Extension   = '.task'
                Pattern     = 'ScheduledTask'
                MatchedLine = "$($Action.Execute) $($Action.Arguments)"
                SizeKB      = 0
                LastModified = 'N/A'
            })
        }
    }
} catch {
    Write-Warning "Could not enumerate scheduled tasks: $_"
}

# Check if VBScript FoD is currently installed (indicates explicit dependency awareness)
Write-Host "  Checking: VBScript Feature on Demand status" -ForegroundColor DarkGray
$VBScriptFoD = $null
try {
    $VBScriptFoD = Get-WindowsCapability -Online -Name 'VBSCRIPT*' -ErrorAction Stop
} catch {
    Write-Warning "Could not check VBScript FoD: $_"
}

# Check current build vs OSLicense availability threshold
$BuildVersion = [System.Environment]::OSVersion.Version
$BuildNumber  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
$FullBuild    = "$($BuildVersion.Build).$BuildNumber"
$OSLicenseMinBuild  = 9278
$OSLicenseSupported = $BuildNumber -ge $OSLicenseMinBuild

# Output
Write-Host "`n--- Results ---" -ForegroundColor Cyan

if ($Results.Count -eq 0) {
    Write-Host "  No VBScript activation dependencies found." -ForegroundColor Green
} else {
    Write-Host "  Found $($Results.Count) file(s) with VBScript activation references:" -ForegroundColor Yellow
    $Results | Format-Table FilePath, MatchedLine, LastModified -AutoSize -Wrap
}

Write-Host "`n--- Environment Summary ---" -ForegroundColor Cyan
Write-Host "  OS Build:              $FullBuild" -ForegroundColor Gray
Write-Host "  OSLicense supported:   $(if ($OSLicenseSupported) { 'YES (build >= 26x00.9278)' } else { 'NO - requires September 2026 patch' })" -ForegroundColor $(if ($OSLicenseSupported) { 'Green' } else { 'Yellow' })
if ($VBScriptFoD) {
    Write-Host "  VBScript FoD state:    $($VBScriptFoD.State)" -ForegroundColor $(if ($VBScriptFoD.State -eq 'Installed') { 'Yellow' } else { 'Green' })
}
Write-Host "  Dependencies found:    $($Results.Count)" -ForegroundColor $(if ($Results.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($ExportCsv) {
    $OutDir  = "$env:ProgramData\EndpointWeekly"
    $OutFile = "$OutDir\VBScriptActivationAudit-$env:COMPUTERNAME.csv"
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
    $Results | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
    Write-Host "`n  CSV exported: $OutFile" -ForegroundColor Cyan
}

if ($script:hadError) {
    Write-Warning "Some files or paths could not be read. Check permissions."
    exit 2
}

exit $(if ($Results.Count -gt 0) { 1 } else { 0 })
