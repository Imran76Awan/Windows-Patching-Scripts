<#
.SYNOPSIS
    Detects Windows 11 devices affected by the KB5124008 File History regression.

.DESCRIPTION
    Read-only diagnostic script. Checks whether the local device has KB5124008 installed,
    has File History configured and enabled, and is showing symptoms of the backup failure —
    a stale Last Backup timestamp and/or FileHistory.exe crash events in the Application log.

    Does NOT modify any system state. Safe to run on production devices.

.PARAMETER BackupStaleDays
    Number of days since the last backup timestamp before a device is considered symptomatic.
    Default: 7 (one week). Lower this on devices configured for hourly backup.

.NOTES
    Blog:   https://endpointweekly.com/blog/kb5124008-file-history-reconnect-drive-error-windows-11.html
    Repo:   https://github.com/Imran76Awan/Windows-Patching-Scripts/tree/main/kb5124008-file-history-reconnect-drive-error-windows-11

.EXAMPLE
    .\Get-FileHistoryKB5124008Status.ps1

.EXAMPLE
    .\Get-FileHistoryKB5124008Status.ps1 -BackupStaleDays 3
#>

[CmdletBinding()]
param(
    [int]$BackupStaleDays = 7
)

$result = [ordered]@{
    ComputerName         = $env:COMPUTERNAME
    OSBuild              = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    DisplayVersion       = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    KB5124008Present     = $false
    KB5129195Present     = $false
    FileHistoryEnabled   = $false
    FileHistoryTargetUrl = $null
    LastBackupDate       = $null
    BackupStaleDays      = $null
    CrashesFound         = 0
    LastCrashTime        = $null
    Verdict              = 'NOT AFFECTED'
}

# 1. Confirm patch state
$result.KB5124008Present = [bool](Get-HotFix -Id KB5124008 -ErrorAction SilentlyContinue)
$result.KB5129195Present = [bool](Get-HotFix -Id KB5129195 -ErrorAction SilentlyContinue)

# 2. Check File History registry (current user hive — run as the user or as SYSTEM with user hive loaded)
$fhReg = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\FileHistory' -ErrorAction SilentlyContinue
if ($fhReg) {
    $result.FileHistoryEnabled   = [bool]($fhReg.Enabled -eq 1)
    $result.FileHistoryTargetUrl = $fhReg.TargetUrl
}

# 3. Read last backup timestamp from File History XML config
$configPath = "$env:LOCALAPPDATA\Microsoft\Windows\FileHistory\Configuration\Config"
if (Test-Path $configPath) {
    try {
        [xml]$config = Get-Content $configPath -ErrorAction Stop
        $lastBackupNode = $config.SelectSingleNode('//LastBackupTime')
        if ($lastBackupNode -and $lastBackupNode.InnerText) {
            $result.LastBackupDate  = [datetime]$lastBackupNode.InnerText
            $result.BackupStaleDays = [math]::Round(((Get-Date) - $result.LastBackupDate).TotalDays, 1)
        }
    } catch {}
}

# 4. Count FileHistory.exe crash events in the Application log (Event ID 1000)
try {
    $crashes = Get-WinEvent -LogName Application -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1000 -and $_.Message -like '*FileHistory.exe*' } |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 10

    $result.CrashesFound  = $crashes.Count
    if ($crashes) { $result.LastCrashTime = $crashes[0].TimeCreated }
} catch {}

# 5. Verdict
if ($result.KB5124008Present) {
    if (-not $result.FileHistoryEnabled) {
        $result.Verdict = 'EXPOSED - KB5124008 present but File History not configured or disabled'
    } elseif ($result.CrashesFound -gt 0 -or ($result.BackupStaleDays -and $result.BackupStaleDays -gt $BackupStaleDays)) {
        $result.Verdict = 'AFFECTED - File History backup failing since KB5124008'
    } else {
        $result.Verdict = 'MONITOR - KB5124008 present, File History enabled, no crash events found yet'
    }
} else {
    $result.Verdict = 'NOT AFFECTED - KB5124008 not installed'
}

$result | Format-List
