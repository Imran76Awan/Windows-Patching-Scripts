<#
.SYNOPSIS
    Reports this device's real progress through all four CVE-2023-24932
    (BlackLotus) Secure Boot mitigations - not just whether the certificate
    has been installed.

.DESCRIPTION
    Read-only. Decodes the AvailableUpdates bitmask under
    HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot, and independently
    verifies two of the four stages directly against the UEFI firmware
    (Get-SecureBootUEFI db/dbx) and the Secure Version Number
    (Get-SecureBootSVN), rather than trusting the registry bit alone.

    The four mitigations, in required order:
      1. Windows UEFI CA 2023 certificate added to the firmware DB   (bit 0x40)
      2. Boot manager replaced with a 2023-signed version            (bit 0x100)
      3. Windows Production PCA 2011 revoked via the DBX              (bit 0x80)
      4. Secure Version Number (SVN) enforcement applied               (bit 0x200)

    Makes no changes to the system. Exits 1 if any mitigation is missing,
    0 if all four are confirmed, so this can be dropped into an Intune
    Proactive Remediation or a ConfigMgr Configuration Item as-is.

.NOTES
    Blog post: https://endpointweekly.com/blog/blacklotus-secure-boot-four-mitigations-configmgr-tracking.html
    Requires: Windows 10/11 with Secure Boot enabled. Run elevated -
    Get-SecureBootUEFI requires administrator rights.
    Prerequisite: devices must be on the July 8, 2025 cumulative update
    or later before mitigations can apply at all.

.EXAMPLE
    .\Get-BlackLotusMitigationStatus.ps1
#>

[CmdletBinding()]
param()

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

Write-Output "BlackLotus (CVE-2023-24932) Mitigation Status"
Write-Output ("-" * 60)

if (-not (Test-Admin)) {
    Write-Output "WARNING: not running elevated - Get-SecureBootUEFI checks will fail."
    Write-Output "Re-run this script as Administrator for a complete result."
    Write-Output ""
}

$secureBootPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot'
$available = (Get-ItemProperty -Path $secureBootPath -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates
if ($null -eq $available) { $available = 0 }
Write-Output ("AvailableUpdates registry value : 0x{0:X}" -f $available)
Write-Output "(A non-zero value here means at least one mitigation is still pending - the"
Write-Output " scheduled task below clears each bit as its mitigation completes.)"
Write-Output ""

$results = [ordered]@{}

# Mitigation 1: 2023 CA cert in DB - verify against real firmware, not just the bit
try {
    $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
    $dbText = [System.Text.Encoding]::ASCII.GetString($dbBytes)
    $results['1. UEFI CA 2023 cert in DB'] = ($dbText -match 'Windows UEFI CA 2023')
} catch {
    $results['1. UEFI CA 2023 cert in DB'] = 'UNKNOWN - Get-SecureBootUEFI failed (run elevated?)'
}

# Mitigation 2: boot manager signed by 2023 CA - the registry bit is the most reliable local signal
$results['2. Boot manager is 2023-signed'] = -not [bool]($available -band 0x100)

# Mitigation 3: 2011 boot manager revoked via DBX - verify against real firmware
try {
    $dbxBytes = (Get-SecureBootUEFI dbx -ErrorAction Stop).bytes
    $dbxText = [System.Text.Encoding]::ASCII.GetString($dbxBytes)
    $results['3. 2011 boot manager revoked (DBX)'] = ($dbxText -match 'Microsoft Windows Production PCA 2011')
} catch {
    $results['3. 2011 boot manager revoked (DBX)'] = 'UNKNOWN - Get-SecureBootUEFI failed (run elevated?)'
}

# Mitigation 4: SVN enforcement - Get-SecureBootSVN exposes a ready-made ComplianceStatus
try {
    $svn = Get-SecureBootSVN -ErrorAction Stop
    $results['4. SVN enforcement applied'] = ($svn.ComplianceStatus -match '^Compliant')
    $script:svnDetail = $svn
} catch {
    $results['4. SVN enforcement applied'] = 'UNKNOWN - Get-SecureBootSVN failed or not available on this OS build'
}

Write-Output "Mitigation status:"
foreach ($k in $results.Keys) {
    Write-Output ("  {0,-38} : {1}" -f $k, $results[$k])
}
if ($script:svnDetail) {
    Write-Output ("    (SVN detail: FirmwareSVN={0} BootManagerSVN={1} StagedSVN={2} - {3})" -f `
        $script:svnDetail.FirmwareSVN, $script:svnDetail.BootManagerSVN, $script:svnDetail.StagedSVN, $script:svnDetail.ComplianceStatus)
}

$knownBits = 0x40 -bor 0x80 -bor 0x100 -bor 0x200
$unmappedBits = $available -band (-bnot $knownBits)
if ($unmappedBits -ne 0) {
    Write-Output ""
    Write-Output ("  Note: AvailableUpdates also has bit(s) 0x{0:X} set that are not among the four" -f $unmappedBits)
    Write-Output "  documented mitigation flags (0x40/0x80/0x100/0x200) - Microsoft has extended this"
    Write-Output "  bitmask over time (e.g. KEK 2K CA rollout), so treat the independently-verified"
    Write-Output "  checks above as authoritative, not the raw registry value on its own."
}

Write-Output ""
$task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction SilentlyContinue
if ($task) {
    Write-Output "Scheduled task \Microsoft\Windows\PI\Secure-Boot-Update state: $($task.State)"
    Write-Output "(This task re-checks every 12 hours and applies whichever bits are still set."
    Write-Output " Trigger it manually with: Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update')"
} else {
    Write-Output "Scheduled task \Microsoft\Windows\PI\Secure-Boot-Update not found - device may predate the prerequisite update."
}

$allConfirmedTrue = ($results.Values | Where-Object { $_ -is [bool] } | Where-Object { $_ -eq $false }).Count -eq 0
$anyUnknown = ($results.Values | Where-Object { $_ -is [string] }).Count -gt 0

Write-Output ""
if ($anyUnknown) {
    Write-Output "Result: INCOMPLETE CHECK - re-run elevated to confirm all four mitigations."
    exit 1
} elseif ($allConfirmedTrue -and $available -eq 0) {
    Write-Output "Result: ALL FOUR MITIGATIONS CONFIRMED - device is fully protected against CVE-2023-24932."
    exit 0
} else {
    Write-Output "Result: NOT YET COMPLETE - one or more mitigations still pending."
    exit 1
}
