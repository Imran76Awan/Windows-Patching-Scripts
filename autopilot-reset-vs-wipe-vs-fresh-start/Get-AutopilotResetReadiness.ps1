<#
.SYNOPSIS
    Reports whether Autopilot Reset can actually be used on this device, and
    which of Autopilot Reset / Wipe / Fresh Start is applicable.

.DESCRIPTION
    Read-only. Autopilot Reset has two hard prerequisites that are easy to
    miss, and one that surprises people:

      1. The Windows Recovery Environment (WinRE) must be configured and
         enabled. If it is not, Autopilot Reset fails immediately with
         ERROR_NOT_SUPPORTED (0x80070032).
      2. Local Autopilot Reset (CTRL + WIN + R at the lock screen) is disabled
         by default and must be allowed by policy.
      3. Autopilot Reset does NOT support Microsoft Entra hybrid joined
         devices. Those need a full Wipe instead - and after a full reset a
         hybrid device can take up to 24 hours to be ready to deploy again.

    This script checks all three and tells you which reset action actually
    applies to this device.

.NOTES
    Blog post: https://endpointweekly.com/blog/autopilot-reset-vs-wipe-vs-fresh-start.html
    Run elevated - reagentc and the Provisioning registry hive require
    administrator rights.

.EXAMPLE
    .\Get-AutopilotResetReadiness.ps1
#>

[CmdletBinding()]
param()

Write-Output "Autopilot Reset Readiness"
Write-Output ("-" * 62)

$blockers = @()

# --- 1. WinRE must be enabled ----------------------------------------------
try {
    $re = reagentc.exe /info 2>&1
    $statusLine = $re | Where-Object { $_ -match 'Windows RE status' }
    $locLine    = $re | Where-Object { $_ -match 'Windows RE location' }
    $verLine    = $re | Where-Object { $_ -match 'Windows RE Version' }
    if ($statusLine) {
        $enabled = $statusLine -match 'Enabled'
        Write-Output ("WinRE status              : {0}" -f ($statusLine -replace '.*:\s*',''))
        if ($locLine) { Write-Output ("WinRE location            : {0}" -f ($locLine -replace '.*:\s*','')) }
        if ($verLine) { Write-Output ("WinRE version             : {0}" -f ($verLine -replace '.*:\s*','')) }
        if (-not $enabled) {
            $blockers += 'WinRE is not enabled - Autopilot Reset fails immediately with 0x80070032. Fix: reagentc.exe /enable'
        }
    } else {
        Write-Output "WinRE status              : could not be determined"
        $blockers += 'Could not determine WinRE state'
    }
} catch {
    Write-Output "WinRE query failed        : $($_.Exception.Message)"
    $blockers += 'reagentc.exe could not be run (elevated?)'
}

# --- 2. Join type - hybrid blocks Autopilot Reset entirely -----------------
$isHybrid = $false
try {
    $ds = dsregcmd /status 2>&1
    $aadj = ($ds | Where-Object { $_ -match '^\s*AzureAdJoined\s*:' }) -replace '.*:\s*',''
    $dj   = ($ds | Where-Object { $_ -match '^\s*DomainJoined\s*:' })  -replace '.*:\s*',''
    Write-Output ""
    Write-Output "AzureAdJoined             : $aadj"
    Write-Output "DomainJoined              : $dj"
    if ($aadj -match 'YES' -and $dj -match 'YES') {
        $isHybrid = $true
        Write-Output "Join type                 : Microsoft Entra HYBRID joined"
        $blockers += 'Autopilot Reset does NOT support Entra hybrid joined devices - use Wipe instead. Expect up to 24h before the device can be redeployed (expedite by re-registering it).'
    } elseif ($aadj -match 'YES') {
        Write-Output "Join type                 : Microsoft Entra joined (cloud only)"
    } else {
        Write-Output "Join type                 : not Entra joined"
        $blockers += 'Device is not Entra joined - Autopilot Reset requires Entra join + MDM management'
    }
} catch {
    Write-Output "dsregcmd query failed."
}

# --- 3. Local Autopilot Reset policy --------------------------------------
# CredentialProviders/DisableAutomaticReDeploymentCredentials: 0 = allowed
Write-Output ""
$found = $false
foreach ($p in @(
    'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\CredentialProviders',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System')) {
    if (Test-Path $p) {
        $v = (Get-ItemProperty $p -ErrorAction SilentlyContinue).DisableAutomaticReDeploymentCredentials
        if ($null -ne $v) {
            $found = $true
            $meaning = if ($v -eq 0) { 'allowed (CTRL+WIN+R works at the lock screen)' } else { 'BLOCKED (default)' }
            Write-Output "Local reset policy        : DisableAutomaticReDeploymentCredentials = $v - $meaning"
            if ($v -ne 0) { $blockers += 'Local Autopilot Reset is blocked by policy - set Autopilot Reset = Allow in an Intune Device restrictions profile' }
        }
    }
}
if (-not $found) {
    Write-Output "Local reset policy        : not configured - local reset is DISABLED by default"
    Write-Output "                            (remote Autopilot Reset from Intune is unaffected)"
}

# --- Verdict ---------------------------------------------------------------
Write-Output ""
if ($blockers.Count -eq 0) {
    Write-Output "Result: Autopilot Reset is usable on this device."
    exit 0
} else {
    Write-Output "Result: Autopilot Reset is NOT straightforwardly usable here:"
    foreach ($b in $blockers) { Write-Output "  - $b" }
    Write-Output ""
    if ($isHybrid) {
        Write-Output "Recommended action for this device: Wipe (full factory reset), not Autopilot Reset."
    }
    exit 1
}
