<#
.SYNOPSIS
    Enables Secure Boot in UEFI firmware on a Lenovo device via WMI, for use
    as the remediation half of an Intune Proactive Remediation.

.DESCRIPTION
    Pairs with Detect-SecureBootLenovo.ps1. Performs, in order:
        1. Disables the BitLocker scheduled tasks that would otherwise
           re-suspend/resume protection mid-run and race with this script.
        2. Suspends BitLocker protection on C: (for one restart only) before
           touching any BIOS setting - a Secure Boot state change alters the
           boot chain measurements BitLocker is keyed against, and doing this
           on a still-active volume is what triggers an unwanted recovery-key
           prompt on next boot.
        3. Confirms the Lenovo BIOS WMI namespace is reachable.
        4. Authenticates to the BIOS with your org's admin password (see the
           SET-BIOS-PASSWORD-HERE placeholder below) and sets SecureBoot to
           Enable.
        5. Logs every step to C:\Windows\Logs\Scripts\SecureBootRemediation.log.

.NOTES
    Blog post: https://endpointweekly.com/blog/secure-boot-not-applicable-lenovo-bios-remediation.html
    Vendor-specific: Lenovo_BiosSetting / Lenovo_SetBiosSetting /
    Lenovo_SaveBiosSettings are Lenovo-only WMI classes. This will not work
    on other OEMs' hardware.

    BEFORE YOU RUN THIS: replace SET-BIOS-PASSWORD-HERE below with your own
    organisation's actual BIOS admin password. This script ships with no
    real password in it - it is not omitted by mistake, it never should
    contain one. If your fleet has more than one BIOS password in use across
    different hardware generations, add each one as its own entry in the
    $BiosPasswords array below and the script tries each in turn.

    Exit 0 = Remediation successful (or already compliant)
    Exit 1 = Remediation failed

.EXAMPLE
    .\Remediate-SecureBootLenovo.ps1
    Deploy as the remediation script in an Intune Proactive Remediation,
    paired with Detect-SecureBootLenovo.ps1, targeting Lenovo devices.
#>

## ============================================================================
## CONFIGURE THIS BEFORE DEPLOYING - replace with your org's real BIOS password(s).
## Add one entry per password in use across your fleet's hardware generations.
$BiosPasswords = @(
    "SET-BIOS-PASSWORD-HERE"
)
## ============================================================================

$Encoding = ",ascii,us"
$LogDir   = "C:\Windows\Logs\Scripts"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

Start-Transcript -Path "$LogDir\SecureBootRemediation.log" -Append -Force

try {

    ## --- Disable BitLocker scheduled tasks so they can't race this script ---
    Write-Host "Disabling BitLocker scheduled tasks..."
    foreach ($task in @("BL-TakeAction2", "BL-Suspend2", "BL-Unsuspend2")) {
        try   { Disable-ScheduledTask -TaskName $task -ErrorAction Stop; Write-Host "  Disabled: $task" }
        catch { Write-Host "  Task not found or already disabled: $task" }
    }

    ## --- Suspend BitLocker and VERIFY it is actually suspended before continuing ---
    Write-Host "Suspending BitLocker..."
    try {
        $BLStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop

        if ($BLStatus.ProtectionStatus -eq "On") {
            Suspend-BitLocker -MountPoint "C:" -RebootCount 1 -ErrorAction Stop

            ## Verify suspension took effect
            $BLCheck = Get-BitLockerVolume -MountPoint "C:"
            Write-Host "  BitLocker Protection Status after suspend: $($BLCheck.ProtectionStatus)"

            if ($BLCheck.ProtectionStatus -ne "Off") {
                Write-Host "  WARNING: BitLocker did not suspend as expected. Proceeding anyway."
            }
        } else {
            Write-Host "  BitLocker already suspended or not active. Status: $($BLStatus.ProtectionStatus)"
        }
    } catch {
        Write-Host "  BitLocker check/suspend error (non-fatal): $_"
    }

    ## --- Confirm WMI namespace is reachable ---
    Write-Host "Checking Lenovo WMI namespace..."
    try {
        Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI -ErrorAction Stop | Select-Object -First 1 | Out-Null
        Write-Host "  WMI namespace: accessible"
    } catch {
        Write-Host "  ERROR: Cannot access Lenovo WMI namespace."
        Stop-Transcript
        exit 1
    }

    ## --- Read current SecureBoot state ---
    $SBObject = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI |
                Where-Object { $_.CurrentSetting -match "SecureBoot" }

    if (-not $SBObject) {
        Write-Host "ERROR: SecureBoot setting not found in Lenovo WMI."
        Stop-Transcript
        exit 1
    }

    $SecureBootValue = $SBObject.CurrentSetting
    Write-Host "Current SecureBoot value: $SecureBootValue"

    if ($SecureBootValue -eq "SecureBoot,Enable") {
        Write-Host "SecureBoot is already enabled. No action needed."
        Stop-Transcript
        exit 0
    }

    ## --- Find a working BIOS password from the list above ---
    Write-Host "Testing BIOS password..."
    $WorkingPassword = $null

    foreach ($PlainPassword in $BiosPasswords) {
        $EncodedPassword = $PlainPassword + $Encoding
        $Test = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi).SaveBiosSettings($EncodedPassword).return
        Write-Host "  Password test result: $Test"

        if ($Test -eq "Success") {
            $WorkingPassword = $EncodedPassword
            break
        }
    }

    if (-not $WorkingPassword) {
        Write-Host "ERROR: No configured BIOS password was accepted. Update `$BiosPasswords at the top of this script."
        Stop-Transcript
        exit 1
    }

    ## --- Enable SecureBoot via WMI ---
    Write-Host "Setting SecureBoot to Enable..."
    $SetResult  = (Get-WmiObject -Class Lenovo_SetBiosSetting  -Namespace root\wmi).SetBiosSetting("SecureBoot,Enable" + "," + $WorkingPassword).return
    Write-Host "  SetBiosSetting result:   $SetResult"

    $SaveResult = (Get-WmiObject -Class Lenovo_SaveBiosSettings -Namespace root\wmi).SaveBiosSettings($WorkingPassword).return
    Write-Host "  SaveBiosSettings result: $SaveResult"

    if ($SaveResult -ne "Success") {
        Write-Host "FAILED: Could not save BIOS settings. Result: $SaveResult"
        Stop-Transcript
        exit 1
    }

    Write-Host "SUCCESS: SecureBoot enabled. Device will apply the change on next restart."
    Stop-Transcript
    exit 0

}
catch {
    Write-Host "Unhandled error: $_"
    Stop-Transcript
    exit 1
}
