<#
.SYNOPSIS
    Detects whether Secure Boot is enabled in UEFI firmware on a Lenovo device,
    for use as the detection half of an Intune Proactive Remediation.

.DESCRIPTION
    A device that shows "Not applicable" in Intune's Secure Boot status report
    is not a reporting glitch - it means Secure Boot is switched off in UEFI
    firmware on that device. This script reads the current Secure Boot setting
    directly from the Lenovo BIOS via WMI and reports compliant/non-compliant.

    Read-only. Makes no changes to the device. Pair with
    Remediate-SecureBootLenovo.ps1 for the remediation half.

.NOTES
    Blog post: https://endpointweekly.com/blog/secure-boot-not-applicable-lenovo-bios-remediation.html
    Vendor-specific: this uses the Lenovo_BiosSetting WMI class and only works
    on Lenovo hardware. Other OEMs expose BIOS settings through their own,
    different WMI namespaces - this script will not detect anything meaningful
    on non-Lenovo devices.

    Exit 0 = Compliant (Secure Boot enabled)
    Exit 1 = Not compliant (remediation required)

.EXAMPLE
    .\Detect-SecureBootLenovo.ps1
    Run standalone to check a single device, or deploy as the detection
    script in an Intune Proactive Remediation targeting Lenovo devices.
#>

try {
    $SecureBoot = Get-WmiObject -Class Lenovo_BiosSetting -Namespace root\WMI -ErrorAction Stop |
                  Where-Object { $_.CurrentSetting -match "SecureBoot" } |
                  Select-Object -ExpandProperty CurrentSetting

    if ($SecureBoot -eq "SecureBoot,Enable") {
        Write-Host "Compliant: SecureBoot is enabled."
        exit 0
    }
    elseif ($SecureBoot -eq "SecureBoot,Disable") {
        Write-Host "Not Compliant: SecureBoot is disabled."
        exit 1
    }
    else {
        Write-Host "Not Compliant: SecureBoot setting not found or unrecognised value: $SecureBoot"
        exit 1
    }
}
catch {
    Write-Host "Error querying Lenovo BIOS WMI: $_"
    exit 1
}
