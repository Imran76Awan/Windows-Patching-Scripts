<#
.SYNOPSIS
    Checks whether a device can actually pass the TPM attestation step that
    Autopilot self-deploying and pre-provisioning modes depend on - the step
    shown on screen as "Securing your hardware".

.DESCRIPTION
    Read-only. Self-deploying and pre-provisioning modes authenticate the
    device into the tenant using TPM 2.0 device attestation. If the TPM is
    absent, not 2.0, or has no valid Endorsement Key (EK) certificate, that
    step fails - typically with a 0x800705B4 timeout rather than a clear
    "attestation unsupported" message.

    This script checks the four things attestation actually needs:
      1. A TPM that is present, enabled, activated and ready
      2. TPM spec version 2.0 (1.2 cannot be used for this)
      3. A valid EK certificate provisioned by the TPM manufacturer
      4. Whether this device already recorded a TPM attestation result during
         its own Autopilot run (from the ESP category status)

    Privacy: reports whether an EK certificate exists and how many were
    found. Never prints the EK certificate itself or its public key - that is
    a hardware identifier for this specific device.

.NOTES
    Blog post: https://endpointweekly.com/blog/autopilot-tpm-attestation-securing-your-hardware.html
    Run elevated - Get-Tpm and Get-TpmEndorsementKeyInfo require administrator
    rights.

.EXAMPLE
    .\Test-AutopilotTpmAttestationReadiness.ps1
#>

[CmdletBinding()]
param()

Write-Output "Autopilot TPM Attestation Readiness  (the 'Securing your hardware' step)"
Write-Output ("-" * 72)

$blockers = @()

# --- 1. Basic TPM state ----------------------------------------------------
try {
    $tpm = Get-Tpm -ErrorAction Stop
    Write-Output "TPM present / ready       : $($tpm.TpmPresent) / $($tpm.TpmReady)"
    Write-Output "TPM enabled / activated   : $($tpm.TpmEnabled) / $($tpm.TpmActivated)"
    Write-Output "Manufacturer              : $($tpm.ManufacturerIdTxt.Trim())  (version $($tpm.ManufacturerVersion.Trim()))"
    if (-not $tpm.TpmPresent) { $blockers += 'No TPM present - self-deploying and pre-provisioning cannot be used' }
    elseif (-not $tpm.TpmReady) { $blockers += 'TPM present but not ready - clear/initialise it in firmware' }
} catch {
    Write-Output "TPM query failed          : $($_.Exception.Message)"
    $blockers += 'Could not query the TPM (run elevated?)'
}

# --- 2. Spec version must be 2.0 -------------------------------------------
try {
    $wmiTpm = Get-CimInstance -Namespace 'root/cimv2/security/microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
    Write-Output "TPM spec version          : $($wmiTpm.SpecVersion)"
    if ($wmiTpm.SpecVersion -notmatch '^\s*2\.0') {
        $blockers += 'TPM is not spec 2.0 - attestation requires TPM 2.0'
    }
} catch {
    Write-Output "TPM spec version          : could not be determined"
}

# --- 3. EK certificate - the actual attestation identity -------------------
try {
    $ek = Get-TpmEndorsementKeyInfo -HashAlgorithm sha256 -ErrorAction Stop
    Write-Output "EK certificate present    : $($ek.IsPresent)"
    Write-Output "  Manufacturer certs      : $($ek.ManufacturerCertificates.Count)  (contents deliberately NOT printed)"
    Write-Output "  Additional certs        : $($ek.AdditionalCertificates.Count)"
    if (-not $ek.IsPresent -or $ek.ManufacturerCertificates.Count -eq 0) {
        $blockers += 'No valid EK certificate - attestation will fail (logs show NoValidEkCert)'
    }
} catch {
    Write-Output "EK certificate query      : failed - $($_.Exception.Message)"
    $blockers += 'Could not read EK certificate info'
}

# --- 4. Is this a VM? Virtual TPMs are explicitly unsupported here ---------
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Write-Output "Model / manufacturer      : $($cs.Manufacturer) / $($cs.Model)"
    if ($cs.Model -match 'Virtual|VMware|VirtualBox|KVM|Xen' -or $cs.Manufacturer -match 'Microsoft Corporation.*Virtual|VMware|innotek|QEMU') {
        $blockers += 'Looks like a virtual machine - Microsoft explicitly does not support self-deploying/pre-provisioning on VMs, including Hyper-V virtual TPMs (fails 0x800705B4)'
    }
} catch { }

# --- 5. What did this device's own Autopilot run record? -------------------
$apKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotSettings'
if (Test-Path $apKey) {
    $s = Get-ItemProperty $apKey
    $raw = $s.'DevicePreparationCategory.Status'
    if ($raw) {
        try {
            $obj = $raw | ConvertFrom-Json
            $sub = $obj.'DevicePreparation.TpmAttestationSubcategory'
            if ($sub) {
                Write-Output ""
                Write-Output "This device's recorded attestation result during its own Autopilot run:"
                Write-Output "  state      : $($sub.subcategoryState)"
                Write-Output "  statusText : $($sub.subcategoryStatusText)"
            }
        } catch { }
    }
    $timeout = $s.TpmAikTaskMaxTimeoutMilliseconds
    if ($timeout) {
        Write-Output "  attestation task timeout : $timeout ms"
    }
}

# --- Verdict ---------------------------------------------------------------
Write-Output ""
if ($blockers.Count -eq 0) {
    Write-Output "Result: READY - this device meets the TPM attestation prerequisites for"
    Write-Output "        Autopilot self-deploying and pre-provisioning modes."
    exit 0
} else {
    Write-Output "Result: NOT READY - attestation would be expected to fail:"
    foreach ($b in $blockers) { Write-Output "  - $b" }
    Write-Output ""
    Write-Output "Note: attestation also needs outbound HTTPS to a set of URLs that differ"
    Write-Output "per TPM vendor. A device that passes every check above and still fails"
    Write-Output "'Securing your hardware' is usually a blocked vendor attestation URL."
    exit 1
}
