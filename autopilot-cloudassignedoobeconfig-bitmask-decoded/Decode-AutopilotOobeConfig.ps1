<#
.SYNOPSIS
    Decodes the CloudAssignedOobeConfig bitmask on an Autopilot-provisioned
    device into the individual OOBE behaviours it actually applied.

.DESCRIPTION
    Read-only. CloudAssignedOobeConfig is a single REG_DWORD under
    HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot that encodes
    several OOBE decisions as bits. This script decodes the bits that
    Microsoft has publicly documented, and - importantly - explicitly reports
    any bits that are set but NOT publicly documented, rather than guessing at
    a meaning for them.

    Publicly documented bits:
      0x01  (1)   SkipCortanaOptIn
      0x02  (2)   OobeUserNotLocalAdmin
      0x04  (4)   SkipExpressSettings
      0x08  (8)   SkipOemRegistration
      0x10  (16)  SkipEula

    Anything else set in the value is reported as undocumented. Microsoft has
    extended this bitmask over time and does not publish a complete current
    map, so treat an undocumented bit as "unknown", never as a guess.

.NOTES
    Blog post: https://endpointweekly.com/blog/autopilot-cloudassignedoobeconfig-bitmask-decoded.html
    Run elevated - the Provisioning registry hive requires administrator rights.

.EXAMPLE
    .\Decode-AutopilotOobeConfig.ps1

.EXAMPLE
    .\Decode-AutopilotOobeConfig.ps1 -Value 1308
    Decode a value captured from another device without reading this one.
#>

[CmdletBinding()]
param(
    [int]$Value
)

# NOTE: deliberately an array of objects, not [ordered]@{1=...;2=...}.
# An OrderedDictionary with INTEGER keys resolves $dict[1] as the element at
# INDEX 1, not the value for KEY 1 - which silently shifts every label by one
# position. Using explicit objects avoids that trap entirely.
$documented = @(
    [pscustomobject]@{ Bit = 1;  Name = 'SkipCortanaOptIn' }
    [pscustomobject]@{ Bit = 2;  Name = 'OobeUserNotLocalAdmin' }
    [pscustomobject]@{ Bit = 4;  Name = 'SkipExpressSettings' }
    [pscustomobject]@{ Bit = 8;  Name = 'SkipOemRegistration' }
    [pscustomobject]@{ Bit = 16; Name = 'SkipEula' }
)

Write-Output "CloudAssignedOobeConfig Decoder"
Write-Output ("-" * 62)

if (-not $PSBoundParameters.ContainsKey('Value')) {
    $key = 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot'
    if (-not (Test-Path $key)) {
        Write-Output "No Autopilot diagnostics key on this device - pass -Value <int> to decode"
        Write-Output "a value captured elsewhere."
        exit 2
    }
    $prop = Get-ItemProperty $key -Name CloudAssignedOobeConfig -ErrorAction SilentlyContinue
    if ($null -eq $prop.CloudAssignedOobeConfig) {
        Write-Output "CloudAssignedOobeConfig not set on this device."
        exit 2
    }
    $Value = [int]$prop.CloudAssignedOobeConfig
    Write-Output "Source                 : this device's registry"
} else {
    Write-Output "Source                 : -Value supplied on the command line"
}

Write-Output ("CloudAssignedOobeConfig : {0}  (0x{0:X})" -f $Value)
Write-Output ""

Write-Output "Documented bits:"
$documentedMask = 0
foreach ($entry in $documented) {
    $documentedMask = $documentedMask -bor $entry.Bit
    $isSet = [bool]($Value -band $entry.Bit)
    $mark  = if ($isSet) { 'SET    ' } else { 'not set' }
    Write-Output ("  0x{0:X2} ({1,4})  {2}  {3}" -f $entry.Bit, $entry.Bit, $mark, $entry.Name)
}

$undocumented = $Value -band (-bnot $documentedMask)
Write-Output ""
if ($undocumented -ne 0) {
    Write-Output ("Undocumented bits also set: 0x{0:X} ({0})" -f $undocumented)
    Write-Output "  Microsoft has extended this bitmask over time and does not publish a"
    Write-Output "  complete current map. These bits are real and deliberately set by your"
    Write-Output "  profile, but their meaning is NOT publicly documented - do not guess."
    Write-Output "  Confirm the corresponding behaviour from the profile in the Intune portal"
    Write-Output "  (Devices > Enrollment > Deployment Profiles) rather than from this number."
} else {
    Write-Output "No undocumented bits set - this value is fully explained by the documented map."
}

exit 0
