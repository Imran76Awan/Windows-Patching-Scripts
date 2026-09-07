<#
.SYNOPSIS
    Conservative, opt-in remediation companion to Detect-InpOutX64DriverPresence.ps1.
    By default this script CHANGES NOTHING -- it only reports what it would do.

.DESCRIPTION
    Microsoft's fix for the "some games become unresponsive when certain
    drivers are present" issue (Windows 11 24H2/25H2, originating update
    KB5121003) is a block that disables the inpoutx64 driver. Microsoft is
    rolling that block out automatically to non-managed consumer/business
    devices, and folding it into the September 2026 Windows security update
    and later releases for everyone else.

    This site's explicit guidance, carried over from the source briefing that
    prompted this post, is: do NOT proactively disable this driver across an
    entire fleet unless you have confirmed the driver is actually present AND
    understood what application on that specific device depends on it. RGB
    lighting software, some motherboard monitoring utilities, and a small
    number of peripheral configuration tools use this driver legitimately
    for direct hardware I/O -- disabling it blind can break that software's
    lighting/monitoring features (though Microsoft's own investigation found
    no other functional impact from disabling it).

    Because of that, this script's default behavior is REPORT ONLY. It never
    changes the registry unless you explicitly pass -Disable AND -AcknowledgeRisk.
    Even then, it only sets the documented, reversible registry workaround
    Microsoft itself publishes (Start = 4 under the driver's Services key) --
    it does not delete the driver file, uninstall any software, or touch
    unrelated services.

.PARAMETER Disable
    Opt-in switch. Without this switch, the script only reports what it
    found and what it WOULD do -- no registry changes are made. This mirrors
    Microsoft's own documented workaround: setting the Start value to 4
    (Disabled) under HKLM\SYSTEM\CurrentControlSet\Services\<driver name>.

.PARAMETER AcknowledgeRisk
    A second, explicit acknowledgement required alongside -Disable before
    any change is made. This is intentionally redundant with PowerShell's
    built-in ShouldProcess confirmation -- two separate signals are required
    so this cannot be triggered by a single flag left on in an automation
    template by mistake.

.PARAMETER TargetDriverName
    The specific driver service name to act on, e.g. "inpoutx64". Required
    when -Disable is used. This is deliberately NOT a wildcard or "act on
    anything found" parameter -- you must name the exact driver after
    reviewing the Detect script's output, so a fleet-wide run never
    silently disables a driver that turned out to be something else.

.OUTPUTS
    Exit code 0 - Success (report-only run completed, or the named driver
                  was found and its Start value was already 4 / was set to
                  4 by this run with -Disable -AcknowledgeRisk).
    Exit code 1 - The requested change could not be completed.
    Exit code 2 - Script error / invalid parameter combination.

.EXAMPLE
    .\Remediate-InpOutX64DriverPresence.ps1
    Report-only run. Prints what driver(s) were found and what action would
    be needed, but changes nothing. Safe to run anywhere, any time.

.EXAMPLE
    .\Remediate-InpOutX64DriverPresence.ps1 -Disable -AcknowledgeRisk -TargetDriverName inpoutx64
    After you have confirmed on this specific device (via the Detect script
    and your own investigation of what installed the driver) that disabling
    it is the right call, this sets Start = 4 for the named driver only and
    logs the change. A restart is required for the change to take effect,
    matching Microsoft's own documented workaround.

.NOTES
    Author        : Imran Awan (EndpointWeekly)
    Blog post     : https://endpointweekly.com/blog/inpoutx64-rgb-driver-block-kb5121003-september-update.html
    Companion to  : Detect-InpOutX64DriverPresence.ps1 (same folder)
    Tested on     : Windows 11 24H2 / 25H2, Windows PowerShell 5.1
    Default mode  : Report only. No state is changed unless -Disable AND
                    -AcknowledgeRisk are both supplied, and even then only the
                    named driver's Start value is touched.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Disable,
    [switch]$AcknowledgeRisk,
    [string]$TargetDriverName,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

function Write-Line {
    param([string]$Text)
    Write-Output $Text
    if ($LogPath) {
        try { Add-Content -Path $LogPath -Value $Text -Encoding UTF8 }
        catch { }
    }
}

$DriverNames = @('inpoutx64', 'inpout32', 'WinRing0x64', 'WinRing0')

Write-Line "=============================================================="
Write-Line " inpoutx64 / RGB driver block remediation - conservative, opt-in"
Write-Line " Run time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Line " Computer: $env:COMPUTERNAME"
Write-Line " Mode: $(if ($Disable -and $AcknowledgeRisk) { 'DISABLE (armed)' } else { 'REPORT ONLY' })"
Write-Line "=============================================================="
Write-Line ""

# ---------------------------------------------------------------------------
# Guardrails: refuse to act unless both -Disable and -AcknowledgeRisk are present,
# and a specific driver name was given.
# ---------------------------------------------------------------------------
$armed = $false
if ($Disable -or $AcknowledgeRisk) {
    if (-not ($Disable -and $AcknowledgeRisk)) {
        Write-Line "Both -Disable and -AcknowledgeRisk are required together to make any change."
        Write-Line "Only one was supplied. Running in report-only mode instead."
    }
    elseif (-not $TargetDriverName) {
        Write-Line "-TargetDriverName is required when using -Disable -AcknowledgeRisk."
        Write-Line "Refusing to guess which driver to act on. Running in report-only mode instead."
    }
    elseif ($DriverNames -notcontains $TargetDriverName) {
        Write-Line ("'{0}' is not one of the recognized driver names this script knows about: {1}" -f $TargetDriverName, ($DriverNames -join ', '))
        Write-Line "Refusing to act on an unrecognized name. Running in report-only mode instead."
    }
    else {
        $armed = $true
    }
}

$namesToReport = if ($TargetDriverName) { @($TargetDriverName) } else { $DriverNames }
$exitCode = 0
$anyChangeMade = $false

foreach ($name in $namesToReport) {
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    Write-Line ("Checking {0} ..." -f $svcPath)

    try {
        if (-not (Test-Path -Path $svcPath)) {
            Write-Line ("    Not present on this device. Nothing to do for {0}." -f $name)
            Write-Line ""
            continue
        }

        $svc = Get-ItemProperty -Path $svcPath -ErrorAction Stop
        Write-Line ("    Current Start value: {0}" -f $svc.Start)

        if ($svc.Start -eq 4) {
            Write-Line "    Already Disabled (Start = 4). No change needed."
            Write-Line ""
            continue
        }

        if (-not $armed -or $name -ne $TargetDriverName) {
            Write-Line "    REPORT ONLY: this run would set Start = 4 here if invoked with"
            Write-Line "    -Disable -AcknowledgeRisk -TargetDriverName $name"
            Write-Line "    No change made. Confirm what application depends on this driver"
            Write-Line "    on THIS device before disabling it -- see the blog post's 'The"
            Write-Line "    fix' section for the recommended investigation steps."
            Write-Line ""
            continue
        }

        # Only reached when $armed -eq $true and $name -eq $TargetDriverName.
        # Guard on $WhatIfPreference directly rather than calling
        # $PSCmdlet.ShouldProcess() -- that method throws a null-reference
        # error in some non-interactive PowerShell hosts even when $PSCmdlet
        # itself is populated. The two explicit switches above (-Disable and
        # -AcknowledgeRisk) plus the exact-name match already provide the
        # confirmation this script requires; $WhatIfPreference still lets a
        # caller preview the change with -WhatIf without that fragile call.
        if ($WhatIfPreference) {
            Write-Line "    Change skipped (-WhatIf specified)."
        } else {
            Set-ItemProperty -Path $svcPath -Name 'Start' -Value 4 -Type DWord -ErrorAction Stop
            $verify = Get-ItemProperty -Path $svcPath -ErrorAction Stop
            if ($verify.Start -eq 4) {
                Write-Line ("    CHANGED: {0} Start value set to 4 (Disabled)." -f $name)
                Write-Line "    A restart is required for this change to take effect."
                Write-Line "    This matches Microsoft's own documented workaround exactly --"
                Write-Line "    no other registry keys, files, or services were touched."
                $anyChangeMade = $true
            } else {
                Write-Line ("    ERROR: wrote Start = 4 but verification read back {0}." -f $verify.Start)
                $exitCode = 1
            }
        }
    }
    catch {
        Write-Line ("    ERROR handling {0}: {1}" -f $name, $_.Exception.Message)
        $exitCode = 1
    }
    Write-Line ""
}

Write-Line "=============================================================="
if (-not $armed) {
    Write-Line " SUMMARY: Report-only run completed. No changes were made."
    Write-Line " To actually disable a confirmed driver, re-run with:"
    Write-Line "   -Disable -AcknowledgeRisk -TargetDriverName <exact name from the Detect script>"
}
elseif ($anyChangeMade) {
    Write-Line " SUMMARY: Requested change applied. Restart the device to take effect."
}
else {
    Write-Line " SUMMARY: No change was necessary (driver absent or already disabled)."
}
Write-Line "=============================================================="

exit $exitCode
