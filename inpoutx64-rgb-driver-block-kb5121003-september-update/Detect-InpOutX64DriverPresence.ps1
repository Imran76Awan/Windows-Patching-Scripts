<#
.SYNOPSIS
    Read-only detection for the inpoutx64 (or similarly named) legacy hardware I/O
    driver linked to game unresponsiveness on Windows 11 24H2/25H2 after KB5121003.

.DESCRIPTION
    Microsoft's Windows 11 25H2/24H2 release health pages document an issue where
    "some games become unresponsive when certain drivers are present." Symptoms
    include the game freezing, closing unexpectedly, EXCEPTION_ACCESS_VIOLATION
    errors, or the device restarting without warning. Microsoft's own investigation
    says this is caused by peripheral or motherboard RGB lighting utilities that
    install a driver or code component with a file name similar to "inpoutx64",
    and that the issue is triggered when specific games (ARC Raiders and others)
    are launched. Microsoft's resolution is a block that disables the inpoutx64
    driver; that block is being folded into the September 2026 Windows security
    update and later releases.

    This script performs a READ-ONLY audit of one device (or is meant to be run
    fleet-wide via RMM/Intune Proactive Remediation "detection" script) to answer:

      1. Is the inpoutx64 service/driver registered on this device at all
         (HKLM\SYSTEM\CurrentControlSet\Services\inpoutx64), and if so, is it
         currently set to load (Start value) or already disabled?
      2. Does the driver file actually exist on disk, and where?
      3. Is Windows already reporting a Code Integrity block against a driver
         with this name (CodeIntegrity-Operational Event ID 3077 or 3076)?
      4. Has the device already installed the September 2026 security update
         (or a later cumulative update) that is expected to carry Microsoft's
         own driver block, based on installed KB/hotfix IDs known at the time
         this script was written? (Best-effort; update the $KnownFixKBs list
         once Microsoft publishes the September 2026 KB number.)
      5. Is a game known to trigger this issue (ARC Raiders, MARVEL Tokon:
         Fighting Souls, THE FINALS) installed, based on common install
         locations and Start Menu shortcuts? (Best-effort signal only.)

    This script NEVER modifies the registry, NEVER stops or disables any
    service or driver, and NEVER deletes any file. It only reads state and
    reports it. Use the companion Remediate-InpOutX64DriverPresence.ps1
    script if you want to take action, and read its own header carefully --
    it defaults to reporting only and requires an explicit switch before it
    will change anything, per this site's guidance not to disable this
    driver across an entire estate without first confirming it is present
    and understanding what depends on it.

.PARAMETER CsvPath
    Optional path to append one CSV row per run, for fleet-wide tracking.

.PARAMETER LogPath
    Optional path to a text log file. If omitted, output goes to the console
    only (and to stdout/stderr, which Intune Proactive Remediations capture).

.OUTPUTS
    Exit code 0  - Healthy. No inpoutx64 driver registered on this device, or
                   the driver is already disabled (Start = 4), or a Code
                   Integrity block against it is already active.
    Exit code 1  - Attention needed. The inpoutx64 driver is registered and
                   set to load (Start is not 4), and no existing Code
                   Integrity block was observed. Review before acting.
    Exit code 2  - Script error (could not query one or more data sources).

.EXAMPLE
    .\Detect-InpOutX64DriverPresence.ps1
    Runs the audit and prints a plain-text report to the console.

.EXAMPLE
    .\Detect-InpOutX64DriverPresence.ps1 -CsvPath C:\Reports\inpoutx64-audit.csv
    Runs the audit and appends one row to a CSV for fleet tracking.

.NOTES
    Author        : Imran Awan (EndpointWeekly)
    Blog post     : https://endpointweekly.com/blog/inpoutx64-rgb-driver-block-kb5121003-september-update.html
    Companion to  : Remediate-InpOutX64DriverPresence.ps1 (same folder)
    Tested on     : Windows 11 24H2 / 25H2, Windows PowerShell 5.1
    Read-only     : Yes. No Set-*, Remove-*, Disable-*, Stop-* cmdlets are used.
#>

[CmdletBinding()]
param(
    [string]$CsvPath,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'
$script:hadError = $false

function Write-Line {
    param([string]$Text)
    Write-Output $Text
    if ($LogPath) {
        try { Add-Content -Path $LogPath -Value $Text -Encoding UTF8 }
        catch { }
    }
}

# Driver/service names this script checks for. inpoutx64 is the name Microsoft
# names explicitly; the 32-bit sibling "inpout32" and a common renamed variant
# are included because RGB utilities sometimes ship one of these instead.
$DriverNames = @('inpoutx64', 'inpout32', 'WinRing0x64', 'WinRing0')

# Games Microsoft's advisory names as trigger applications. Best-effort only --
# this is not an exhaustive or officially published list of every affected
# folder name, just the ones named in Microsoft's own release health text.
$KnownGameHints = @(
    @{ Name = 'ARC Raiders';                  Hint = '*ARC Raiders*' }
    @{ Name = 'MARVEL Tokon: Fighting Souls';  Hint = '*Tokon*' }
    @{ Name = 'THE FINALS';                    Hint = '*THE FINALS*' }
)

# Update this list once Microsoft publishes the exact September 2026 (and
# later) KB numbers that are confirmed to carry the inpoutx64 driver block.
# KB5121003 (August 11, 2026) is the originating update for the underlying
# issue, not the fix -- it is listed here only for report context.
$OriginatingKB = 'KB5121003'
$KnownFixKBs   = @()   # e.g. @('KB51NNNNN') once confirmed by Microsoft

Write-Line "=============================================================="
Write-Line " inpoutx64 / RGB driver block audit - read only"
Write-Line " Run time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Line " Computer: $env:COMPUTERNAME"
Write-Line "=============================================================="
Write-Line ""

$result = [ordered]@{
    ComputerName          = $env:COMPUTERNAME
    Timestamp             = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    DriverServiceFound    = $false
    DriverServiceName     = ''
    DriverStartValue      = $null
    DriverStartMeaning    = ''
    DriverFileFound       = $false
    DriverFilePath        = ''
    CodeIntegrityBlockSeen = $false
    CodeIntegrityBlockDetail = ''
    SuspectedGameInstalled = ''
    FixKBInstalled        = $false
    FixKBFound            = ''
    Verdict               = ''
}

# ---------------------------------------------------------------------------
# 1. Registry: is the driver service registered, and what is its Start value?
# ---------------------------------------------------------------------------
Write-Line "[1] Checking HKLM\SYSTEM\CurrentControlSet\Services\<driver> ..."
foreach ($name in $DriverNames) {
    $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
    try {
        if (Test-Path -Path $svcPath) {
            $svc = Get-ItemProperty -Path $svcPath -ErrorAction Stop
            $result.DriverServiceFound = $true
            $result.DriverServiceName  = $name
            $result.DriverStartValue   = $svc.Start
            $meaning = switch ($svc.Start) {
                0 { 'Boot (0) - loads at boot, before drivers are typically expected for a lighting utility' }
                1 { 'System (1) - loads during kernel initialization' }
                2 { 'Automatic (2) - loads automatically at startup' }
                3 { 'Manual/Demand (3) - loads only when something requests it' }
                4 { 'Disabled (4) - the driver is disabled and will not load' }
                default { "Unrecognized Start value: $($svc.Start)" }
            }
            $result.DriverStartMeaning = $meaning
            Write-Line ("    FOUND  : {0}  (Start = {1} -> {2})" -f $name, $svc.Start, $meaning)

            $imagePath = $svc.ImagePath
            if ($imagePath) {
                $expanded = [System.Environment]::ExpandEnvironmentVariables($imagePath)
                if (Test-Path -Path $expanded) {
                    $result.DriverFileFound = $true
                    $result.DriverFilePath  = $expanded
                    Write-Line ("    FILE   : {0} (exists on disk)" -f $expanded)
                } else {
                    Write-Line ("    FILE   : {0} (registry points here, file not found)" -f $expanded)
                }
            }
        } else {
            Write-Line ("    not present: {0}" -f $name)
        }
    } catch {
        Write-Line ("    ERROR checking {0}: {1}" -f $name, $_.Exception.Message)
        $script:hadError = $true
    }
}
Write-Line ""

# ---------------------------------------------------------------------------
# 2. Driver store / loaded driver cross-check (Win32_SystemDriver)
# ---------------------------------------------------------------------------
Write-Line "[2] Cross-checking loaded/known drivers via Win32_SystemDriver ..."
try {
    $sysDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
        Where-Object { $DriverNames -contains $_.Name }
    if ($sysDrivers) {
        foreach ($d in $sysDrivers) {
            Write-Line ("    {0}  State={1}  Started={2}  PathName={3}" -f $d.Name, $d.State, $d.Started, $d.PathName)
        }
    } else {
        Write-Line "    No matching entries in Win32_SystemDriver."
    }
} catch {
    Write-Line ("    ERROR querying Win32_SystemDriver: {0}" -f $_.Exception.Message)
    $script:hadError = $true
}
Write-Line ""

# ---------------------------------------------------------------------------
# 3. Code Integrity Operational log: has this driver already been blocked?
# ---------------------------------------------------------------------------
Write-Line "[3] Checking CodeIntegrity-Operational log for existing block events (3076/3077) ..."
try {
    $ciEvents = Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 500 -ErrorAction Stop |
        Where-Object { $_.Id -in 3076, 3077 }
    $matching = $ciEvents | Where-Object {
        $msg = $_.Message
        ($DriverNames | Where-Object { $msg -match [regex]::Escape($_) }).Count -gt 0
    }
    if ($matching) {
        $result.CodeIntegrityBlockSeen = $true
        foreach ($e in $matching | Select-Object -First 5) {
            $detail = "EventId=$($e.Id) Time=$($e.TimeCreated)"
            $result.CodeIntegrityBlockDetail += "$detail; "
            Write-Line ("    BLOCK EVENT: {0}" -f $detail)
        }
    } else {
        Write-Line "    No 3076/3077 Code Integrity events reference these driver names in the most recent 500 entries."
    }
} catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
    Write-Line "    CodeIntegrity-Operational log not found or not enabled on this device."
} catch {
    Write-Line ("    ERROR reading CodeIntegrity-Operational log: {0}" -f $_.Exception.Message)
    $script:hadError = $true
}
Write-Line ""

# ---------------------------------------------------------------------------
# 4. Has a known fix KB already been installed?
# ---------------------------------------------------------------------------
Write-Line "[4] Checking installed updates against known fix KB list ..."
Write-Line ("    Originating update (cause, not fix): {0}" -f $OriginatingKB)
if ($KnownFixKBs.Count -eq 0) {
    Write-Line "    No confirmed fix KB number is recorded in this script yet."
    Write-Line "    Update `$KnownFixKBs once Microsoft publishes the September 2026 KB."
} else {
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop
        foreach ($kb in $KnownFixKBs) {
            $found = $hotfixes | Where-Object { $_.HotFixID -ieq $kb }
            if ($found) {
                $result.FixKBInstalled = $true
                $result.FixKBFound = $kb
                Write-Line ("    INSTALLED: {0}" -f $kb)
            }
        }
        if (-not $result.FixKBInstalled) {
            Write-Line "    None of the known fix KBs are installed on this device yet."
        }
    } catch {
        Write-Line ("    ERROR querying Get-HotFix: {0}" -f $_.Exception.Message)
        $script:hadError = $true
    }
}
Write-Line ""

# ---------------------------------------------------------------------------
# 5. Best-effort check for a trigger game being installed
# ---------------------------------------------------------------------------
Write-Line "[5] Best-effort check for known trigger games (informational only) ..."
try {
    $searchRoots = @(
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
    ) | Where-Object { $_ -and (Test-Path $_) }

    $foundGames = @()
    foreach ($root in $searchRoots) {
        foreach ($g in $KnownGameHints) {
            $hits = Get-ChildItem -Path $root -Filter $g.Hint -Recurse -Depth 2 -ErrorAction SilentlyContinue
            if ($hits) { $foundGames += $g.Name }
        }
    }
    $foundGames = $foundGames | Select-Object -Unique
    if ($foundGames) {
        $result.SuspectedGameInstalled = ($foundGames -join '; ')
        Write-Line ("    Possible match(es): {0}" -f $result.SuspectedGameInstalled)
    } else {
        Write-Line "    No obvious match for the named trigger games (best-effort scan only)."
    }
} catch {
    Write-Line ("    Skipped game scan due to error: {0}" -f $_.Exception.Message)
}
Write-Line ""

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
Write-Line "=============================================================="
if (-not $result.DriverServiceFound) {
    $result.Verdict = 'HEALTHY - driver not present on this device'
    Write-Line " RESULT: HEALTHY"
    Write-Line " No inpoutx64 (or listed sibling) driver is registered on this device."
    Write-Line " No action needed for this specific issue."
    $exitCode = 0
}
elseif ($result.DriverStartValue -eq 4) {
    $result.Verdict = 'HEALTHY - driver present but already disabled'
    Write-Line " RESULT: HEALTHY"
    Write-Line " The driver is registered but its Start value is already 4 (Disabled)."
    Write-Line " Either Microsoft's automatic block or a prior manual workaround already applied."
    $exitCode = 0
}
elseif ($result.CodeIntegrityBlockSeen) {
    $result.Verdict = 'HEALTHY - Code Integrity is already blocking this driver from loading'
    Write-Line " RESULT: HEALTHY"
    Write-Line " A Code Integrity 3076/3077 event already shows this driver being blocked."
    $exitCode = 0
}
else {
    $result.Verdict = 'ATTENTION - driver present and enabled, no existing block observed'
    Write-Line " RESULT: ATTENTION NEEDED"
    Write-Line " This device has the inpoutx64 (or a listed sibling) driver registered and"
    Write-Line " set to load, with no existing disable or Code Integrity block detected."
    Write-Line " Do NOT disable this driver blindly. Find out what application installed"
    Write-Line " it (RGB lighting software, motherboard utility) before touching it -- see"
    Write-Line " the blog post's 'The fix' section for the safe order of operations."
    $exitCode = 1
}
Write-Line "=============================================================="

if ($CsvPath) {
    try {
        $row = [pscustomobject]$result
        $writeHeader = -not (Test-Path $CsvPath)
        $row | Export-Csv -Path $CsvPath -NoTypeInformation -Append -Force
    } catch {
        Write-Line ("CSV export failed: {0}" -f $_.Exception.Message)
        $script:hadError = $true
    }
}

if ($script:hadError -and $exitCode -eq 0) {
    # A query failed but the visible evidence looked healthy -- fail loud
    # rather than report a false clean result.
    Write-Line "One or more checks failed to run cleanly; treat this result as inconclusive."
    exit 2
}

exit $exitCode
