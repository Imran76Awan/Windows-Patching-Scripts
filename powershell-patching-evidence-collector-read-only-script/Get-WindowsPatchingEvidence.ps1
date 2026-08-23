<#
.SYNOPSIS
    Read-only evidence collector for Windows patching failures. Gathers the facts a
    patching triage actually needs, and refuses to guess where a naive check would lie.

.DESCRIPTION
    Get-WindowsPatchingEvidence collects, in one pass, the evidence needed to work out
    why a Windows device is not patching: what build it is really on, whether a reboot
    is genuinely pending, which servicing components are running, which policy hive is
    actually in force, what the update agent's own resolved verdict is, and what the
    event logs recorded.

    NOTHING IS MODIFIED. Every operation is a read. There is no Set-, New-, Remove-,
    Stop-, Start-, Restart- or Rename- cmdlet acting on device state anywhere in this
    file, no "net stop", no folder rename, no wuauclt, no usoclient, and no DISM repair
    switch. The only thing the script ever writes is the HTML report you explicitly ask
    for with -OutputHtml. Run -VerifyReadOnly to have the script audit its own source
    and prove that.

    That restraint is the point. On a patching escalation the evidence is the scarce
    resource: resetting SoftwareDistribution, renaming catroot2, end-tasking TiWorker
    or clearing the CBS logs all destroy the artefact that would have identified root
    cause. Collect first. Decide second. Change third, if at all.

    The script is built around six specific traps that make naive triage scripts return
    confident, plausible, wrong answers:

      1. SUBKEY-AWARE PENDING-REBOOT DETECTION. The Component Based Servicing markers
         RebootPending, RebootInProgress and PackagesPending are SUBKEYS, not values. A
         Get-ItemProperty test for a value called "RebootPending" can never return true,
         so a script written that way reports "no reboot pending" forever. Microsoft's
         own published CheckForPendingReboot.ps1 gets this right - it opens the CBS key
         and enumerates GetSubKeyNames(). So does this script.

      2. KEY EXISTENCE IS NOT EVIDENCE. On Windows policy hives a key routinely exists
         holding zero values, because something else created it. Measured on the lab
         device: ...\Policies\Microsoft\Windows\WindowsUpdate\AU exists with ValueCount
         0; ...\CurrentVersion\Policies\Servicing exists holding only CountryCode;
         ...\Policies\Microsoft\SystemCertificates\AuthRoot exists with 0 values and 3
         auto-created subkeys. This script never reports a Test-Path result as a
         verdict. It reports the key state (exists / ValueCount / SubKeyCount) and then
         tests for the SPECIFIC values that carry meaning.

      3. BOTH POLICY HIVES, SIDE BY SIDE. The classic Group Policy hive
         SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate and the MDM hive
         SOFTWARE\Microsoft\PolicyManager\current\device\Update are different stores
         with different contents. Auditing only the classic hive on an Intune-managed
         device finds almost nothing. This script reads both and prints them together.

      4. THE REAL UBR. [Environment]::OSVersion.Version returns a revision of .0 and
         Win32_OperatingSystem.Version returns no revision at all, so neither can tell
         you the patch level. Only SOFTWARE\Microsoft\Windows NT\CurrentVersion carries
         the UBR. This script reads the registry and shows all three so the gap is
         visible. It also pairs the UBR with CurrentBuild, because the same UBR can
         appear on two different releases.

      5. IsWUfBConfigured IS NOT A WUfB TEST. The update agent's resolved state key
         ...\WindowsUpdate\UpdatePolicy\PolicyState was measured holding
         IsWUfBConfigured=0 at the same instant as IsDeferralIsActive=1 and
         QualityUpdatesDeferralInDays=7. This script prints the value for the record and
         explicitly refuses to use it as a management test; the management verdict is
         built from the policy values actually present.

      6. THE MDM WMI BRIDGE LIES TO A NON-SYSTEM CALLER. Microsoft documents that "For
         all device settings, the WMI Bridge client must be executed under local system
         user." Measured as an elevated administrator - NOT SYSTEM -
         MDM_Policy_Result01_Update02 returned every documented default with no error
         raised, while the registry held completely different numbers. The bridge query
         here is therefore opt-in (-IncludeMdmBridge) and its result is labelled
         UNTRUSTED unless the process is genuinely running as SYSTEM.

.PARAMETER OutputHtml
    Path to also write a self-contained, styled HTML version of the report - the same
    evidence as the console output, formatted for attaching to a ticket or sharing with
    a colleague. No external CSS, fonts, scripts or images are referenced, so the file
    opens correctly offline and behind a restrictive proxy. Honours -Redact.

.PARAMETER Redact
    Mask the machine name, the enrollment and provider GUIDs, and the hardware serial
    numbers, so the report can be posted publicly or attached to a vendor case. Values
    are masked, never removed - you can still see that a field is populated.

.PARAMETER IncludeMdmBridge
    Also query the MDM WMI bridge class MDM_Policy_Result01_Update02. Off by default
    because the bridge silently returns documented defaults to a caller that is not
    running as SYSTEM. When it is queried, the result is compared against the registry
    and flagged as untrusted if this process is not SYSTEM.

.PARAMETER EventCount
    How many of the most recent events to examine per channel. Default 400.

.PARAMETER VerifyReadOnly
    Scan this script's own source for device-mutating commands and report the result.
    The patterns are assembled at run time from fragments so the pattern list itself
    cannot produce a false positive.

.EXAMPLE
    .\Get-WindowsPatchingEvidence.ps1

    Default console run. Read-only, nothing changed.

.EXAMPLE
    .\Get-WindowsPatchingEvidence.ps1 -OutputHtml .\patching-evidence.html

    Same run, plus a self-contained HTML report for the ticket.

.EXAMPLE
    .\Get-WindowsPatchingEvidence.ps1 -Redact -OutputHtml .\share.html

    Machine name, GUIDs and serials masked, so the report can be shared publicly.

.EXAMPLE
    .\Get-WindowsPatchingEvidence.ps1 -VerifyReadOnly

    Audits the script's own source for mutating commands before running the collection.

.NOTES
    Companion script for endpointweekly.com.
    Repository : https://github.com/Imran76Awan/Windows-Patching-Scripts

    Author     : Imran Awan
    Requires   : Windows PowerShell 5.1 or PowerShell 7. Local administrator rights are
                 needed to read the CBS hive and the Setup event log.
    Read-only  : Yes. No device configuration is changed anywhere.

    Exit codes:
      0 - Evidence collected, nothing that blocks patching was found.
      1 - Evidence collected and at least one blocking condition was found
          (pending reboot, a stopped update service, a stale release pin).
      2 - Collection could not complete - the output would be misleading, so it is
          reported as incomplete rather than clean.

    Microsoft references:
      CheckForPendingReboot.ps1 (CBS subkey enumeration)
        https://learn.microsoft.com/en-us/previous-versions/system-center/virtual-machine-manager-2008-r2/ee649098(v=technet.10)
      Using PowerShell scripting with the WMI Bridge Provider (SYSTEM requirement)
        https://learn.microsoft.com/en-us/windows/client-management/mdm/using-powershell-scripting-with-the-wmi-bridge-provider
      MDM_Policy_Result01_Update02 class
        https://learn.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-policy-result01-update02
      Policy CSP - Update (allowed values and GP mappings)
        https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update
      Windows Update log files
        https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-logs
#>

[CmdletBinding()]
param(
    [string] $OutputHtml,
    [switch] $Redact,
    [switch] $IncludeMdmBridge,
    [ValidateRange(50, 2000)]
    [int] $EventCount = 400,
    [switch] $VerifyReadOnly
)

$ErrorActionPreference = 'Continue'

# ===========================================================================
# Report accumulator. Everything printed to the console is also stashed here
# so the HTML renderer can rebuild the same report without re-reading anything.
# ===========================================================================

$Script:Report = [ordered]@{
    Meta      = [ordered]@{}
    Identity  = [ordered]@{}
    Reboot    = [ordered]@{ Sources = @(); Pending = $false }
    Services  = @()
    PolicyOld = [ordered]@{}
    PolicyNew = [ordered]@{}
    PolicyDo  = [ordered]@{}
    Agent     = [ordered]@{}
    Bridge    = $null
    Inventory = [ordered]@{}
    Events    = [ordered]@{ Channels = @(); Interesting = @() }
    Restart   = [ordered]@{}
    Findings  = @()
    ReadOnly  = $null
}

$Script:Findings = New-Object System.Collections.Generic.List[psobject]
$Script:Incomplete = New-Object System.Collections.Generic.List[string]

# ===========================================================================
# Output helpers
# ===========================================================================

function Write-Rule {
    param([string] $Title)
    Write-Host ''
    Write-Host ('-' * 78)
    Write-Host (' ' + $Title)
    Write-Host ('-' * 78)
}

function Write-Field {
    param([string] $Name, $Value)
    $label = [string]$Name
    if ($label.Length -lt 34) { $label = $label.PadRight(34, ' ') }
    Write-Host ('  ' + $label + ' : ' + [string]$Value)
}

function Write-Note {
    param([string] $Text)
    Write-Host ('    -> ' + $Text)
}

function Add-Finding {
    # Severity is one of: Blocking, Warning, Note.
    param(
        [ValidateSet('Blocking', 'Warning', 'Note')]
        [string] $Severity,
        [string] $Text
    )
    $Script:Findings.Add([pscustomobject]@{ Severity = $Severity; Text = $Text })
}

function Add-Incomplete {
    param([string] $Text)
    $Script:Incomplete.Add($Text)
}

# ===========================================================================
# Redaction
# ===========================================================================

function Protect-Value {
    # Masks the middle of a value so you can still see that it is populated. Returns
    # the value untouched when -Redact was not supplied. Never deletes a field: an
    # absent field and a masked field are different pieces of evidence.
    param($Value)

    if ($null -eq $Value) { return '<null>' }
    $text = ([string]$Value).Trim()
    if ($text.Length -eq 0) { return '<empty>' }
    if (-not $Redact) { return $text }
    if ($text.Length -le 4) { return (('*' * $text.Length) + ' (masked)') }

    $head = $text.Substring(0, 2)
    $tail = $text.Substring($text.Length - 2, 2)
    return ($head + ('*' * ($text.Length - 4)) + $tail + ' (masked)')
}

function Protect-Text {
    # Scrubs GUIDs out of free text (event messages, URLs, provider paths) when
    # -Redact is on. Tenant, device and enrollment identifiers are all GUIDs, and
    # they turn up inside strings that are otherwise safe to publish.
    param([string] $Text)

    if ($null -eq $Text) { return '' }
    if (-not $Redact) { return $Text }

    $guid = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $out = [System.Text.RegularExpressions.Regex]::Replace($Text, $guid, '<guid-masked>')
    if ($Script:RealComputerName -and $Script:RealComputerName.Length -gt 2) {
        $out = [System.Text.RegularExpressions.Regex]::Replace(
            $out, [System.Text.RegularExpressions.Regex]::Escape($Script:RealComputerName),
            '<host-masked>', 'IgnoreCase')
    }
    return $out
}

# ===========================================================================
# Registry helpers - the heart of the empty-key handling
# ===========================================================================

function Get-RegKeyFacts {
    # Returns the STATE of a key, never a bare boolean. Exists / ValueCount /
    # SubKeyCount / the value names. This is the shape every policy-hive check in
    # this script consumes, because "the key exists" on its own is not evidence.
    param([string] $Path)

    $result = [pscustomobject]@{
        Path         = $Path
        Exists       = $false
        ValueCount   = 0
        SubKeyCount  = 0
        ValueNames   = @()
        SubKeyNames  = @()
    }

    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $result.Exists      = $true
        $result.ValueCount  = [int]$key.ValueCount
        $result.SubKeyCount = [int]$key.SubKeyCount
        $result.ValueNames  = @($key.Property)
        if ($result.SubKeyCount -gt 0) {
            $result.SubKeyNames = @(Get-ChildItem -LiteralPath $Path -ErrorAction SilentlyContinue |
                ForEach-Object { $_.PSChildName })
        }
    }
    catch {
        Add-Incomplete ('Could not read key ' + $Path + ' : ' + $_.Exception.Message)
    }

    return $result
}

function Get-RegValue {
    # Reads ONE specific value and distinguishes the three states that matter:
    # value present with data, value present but empty, value absent. A script that
    # collapses those three into a boolean is where wrong verdicts come from.
    param([string] $Path, [string] $Name)

    $result = [pscustomobject]@{
        Present = $false
        IsEmpty = $false
        Value   = $null
        Display = '<absent>'
    }

    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $props) { return $result }

    $prop = $props.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $result }

    $result.Present = $true
    $result.Value   = $prop.Value

    if ($null -eq $prop.Value -or ([string]$prop.Value).Trim().Length -eq 0) {
        $result.IsEmpty = $true
        $result.Display = '<present but EMPTY>'
    }
    else {
        $result.Display = [string]$prop.Value
    }

    return $result
}

function Get-HklmSubKeyNames {
    # Opens an HKLM subkey with the .NET registry API and enumerates its SUBKEY
    # names. This is the call Microsoft's own CheckForPendingReboot.ps1 makes, and
    # the only correct way to test for the CBS reboot markers - they are subkeys,
    # so no value-based test can ever see them.
    param([string] $SubKeyPath)

    $base = $null
    $key  = $null
    try {
        $base = [Microsoft.Win32.Registry]::LocalMachine
        $key  = $base.OpenSubKey($SubKeyPath)
        if ($null -eq $key) { return $null }
        return @($key.GetSubKeyNames())
    }
    catch {
        Add-Incomplete ('Could not enumerate subkeys of HKLM\' + $SubKeyPath + ' : ' + $_.Exception.Message)
        return $null
    }
    finally {
        if ($null -ne $key) { $key.Close() }
    }
}

function Get-PolicyManagerValues {
    # PolicyManager decorates each policy with metadata siblings named
    # <Policy>_ProviderSet, <Policy>_WinningProvider and <Policy>_LastWrite. Counting
    # raw value names therefore triples the apparent policy count. This returns the
    # real policy names and the metadata separately.
    param([string] $Path)

    $result = [pscustomobject]@{
        Exists     = $false
        RawCount   = 0
        Policies   = [ordered]@{}
        MetaCount  = 0
    }

    if (-not (Test-Path -LiteralPath $Path)) { return $result }
    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $props) { return $result }

    $result.Exists = $true
    $names = @($props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name })
    $result.RawCount = $names.Count

    foreach ($n in $names) {
        if ($n -match '_(ProviderSet|WinningProvider|LastWrite)$') {
            $result.MetaCount = $result.MetaCount + 1
            continue
        }
        $v = $props.PSObject.Properties[$n].Value
        $result.Policies[$n] = $v
    }

    return $result
}

function ConvertTo-HtmlSafe {
    param($Text)
    if ($null -eq $Text) { return '' }
    return ([string]$Text).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

# ===========================================================================
# Read-only self-audit
# ===========================================================================

function Test-ScriptIsReadOnly {
    # Scans this script's own source for commands that would change device state.
    # The needles are assembled from fragments at run time so that the needle list
    # itself cannot match, which is what would otherwise make this check useless.
    param([string] $ScriptPath)

    $result = [pscustomobject]@{
        Checked  = $false
        Path     = $ScriptPath
        Hits     = @()
        Patterns = 0
        Tokens   = 0
    }

    if ([string]::IsNullOrEmpty($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        Add-Incomplete 'Read-only self-audit skipped: could not locate this script on disk.'
        return $result
    }

    $needles = @(
        ('Set'     + '-ItemProperty'),
        ('New'     + '-ItemProperty'),
        ('Remove'  + '-ItemProperty'),
        ('Remove'  + '-Item '),
        ('Rename'  + '-Item'),
        ('Stop'    + '-Service'),
        ('Start'   + '-Service'),
        ('Restart' + '-Service'),
        ('Set'     + '-Service'),
        ('Stop'    + '-Process'),
        ('Restart' + '-Computer'),
        ('Set'     + '-CimInstance'),
        ('Invoke'  + '-CimMethod'),
        ('Remove'  + '-CimInstance'),
        ('net '    + 'stop'),
        ('wuau'    + 'clt'),
        ('uso'     + 'client'),
        ('Restore' + 'Health'),
        ('Start'   + 'ComponentCleanup'),
        ('Reset'   + 'Base'),
        ('sfc '    + '/scannow')
    )
    $result.Patterns = $needles.Count

    # A plain line-by-line grep is WRONG here, and the first version of this
    # function proved it: it matched the words "net stop", "wuauclt" and
    # "usoclient" inside this script's own help text and reported three
    # violations that do not exist. Tokenise instead, and throw the comment
    # tokens away, so only real code is searched.
    $parseErrors = $null
    $tokens = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, [ref]$tokens, [ref]$parseErrors)

    if ($null -eq $tokens) {
        Add-Incomplete 'Read-only self-audit skipped: could not tokenise this script.'
        return $result
    }
    if (@($parseErrors).Count -gt 0) {
        Add-Incomplete ('This script has ' + @($parseErrors).Count + ' parse error(s) - the self-audit result is unreliable.')
    }

    $codeTokens = @($tokens | Where-Object { $_.Kind -ne 'Comment' })
    $result.Tokens = $codeTokens.Count

    $hits = New-Object System.Collections.Generic.List[psobject]
    foreach ($t in $codeTokens) {
        $text = [string]$t.Text
        if ([string]::IsNullOrEmpty($text)) { continue }
        foreach ($n in $needles) {
            if ($text.IndexOf($n, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $hits.Add([pscustomobject]@{
                    Line   = $t.Extent.StartLineNumber
                    Needle = $n
                    Text   = $text.Trim()
                })
            }
        }
    }

    $result.Checked = $true
    $result.Hits    = @($hits)
    return $result
}

# ===========================================================================
# HTML report
# ===========================================================================

function New-EvidenceHtmlReport {
    # Builds one self-contained HTML string. No external CSS, fonts, scripts or
    # images - everything is inlined, so the file renders identically offline, from
    # a USB stick, or behind a proxy that blocks outbound requests. Purely a
    # rendering step: every value has already been through Protect-Value or
    # Protect-Text, so nothing is masked or unmasked here.
    param($Data)

    $esc = { param($v) ConvertTo-HtmlSafe $v }

    $blocking = @($Data.Findings | Where-Object { $_.Severity -eq 'Blocking' })
    $warning  = @($Data.Findings | Where-Object { $_.Severity -eq 'Warning' })
    $healthy  = ($blocking.Count -eq 0)

    $statusText = if ($healthy) {
        'No blocking condition found - ' + $warning.Count + ' item(s) worth reading'
    } else {
        $blocking.Count.ToString() + ' blocking condition(s) found'
    }
    $statusColor = if ($healthy) { '#0f766e' } else { '#b91c1c' }
    $statusBg    = if ($healthy) { '#f0fdfa' } else { '#fef2f2' }

    $findingRows = ''
    foreach ($f in $Data.Findings) {
        $tag = switch ($f.Severity) {
            'Blocking' { 'tag-red' }
            'Warning'  { 'tag-amber' }
            default    { 'tag-teal' }
        }
        $findingRows += '<tr><td style="width:110px"><span class="tag ' + $tag + '">' +
            (& $esc $f.Severity) + '</span></td><td>' + (& $esc $f.Text) + '</td></tr>'
    }
    if ($findingRows -eq '') {
        $findingRows = '<tr><td colspan="2">Nothing flagged.</td></tr>'
    }

    $identityRows = ''
    foreach ($k in $Data.Identity.Keys) {
        $identityRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.Identity[$k]) + '</code></td></tr>'
    }

    $rebootRows = ''
    foreach ($s in $Data.Reboot.Sources) {
        $cls = if ($s.Pending) { 'tag-red' } else { 'tag-teal' }
        $txt = if ($s.Pending) { 'PENDING' } else { 'clear' }
        $rebootRows += '<tr><td>' + (& $esc $s.Name) + '</td><td><span class="tag ' + $cls + '">' + $txt +
            '</span></td><td><code>' + (& $esc $s.Evidence) + '</code></td><td class="muted">' +
            (& $esc $s.Method) + '</td></tr>'
    }

    $serviceRows = ''
    foreach ($s in $Data.Services) {
        $cls = if ($s.Concern) { 'tag-amber' } else { 'tag-teal' }
        $serviceRows += '<tr><td><code>' + (& $esc $s.Name) + '</code></td><td>' + (& $esc $s.Status) +
            '</td><td>' + (& $esc $s.StartType) + '</td><td><span class="tag ' + $cls + '">' +
            (& $esc $s.Verdict) + '</span></td></tr>'
    }

    $oldRows = ''
    foreach ($k in $Data.PolicyOld.Keys) {
        $oldRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.PolicyOld[$k]) + '</code></td></tr>'
    }
    $newRows = ''
    foreach ($k in $Data.PolicyNew.Keys) {
        $newRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.PolicyNew[$k]) + '</code></td></tr>'
    }
    $doRows = ''
    foreach ($k in $Data.PolicyDo.Keys) {
        $doRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.PolicyDo[$k]) + '</code></td></tr>'
    }

    $agentRows = ''
    foreach ($k in $Data.Agent.Keys) {
        $agentRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.Agent[$k]) + '</code></td></tr>'
    }

    $bridgeSection = ''
    if ($null -ne $Data.Bridge) {
        $bridgeRows = ''
        foreach ($r in $Data.Bridge.Rows) {
            $cls = if ($r.Matches) { 'tag-teal' } else { 'tag-red' }
            $txt = if ($r.Matches) { 'agrees' } else { 'DISAGREES' }
            $bridgeRows += '<tr><td>' + (& $esc $r.Name) + '</td><td><code>' + (& $esc $r.Bridge) +
                '</code></td><td><code>' + (& $esc $r.Registry) + '</code></td><td><span class="tag ' + $cls +
                '">' + $txt + '</span></td></tr>'
        }
        $bridgeSection = '<div class="card"><h2>6. MDM WMI bridge (opt-in)</h2>' +
            '<p class="warn"><strong>' + (& $esc $Data.Bridge.Trust) + '</strong></p>' +
            '<table><tr><th>Policy</th><th>Bridge said</th><th>Registry holds</th><th></th></tr>' +
            $bridgeRows + '</table>' +
            '<p class="muted">Microsoft: "For all device settings, the WMI Bridge client must be executed under local system user." ' +
            'A non-SYSTEM caller was measured getting documented defaults back with no error raised.</p></div>'
    }

    $invRows = ''
    foreach ($k in $Data.Inventory.Keys) {
        $invRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.Inventory[$k]) + '</code></td></tr>'
    }

    $chanRows = ''
    foreach ($c in $Data.Events.Channels) {
        $chanRows += '<tr><td><code>' + (& $esc $c.Channel) + '</code></td><td>' + (& $esc $c.Records) +
            '</td><td>' + (& $esc $c.Examined) + '</td><td class="muted">' + (& $esc $c.Breakdown) + '</td></tr>'
    }
    $intRows = ''
    foreach ($e in $Data.Events.Interesting) {
        $intRows += '<tr><td>' + (& $esc $e.Id) + '</td><td>' + (& $esc $e.When) + '</td><td>' +
            (& $esc $e.Message) + '</td></tr>'
    }
    if ($intRows -eq '') { $intRows = '<tr><td colspan="3">No flagged events in the window examined.</td></tr>' }

    $restartRows = ''
    foreach ($k in $Data.Restart.Keys) {
        $restartRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $Data.Restart[$k]) + '</code></td></tr>'
    }

    $readOnlyLine = 'not audited this run (pass -VerifyReadOnly)'
    if ($null -ne $Data.ReadOnly -and $Data.ReadOnly.Checked) {
        if (@($Data.ReadOnly.Hits).Count -eq 0) {
            $readOnlyLine = 'Self-audit passed: ' + $Data.ReadOnly.Patterns +
                ' device-mutating command patterns searched across ' + $Data.ReadOnly.Tokens +
                ' code tokens (comments excluded), 0 found.'
        }
        else {
            $readOnlyLine = 'Self-audit FAILED: ' + @($Data.ReadOnly.Hits).Count + ' hit(s) - see console output.'
        }
    }

    $incompleteSection = ''
    if (@($Data.Meta.Incomplete).Count -gt 0) {
        $items = ''
        foreach ($i in $Data.Meta.Incomplete) { $items += '<li>' + (& $esc $i) + '</li>' }
        $incompleteSection = '<div class="card"><h2>Collection gaps</h2><ul class="gaps">' + $items +
            '</ul><p class="muted">These reads did not complete. Treat the affected sections as unknown, not as clean.</p></div>'
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows Patching Evidence Report</title>
<style>
  :root{--teal:#0f766e;--teal-dark:#115e59;--ink:#0f172a;--muted:#64748b;--border:#e2e8f0;--bg:#f8fafc}
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
  header{background:linear-gradient(135deg,#115e59,#0f766e);color:#fff;padding:32px 28px}
  header h1{margin:0 0 6px;font-size:22px}
  header p{margin:0;color:#ccfbf1;font-size:13px}
  .wrap{max-width:960px;margin:0 auto;padding:0 20px 60px}
  .status{margin:-20px auto 24px;max-width:920px;background:$statusBg;border:1px solid $statusColor;border-radius:12px;padding:16px 20px;font-weight:600;color:$statusColor}
  .card{background:#fff;border:1px solid var(--border);border-radius:12px;padding:22px 24px;margin-bottom:18px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .card h2{margin:0 0 14px;font-size:14px;color:var(--teal-dark);text-transform:uppercase;letter-spacing:.04em}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;padding:8px 6px;border-bottom:2px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  td{padding:8px 6px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:12px;font-family:Consolas,'Cascadia Code',monospace;word-break:break-word}
  .keypath{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:10px 14px;margin:0 0 12px;font-family:Consolas,'Cascadia Code',monospace;font-size:12px;overflow-x:auto}
  .tag{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
  .tag-teal{background:#ccfbf1;color:#115e59}
  .tag-red{background:#fee2e2;color:#991b1b}
  .tag-amber{background:#fef3c7;color:#92400e}
  .muted{font-size:12px;color:var(--muted)}
  .warn{background:#fffbeb;border-left:4px solid #f59e0b;padding:10px 14px;border-radius:6px;font-size:13px;margin:0 0 12px;color:#78350f}
  .gaps{margin:6px 0 0;padding-left:20px;font-size:13px}
  .two{display:flex;gap:18px;flex-wrap:wrap}
  .two > div{flex:1 1 380px;min-width:0}
  footer{max-width:920px;margin:0 auto;padding:20px;text-align:center;font-size:12px;color:var(--muted)}
  footer a{color:var(--teal-dark)}
</style>
</head>
<body>
<header>
  <h1>Windows Patching Evidence Report</h1>
  <p>Generated $($Data.Meta.Generated) &middot; PowerShell $($Data.Meta.PSVersion) &middot; Host $($Data.Meta.ComputerName) &middot; Read-only, nothing modified</p>
</header>
<div class="wrap">
  <div class="status">$statusText</div>

  <div class="card">
    <h2>Findings</h2>
    <table>$findingRows</table>
    <p class="muted">$readOnlyLine</p>
  </div>

  <div class="card">
    <h2>1. Identity and real patch level</h2>
    <div class="keypath">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion</div>
    <table>$identityRows</table>
    <p class="muted">Only the registry carries the UBR. <code>[Environment]::OSVersion.Version</code> reports revision <code>.0</code> and <code>Win32_OperatingSystem.Version</code> reports no revision at all, so neither can be used as a patch level. Always pair the UBR with CurrentBuild - the same UBR can appear on two different releases.</p>
  </div>

  <div class="card">
    <h2>2. Pending reboot - all sources</h2>
    <table>
      <tr><th>Source</th><th>State</th><th>Evidence</th><th>How it was read</th></tr>
      $rebootRows
    </table>
    <p class="muted">The Component Based Servicing markers are SUBKEYS. They are enumerated with <code>GetSubKeyNames()</code>, the way Microsoft's own published CheckForPendingReboot.ps1 does it. A value-based test can never see them.</p>
  </div>

  <div class="card">
    <h2>3. Servicing and update services</h2>
    <table>
      <tr><th>Service</th><th>Status</th><th>Start type</th><th>Verdict</th></tr>
      $serviceRows
    </table>
    <p class="muted"><code>trustedinstaller</code> and <code>msiserver</code> being Stopped/Manual while idle is normal and is the most common false alarm in this whole space. This report says so instead of flagging it.</p>
  </div>

  <div class="card">
    <h2>4. Policy - both hives, side by side</h2>
    <div class="two">
      <div>
        <div class="keypath">HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate</div>
        <table>$oldRows</table>
      </div>
      <div>
        <div class="keypath">HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update</div>
        <table>$newRows</table>
      </div>
    </div>
    <p class="muted" style="margin-top:14px">Delivery Optimization, same treatment:</p>
    <table>$doRows</table>
  </div>

  <div class="card">
    <h2>5. The agent's own resolved verdict</h2>
    <div class="keypath">HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState</div>
    <table>$agentRows</table>
    <p class="warn"><strong>IsWUfBConfigured is reported for the record and is NOT used as a management test.</strong> It was measured reading 0 on the same device, at the same instant, as IsDeferralIsActive=1 and a 7-day quality deferral.</p>
  </div>

  $bridgeSection

  <div class="card">
    <h2>7. Inventory - what is actually installed</h2>
    <table>$invRows</table>
    <p class="muted"><code>Win32_QuickFixEngineering</code>, and therefore <code>Get-HotFix</code>, returns only Component Based Servicing updates. The CBS package count is the honest denominator.</p>
  </div>

  <div class="card">
    <h2>8. Event evidence</h2>
    <table>
      <tr><th>Channel</th><th>Records</th><th>Examined</th><th>Breakdown</th></tr>
      $chanRows
    </table>
    <p class="muted" style="margin-top:14px">Events worth reading:</p>
    <table>
      <tr><th style="width:70px">ID</th><th style="width:150px">When</th><th>Message</th></tr>
      $intRows
    </table>
  </div>

  <div class="card">
    <h2>9. Restart-suppression surface</h2>
    <table>$restartRows</table>
    <p class="muted">Active hours live in the UX settings key, not in a policy key, so a policy-only audit cannot see a user-chosen restart-suppression window.</p>
  </div>

  $incompleteSection
</div>
<footer>
  Read-only evidence report &middot; nothing on this device was modified &middot;
  <a href="https://github.com/Imran76Awan/Windows-Patching-Scripts" target="_blank" rel="noopener">Get-WindowsPatchingEvidence.ps1</a>
</footer>
</body>
</html>
"@
}

# ===========================================================================
# Banner
# ===========================================================================

$Script:RealComputerName = $env:COMPUTERNAME
$generated = Get-Date

Write-Host ''
Write-Host 'Windows Patching Evidence Collector (read-only)'
Write-Host ('Generated  : ' + $generated.ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ('PowerShell : ' + $PSVersionTable.PSVersion.ToString())
Write-Host ('Host       : ' + (Protect-Value $env:COMPUTERNAME))
Write-Host  'Mode       : COLLECT ONLY. Nothing on this device is changed.'
if ($Redact) { Write-Host 'Redaction  : ON - machine name, GUIDs and serials masked.' }

$identityForContext = [Security.Principal.WindowsIdentity]::GetCurrent()
$isSystem  = $identityForContext.IsSystem
$isAdmin   = ([Security.Principal.WindowsPrincipal]$identityForContext).IsInRole(
                [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host ('Context    : ' + $(if ($isSystem) { 'SYSTEM' } elseif ($isAdmin) { 'elevated administrator (NOT SYSTEM)' } else { 'standard user' }))
if (-not $isAdmin -and -not $isSystem) {
    Add-Finding -Severity 'Warning' -Text 'Not running elevated. The CBS hive and the Setup event log will not be readable, so pending-reboot and staging evidence will be incomplete.'
}

$Script:Report.Meta.Generated    = $generated.ToString('yyyy-MM-dd HH:mm:ss')
$Script:Report.Meta.PSVersion    = $PSVersionTable.PSVersion.ToString()
$Script:Report.Meta.ComputerName = Protect-Value $env:COMPUTERNAME
$Script:Report.Meta.Redacted     = [bool]$Redact
$Script:Report.Meta.Context      = if ($isSystem) { 'SYSTEM' } elseif ($isAdmin) { 'Administrator' } else { 'User' }

# ===========================================================================
# 0. Read-only self-audit
# ===========================================================================

if ($VerifyReadOnly) {
    Write-Rule '0. Read-only self-audit'
    $selfPath = $PSCommandPath
    if ([string]::IsNullOrEmpty($selfPath)) { $selfPath = $MyInvocation.MyCommand.Path }
    $audit = Test-ScriptIsReadOnly -ScriptPath $selfPath
    $Script:Report.ReadOnly = $audit

    if (-not $audit.Checked) {
        Write-Field 'Self-audit' 'skipped - source not readable'
    }
    elseif (@($audit.Hits).Count -eq 0) {
        Write-Field 'Code tokens searched' $audit.Tokens
        Write-Field 'Mutating patterns searched' $audit.Patterns
        Write-Field 'Device-mutating commands found' '0'
        Write-Note 'Comment tokens are excluded, so the help text above does not match itself.'
        Write-Note 'The only write this script performs is the -OutputHtml report file.'
    }
    else {
        Write-Field 'Device-mutating commands found' (@($audit.Hits).Count)
        foreach ($h in $audit.Hits) {
            Write-Host ('    line ' + $h.Line + ' [' + $h.Needle + '] ' + $h.Text)
        }
        Add-Finding -Severity 'Blocking' -Text 'Read-only self-audit failed - this copy of the script contains a device-mutating command. Do not run it on a production device.'
    }
}

# ===========================================================================
# 1. Identity and real patch level
# ===========================================================================

Write-Rule '1. Identity and real patch level'

$ntPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$nt = Get-ItemProperty -LiteralPath $ntPath -ErrorAction SilentlyContinue
if ($null -eq $nt) {
    Add-Incomplete 'Could not read HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion - build identity unknown.'
}

$currentBuild  = if ($nt) { [string]$nt.CurrentBuild } else { '<unknown>' }
$ubr           = if ($nt) { [string]$nt.UBR } else { '<unknown>' }
$displayVer    = if ($nt) { [string]$nt.DisplayVersion } else { '<unknown>' }
$productName   = if ($nt) { [string]$nt.ProductName } else { '<unknown>' }
$buildLabEx    = if ($nt) { [string]$nt.BuildLabEx } else { '<unknown>' }
$editionId     = if ($nt) { [string]$nt.EditionID } else { '<unknown>' }
$releaseId     = if ($nt) { [string]$nt.ReleaseId } else { '<unknown>' }
$realBuild     = $currentBuild + '.' + $ubr

$osVersionDotNet = [Environment]::OSVersion.Version.ToString()
$cimOs = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$cimVersion = if ($cimOs) { [string]$cimOs.Version } else { '<unknown>' }
$cimCaption = if ($cimOs) { [string]$cimOs.Caption } else { '<unknown>' }

$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
$serial = if ($bios) { Protect-Value $bios.SerialNumber } else { '<unknown>' }

Write-Field 'Caption (WMI)'                    $cimCaption
Write-Field 'DisplayVersion (registry)'        $displayVer
Write-Field 'Real build (CurrentBuild.UBR)'    $realBuild
Write-Field 'EditionID'                        $editionId
Write-Field 'ProductName (registry)'          $productName
Write-Field 'ReleaseId'                        $releaseId
Write-Field 'BuildLabEx'                       $buildLabEx
Write-Field 'Serial number'                    $serial
Write-Host ''
Write-Field '[Environment]::OSVersion.Version' $osVersionDotNet
Write-Field 'Win32_OperatingSystem.Version'    $cimVersion
Write-Note 'Neither of the two lines above carries the UBR. Only the registry does.'

if ($productName -notmatch 'Windows 11' -and $currentBuild -match '^\d+$' -and [int]$currentBuild -ge 22000) {
    Write-Note ('ProductName reads "' + $productName + '" on a build ' + $currentBuild + ' device. Real quirk - do not key version detection on ProductName.')
    Add-Finding -Severity 'Note' -Text ('ProductName reads "' + $productName + '" although CurrentBuild is ' + $currentBuild + '. Any compliance check keyed on ProductName silently misclassifies this device. Use CurrentBuild or DisplayVersion.')
}

$labBuild = $null
if ($buildLabEx -match '^(\d+)\.') { $labBuild = $Matches[1] }
if ($null -ne $labBuild -and $currentBuild -match '^\d+$') {
    if ($labBuild -ne $currentBuild) {
        Write-Note ('BuildLabEx carries lab build ' + $labBuild + ' on a ' + $currentBuild + ' OS - this device was installed as an earlier release and moved up in place.')
        Add-Finding -Severity 'Note' -Text ('BuildLabEx build (' + $labBuild + ') does not match CurrentBuild (' + $currentBuild + '): the device was installed as an earlier release and upgraded in place.')
    }
}

$Script:Report.Identity['Caption (WMI)']                     = $cimCaption
$Script:Report.Identity['DisplayVersion (registry)']         = $displayVer
$Script:Report.Identity['Real build (CurrentBuild.UBR)']     = $realBuild
$Script:Report.Identity['EditionID']                         = $editionId
$Script:Report.Identity['ProductName (registry)']            = $productName
$Script:Report.Identity['ReleaseId']                         = $releaseId
$Script:Report.Identity['BuildLabEx']                        = $buildLabEx
$Script:Report.Identity['Serial number']                     = $serial
$Script:Report.Identity['[Environment]::OSVersion.Version']  = $osVersionDotNet
$Script:Report.Identity['Win32_OperatingSystem.Version']     = $cimVersion

# ===========================================================================
# 2. Pending reboot - every source, read the correct way
# ===========================================================================

Write-Rule '2. Pending reboot - every source, read the correct way'

$rebootSources = New-Object System.Collections.Generic.List[psobject]

function Add-RebootSource {
    param([string] $Name, [bool] $Pending, [string] $Evidence, [string] $Method)
    $rebootSources.Add([pscustomobject]@{
        Name     = $Name
        Pending  = $Pending
        Evidence = $Evidence
        Method   = $Method
    })
}

# 2a. CBS markers. SUBKEYS, not values.
$cbsRelative = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
$cbsSubKeys  = Get-HklmSubKeyNames -SubKeyPath $cbsRelative

if ($null -eq $cbsSubKeys) {
    Add-RebootSource -Name 'CBS RebootPending'    -Pending $false -Evidence 'unreadable' -Method 'GetSubKeyNames() - FAILED'
    Add-RebootSource -Name 'CBS RebootInProgress' -Pending $false -Evidence 'unreadable' -Method 'GetSubKeyNames() - FAILED'
    Add-RebootSource -Name 'CBS PackagesPending'  -Pending $false -Evidence 'unreadable' -Method 'GetSubKeyNames() - FAILED'
    Add-Incomplete 'CBS subkeys unreadable - pending-reboot state is UNKNOWN, not clear. Run elevated.'
}
else {
    Write-Field 'CBS subkeys present' ($cbsSubKeys.Count)
    Write-Host  ('    ' + ($cbsSubKeys -join ', '))
    foreach ($marker in @('RebootPending', 'RebootInProgress', 'PackagesPending')) {
        $hit = ($cbsSubKeys -contains $marker)
        Add-RebootSource -Name ('CBS ' + $marker) -Pending $hit `
            -Evidence ($(if ($hit) { 'subkey present' } else { 'subkey absent' })) `
            -Method 'GetSubKeyNames() -contains'
    }

    # Deliberate contrast: what the value-based check would have said.
    $cbsValueProbe = Get-RegValue -Path ('HKLM:\' + $cbsRelative) -Name 'RebootPending'
    Write-Field 'naive VALUE check RebootPending' $cbsValueProbe.Display
    Write-Note 'That naive line is what a Get-ItemProperty script reports. It reads "absent" whether or not a reboot is pending, because RebootPending is a subkey.'
}

# 2b. Windows Update client marker. This one IS a key, so key presence is the test.
$auRebootPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$auRebootHit  = Test-Path -LiteralPath $auRebootPath
Add-RebootSource -Name 'WU Auto Update\RebootRequired' -Pending $auRebootHit `
    -Evidence ($(if ($auRebootHit) { 'key present' } else { 'key absent' })) -Method 'Test-Path on a key that really is a key'

# 2c. Session Manager file-rename queue.
$pfroPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$pfro = Get-RegValue -Path $pfroPath -Name 'PendingFileRenameOperations'
$pfroCount = 0
if ($pfro.Present -and -not $pfro.IsEmpty) { $pfroCount = @($pfro.Value).Count }
Add-RebootSource -Name 'PendingFileRenameOperations' -Pending ($pfroCount -gt 0) `
    -Evidence ($(if ($pfroCount -gt 0) { $pfroCount.ToString() + ' queued rename(s)' } else { 'value absent' })) `
    -Method 'specific VALUE read, then counted'

# 2d. Servicing transaction file.
$pendingXml = Test-Path -LiteralPath (Join-Path $env:SystemRoot 'WinSxS\pending.xml')
Add-RebootSource -Name 'WinSxS\pending.xml' -Pending $pendingXml `
    -Evidence ($(if ($pendingXml) { 'file present - transaction mid-flight' } else { 'file absent' })) -Method 'Test-Path on a file'

# 2e. Rename pending.
$activeName = (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName').Value
$configName = (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'       -Name 'ComputerName').Value
$renamePending = ($null -ne $activeName -and $null -ne $configName -and $activeName -ne $configName)
Add-RebootSource -Name 'Computer rename pending' -Pending $renamePending `
    -Evidence ($(if ($renamePending) { 'Active and configured names differ' } else { 'names agree' })) -Method 'two VALUE reads, compared'

Write-Host ''
$rebootSources | Select-Object Name,
    @{ n = 'Pending'; e = { if ($_.Pending) { 'YES' } else { 'no' } } },
    Evidence, Method |
    Format-Table -AutoSize | Out-String -Width 160 | Write-Host

$rebootPending = @($rebootSources | Where-Object { $_.Pending }).Count -gt 0
$Script:Report.Reboot.Sources = @($rebootSources)
$Script:Report.Reboot.Pending = $rebootPending

if ($rebootPending) {
    $names = (@($rebootSources | Where-Object { $_.Pending } | ForEach-Object { $_.Name }) -join ', ')
    Write-Field 'VERDICT' ('reboot pending (' + $names + ')')
    Add-Finding -Severity 'Blocking' -Text ('A restart is genuinely pending. Sources reporting it: ' + $names + '. Further update installs will queue behind it.')
}
else {
    Write-Field 'VERDICT' 'no restart pending on any source'
}

# CBS SessionsPending is NOT a pending-reboot signal - measured present on a device
# with no pending reboot. Reported as context so nobody misreads it as one.
$sessionsPending = Get-RegKeyFacts -Path ('HKLM:\' + $cbsRelative + '\SessionsPending')
if ($sessionsPending.Exists) {
    $excl = Get-RegValue -Path ('HKLM:\' + $cbsRelative + '\SessionsPending') -Name 'Exclusive'
    Write-Field 'CBS SessionsPending (context)' ('exists, ValueCount ' + $sessionsPending.ValueCount + ', Exclusive=' + $excl.Display)
    Write-Note 'SessionsPending exists on healthy devices. It is not a pending-reboot marker. Do not treat it as one.'
}

# ===========================================================================
# 3. Servicing and update services
# ===========================================================================

Write-Rule '3. Servicing and update services'

# Expected steady state, so a normal Stopped service is not reported as a fault.
$expected = @(
    @{ Name = 'wuauserv';         Role = 'Windows Update agent';        MustRun = $false; NormalWhenStopped = $true  },
    @{ Name = 'bits';             Role = 'Background transfer';         MustRun = $false; NormalWhenStopped = $true  },
    @{ Name = 'cryptsvc';         Role = 'Catalog and signature trust'; MustRun = $true;  NormalWhenStopped = $false },
    @{ Name = 'trustedinstaller'; Role = 'CBS servicing host';          MustRun = $false; NormalWhenStopped = $true  },
    @{ Name = 'msiserver';        Role = 'Windows Installer';           MustRun = $false; NormalWhenStopped = $true  },
    @{ Name = 'UsoSvc';           Role = 'Update Session Orchestrator'; MustRun = $true;  NormalWhenStopped = $false },
    @{ Name = 'DoSvc';            Role = 'Delivery Optimization';       MustRun = $false; NormalWhenStopped = $true  }
)

$serviceRows = New-Object System.Collections.Generic.List[psobject]
foreach ($e in $expected) {
    $svc = Get-Service -Name $e.Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        $serviceRows.Add([pscustomobject]@{
            Name = $e.Name; Status = 'not present'; StartType = '-'; Role = $e.Role
            Verdict = 'MISSING'; Concern = $true
        })
        Add-Finding -Severity 'Blocking' -Text ('Service ' + $e.Name + ' (' + $e.Role + ') is not present on this device.')
        continue
    }

    $status = [string]$svc.Status
    $start  = [string]$svc.StartType
    $concern = $false
    $verdict = 'normal'

    if ($start -eq 'Disabled') {
        $verdict = 'DISABLED'
        $concern = $true
        Add-Finding -Severity 'Blocking' -Text ('Service ' + $e.Name + ' (' + $e.Role + ') is Disabled. Updates cannot complete in this state.')
    }
    elseif ($status -ne 'Running' -and $e.MustRun) {
        $verdict = 'should be running'
        $concern = $true
        Add-Finding -Severity 'Blocking' -Text ('Service ' + $e.Name + ' (' + $e.Role + ') is ' + $status + ' but is expected to be running.')
    }
    elseif ($status -ne 'Running' -and $e.NormalWhenStopped) {
        $verdict = 'normal when idle'
    }

    $serviceRows.Add([pscustomobject]@{
        Name = $e.Name; Status = $status; StartType = $start; Role = $e.Role
        Verdict = $verdict; Concern = $concern
    })
}

$serviceRows | Select-Object Name, Status, StartType, Verdict, Role |
    Format-Table -AutoSize | Out-String -Width 160 | Write-Host
Write-Note 'trustedinstaller and msiserver Stopped/Manual while idle is correct, not a fault. That is the single most common false alarm in patching triage.'
$Script:Report.Services = @($serviceRows)

# Servicing binaries, so a log line naming a file does not send you hunting in the
# wrong directory.
$binaries = @(
    @{ Path = (Join-Path $env:SystemRoot 'System32\wuaueng.dll');            Note = 'WU agent engine - ServiceDll for wuauserv' },
    @{ Path = (Join-Path $env:SystemRoot 'System32\wuapi.dll');              Note = 'WU client COM API' },
    @{ Path = (Join-Path $env:SystemRoot 'servicing\TrustedInstaller.exe');  Note = 'Windows Modules Installer' },
    @{ Path = (Join-Path $env:SystemRoot 'System32\poqexec.exe');            Note = 'Primitive Operations Queue Executor - runs the boot-time queue' },
    @{ Path = (Join-Path $env:SystemRoot 'UUS\amd64\MoUsoCoreWorker.exe');   Note = 'Orchestrator worker - in UUS, NOT System32' }
)
Write-Host ''
Write-Host '  Servicing binaries (version drift between the agent and the OS is normal):'
foreach ($b in $binaries) {
    if (Test-Path -LiteralPath $b.Path) {
        $vi = (Get-Item -LiteralPath $b.Path -ErrorAction SilentlyContinue).VersionInfo
        Write-Host ('    ' + (Split-Path $b.Path -Leaf).PadRight(24) + ' ' + ([string]$vi.FileVersion).PadRight(46) + $b.Note)
    }
    else {
        Write-Host ('    ' + (Split-Path $b.Path -Leaf).PadRight(24) + ' ' + 'ABSENT'.PadRight(46) + $b.Note)
    }
}

# ===========================================================================
# 4. Policy - both hives, side by side
# ===========================================================================

Write-Rule '4. Policy - both hives, side by side'

$classicPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$classicAu   = $classicPath + '\AU'
$classic     = Get-RegKeyFacts -Path $classicPath
$classicAuK  = Get-RegKeyFacts -Path $classicAu

Write-Host '  Classic Group Policy hive:'
Write-Host ('    ' + $classicPath)
Write-Field '  exists / ValueCount / SubKeys' ([string]$classic.Exists + ' / ' + $classic.ValueCount + ' / ' + $classic.SubKeyCount)
if ($classic.ValueCount -gt 0) {
    Write-Field '  values' (($classic.ValueNames | Sort-Object) -join ', ')
    foreach ($n in ($classic.ValueNames | Sort-Object)) {
        $v = Get-RegValue -Path $classicPath -Name $n
        Write-Host ('      ' + $n.PadRight(30) + ' = ' + $v.Display)
        $Script:Report.PolicyOld[$n] = $v.Display
    }
}
if ($classic.ValueCount -eq 0 -and $classic.Exists) {
    $Script:Report.PolicyOld['(key exists, no values)'] = 'ValueCount 0'
}
if (-not $classic.Exists) {
    $Script:Report.PolicyOld['(key absent)'] = 'no classic WindowsUpdate policy key'
}

Write-Host ''
Write-Host ('    ' + $classicAu + '  <- the legacy AU subkey')
Write-Field '  Test-Path says' $classicAuK.Exists
Write-Field '  ValueCount / SubKeyCount' ([string]$classicAuK.ValueCount + ' / ' + $classicAuK.SubKeyCount)

# The three values that actually decide whether legacy AU policy is in force.
$auSignals = @('UseWUServer', 'NoAutoUpdate', 'AUOptions', 'ScheduledInstallDay')
$auLive = 0
foreach ($n in $auSignals) {
    $v = Get-RegValue -Path $classicAu -Name $n
    Write-Host ('      ' + $n.PadRight(30) + ' = ' + $v.Display)
    if ($v.Present) { $auLive = $auLive + 1 }
    $Script:Report.PolicyOld['AU\' + $n] = $v.Display
}
if ($classicAuK.Exists -and $auLive -eq 0) {
    Write-Note 'The AU key EXISTS and holds ZERO legacy values. "Test-Path returned true" is not evidence of legacy AU management. That is why this section tests named values and reports ValueCount.'
    Add-Finding -Severity 'Note' -Text 'The legacy ...\WindowsUpdate\AU key exists with ValueCount 0. A Test-Path-only check would report this device as legacy-AU managed. It is not.'
}

# The MDM hive - where an Intune-managed device actually keeps its update policy.
$pmUpdatePath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
$pmUpdate = Get-PolicyManagerValues -Path $pmUpdatePath
Write-Host ''
Write-Host '  MDM policy hive:'
Write-Host ('    ' + $pmUpdatePath)
Write-Field '  exists' $pmUpdate.Exists
Write-Field '  raw value names' $pmUpdate.RawCount
Write-Field '  real policies (metadata excluded)' (@($pmUpdate.Policies.Keys).Count)
foreach ($n in $pmUpdate.Policies.Keys) {
    $raw = $pmUpdate.Policies[$n]
    $shown = if ($null -eq $raw) { '<null>' }
             elseif (([string]$raw).Trim().Length -eq 0) { '<present but EMPTY>' }
             else { [string]$raw }
    Write-Host ('      ' + $n.PadRight(38) + ' = ' + $shown)
    $Script:Report.PolicyNew[$n] = $shown
}

if ($classic.ValueCount -lt @($pmUpdate.Policies.Keys).Count) {
    Add-Finding -Severity 'Warning' -Text ('The classic Group Policy hive holds ' + $classic.ValueCount +
        ' value(s) while the MDM hive holds ' + @($pmUpdate.Policies.Keys).Count +
        ' policy value(s). Auditing only the classic hive on this device would miss most of the configuration in force.')
}

# The stale-pin check: a release pin that the installed release has already passed.
$pinClassic = Get-RegValue -Path $classicPath -Name 'TargetReleaseVersionInfo'
$pinMdm     = Get-RegValue -Path $pmUpdatePath -Name 'TargetReleaseVersion'
Write-Host ''
Write-Field 'Classic TargetReleaseVersionInfo' $pinClassic.Display
Write-Field 'MDM TargetReleaseVersion'         $pinMdm.Display
Write-Field 'Installed DisplayVersion'         $displayVer
if ($pinClassic.Present -and -not $pinClassic.IsEmpty -and $displayVer -ne '<unknown>' -and $pinClassic.Display -ne $displayVer) {
    Write-Note ('The device is pinned to ' + $pinClassic.Display + ' but is running ' + $displayVer + '. The pin has been overtaken - it is no longer describing this device.')
    Add-Finding -Severity 'Warning' -Text ('Release pin mismatch: TargetReleaseVersionInfo=' + $pinClassic.Display +
        ' while the installed DisplayVersion is ' + $displayVer + '. The pin has been overtaken, so it is not what is holding this device back. Investigate what moved the device past it.')
}
if ($pinMdm.Present -and $pinMdm.IsEmpty) {
    Write-Note 'The MDM TargetReleaseVersion value is present but EMPTY. Present-and-empty is a third state that a Test-Path or a truthiness check both get wrong.'
}

# Delivery Optimization - the same lesson, sharper.
$doClassicPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
$doClassic = Get-RegKeyFacts -Path $doClassicPath
$doMdm     = Get-PolicyManagerValues -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization'
Write-Host ''
Write-Field 'Classic DO policy key exists' $doClassic.Exists
Write-Field 'MDM DO policies in force'     (@($doMdm.Policies.Keys).Count)
$Script:Report.PolicyDo['Classic Policies\...\DeliveryOptimization key'] =
    ($(if ($doClassic.Exists) { 'exists, ValueCount ' + $doClassic.ValueCount } else { 'DOES NOT EXIST' }))
$Script:Report.PolicyDo['MDM PolicyManager DeliveryOptimization policies'] = (@($doMdm.Policies.Keys).Count)
foreach ($n in $doMdm.Policies.Keys) {
    $Script:Report.PolicyDo[$n] = [string]$doMdm.Policies[$n]
}
if (-not $doClassic.Exists -and @($doMdm.Policies.Keys).Count -gt 0) {
    Write-Note ('The classic DO policy key does not exist, yet ' + @($doMdm.Policies.Keys).Count + ' DO policies are in force via MDM. A GPO-shaped audit of DO on this device finds nothing at all.')
    Add-Finding -Severity 'Note' -Text ('Delivery Optimization: the classic policy key does not exist while ' +
        @($doMdm.Policies.Keys).Count + ' DO policies are in force through the MDM hive. The documented "Group policy mapping" registry path is where the GPO twin would land, not where MDM writes.')
}

$conflict = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict' -Name 'MDMWinsOverGP'
Write-Field 'MDMWinsOverGP' $conflict.Display

# ===========================================================================
# 5. The agent's own resolved verdict
# ===========================================================================

Write-Rule "5. The agent's own resolved verdict"

$policyStatePath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState'
$policyStateKey  = Get-RegKeyFacts -Path $policyStatePath
Write-Field 'PolicyState key' ($(if ($policyStateKey.Exists) { 'exists, ValueCount ' + $policyStateKey.ValueCount } else { 'absent' }))

$wufbEvidence = New-Object System.Collections.Generic.List[string]
if ($policyStateKey.Exists) {
    $psProps = Get-ItemProperty -LiteralPath $policyStatePath -ErrorAction SilentlyContinue
    foreach ($n in ($policyStateKey.ValueNames | Sort-Object)) {
        $v = $psProps.PSObject.Properties[$n].Value
        Write-Host ('    ' + $n.PadRight(46) + ' = ' + [string]$v)
        $Script:Report.Agent[$n] = [string]$v
    }

    $isWufb   = Get-RegValue -Path $policyStatePath -Name 'IsWUfBConfigured'
    $deferral = Get-RegValue -Path $policyStatePath -Name 'IsDeferralIsActive'
    $qDefer   = Get-RegValue -Path $policyStatePath -Name 'QualityUpdatesDeferralInDays'

    Write-Host ''
    Write-Note ('IsWUfBConfigured = ' + $isWufb.Display + '. Recorded, NOT used as a management test.')
    if ($deferral.Present -and [string]$deferral.Value -eq '1') {
        $wufbEvidence.Add('IsDeferralIsActive=1')
    }
    if ($qDefer.Present -and [string]$qDefer.Value -ne '0') {
        $wufbEvidence.Add('QualityUpdatesDeferralInDays=' + $qDefer.Display)
    }
    if ($isWufb.Present -and [string]$isWufb.Value -eq '0' -and $wufbEvidence.Count -gt 0) {
        Write-Note ('IsWUfBConfigured reads 0 while ' + ($wufbEvidence -join ' and ') + ' on the same read. This is exactly why the value cannot be a test.')
        Add-Finding -Severity 'Note' -Text ('IsWUfBConfigured=0 was read at the same instant as ' + ($wufbEvidence -join ' and ') +
            '. Never branch a script on IsWUfBConfigured - it disagrees with the deferral state it sits beside.')
    }
}
else {
    Add-Incomplete 'PolicyState key not readable - the update agent has recorded no resolved policy verdict, or this process cannot read it.'
}

# The management verdict, built from evidence rather than from one flag.
if (@($pmUpdate.Policies.Keys).Count -gt 0) { $wufbEvidence.Add('MDM Update policies present: ' + @($pmUpdate.Policies.Keys).Count) }
if ($classic.ValueCount -gt 0)              { $wufbEvidence.Add('classic WindowsUpdate policy values: ' + $classic.ValueCount) }
if ($auLive -gt 0)                          { $wufbEvidence.Add('legacy AU values present: ' + $auLive) }

Write-Host ''
if ($wufbEvidence.Count -gt 0) {
    Write-Field 'Update management verdict' 'MANAGED'
    foreach ($e in $wufbEvidence) { Write-Host ('      because: ' + $e) }
}
else {
    Write-Field 'Update management verdict' 'no update policy evidence found - unmanaged'
}
$Script:Report.Agent['VERDICT (built from evidence, not from IsWUfBConfigured)'] =
    ($(if ($wufbEvidence.Count -gt 0) { 'MANAGED - ' + ($wufbEvidence -join '; ') } else { 'unmanaged' }))

# Enrollment, so you know which authority to go and look at.
$enrollRoot = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
$enrollments = @(Get-ChildItem -LiteralPath $enrollRoot -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^[0-9A-Fa-f-]{36}$' })
foreach ($en in $enrollments) {
    $prov = Get-RegValue -Path $en.PSPath -Name 'ProviderID'
    $disc = Get-RegValue -Path $en.PSPath -Name 'DiscoveryServiceFullURL'
    if ($prov.Present -or $disc.Present) {
        Write-Field 'Enrollment' ((Protect-Value $en.PSChildName) + '  ProviderID=' + $prov.Display)
        if ($disc.Present) { Write-Note ('DiscoveryServiceFullURL = ' + (Protect-Text $disc.Display)) }
        $Script:Report.Agent['Enrollment ' + (Protect-Value $en.PSChildName)] =
            ('ProviderID=' + $prov.Display + '  ' + (Protect-Text $disc.Display))
    }
}

# ===========================================================================
# 6. MDM WMI bridge - opt-in, and only trusted as SYSTEM
# ===========================================================================

if ($IncludeMdmBridge) {
    Write-Rule '6. MDM WMI bridge - opt-in, and only trusted as SYSTEM'

    $trust = if ($isSystem) {
        'Running as SYSTEM - the bridge result is trustworthy.'
    } else {
        'NOT running as SYSTEM. Microsoft: "For all device settings, the WMI Bridge client must be executed under local system user." A non-SYSTEM caller has been measured getting the documented DEFAULTS back with no error raised. Treat every number below as untrusted.'
    }
    Write-Host ('  ' + $trust)

    $bridge = $null
    try {
        $bridge = Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' `
            -ClassName 'MDM_Policy_Result01_Update02' -ErrorAction Stop
    }
    catch {
        Write-Field 'Bridge query' ('failed: ' + $_.Exception.Message)
        Add-Incomplete ('MDM bridge query failed: ' + $_.Exception.Message)
    }

    if ($null -ne $bridge) {
        $compare = @(
            @{ Name = 'AllowAutoUpdate';                    Default = '2' },
            @{ Name = 'DeferQualityUpdatesPeriodInDays';    Default = '0' },
            @{ Name = 'ConfigureDeadlineForQualityUpdates'; Default = '7' },
            @{ Name = 'ConfigureDeadlineGracePeriod';       Default = '2' }
        )

        $rows = New-Object System.Collections.Generic.List[psobject]
        $allDefault = $true
        $anyMismatch = $false

        foreach ($c in $compare) {
            $bv = $bridge.PSObject.Properties[$c.Name]
            $bridgeVal = if ($null -eq $bv) { '<not exposed>' } else { [string]$bv.Value }
            $regVal = if ($pmUpdate.Policies.Contains($c.Name)) { [string]$pmUpdate.Policies[$c.Name] } else { '<absent>' }
            $match = ($bridgeVal -eq $regVal)
            if (-not $match) { $anyMismatch = $true }
            if ($bridgeVal -ne $c.Default) { $allDefault = $false }

            $rows.Add([pscustomobject]@{
                Name = $c.Name; Bridge = $bridgeVal; Registry = $regVal; Matches = $match
            })
            Write-Host ('    ' + $c.Name.PadRight(38) + ' bridge=' + $bridgeVal.PadRight(8) +
                        ' registry=' + $regVal.PadRight(8) + $(if ($match) { '' } else { '  <-- DISAGREE' }))
        }

        $Script:Report.Bridge = [pscustomobject]@{ Trust = $trust; Rows = @($rows) }

        if ($anyMismatch -and -not $isSystem) {
            Write-Note 'The bridge disagrees with the registry, and this process is not SYSTEM. The registry is the evidence here; the bridge output is not.'
            Add-Finding -Severity 'Warning' -Text 'The MDM WMI bridge returned values that disagree with the registry while this process is not SYSTEM. Discard the bridge numbers - they are the fallback defaults, not this device.'
        }
        if ($allDefault -and $anyMismatch) {
            Write-Note 'Every bridge value equals its documented default while the registry holds different numbers. That is the exact signature of the silent-defaults fallback.'
        }
    }
}

# ===========================================================================
# 7. Inventory - what is actually installed
# ===========================================================================

Write-Rule '7. Inventory - what is actually installed'

$hotfixes = @(Get-HotFix -ErrorAction SilentlyContinue)
Write-Field 'Get-HotFix rows' $hotfixes.Count
if ($hotfixes.Count -gt 0) {
    $hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 6 HotFixID, Description, InstalledOn |
        Format-Table -AutoSize | Out-String -Width 120 | Write-Host
}

$cbsPackages = Get-HklmSubKeyNames -SubKeyPath ($cbsRelative + '\Packages')
$cbsPackageCount = if ($null -eq $cbsPackages) { '<unreadable>' } else { $cbsPackages.Count }
Write-Field 'CBS Packages subkeys' $cbsPackageCount
Write-Note 'Win32_QuickFixEngineering - and therefore Get-HotFix - returns only Component Based Servicing updates. The gap between those two numbers is why Get-HotFix is the wrong basis for a compliance report.'

$Script:Report.Inventory['Get-HotFix rows']                = $hotfixes.Count
$Script:Report.Inventory['CBS Packages subkeys']           = $cbsPackageCount
if ($hotfixes.Count -gt 0) {
    $newest = $hotfixes | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $Script:Report.Inventory['Newest Get-HotFix row']      = ([string]$newest.HotFixID + ' (' + [string]$newest.InstalledOn + ')')
}
$Script:Report.Inventory['Real patch level to report']     = ($displayVer + ' / ' + $realBuild)

# The classic last-scan check, and whether it still exists on this build.
Write-Host ''
Write-Host '  Legacy Auto Update Results keys (the classic LastSuccessTime check):'
$resultsAlive = 0
foreach ($n in @('Detect', 'Download', 'Install')) {
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\' + $n
    $facts = Get-RegKeyFacts -Path $p
    $lst = Get-RegValue -Path $p -Name 'LastSuccessTime'
    Write-Host ('    Results\' + $n.PadRight(10) + ' exists=' + ([string]$facts.Exists).PadRight(6) + ' LastSuccessTime=' + $lst.Display)
    if ($facts.Exists) { $resultsAlive = $resultsAlive + 1 }
    $Script:Report.Inventory['Auto Update\Results\' + $n] = ('exists=' + $facts.Exists + ' LastSuccessTime=' + $lst.Display)
}
if ($resultsAlive -eq 0) {
    Write-Note 'None of the three Results keys exist on this build, so the classic LastSuccessTime scan check returns nothing. Use the event log for last-scan evidence instead.'
    Add-Finding -Severity 'Note' -Text 'The legacy Auto Update\Results\{Detect,Download,Install} keys do not exist on this build. Any monitoring rule reading LastSuccessTime from them is silently returning nothing, which most dashboards render as "never scanned".'
}

# ===========================================================================
# 8. Event evidence
# ===========================================================================

Write-Rule '8. Event evidence'

$channels = @(
    @{ Name = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Interesting = @(20, 25, 31, 34, 43) },
    @{ Name = 'Setup';                                             Interesting = @(3, 4, 1013, 1014) }
)

$interesting = New-Object System.Collections.Generic.List[psobject]

foreach ($ch in $channels) {
    $logInfo = $null
    try { $logInfo = Get-WinEvent -ListLog $ch.Name -ErrorAction Stop } catch { }
    if ($null -eq $logInfo) {
        Write-Field $ch.Name 'channel not readable'
        Add-Incomplete ('Event channel not readable: ' + $ch.Name)
        continue
    }

    $events = @()
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = $ch.Name } -MaxEvents $EventCount -ErrorAction Stop)
    }
    catch {
        Add-Incomplete ('Could not read events from ' + $ch.Name + ' : ' + $_.Exception.Message)
    }

    $groups = @($events | Group-Object Id | Sort-Object { [int]$_.Name })
    $breakdown = (@($groups | ForEach-Object { 'Id ' + $_.Name + ' x' + $_.Count }) -join ', ')

    Write-Host ('  ' + $ch.Name)
    Write-Field '  channel records (total)' $logInfo.RecordCount
    Write-Field '  examined (most recent)'  $events.Count
    Write-Field '  breakdown'               $breakdown

    $Script:Report.Events.Channels += [pscustomobject]@{
        Channel   = $ch.Name
        Records   = $logInfo.RecordCount
        Examined  = $events.Count
        Breakdown = $breakdown
    }

    foreach ($ev in $events) {
        if ($ch.Interesting -contains $ev.Id) {
            $msg = [string]$ev.Message
            if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) + '...' }
            $interesting.Add([pscustomobject]@{
                Id      = $ev.Id
                When    = $ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Message = (Protect-Text ($msg -replace '\s+', ' '))
            })
        }
    }
    Write-Host ''
}

$topInteresting = @($interesting | Select-Object -First 20)
if ($topInteresting.Count -gt 0) {
    Write-Host '  Events worth reading:'
    foreach ($e in $topInteresting) {
        Write-Host ('    ' + ([string]$e.Id).PadLeft(4) + '  ' + $e.When + '  ' + $e.Message)
    }
    Add-Finding -Severity 'Warning' -Text (@($interesting).Count.ToString() +
        ' failure or corruption-class event(s) found in the window examined. Read them before changing anything.')
}
else {
    Write-Host '  No failure-class events in the window examined.'
}
$Script:Report.Events.Interesting = $topInteresting

Write-Note 'Event counts grow between reads. Quote them as "at time of measurement", never as a fixed device property.'

# ===========================================================================
# 9. Restart-suppression surface
# ===========================================================================

Write-Rule '9. Restart-suppression surface'

$uxPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$ahStart = Get-RegValue -Path $uxPath -Name 'ActiveHoursStart'
$ahEnd   = Get-RegValue -Path $uxPath -Name 'ActiveHoursEnd'
Write-Field 'ActiveHoursStart' $ahStart.Display
Write-Field 'ActiveHoursEnd'   $ahEnd.Display

if ($ahStart.Present -and $ahEnd.Present) {
    $s = [int]$ahStart.Value
    $e = [int]$ahEnd.Value
    $window = if ($e -ge $s) { $e - $s } else { (24 - $s) + $e }
    Write-Field 'Suppression window (hours)' $window
    if ($window -ge 12) {
        Write-Note 'A window this wide suppresses automatic restarts for most of the day, and it lives in the UX key rather than in a policy key, so a policy-only audit cannot see it.'
        Add-Finding -Severity 'Warning' -Text ('Active hours span ' + $window +
            ' hours (' + $ahStart.Display + ' to ' + $ahEnd.Display +
            '). Automatic restarts are suppressed for most of the day. This value is user-chosen and invisible to a policy-key audit.')
    }
    $Script:Report.Restart['Suppression window (hours)'] = $window
}

$Script:Report.Restart['ActiveHoursStart'] = $ahStart.Display
$Script:Report.Restart['ActiveHoursEnd']   = $ahEnd.Display
$noAutoReboot = Get-RegValue -Path $pmUpdatePath -Name 'ConfigureDeadlineNoAutoReboot'
$deadlineQ    = Get-RegValue -Path $pmUpdatePath -Name 'ConfigureDeadlineForQualityUpdates'
$graceP       = Get-RegValue -Path $pmUpdatePath -Name 'ConfigureDeadlineGracePeriod'
$deferQ       = Get-RegValue -Path $pmUpdatePath -Name 'DeferQualityUpdatesPeriodInDays'
Write-Field 'ConfigureDeadlineNoAutoReboot'      $noAutoReboot.Display
Write-Field 'DeferQualityUpdatesPeriodInDays'    $deferQ.Display
Write-Field 'ConfigureDeadlineForQualityUpdates' $deadlineQ.Display
Write-Field 'ConfigureDeadlineGracePeriod'       $graceP.Display
$Script:Report.Restart['ConfigureDeadlineNoAutoReboot']      = $noAutoReboot.Display
$Script:Report.Restart['DeferQualityUpdatesPeriodInDays']    = $deferQ.Display
$Script:Report.Restart['ConfigureDeadlineForQualityUpdates'] = $deadlineQ.Display
$Script:Report.Restart['ConfigureDeadlineGracePeriod']       = $graceP.Display

if ($deferQ.Present -and $deadlineQ.Present -and $graceP.Present) {
    $total = 0
    foreach ($v in @($deferQ.Value, $deadlineQ.Value, $graceP.Value)) {
        $n = 0
        if ([int]::TryParse([string]$v, [ref]$n)) { $total = $total + $n }
    }
    Write-Field 'Effective worst-case window (days)' $total
    Write-Note 'Deferral plus deadline plus grace. This is the number to quote to a security team, not the deferral alone.'
    $Script:Report.Restart['Effective worst-case window (days)'] = $total
}

# ===========================================================================
# Findings and verdict
# ===========================================================================

Write-Rule 'Findings'

$Script:Report.Findings      = @($Script:Findings)
$Script:Report.Meta.Incomplete = @($Script:Incomplete)

if (@($Script:Findings).Count -eq 0) {
    Write-Host '  Nothing flagged.'
}
else {
    foreach ($sev in @('Blocking', 'Warning', 'Note')) {
        foreach ($f in @($Script:Findings | Where-Object { $_.Severity -eq $sev })) {
            Write-Host ('  [' + $sev.ToUpper() + '] ' + $f.Text)
        }
    }
}

if (@($Script:Incomplete).Count -gt 0) {
    Write-Host ''
    Write-Host '  Collection gaps (treat these areas as UNKNOWN, not clean):'
    foreach ($i in $Script:Incomplete) { Write-Host ('    - ' + $i) }
}

$blockingCount = @($Script:Findings | Where-Object { $_.Severity -eq 'Blocking' }).Count

Write-Host ''
Write-Host ('  Blocking: ' + $blockingCount +
            '   Warning: ' + @($Script:Findings | Where-Object { $_.Severity -eq 'Warning' }).Count +
            '   Note: '    + @($Script:Findings | Where-Object { $_.Severity -eq 'Note' }).Count)

# ===========================================================================
# HTML report
# ===========================================================================

$exitCode = 0
if (@($Script:Incomplete).Count -gt 0) { $exitCode = 2 }
elseif ($blockingCount -gt 0)          { $exitCode = 1 }

if ($OutputHtml) {
    try {
        $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputHtml)
        $html = New-EvidenceHtmlReport -Data $Script:Report
        [System.IO.File]::WriteAllText($resolved, $html, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ''
        Write-Host ('  HTML report written: ' + $resolved)
        Write-Host ('  Size: ' + ([System.IO.FileInfo]$resolved).Length + ' bytes, self-contained, no external references.')
    }
    catch {
        Write-Host ''
        Write-Host ('  HTML report FAILED: ' + $_.Exception.Message)
        $exitCode = 2
    }
}

Write-Host ''
Write-Host ('  Done. Read-only. Exit code ' + $exitCode + '.')
Write-Host ''

exit $exitCode
