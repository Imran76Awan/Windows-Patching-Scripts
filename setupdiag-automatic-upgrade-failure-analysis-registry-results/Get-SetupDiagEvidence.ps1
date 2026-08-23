<#
.SYNOPSIS
    Collects the automatic SetupDiag verdict (registry + XML), finds any raw
    Windows Setup logs still on disk, and optionally downloads and runs
    Microsoft's own SetupDiag.exe against them - producing a single console
    summary and a self-contained HTML report.

.DESCRIPTION
    This is NOT a pure read-only collector like Get-WindowsPatchingEvidence.ps1.
    Steps 1-3 below are read-only. Step 4 is an explicit, opt-in action: with
    -AllowDownload, it fetches SetupDiag.exe from the Microsoft Download Center
    and runs it against whatever raw logs it found. That run writes its own
    output file (path you choose via -SetupDiagOutput) and nothing else on the
    device is modified - no service is touched, no registry value is set unless
    you separately pass /AddReg yourself.

    1. Reads HKLM:\SYSTEM\Setup\SetupDiag\Results (the automatic verdict Windows
       Setup itself wrote).
    2. Checks for the automatic XML at $env:WinDir\Logs\SetupDiag.
    3. Checks the four documented raw-log locations and reports which exist:
         $Windows.~bt\Sources\Panther
         $Windows.~bt\Sources\Rollback
         Windows\Panther
         Windows\Panther\NewOS
    4. If -AllowDownload is passed and SetupDiag.exe isn't already at
       -SetupDiagPath, downloads it and runs it offline against the first raw
       log folder found, independently reproducing (or contradicting) the
       registry's stored verdict.

.PARAMETER OutputHtml
    Path to write a self-contained HTML report. No external CSS/fonts/scripts -
    opens correctly offline or behind a restrictive proxy.

.PARAMETER Redact
    Masks the computer name in both console and HTML output.

.PARAMETER AllowDownload
    Opt-in. Without this switch, the script only reports what's already on
    disk/in the registry and skips the live SetupDiag run entirely.

.PARAMETER SetupDiagPath
    Where to find or save SetupDiag.exe. Default: $env:TEMP\SetupDiag.exe.

.PARAMETER SetupDiagOutput
    Where SetupDiag.exe should write its own result log. Default:
    $env:TEMP\SetupDiag-Results.log.

.EXAMPLE
    .\Get-SetupDiagEvidence.ps1
    Registry + log-discovery only. No download, no execution, no writes.

.EXAMPLE
    .\Get-SetupDiagEvidence.ps1 -AllowDownload -OutputHtml C:\Reports\setupdiag.html -Redact
    Full run: downloads SetupDiag.exe if needed, runs it against whatever raw
    logs exist, and writes a redacted HTML report.
#>

[CmdletBinding()]
param(
    [string] $OutputHtml,
    [switch] $Redact,
    [switch] $AllowDownload,
    [string] $SetupDiagPath   = (Join-Path $env:TEMP 'SetupDiag.exe'),
    [string] $SetupDiagOutput = (Join-Path $env:TEMP 'SetupDiag-Results.log')
)

$ErrorActionPreference = 'Stop'

function ConvertTo-HtmlSafe {
    param($Text)
    if ($null -eq $Text) { return '' }
    return ([string]$Text).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Protect-Value {
    param($Value)
    if ($Redact -and $Value -eq $env:COMPUTERNAME) { return 'WKSTN-01' }
    return $Value
}

# ===========================================================================
# 1. Registry - the automatic verdict
# ===========================================================================

$regPath = 'HKLM:\SYSTEM\Setup\SetupDiag\Results'
$regData = [ordered]@{}
$regFound = Test-Path -LiteralPath $regPath
if ($regFound) {
    $item = Get-ItemProperty -LiteralPath $regPath -ErrorAction SilentlyContinue
    foreach ($p in @('DateTime','ProfileName','ProfileGuid','FailureDetails','HostOSVersion',
                      'TargetOSVersion','SetupDiagVersion','UpgradeStartTime','UpgradeEndTime',
                      'UpgradeElapsedTime')) {
        if ($item.PSObject.Properties.Name -contains $p) { $regData[$p] = [string]$item.$p }
    }
}

# ===========================================================================
# 2. The automatic XML
# ===========================================================================

$xmlDir   = Join-Path $env:WinDir 'Logs\SetupDiag'
$xmlFile  = Get-ChildItem -LiteralPath $xmlDir -Filter 'SetupDiagResults*.xml' -ErrorAction SilentlyContinue |
            Select-Object -First 1
$xmlFound = $null -ne $xmlFile

# ===========================================================================
# 3. Raw log discovery (read-only)
# ===========================================================================

$candidates = @(
    @{ Name = 'Downlevel ($Windows.~bt\Sources\Panther)'; Path = 'C:\$WINDOWS.~BT\Sources\Panther' },
    @{ Name = 'Rollback ($Windows.~bt\Sources\Rollback)'; Path = 'C:\$WINDOWS.~BT\Sources\Rollback' },
    @{ Name = 'Post-upgrade (Windows\Panther)';           Path = (Join-Path $env:WinDir 'Panther') },
    @{ Name = 'Post-upgrade, NewOS (Windows\Panther\NewOS)'; Path = (Join-Path $env:WinDir 'Panther\NewOS') }
)

$logRows = @()
$firstRawLogFolder = $null
foreach ($c in $candidates) {
    $exists = Test-Path -LiteralPath $c.Path
    $fileCount = 0
    if ($exists) {
        $fileCount = (Get-ChildItem -LiteralPath $c.Path -File -ErrorAction SilentlyContinue | Measure-Object).Count
        if (-not $firstRawLogFolder -and $fileCount -gt 0) { $firstRawLogFolder = $c.Path }
    }
    $logRows += [pscustomobject]@{ Name = $c.Name; Path = $c.Path; Exists = $exists; Files = $fileCount }
}

# ===========================================================================
# 4. Optional: download + run SetupDiag.exe against whatever was found
# ===========================================================================

$runOutput   = $null
$runSummary  = 'Skipped (pass -AllowDownload to enable).'
$matchedRule = $null

if ($AllowDownload) {
    if (-not (Test-Path -LiteralPath $SetupDiagPath)) {
        Write-Host "Downloading SetupDiag.exe to $SetupDiagPath ..."
        Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=870142' -OutFile $SetupDiagPath
    }

    if (-not $firstRawLogFolder) {
        $runSummary = 'No raw log folder with files was found - nothing to run SetupDiag against.'
    }
    else {
        $runOutput = & $SetupDiagPath "/Output:$SetupDiagOutput" "/LogsPath:$firstRawLogFolder" 2>&1 |
                     Out-String
        $matchLine = ($runOutput -split "`n" | Where-Object { $_ -match 'processing rule:\s*(\S+)\.\s*$' } |
                      Select-Object -Last 1)
        $issueLine = ($runOutput -split "`n" | Where-Object { $_ -match 'SetupDiag found \d+ matching issue' })
        if ($runOutput -match 'Error: SetupDiag reports') {
            $errLine = (($runOutput -split "`n") | Where-Object { $_ -match 'Error: SetupDiag reports' } |
                        Select-Object -First 1).Trim()
            $matchedRule = $errLine
        }
        $runSummary = if ($issueLine) { ($issueLine | Select-Object -Last 1).Trim() } else { 'Run completed - see console output.' }
    }
}

# ===========================================================================
# Console summary
# ===========================================================================

Write-Host ''
Write-Host 'SetupDiag Evidence Collector'
Write-Host ('Host       : ' + (Protect-Value $env:COMPUTERNAME))
Write-Host ('Generated  : ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ''
Write-Host '-- 1. Automatic registry verdict --'
if ($regFound) { $regData.GetEnumerator() | ForEach-Object { Write-Host ("  {0,-18} {1}" -f $_.Key, $_.Value) } }
else { Write-Host '  Not present - Windows Setup has not recorded an automatic result on this device.' }

Write-Host ''
Write-Host '-- 2. Automatic XML --'
Write-Host ('  ' + $(if ($xmlFound) { "Found: $($xmlFile.FullName) ($($xmlFile.Length) bytes)" } else { 'Not present.' }))

Write-Host ''
Write-Host '-- 3. Raw log folders --'
$logRows | ForEach-Object { Write-Host ("  [{0}] {1} - {2} file(s)" -f $(if ($_.Exists) {'x'} else {' '}), $_.Name, $_.Files) }

Write-Host ''
Write-Host '-- 4. Live SetupDiag run --'
Write-Host ('  ' + $runSummary)

# ===========================================================================
# HTML report
# ===========================================================================

if ($OutputHtml) {
    $esc = { param($v) ConvertTo-HtmlSafe $v }

    $regRows = ''
    if ($regFound) {
        foreach ($k in $regData.Keys) {
            $regRows += '<tr><td>' + (& $esc $k) + '</td><td><code>' + (& $esc $regData[$k]) + '</code></td></tr>'
        }
    } else {
        $regRows = '<tr><td colspan="2">No automatic registry record on this device.</td></tr>'
    }

    $logHtmlRows = ''
    foreach ($r in $logRows) {
        $cls = if ($r.Exists) { 'tag-teal' } else { 'tag-amber' }
        $txt = if ($r.Exists) { "present, $($r.Files) file(s)" } else { 'not present' }
        $logHtmlRows += '<tr><td>' + (& $esc $r.Name) + '</td><td><code>' + (& $esc $r.Path) +
            '</code></td><td><span class="tag ' + $cls + '">' + $txt + '</span></td></tr>'
    }

    $runSection = '<p class="muted">' + (& $esc $runSummary) + '</p>'
    if ($matchedRule) {
        $runSection = '<p class="warn"><strong>' + (& $esc $matchedRule) + '</strong></p>' + $runSection
    }
    if ($runOutput) {
        $runSection += '<pre>' + (& $esc $runOutput) + '</pre>'
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SetupDiag Evidence Report</title>
<style>
  :root{--teal:#0f766e;--teal-dark:#115e59;--ink:#0f172a;--muted:#64748b;--border:#e2e8f0;--bg:#f8fafc}
  *{box-sizing:border-box}
  body{margin:0;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
  header{background:linear-gradient(135deg,#115e59,#0f766e);color:#fff;padding:32px 28px}
  header h1{margin:0 0 6px;font-size:22px}
  header p{margin:0;color:#ccfbf1;font-size:13px}
  .wrap{max-width:900px;margin:0 auto;padding:0 20px 60px}
  .card{background:#fff;border:1px solid var(--border);border-radius:12px;padding:22px 24px;margin-bottom:18px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
  .card h2{margin:0 0 14px;font-size:14px;color:var(--teal-dark);text-transform:uppercase;letter-spacing:.04em}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{text-align:left;padding:8px 6px;border-bottom:2px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
  td{padding:8px 6px;border-bottom:1px solid #f1f5f9;vertical-align:top}
  code{background:#f1f5f9;padding:2px 6px;border-radius:4px;font-size:12px;font-family:Consolas,'Cascadia Code',monospace;word-break:break-word}
  .tag{display:inline-block;font-size:11px;font-weight:700;padding:2px 9px;border-radius:999px;white-space:nowrap}
  .tag-teal{background:#ccfbf1;color:#115e59}
  .tag-amber{background:#fef3c7;color:#92400e}
  .muted{font-size:12px;color:var(--muted)}
  .warn{background:#fffbeb;border-left:4px solid #f59e0b;padding:10px 14px;border-radius:6px;font-size:13px;margin:0 0 12px;color:#78350f}
  pre{background:#0f172a;color:#e2e8f0;border-radius:8px;padding:14px 16px;font-size:12px;overflow-x:auto;font-family:Consolas,'Cascadia Code',monospace;max-height:420px}
  footer{max-width:900px;margin:0 auto;padding:20px;text-align:center;font-size:12px;color:var(--muted)}
  footer a{color:var(--teal-dark)}
</style>
</head>
<body>
<header>
  <h1>SetupDiag Evidence Report</h1>
  <p>Generated $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) &middot; Host $(& $esc (Protect-Value $env:COMPUTERNAME))</p>
</header>
<div class="wrap">

  <div class="card">
    <h2>1. Automatic registry verdict</h2>
    <table>$regRows</table>
  </div>

  <div class="card">
    <h2>2. Automatic XML output</h2>
    <p>$(if ($xmlFound) { '<code>' + (& $esc $xmlFile.FullName) + '</code> &mdash; ' + $xmlFile.Length + ' bytes' } else { 'Not present.' })</p>
  </div>

  <div class="card">
    <h2>3. Raw log folders (read-only check)</h2>
    <table>
      <tr><th>Location</th><th>Path</th><th>State</th></tr>
      $logHtmlRows
    </table>
  </div>

  <div class="card">
    <h2>4. Live SetupDiag run</h2>
    $runSection
  </div>

</div>
<footer>
  Registry and XML reads are read-only. The live run in Section 4 only executes when -AllowDownload is passed. &middot;
  <a href="https://github.com/Imran76Awan/Windows-Patching-Scripts" target="_blank" rel="noopener">Get-SetupDiagEvidence.ps1</a>
</footer>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($OutputHtml, $html, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ''
    Write-Host ("HTML report written to: {0}" -f $OutputHtml)
}
