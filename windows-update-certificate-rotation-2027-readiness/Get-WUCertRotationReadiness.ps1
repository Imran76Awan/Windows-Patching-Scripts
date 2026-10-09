<#
.SYNOPSIS
    Reports whether this Windows device meets the update baseline required to keep talking to
    Windows Update after the 2027 Windows Update certificate rotation. Read-only.

.DESCRIPTION
    Microsoft is rotating the certificates that Windows Update uses to prove a device is talking
    to an authoritative Windows Update server. A set of those certificates expires on
    17 May 2027 and 19 June 2027. Devices that are not patched to the required baseline by then
    stop receiving all types of updates from Windows Update.

    This script reads the local OS build and update revision (UBR), maps the device to the row of
    Microsoft's published action table that applies to it, and reports whether the device is
    already compliant, needs a specific update, or needs an OS upgrade.

    It is READ-ONLY. It reads the registry and CIM, writes nothing, installs nothing, and makes
    no network calls.

    The minimum builds below were taken from Microsoft's own release-information tables
    (see .LINK) and are the "B" release - the Patch Tuesday security update - for the month
    Microsoft names in its guidance. A later build on the same line also satisfies the
    requirement, which is what the numeric comparison checks.

.PARAMETER ExportCsv
    Also write the result as a single-row CSV, for collecting across a fleet.

.PARAMETER CsvPath
    Where to write that CSV. Default: .\WUCertRotationReadiness.csv

.PARAMETER ShowMatrix
    Print the full decision matrix this script uses, then exit. Nothing is assessed.

.PARAMETER TestBuild
    Evaluate the matrix against a build you supply, in the form <build>.<ubr>, instead of reading
    the local device. Use it to confirm how the script will classify a build before you meet one
    in the field. The output is clearly marked as a test and the device fields are left blank.

.EXAMPLE
    .\Get-WUCertRotationReadiness.ps1

    Assess the local device and print the result.

.EXAMPLE
    .\Get-WUCertRotationReadiness.ps1 -ShowMatrix

    Print every build threshold and deadline the script knows about, without assessing anything.

.EXAMPLE
    .\Get-WUCertRotationReadiness.ps1 -TestBuild 19045.6000

    Show how the script classifies a Windows 10 22H2 device on build 19045.6000, without
    touching the local device.

.EXAMPLE
    .\Get-WUCertRotationReadiness.ps1 -ExportCsv -CsvPath C:\Temp\wu-cert.csv

    Assess the device and append the result to a CSV you can gather centrally.

.NOTES
    Exit codes: 0 = no action needed. 1 = action required (update or upgrade). 2 = could not
    assess (unrecognised build, or a read failed). Never returns 0 after a failed read.

    Works on Windows PowerShell 5.1 and PowerShell 7.
    Blog post: https://endpointweekly.com/blog/windows-update-certificate-rotation-2027-readiness.html

.LINK
    https://techcommunity.microsoft.com/blog/windows-itpro-blog/prepare-for-windows-update-certificate-rotation-in-2027/4562463
.LINK
    https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
.LINK
    https://learn.microsoft.com/en-us/windows/release-health/release-information
.LINK
    https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info
#>
[CmdletBinding()]
param(
    [switch] $ExportCsv,
    [string] $CsvPath = '.\WUCertRotationReadiness.csv',
    [switch] $ShowMatrix,
    [ValidatePattern('^\d{4,6}\.\d{1,6}$')] [string] $TestBuild
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:hadError = $false

# Keyed by the OS major build number, which is unambiguous across client and server SKUs.
# MinUbr is the Update Build Revision of the Patch Tuesday ("B") security release for the month
# Microsoft names. $null MinUbr means Microsoft requires no action for that build.
$BuildMatrix = @(
    [pscustomobject]@{ Build = 26300; Name = 'Windows 11, version 26H2';                                  MinUbr = $null; Kb = '';           Deadline = ''           }
    [pscustomobject]@{ Build = 28000; Name = 'Windows 11, version 26H1';                                  MinUbr = $null; Kb = '';           Deadline = ''           }
    [pscustomobject]@{ Build = 26200; Name = 'Windows 11, version 25H2';                                  MinUbr = $null; Kb = '';           Deadline = ''           }
    [pscustomobject]@{ Build = 26100; Name = 'Windows 11, version 24H2 / Windows Server 2025';            MinUbr = 6584;  Kb = 'KB5065426';  Deadline = '2027-06-19' }
    [pscustomobject]@{ Build = 22631; Name = 'Windows 11, version 23H2';                                  MinUbr = 7376;  Kb = 'KB5099414';  Deadline = '2027-06-19' }
    [pscustomobject]@{ Build = 20348; Name = 'Windows Server 2022';                                       MinUbr = 5386;  Kb = 'KB5099540';  Deadline = '2027-06-19' }
    [pscustomobject]@{ Build = 19045; Name = 'Windows 10, version 22H2';                                  MinUbr = 7548;  Kb = 'KB5099539';  Deadline = '2027-06-19' }
    [pscustomobject]@{ Build = 19044; Name = 'Windows 10 Enterprise LTSC 2021';                           MinUbr = 7548;  Kb = 'KB5099539';  Deadline = '2027-06-19' }
    [pscustomobject]@{ Build = 17763; Name = 'Windows 10 Enterprise LTSC 2019 / Windows Server 2019';     MinUbr = 9020;  Kb = 'KB5099538';  Deadline = '2027-05-17' }
    [pscustomobject]@{ Build = 14393; Name = 'Windows Server 2016';                                       MinUbr = 9339;  Kb = 'KB5099535';  Deadline = '2027-05-17' }
)

if ($ShowMatrix) {
    Write-Host ''
    Write-Host 'Windows Update certificate rotation 2027 - decision matrix used by this script'
    Write-Host 'Minimum build = the Patch Tuesday security release for the month Microsoft names.'
    Write-Host ''
    $BuildMatrix |
        Select-Object @{ n = 'Build'; e = { $_.Build } },
                      @{ n = 'Windows version'; e = { $_.Name } },
                      @{ n = 'Minimum build'; e = { if ($null -eq $_.MinUbr) { 'no action' } else { '{0}.{1}' -f $_.Build, $_.MinUbr } } },
                      @{ n = 'KB'; e = { if ($_.Kb) { $_.Kb } else { '-' } } },
                      @{ n = 'Deadline'; e = { if ($_.Deadline) { $_.Deadline } else { '-' } } } |
        Format-Table -AutoSize | Out-String | Write-Host
    Write-Host 'Any build not listed is either out of support or not covered by this script.'
    Write-Host 'Check https://learn.microsoft.com/windows/release-health/ for that device.'
    Write-Host ''
    exit 0
}

# ---- Read the local build -------------------------------------------------------------------
$cvKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = $null; $ubr = $null; $displayVersion = ''; $productName = ''; $caption = ''

$isTest = [bool]$TestBuild
if ($isTest) {
    $parts = $TestBuild.Split('.')
    $build = [int]$parts[0]
    $ubr = [int]$parts[1]
    $displayVersion = 'supplied by -TestBuild'
    $caption = 'not read (test mode)'
}
else {
try {
    $cv = Get-ItemProperty -Path $cvKey
    $build = [int]$cv.CurrentBuildNumber
    # UBR is the fourth part of the version, e.g. the 6584 in 10.0.26100.6584.
    if ($cv.PSObject.Properties['UBR']) { $ubr = [int]$cv.UBR }
    if ($cv.PSObject.Properties['DisplayVersion']) { $displayVersion = [string]$cv.DisplayVersion }
    elseif ($cv.PSObject.Properties['ReleaseId']) { $displayVersion = [string]$cv.ReleaseId }
    if ($cv.PSObject.Properties['ProductName']) { $productName = [string]$cv.ProductName }
}
catch {
    Write-Warning ("Could not read {0}: {1}" -f $cvKey, $_.Exception.Message)
    $script:hadError = $true
}

try { $caption = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption }
catch { Write-Warning ("Could not read Win32_OperatingSystem: " + $_.Exception.Message); $script:hadError = $true }
}

if ($script:hadError -or $null -eq $build -or $null -eq $ubr) {
    Write-Warning 'Assessment aborted: the local build could not be read completely.'
    exit 2
}

$installed = '{0}.{1}' -f $build, $ubr
$row = $BuildMatrix | Where-Object { $_.Build -eq $build } | Select-Object -First 1

# ---- Decide ---------------------------------------------------------------------------------
if ($null -eq $row) {
    $status = 'Unknown'
    $detail = 'This build is not in the matrix. It is either out of support or a SKU this script does not map.'
    $action = 'Check Windows release health for this version. Out-of-support devices must be upgraded to a supported version of Windows before the 2027 expiry dates.'
    $deadline = 'see release health'
    $exit = 2
}
elseif ($null -eq $row.MinUbr) {
    $status = 'No action needed'
    $detail = 'Microsoft lists this version under "Windows 11, version 25H2 and later", which requires no action.'
    $action = 'Keep taking monthly quality updates as normal.'
    $deadline = 'n/a'
    $exit = 0
}
elseif ($ubr -ge $row.MinUbr) {
    $status = 'No action needed'
    $detail = ('Installed {0} is at or above the required {1}.{2} ({3}).' -f $installed, $row.Build, $row.MinUbr, $row.Kb)
    $action = 'Keep taking monthly quality updates as normal.'
    $deadline = $row.Deadline
    $exit = 0
}
else {
    $status = 'Action required'
    $detail = ('Installed {0} is BELOW the required {1}.{2} ({3}).' -f $installed, $row.Build, $row.MinUbr, $row.Kb)
    $action = ('Install {0} or any later cumulative update before {1}. If the device cannot reach Windows Update, get the package from the Microsoft Update Catalog or push it with your management tooling.' -f $row.Kb, $row.Deadline)
    $deadline = $row.Deadline
    $exit = 1
}

$osName = if ($caption) { $caption } elseif ($productName) { $productName } else { 'Unknown' }
$versionName = if ($null -ne $row) { $row.Name } else { 'Unrecognised build' }

# ---- Report ---------------------------------------------------------------------------------
Write-Host ''
if ($isTest) { Write-Host 'Windows Update certificate rotation 2027 - MATRIX TEST (no device was read)' }
else { Write-Host 'Windows Update certificate rotation 2027 - device readiness (read-only)' }
Write-Host ''
Write-Host ('  Device          : {0}' -f $(if ($isTest) { '(test mode)' } else { $env:COMPUTERNAME }))
Write-Host ('  Operating system: {0}' -f $osName)
Write-Host ('  Release         : {0}' -f $(if ($displayVersion) { $displayVersion } else { 'not reported' }))
Write-Host ('  Installed build : {0}' -f $installed)
Write-Host ('  Matched row     : {0}' -f $versionName)
Write-Host ''
Write-Host ('  STATUS          : {0}' -f $status)
Write-Host ('  Why             : {0}' -f $detail)
Write-Host ('  Deadline        : {0}' -f $deadline)
Write-Host ('  Next step       : {0}' -f $action)
Write-Host ''
Write-Host '  Note: this does not apply to devices that get updates from WSUS.'
Write-Host ''

if ($ExportCsv) {
    $record = [pscustomobject]@{
        ComputerName    = $env:COMPUTERNAME
        AssessedUtc     = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        OperatingSystem = $osName
        Release         = $displayVersion
        InstalledBuild  = $installed
        MatchedVersion  = $versionName
        RequiredBuild   = $(if ($null -ne $row -and $null -ne $row.MinUbr) { '{0}.{1}' -f $row.Build, $row.MinUbr } else { '' })
        RequiredKb      = $(if ($null -ne $row) { $row.Kb } else { '' })
        Deadline        = $deadline
        Status          = $status
    }
    try {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvPath)
        if (Test-Path -LiteralPath $full) { $record | Export-Csv -LiteralPath $full -NoTypeInformation -Append }
        else { $record | Export-Csv -LiteralPath $full -NoTypeInformation }
        Write-Host ('  CSV written to  : {0}' -f $full)
        Write-Host ''
    }
    catch {
        Write-Warning ('Could not write the CSV: ' + $_.Exception.Message)
        exit 2
    }
}

exit $exit
