<#
.SYNOPSIS
    Checks whether a device is configured for Microsoft Entra hybrid join via
    Autopilot, and - when run on the connector server - whether the Intune
    Connector for Active Directory meets the minimum supported version.

.DESCRIPTION
    Read-only. Two modes, chosen automatically by what it finds:

    On an Autopilot-provisioned CLIENT it reports:
      - CloudAssignedDomainJoinMethod (0 = Entra join, 1 = Entra hybrid join)
      - HybridJoinSkipDCConnectivityCheck (whether the DC reachability check
        during OOBE was skipped by the profile)
      - The current Entra/domain join state from dsregcmd

    On the CONNECTOR SERVER it reports the installed Intune Connector for
    Active Directory version and compares it against the minimum supported
    build, 6.2501.2000.5. Connectors older than that can no longer process
    enrollment requests at all - hybrid Autopilot fails with an offline
    domain join timeout rather than an obvious "your connector is too old"
    message.

    Makes no changes. Exits 1 if a problem is found, 0 if healthy, 2 if this
    device is neither a hybrid Autopilot client nor a connector server.

.NOTES
    Blog post: https://endpointweekly.com/blog/hybrid-autopilot-odj-connector-version-floor.html
    Run elevated. Run it on the connector server to check the connector
    version; run it on a client to check the profile's join method.

.EXAMPLE
    .\Test-HybridAutopilotOdjReadiness.ps1
#>

[CmdletBinding()]
param(
    [string]$MinimumConnectorVersion = '6.2501.2000.5'
)

Write-Output "Hybrid Autopilot / ODJ Connector Readiness"
Write-Output ("-" * 62)

$foundSomething = $false
$problem = $false

# ---------------------------------------------------------------------------
# Client-side: what join method did the Autopilot profile actually assign?
# ---------------------------------------------------------------------------
$cacheKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache'
$diagKey  = 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot'

if (Test-Path $cacheKey) {
    $foundSomething = $true
    Write-Output "CLIENT: Autopilot profile cache found."
    $cache = Get-ItemProperty $cacheKey
    if ($cache.PolicyJsonCache) {
        try {
            $p = $cache.PolicyJsonCache | ConvertFrom-Json
            $djm = $p.CloudAssignedDomainJoinMethod
            switch ($djm) {
                1 {
                    Write-Output "  CloudAssignedDomainJoinMethod : 1 (Microsoft Entra HYBRID join)"
                    Write-Output "  -> This device's profile depends on the Intune Connector for AD."
                }
                0 {
                    Write-Output "  CloudAssignedDomainJoinMethod : 0 (Microsoft Entra join)"
                    Write-Output "  -> Cloud-only. The ODJ connector is not involved for this profile."
                }
                default {
                    Write-Output "  CloudAssignedDomainJoinMethod : $djm (unrecognised value)"
                }
            }
            if ($null -ne $p.HybridJoinSkipDCConnectivityCheck) {
                Write-Output "  HybridJoinSkipDCConnectivityCheck : $($p.HybridJoinSkipDCConnectivityCheck)"
                if ($p.HybridJoinSkipDCConnectivityCheck -eq 1) {
                    Write-Output "     (1 = the profile skipped the domain controller reachability check"
                    Write-Output "      during OOBE. Useful off-VPN, but it also means a genuinely"
                    Write-Output "      unreachable DC surfaces later as a join failure, not up front.)"
                }
            }
        } catch {
            Write-Output "  PolicyJsonCache present but not parseable."
        }
    }

    # Current real join state, straight from dsregcmd
    try {
        $ds = dsregcmd /status 2>&1
        foreach ($line in $ds) {
            if ($line -match '^\s*(AzureAdJoined|DomainJoined|EnterpriseJoined)\s*:') {
                Write-Output ("  {0}" -f $line.Trim())
            }
        }
    } catch {
        Write-Output "  dsregcmd not available."
    }
    Write-Output ""
}

# ---------------------------------------------------------------------------
# Server-side: is the Intune Connector for AD present, and new enough?
# ---------------------------------------------------------------------------
$connectorPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$connector = $null
foreach ($path in $connectorPaths) {
    $hit = Get-ItemProperty $path -ErrorAction SilentlyContinue |
           Where-Object { $_.DisplayName -like '*Intune Connector for Active Directory*' -or
                          $_.DisplayName -like '*Intune ODJ Connector*' } |
           Select-Object -First 1
    if ($hit) { $connector = $hit; break }
}

if ($connector) {
    $foundSomething = $true
    Write-Output "SERVER: Intune Connector for Active Directory found."
    Write-Output "  DisplayName : $($connector.DisplayName)"
    Write-Output "  Version     : $($connector.DisplayVersion)"
    Write-Output "  Minimum     : $MinimumConnectorVersion"
    try {
        $installed = [version]$connector.DisplayVersion
        $minimum   = [version]$MinimumConnectorVersion
        if ($installed -lt $minimum) {
            Write-Output "  Result      : TOO OLD - this connector can no longer process enrollments."
            Write-Output "                Hybrid Autopilot will fail with an offline domain join"
            Write-Output "                timeout rather than an explicit version error. Upgrade it."
            $problem = $true
        } else {
            Write-Output "  Result      : OK - meets the minimum supported version."
        }
    } catch {
        Write-Output "  Result      : could not parse version for comparison - check manually."
        $problem = $true
    }

    $svc = Get-Service -Name '*ODJConnector*' -ErrorAction SilentlyContinue
    if ($svc) {
        foreach ($s in $svc) {
            Write-Output ("  Service     : {0} = {1} (StartType {2})" -f $s.Name, $s.Status, $s.StartType)
            if ($s.Status -ne 'Running') { $problem = $true }
        }
    }
    Write-Output ""
}

if (-not $foundSomething) {
    Write-Output "Neither an Autopilot profile cache nor the Intune Connector for AD was found"
    Write-Output "on this device - it is neither a hybrid Autopilot client nor the connector"
    Write-Output "server, so there is nothing to check here."
    exit 2
}

if ($problem) { exit 1 } else { exit 0 }
