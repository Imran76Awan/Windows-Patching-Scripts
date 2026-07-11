# Windows Patching Scripts

PowerShell scripts for Windows vulnerability management and patch compliance in Microsoft Intune and Windows Autopatch environments.

Built for the post-MDASH era — where Microsoft's AI vulnerability discovery system (Multi-model Agentic Scanning Harness) can surface and patch CVEs faster than traditional monthly cycles.

---

## Scripts

### [`windows-vulnerability-management/`](./windows-vulnerability-management/)

| Script | Purpose |
|--------|---------|
| `Check-PatchCompliance.ps1` | Audit all Intune-managed devices for patch compliance; flags devices with stale sync or non-compliant state |
| `Get-IntuneNonCompliantDevices.ps1` | List non-compliant devices with failing policy details; useful for triage after an out-of-band patch |
| `Verify-HotpatchStatus.ps1` | Check which devices are hotpatch-eligible (Windows 11 24H2 Enterprise + VBS) vs. requiring a reboot-based patch |

---

## Requirements

- PowerShell 7.2+
- [Microsoft.Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
- Intune admin permissions:
  - `DeviceManagementManagedDevices.Read.All`
  - `DeviceManagementConfiguration.Read.All` (for policy details)

---

## Usage

```powershell
# Install the Graph module if not already present
Install-Module Microsoft.Graph -Scope CurrentUser

# Check patch compliance across all devices
.\windows-vulnerability-management\Check-PatchCompliance.ps1

# Export non-compliant devices with failing policy details
.\windows-vulnerability-management\Get-IntuneNonCompliantDevices.ps1 -IncludePolicyDetails -ExportCsv

# Identify hotpatch-eligible vs reboot-required devices
.\windows-vulnerability-management\Verify-HotpatchStatus.ps1 -ExportCsv
```

### [`windows-11-start-menu-policy/`](./windows-11-start-menu-policy/)

| Script | Purpose |
|--------|---------|
| `Get-StartMenuPolicyState.ps1` | Read MDM and GPO registry hives to report all applied Start menu policies; shows whether each is via Intune CSP or Group Policy |
| `Export-StartMenuPinConfig.ps1` | Resolve installed apps to PackageFamilyName and build a valid ConfigureStartPins JSON payload ready for Intune custom OMA-URI |

---

## Requirements

- PowerShell 7.2+
- [Microsoft.Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) (vulnerability management scripts only)
- Intune admin permissions for Graph scripts:
  - `DeviceManagementManagedDevices.Read.All`
  - `DeviceManagementConfiguration.Read.All` (for policy details)
- Start menu scripts require no special permissions (standard user for registry reads)

---

## Usage

```powershell
# ── Vulnerability management ──────────────────────────────────────────────────
Install-Module Microsoft.Graph -Scope CurrentUser

.\windows-vulnerability-management\Check-PatchCompliance.ps1
.\windows-vulnerability-management\Get-IntuneNonCompliantDevices.ps1 -IncludePolicyDetails -ExportCsv
.\windows-vulnerability-management\Verify-HotpatchStatus.ps1 -ExportCsv

# ── Start menu policy ─────────────────────────────────────────────────────────
# Report all applied Start menu CSP/GPO policies on the local device
.\windows-11-start-menu-policy\Get-StartMenuPolicyState.ps1 -ExportCsv

# Build a ConfigureStartPins JSON payload for Intune deployment
.\windows-11-start-menu-policy\Export-StartMenuPinConfig.ps1 -AppNames "Calculator","Notepad" -ExportJson
```

---

## Related

Full write-up on MDASH, hotpatch, and Windows Autopatch configuration:  
**[Microsoft's AI Is Hunting Windows Vulnerabilities Before Attackers Do](https://endpointweekly.com/blog/windows-ai-vulnerability-management-mdash.html)** — EndpointWeekly

Windows 11 Start menu policy settings (CSP + GPO reference):  
**[Windows 11 Start Menu Policy Settings: The Complete Intune & CSP Reference](https://endpointweekly.com/blog/windows-11-start-menu-policy-settings-intune-csp.html)** — EndpointWeekly
