# Windows Patching Scripts

PowerShell scripts for Windows patching, servicing and Secure Boot in Microsoft Intune and
Windows Autopatch environments, each paired with a write-up on
[EndpointWeekly](https://endpointweekly.com/blog.html).

## Standards every script in this repo meets

- **Read-only unless the filename says otherwise.** Anything named `Get-` or `Test-` reports
  and never changes state. Microsoft Graph access is `-Method GET` only, least-privilege
  `.Read` scopes. The one `Remediate-` script states plainly what it writes.
- **Runs on Windows PowerShell 5.1 and PowerShell 7.** Verified with 0 parse errors on both.
  No PowerShell 7-only syntax: the null-conditional operator (`$x?.Prop`) silently yields
  nothing on 5.1 instead of erroring, and a non-ASCII character inside a string literal makes
  5.1 fail to parse the file at all. Both bugs have been found and fixed in these repos.
- **ASCII-only.** 0 non-ASCII bytes per file, for the reason above.
- **Fails loud.** A script aborts rather than reporting a clean or zero result after a failed
  query, and distinguishes "the query failed" from "the thing is genuinely absent".
- **Asks before installing.** No silent `Install-Module -Force`.

## Scripts (11)

| Script | What it tells you | Written guide |
|---|---|---|
| [`Get-PasskeyRegistrationStatus.ps1`](Daily-Tasks/) | Reports FIDO2 passkey registration status for all Entra ID users. | [How to Enable Passkeys with Microsoft Authenticator in Microsoft 365](https://endpointweekly.com/blog/microsoft-authenticator-passkeys-entra-id-intune.html) |
| [`Get-BlackLotusMitigationStatus.ps1`](blacklotus-secure-boot-four-mitigations-configmgr-tracking/) | Reports this device's real progress through all four CVE-2023-24932 (BlackLotus) Secure Boot mitigations - not just whether the certificate... | [BlackLotus Isn't Fixed When the Certificate Updates: Tracking...](https://endpointweekly.com/blog/blacklotus-secure-boot-four-mitigations-configmgr-tracking.html) |
| [`Get-OrgSecureBootFleetReport.ps1`](blacklotus-secure-boot-four-mitigations-configmgr-tracking/) | Read-only fleet-wide report on Secure Boot / BlackLotus (CVE-2023-24932) mitigation status, pulled from your own organisation's Intune tenant... | [BlackLotus Isn't Fixed When the Certificate Updates: Tracking...](https://endpointweekly.com/blog/blacklotus-secure-boot-four-mitigations-configmgr-tracking.html) |
| [`Get-PasskeyRegistrationStatus.ps1`](entra-passkeys-sms-migration/) | Reports passkey registration progress across your Entra ID tenant. | [Passkeys Are Now the Default in Entra ID: What You Need to Do...](https://endpointweekly.com/blog/entra-passkeys-default-authentication-2026.html) |
| [`Get-SMSOnlyUsers.ps1`](entra-passkeys-sms-migration/) | Finds Entra ID users who rely on SMS/voice MFA only and have no passkey or Authenticator app registered. | [Passkeys Are Now the Default in Entra ID: What You Need to Do...](https://endpointweekly.com/blog/entra-passkeys-default-authentication-2026.html) |
| [`Get-PatchTuesdayBuildCompliance.ps1`](kb5121003-kb5120240-august-2026-patch-tuesday-whats-new/) | Confirms a device actually landed on the expected build after August 2026 Patch Tuesday (KB5121003 / KB5120240), rather than trusting Windows... | [KB5121003 and KB5120240: What's Actually New in August 2026's...](https://endpointweekly.com/blog/kb5121003-kb5120240-august-2026-patch-tuesday-whats-new.html) |
| [`Remediate-PatchTuesdayBuildComplianceReport.ps1`](kb5121003-kb5120240-august-2026-patch-tuesday-whats-new/) | Report-only remediation companion to Get-PatchTuesdayBuildCompliance.ps1. | [KB5121003 and KB5120240: What's Actually New in August 2026's...](https://endpointweekly.com/blog/kb5121003-kb5120240-august-2026-patch-tuesday-whats-new.html) |
| [`Test-WebAuthnLogExposure.ps1`](pass-the-passkey-entra-signature-replay-cve-2026-34348/) | Checks whether this device's WebAuthn event log is likely patched against CVE-2026-34348 (the Pass-the-Passkey signature-logging issue), and... | [Pass-the-Passkey: How a Windows Event Log Let Attackers Replay...](https://endpointweekly.com/blog/pass-the-passkey-entra-signature-replay-cve-2026-34348.html) |
| [`Check-PatchCompliance.ps1`](windows-vulnerability-management/) | Checks patch compliance for all Windows devices managed by Microsoft Intune. Flags devices missing Critical or High severity patches older... | [Microsoft's AI Is Hunting Windows Vulnerabilities Before...](https://endpointweekly.com/blog/windows-ai-vulnerability-management-mdash.html) |
| [`Get-IntuneNonCompliantDevices.ps1`](windows-vulnerability-management/) | Retrieves all non-compliant devices from Intune with detailed policy failure reasons. | [Microsoft's AI Is Hunting Windows Vulnerabilities Before...](https://endpointweekly.com/blog/windows-ai-vulnerability-management-mdash.html) |
| [`Verify-HotpatchStatus.ps1`](windows-vulnerability-management/) | Verifies Windows Hotpatch eligibility and current hotpatch status for Intune-managed devices. | [Microsoft's AI Is Hunting Windows Vulnerabilities Before...](https://endpointweekly.com/blog/windows-ai-vulnerability-management-mdash.html) |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- [Microsoft.Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation)
  for the Graph-based scripts. Local-only scripts need no module; each script's help says which.
- Least-privilege Graph permissions, per script. Commonly:
  - `DeviceManagementManagedDevices.Read.All`
  - `DeviceManagementConfiguration.Read.All`

Run elevated: several read `HKLM` hives, servicing logs under `C:WindowsLogs`, or Secure
Boot / TPM state.

## Sibling repos

| Repo | Holds |
|---|---|
| [Windows-11-Scripts](https://github.com/Imran76Awan/Windows-11-Scripts) | Windows 11 topics - Start menu policy, servicing channel, and the Windows 11 deep-dive series |
| [Windows-Autopilot-Scripts](https://github.com/Imran76Awan/Windows-Autopilot-Scripts) | Autopilot diagnostics |
| [Daily-Tasks](https://github.com/Imran76Awan/Daily-Tasks) | Intune and Entra audits |

The Start menu and servicing-channel scripts moved to Windows-11-Scripts; Autopilot scripts
moved to Windows-Autopilot-Scripts. This repo keeps patching, servicing and Secure Boot.

_This script table is generated from each script's `.SYNOPSIS` and the blog URL in its
`.NOTES`, so it cannot drift out of step with the files._
