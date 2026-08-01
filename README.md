# Invoke-ADHardening

A PowerShell module that audits Active Directory for the 10 most common
hardening gaps found on internal pentests, and (opt-in) remediates them.

Each check maps 1:1 to an item in the companion video,
["10 Active Directory Weaknesses I Find in Almost Every Pentest"](https://youtu.be/vXPeJZ7n0Xs),
so defenders can watch the video, run the tool, and remediate in a tight
loop.

This is **not** a competitor to PingCastle, Purple Knight, or Locksmith —
those are credited as prior art in the banner and (for AD CS / ESC*)
explicitly delegated to.

---

## What it checks

| ID       | Check                                  | Severity | Auto-fix |
|----------|----------------------------------------|----------|----------|
| ADH-001  | LLMNR disabled via GPO                 | High     | Yes      |
| ADH-002  | `ms-DS-MachineAccountQuota` = 0        | High     | Yes      |
| ADH-003  | SMB signing required (server + client) | High     | Yes      |
| ADH-004  | LDAP signing + channel binding on DCs  | Critical | Yes (gated) |
| ADH-005  | IPv6 / mitm6 mitigations               | High     | Yes (GPO firewall) |
| ADH-006  | Pre-Windows 2000 Compatible Access     | Medium   | Yes      |
| ADH-007  | Kerberoasting / AS-REP roastable accts | High–Critical | No (guidance) |
| ADH-008  | Unconstrained delegation on non-DCs    | Critical | No (guidance) |
| ADH-009  | Default Domain Password Policy baseline| High     | Yes      |
| ADH-010  | AD CS misconfigurations (ESC1–15)      | Critical | No (defers to Locksmith) |

Audit mode is provably read-only: a Pester test (`Tests/AuditPhase.ReadOnly.Tests.ps1`)
fails the build if any audit-path file invokes a mutating cmdlet.

---

## Install

Requirements:

- Windows with PowerShell 5.1 or later
- RSAT: the `ActiveDirectory` and `GroupPolicy` modules
- A domain-joined session as at least a domain user (some checks need more —
  see "What the checks need" below)

Clone and import:

```powershell
git clone https://github.com/HenryHuevo/Invoke-ADHardening.git C:\Tools\Invoke-ADHardening
Import-Module C:\Tools\Invoke-ADHardening\Invoke-ADHardening.psd1
```

---

## Run an audit

```powershell
# Full audit, default behaviour
Invoke-ADHardening

# Subset of checks
Invoke-ADHardening -IncludeCheckIds ADH-001,ADH-003

# Everything except the network-firewall check
Invoke-ADHardening -ExcludeCheckIds ADH-005

# Skip the banner / Read-Host gate (unattended runs)
Invoke-ADHardening -NoBanner

# Custom output directory
Invoke-ADHardening -OutputPath C:\Audits\2026-05-31
```

Every run writes to `Reports/<yyyy-MM-dd_HHmmss>/`:

| File              | Audience |
|-------------------|----------|
| `report.html`     | Leadership / share-out — one collapsed row per check, filterable, dark/light |
| `report.csv`      | Excel tracking — Evidence flattened to JSON strings |
| `report.json`     | SIEM / automation — full structured findings |
| `findings.jsonl`  | One JSON finding per line (streamed as checks run) |
| `audit.log`       | Timestamped INFO/CHECK/PASS/FAIL/WARN/ERROR/FIX/DEBUG |

---

## Apply fixes (Implement mode)

Implement mode consumes a saved audit and **previews every applicable fix with
`-WhatIf` first** — nothing is changed yet. It then asks `y/N` whether to apply
the previewed changes, and if you say yes, whether to apply them **[A]ll at
once** or review them **[O]ne-by-one** (`[A]pply / [S]kip / Skip [R]est /
[Q]uit` per finding). Only auto-fixable `Fail`/`Warning` findings still in
scope are offered; ADH-007/-008/-010 need human judgment and are never
auto-applied.

```powershell
# 1. Audit.
Invoke-ADHardening

# 2. Review the report.
Start-Process .\Reports\2026-05-31_142201\report.html

# 3. Preview the fixes, then choose to apply (all at once or one-by-one).
Invoke-ADHardening -Mode Implement -ReportPath .\Reports\2026-05-31_142201

# Unattended apply (no prompts) — applies every applicable fix.
Invoke-ADHardening -Mode Implement -ReportPath .\Reports\2026-05-31_142201 -Force -Confirm:$false

# Unattended dry run (no prompts, no changes) — previews every fix under -WhatIf.
Invoke-ADHardening -Mode Implement -ReportPath .\Reports\2026-05-31_142201 -Confirm:$false
```

Each applied fix is re-checked to verify it took effect, and the run writes
`implementation-report.html` + `implementation-summary.json` into its own
`Reports/<timestamp>/` directory (a dry-run report is still written if you
preview and decline; `[Q]uit` mid-run writes none).

All GPO-based fixes write to a single dedicated GPO **`Invoke-ADHardening Hardening`**
(or `Invoke-ADHardening DC Hardening` for DC-OU-scoped settings). The Default
Domain Policy is never modified. Reverting a fix is one unlink in GPMC.

Fixes configure the **real, named GPO policy** — the same item you would click
in the Group Policy editor — not a raw registry value stuffed into a GPO:

- **Administrative Templates** (e.g. ADH-001 "Turn off multicast name
  resolution") are set via `Set-GPRegistryValue` (their native `registry.pol`
  backing).
- **Security Options** (ADH-003 "Microsoft network server/client: Digitally
  sign communications (always)"; ADH-004 "Domain controller: LDAP server
  signing / channel binding token requirements") are written as proper
  Security Options in the GPO's `GptTmpl.inf` via the `Set-ADHGpoSecurityOption`
  helper, so GPMC shows them as the named policy rather than an "Extra Registry
  Setting". No external tooling (e.g. LGPO.exe) is required.

---

## What the checks need

Most checks only need a domain user. A few need more:

- **ADH-004 LDAP signing**: reads the GPOs applied to the Domain Controllers
  OU (registry policy, then Security-Options XML). Needs GPO read rights (any
  authenticated user by default), not local admin on each DC. It reflects
  policy intent (what GPO will push), not each DC's live registry.
- **ADH-005 IPv6 mitm6**: the `NetSecurity` module (`Get-NetFirewallRule`)
  to enumerate GPO firewall rules. If missing, returns `Warning` with
  manual-verification guidance. The auto-fix (`Set-IPv6Mitm6Mitigated`) adds
  three **Block** rules to the Invoke-ADHardening Hardening GPO — inbound
  DHCPv6 (UDP 546), inbound Router Advertisement (ICMPv6 134), and outbound
  DHCPv6 (UDP 546→547) — the host-level fallback to switch-level RA/DHCPv6
  Guard. It does **not** disable IPv6 (unsupported by Microsoft) and cannot
  configure switch-level guards, so a `Pass` only means the GPO rules exist.
- **ADH-010 AD CS**: the `Locksmith` module
  (`Install-Module -Name Locksmith -Scope CurrentUser`). If missing, returns
  `Warning` with install instructions. If no CA is deployed, returns
  `NotApplicable`. The check invokes Locksmith in audit-only CSV mode
  (`Invoke-Locksmith -Mode 2`) and drops the resulting
  `Locksmith <timestamp> ADCSIssues.CSV` into the run's
  `Reports/<timestamp>/` directory for full detail.

The HTML/CSV/JSON reports always include an `AuditMethod`,
`RequiresElevation`, and `Limitations` block under each finding's evidence,
so an operator can see exactly how the check looked and what the result does
not prove.

---

## Repo layout

```
Invoke-ADHardening.psd1          Manifest
Invoke-ADHardening.psm1          Module loader
Public/
  Invoke-ADHardening.ps1         The only exported function
Private/
  Checks/   Test-*.ps1           One per ADH-NNN, read-only
  Fixes/    Set-*.ps1            Auto-fix functions, SupportsShouldProcess
  Helpers/                       Banner, prereqs, logger, finding factory,
                                 audit phase, report exporter, GPO helper
  Probes/   Invoke-ADH*Probe.ps1 Optional network-behaviour probes (not yet
                                 wired into checks)
Reports/                         Runtime output, one dir per run
Tests/                           Pester tests — checks, helpers, implement phase,
                                 and the read-only invariant
lab/                             Sample audit artifacts for docs/demos (lab/sample/,
                                 zipped as lab/sample.zip)
CLAUDE.md                        Contributor / agent documentation
LICENSE                          GNU AGPLv3 license
```

Design notes, naming conventions, and the read-only invariant are documented
in [`CLAUDE.md`](CLAUDE.md).

---

## Running the tests

From PowerShell with Pester 5 installed:

```powershell
Invoke-Pester -Path .\Tests -Output Detailed
```

The unit tests stub out the AD/GPO cmdlets, so they can run on a non-domain
machine (even a CI runner without RSAT). The read-only AST test runs
anywhere PowerShell + Pester are installed.

---

## License

GNU Affero General Public License v3.0 (AGPLv3) — see [`LICENSE`](LICENSE).
Free to use, study, modify, and redistribute, including commercially; if you
distribute a modified version or offer it to users over a network, you must
make your modified source available under the same license.

## Credits

Built standing on the shoulders of: PingCastle (Vincent Le Toux), Purple
Knight (Semperis), Locksmith (Jake Hildreth / TrimarcJake), Certify /
Certipy (SpecterOps / Oliver Lyak), NetExec, Impacket, BloodHound, and the
broader AD security community.

## Disclaimer

Audit mode is read-only. Implement mode prompts before every change and
relies on standard PowerShell `SupportsShouldProcess` semantics. You are
responsible for testing in a lab first and for the state of your production
environment.
