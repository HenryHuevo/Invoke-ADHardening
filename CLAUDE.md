# Invoke-ADHardening

PowerShell module that audits Active Directory for the 10 most common
misconfigurations found on internal pentests, and (opt-in) remediates them.
Each check maps 1:1 to an item in the companion video,
["10 Active Directory Weaknesses I Find in Almost Every Pentest"](https://youtu.be/vXPeJZ7n0Xs),
so defenders can watch the video, run the tool, and remediate in a tight
loop.

The module, manifest, public function, and banner use
**`Invoke-ADHardening`**, and all internal identifiers use the short
**`ADH`** stem — check IDs `ADH-001`..`ADH-010`, log path variable
`$script:ADHLogPath`, finding factory `New-ADHFinding`, helpers like
`Test-ADHPrerequisites` / `Invoke-ADHAuditPhase` / `Export-ADHReport`,
probes like `Invoke-ADHLlmnrProbe`, and so on.

This is **not** a competitor to PingCastle, Purple Knight, or Locksmith.
Those tools are credited in the banner as prior art and (for AD CS / ESC*)
explicitly delegated to.

---

## How it works

`Invoke-ADHardening` is the only exported function. It does two things:

1. **Audit mode (default, read-only)** — runs each `Test-*` check, aggregates
   findings, emits HTML/CSV/JSON/log reports to `Reports/<timestamp>/`.
2. **Implement mode (opt-in)** — consumes a saved audit report and prompts
   per-finding before applying matching `Set-*` fixes. Audit is *not* re-run
   inside implement; the operator runs audit, reviews, then implements.

```
Invoke-ADHardening                                    # full audit
Invoke-ADHardening -IncludeCheckIds ADH-001,ADH-003 # subset
Invoke-ADHardening -Mode Implement -ReportPath .\Reports\2026-05-13_142201
Invoke-ADHardening -NoBanner                          # skip banner/prompt
```

### Orchestrator flow (`Public/Invoke-ADHardening.ps1`)

1. Build `Reports/<timestamp>/` directory and set `$script:ADHLogPath` (the
   resolved absolute path — all logging keys off this).
2. `Show-Invoke-ADHardeningBanner` (skippable with `-NoBanner`, blocks on
   `Read-Host`).
3. `Test-ADHPrerequisites` — RSAT modules present, AD reachable, principal
   resolvable. Bail on `$false`.
4. `$checkRegistry` is the source of truth for which checks exist and which
   fix function each maps to (`Id` / `Test` / `Fix`). Filter by
   `-IncludeCheckIds` / `-ExcludeCheckIds`.
5. Dispatch to `Invoke-ADHAuditPhase` or `Invoke-ADHImplementPhase`.

### Check registry

| Id        | Test                          | Fix                          | Category            | Severity |
|-----------|-------------------------------|------------------------------|---------------------|----------|
| ADH-001  | Test-LLMNR                    | Set-LLMNRDisabled            | Legacy Protocols    | High     |
| ADH-002  | Test-MachineAccountQuota      | Set-MachineAccountQuota      | Domain Object       | High     |
| ADH-003  | Test-SMBSigning               | Set-SMBSigningRequired       | Relay Defenses      | High     |
| ADH-004  | Test-LDAPSigning              | Set-LDAPSigningEnforced      | Relay Defenses      | Critical |
| ADH-005  | Test-IPv6Mitm6                | Set-IPv6Mitm6Mitigated       | Relay Defenses      | High     |
| ADH-006  | Test-PreWin2000Group          | Set-PreWin2000GroupCleaned   | Legacy Compatibility| Medium   |
| ADH-007  | Test-Kerberoasting            | (none — guidance)            | Kerberos            | Critical |
| ADH-008  | Test-UnconstrainedDelegation  | (none — guidance)            | Delegation          | Critical |
| ADH-009  | Test-PasswordPolicy           | Set-PasswordPolicyBaseline   | Identity            | High     |
| ADH-010  | Test-ADCSMisconfig            | (none — defer to Locksmith)  | AD CS               | Critical |

---

## Repo layout

```
README.md                        User-facing docs (install, run, check table, credits).
Invoke-ADHardening.psd1          Manifest (RequiredModules: ActiveDirectory, GroupPolicy)
Invoke-ADHardening.psm1          Loader: dot-sources Private/ + Public/, exports Public/ only
Public/
  Invoke-ADHardening.ps1         Orchestrator (the only exported function)
Private/
  Checks/   Test-*.ps1           One per ADH-NNN. Read-only. Return one finding object.
  Fixes/    Set-*.ps1            One per check with AutoFixAvailable=$true. SupportsShouldProcess.
  Helpers/                       Shared infrastructure (see below)
  Probes/   Invoke-ADH*Probe.ps1 Optional network behaviour probes. Not wired into any
                                 check; referenced from check evidence as a roadmap item.
Reports/                         Runtime output. Each run gets Reports/<yyyy-MM-dd_HHmmss>/.
lab/                             Sample artifacts for docs/demos. lab/sample/ holds a
                                 captured audit run (audit.log, findings.jsonl,
                                 report.{json,csv,html}); lab/sample.zip is the zipped copy.
                                 Not part of the module or test path.
Tests/     *.Tests.ps1           Pester. AuditPhase.ReadOnly.Tests.ps1 is the load-bearing one.
  Checks/  *.Tests.ps1           Per-check suite with mocked AD/GPO/NetSecurity cmdlets.
  Helpers/ *.Tests.ps1           Helper-level tests (e.g. the multi-GPO Get-ADHGpoSettingForOu
                                 regression coverage).
  Fixtures/                      Shared fixture data (e.g. findings.jsonl for implement-phase tests).
```

### Helpers (`Private/Helpers/`)

- **`New-ADHFinding`** — the finding-object factory. Every check returns
  one of these. Schema is locked; downstream consumers (report renderer,
  implement phase, JSON sinks) depend on it. See "Finding schema" below.
- **`Write-ADHLog`** — central logger. Appends to `audit.log`; with
  `-Finding`, also appends a JSONL line to `findings.jsonl`; with
  `-Console`, mirrors to host with a level-coloured line. Requires
  `$script:ADHLogPath`.
- **`Test-ADHPrerequisites`** — RSAT + AD reachability gate.
- **`Show-Invoke-ADHardeningBanner`** — banner + credits + `Read-Host` gate.
- **`Invoke-ADHAuditPhase`** — dispatches each `Test-*` by name via
  `Get-Command`/`&`. Wraps each in try/catch so one broken check does not
  kill the run; on crash, synthesises an `Error`-status finding so it still
  shows up in the report. Calls `Export-ADHReport`, prints summary.
- **`Export-ADHReport`** — writes `report.json`, `report.csv` (Evidence /
  AffectedObjects / References flattened), and `report.html` via
  `New-ADHHtmlReport`. `ConvertTo-ADHEvidenceMap` (normalise Evidence from a
  hashtable *or* a JSON-round-tripped PSCustomObject) lives alongside it.
  It passes the run directory through as `-RunPath`, so every implement command
  printed on the page pins `-ReportPath` to *this* audit — reading an older
  report and copying its command remediates from that audit, not from whichever
  one happens to be newest. The page's call to action names the auto-fixable
  check IDs ("ADH-003, ADH-004, ADH-005 and ADH-009 have automated fixes ...")
  and offers the bare `-Mode Implement` command, which with no
  `-IncludeCheckIds` applies all of them; each check's own row still carries a
  scoped `-IncludeCheckIds <id>` variant.
- **`Get-ADHReportAssets`** — the shared report design system:
  `Get-ADHReportStyle` (CSS), `Get-ADHReportScript` (JS),
  `Get-ADHReportBootScript` (pre-paint theme), and `Format-ADHHtmlText`
  (HTML-encode with a fallback). **Both** `New-ADHHtmlReport` and
  `New-ADHImplementationReport` render from these, so the two pages are one
  design rather than two that drift. The file header documents the markup
  contract (`#theme`, `.chip[data-filter][data-sig]`, `#sortby`, `#records >
  details.rec`, `#readout[data-noun]`, `#empty`, `#expand`, `.copy[data-copy]`).
  It is in the read-only audit path, so it is listed in the read-only test's
  `$script:auditFiles`.
  - Self-contained: inline CSS/JS, no external requests, opens from `file://`
    on an air-gapped box.
  - **No chart and no severity rating on either page** — status is the only
    signal, so the collapsed list of checks *is* the overview. Each check is a
    `<details class="rec">` row (id · status · name · category) that opens onto
    its detail, plus an Expand-all / Collapse-all toggle. Disclosure is native
    `<details>`, so the page still reads with JS disabled. Severity is still on
    the finding object and still in `report.json` / `report.csv`; it is only
    absent from the HTML.
  - Colour encodes state only, via a `--sig` custom property keyed off a
    `data-sig` attribute (`jade` / `brass` / `rose` / `violet` / `quiet`), and
    never alone — every state is spelled out beside its colour. Both ramps are
    validated for CVD separation and contrast against their own surfaces.
  - Dark/light toggle, dark by default, persisted to `localStorage` where the
    browser allows it on `file://`.
  - **Keep this file pure ASCII** — Windows PowerShell reads a BOM-less `.ps1`
    as ANSI, so a literal non-ASCII glyph in the embedded CSS/JS reaches the
    browser as mojibake. Use `\uXXXX` in JS and `&#NNN;` in HTML.
- **`Get-ADHGpoSettingForOu`** — generic GPO-setting lookup at a given OU.
  Tries Registry Policy (`Get-GPRegistryValue`) first, falls back to parsing
  Security Options out of `Get-GPOReport` XML. Used by checks where the
  setting may be expressed either way (e.g. ADH-004 LDAP signing).
- **`Set-ADHGpoSecurityOption`** / **`Get-ADHGpoSecurityOption`** — write/read
  a GPO **Security Option** (the real named policy under Security Settings >
  Local Policies > Security Options), which the in-box GroupPolicy module
  cannot set. `Set-` merges `[Registry Values]` lines into the GPO's
  `GptTmpl.inf` under SYSVOL, bumps the computer version in `GPT.ini` + the AD
  object's `versionNumber`, and merges the Security CSE GUID into
  `gPCMachineExtensionNames` (preserving any existing CSE — the LLMNR Admin
  Template's Registry CSE shares the same GPO). `Get-` reads a value back from
  `GptTmpl.inf` for before/after change records. Used by the ADH-003 (SMB
  signing) and ADH-004 (LDAP signing) fixes so settings render as the named
  policy, not an "Extra Registry Setting". Fix-support only — NOT in the
  read-only audit path (it deliberately uses `Set-ADObject`). No external
  tooling (LGPO.exe) required. `Set-GPRegistryValue` is the right tool for
  genuine Administrative Templates (ADH-001 LLMNR).
- **`Set-ADHGpoSystemAccess`** / **`Get-ADHGpoSystemAccess`** — write/read
  **Account Policy** (Password + Account Lockout policy), which lives in the
  `[System Access]` section of `GptTmpl.inf` — a different section from the
  Security Options above, but the same file and same Security CSE. Used by the
  ADH-009 (password policy) fix. Encoding follows the security-template
  convention, **not** the GUI/`Set-ADDefaultDomainPasswordPolicy` one — notably
  `MaximumPasswordAge = -1` means "never expire" (GUI 0 days), and
  lockout durations are in minutes. NB: account policy only takes effect from a
  GPO linked at the **domain root** (and, to beat Default Domain Policy, the
  link must be **Enforced**) — the fix owns that link. The `[System Access]`
  writer, the `[Registry Values]` Security-Option writer, and the shared
  version-bump/CSE plumbing (`Merge-ADHGptTmplSection` /
  `Update-ADHGpoMachineVersion`) all live in `Set-ADHGpoSecurityOption.ps1`.
- **`Invoke-ADHImplementPhase`** — implement (remediation) phase. Loads a
  saved audit (`findings.jsonl`, falling back to `report.json`), filters to
  auto-fixable `Fail`/`Warning` findings still in scope, then (interactive
  flow) **previews every applicable fix under `-WhatIf` first**, prompts
  `y/N` to actually apply, and if yes asks **[A]ll at once** (no further
  prompts) vs **[O]ne-by-one** (`[A]pply / [S]kip / Skip [R]est / [Q]uit`
  per finding). Each applied fix re-runs the matching `Test-*` to verify, and
  the phase emits `implementation-report.html` + `implementation-summary.json`
  (a dry-run report is still written if the operator previews then declines;
  `[Q]uit` writes none). Unattended runs pass `-Confirm:$false`, which skips
  the interactive flow: `-Force` then applies, otherwise everything runs as a
  `-WhatIf` dry run. Intentionally **not** in the read-only audit path — do
  not add it to `$auditFiles` in the read-only test.
- **`New-ADHImplementationReport`** — renders the implement-phase results as a
  self-contained HTML report off the same `Get-ADHReportAssets` design system as
  the audit report. One collapsed row per fix attempt, in run order: id ·
  action (Applied / WhatIf / Skipped / Failed) · check name · step N of M.
  Opened, it shows the `before -> after` re-check transition and whether it
  verified, the fix function that ran, the note the phase recorded, and the raw
  change record.

### Probes (`Private/Probes/`)

Optional active probes (`Invoke-ADHLlmnrProbe`, `Invoke-ADHSmbSigningProbe`,
`Invoke-ADHLdapSigningProbe`) that measure on-the-wire behaviour rather than
policy state. They are **not** wired into the default audit path — checks
reference them in evidence only as "an opt-in on-the-wire probe is on the
project roadmap". Treat them as isolated utilities; do not call them from `Test-*` without
also handling their limitations (broadcast-domain scope, false negatives).

---

## Finding schema

Every `Test-*` returns exactly one object built by `New-ADHFinding`:

```
CheckId          'ADH-001'                    string
CheckName        'LLMNR Disabled'              string
Category         'Legacy Protocols'            string
Severity         Critical|High|Medium|Low|Info
Status           Pass|Fail|Warning|Error|NotApplicable
Description      human summary                 string
Evidence         raw supporting data           hashtable
AffectedObjects  e.g. failing DC hostnames     string[]
RemediationSteps copy-pasteable guidance       string
AutoFixAvailable                               bool
FixFunction      e.g. 'Set-LLMNRDisabled'      string
References       URLs + MITRE IDs              string[]
Timestamp        UTC                           DateTime
```

`Evidence` convention: include `AuditMethod`, `RequiresElevation`, and
`Limitations` keys so the report explains *how* the check looked and what
the result does not prove. Existing checks all do this; mirror them.

---

## Naming and code conventions

- **Module / public function / banner**: `Invoke-ADHardening`.
- **Internal stem**: `ADH` (`ADH-001`..`ADH-010`, `$script:ADHLogPath`,
  `New-ADHFinding`, `Write-ADHLog`, `Test-ADHPrerequisites`, etc.).
  Keep new helpers on the `ADH` stem.
- **Check files**: `Private/Checks/Test-<Subject>.ps1` containing one
  function `Test-<Subject>` returning one finding. Subject is descriptive,
  not the ADH ID (`Test-LLMNR`, not `Test-ADH001`).
- **Fix files**: `Private/Fixes/Set-<Subject>.ps1`, `SupportsShouldProcess`
  with `ConfirmImpact='High'`, emit a `changeRecord` (before/after/success/
  error) appended to `changes.jsonl` in a `finally` block.
- **GPO conventions**:
  - Domain-wide fixes use a single dedicated GPO **`Invoke-ADHardening Hardening`**
    (created on first fix, reused thereafter). Never modify Default Domain Policy.
  - DC-scoped fixes use a separate **`Invoke-ADHardening DC Hardening`** GPO
    linked to the Domain Controllers OU.
- **Logging**: never `Write-Host` directly except in the banner and audit
  summary. Use `Write-ADHLog -Level <INFO|CHECK|PASS|FAIL|WARN|ERROR|FIX|DEBUG>`.
  Pass `-Console` to mirror to host; pass `-Finding $finding` to also append
  to `findings.jsonl`.
- **Error handling**: every `Test-*` has a top-level try/catch that emits an
  `Error`-status finding rather than throwing. A broken check must never take
  down the audit run.
- **Comment-based help** on every function: `.SYNOPSIS`, `.DESCRIPTION`,
  `.PARAMETER`, `.EXAMPLE` / `.OUTPUTS`.
- **PowerShell 5.1 compatible** (per manifest). No PS7-only syntax.

---

## The read-only invariant (load-bearing)

`Tests/AuditPhase.ReadOnly.Tests.ps1` enforces, by static AST analysis, that
nothing in the audit code path (`Private/Checks/*`, `Invoke-ADHAuditPhase`,
`Export-ADHReport`, `Write-ADHLog`, `New-ADHFinding`,
`Test-ADHPrerequisites`, `Show-Invoke-ADHardeningBanner`) invokes any
mutating cmdlet. The forbidden regex covers `Set-/New-/Remove-/Disable-/
Enable-AD*`, `*-GP*` (write verbs), group-member mutation, `*-ItemProperty`,
`*-Item`, service control, firewall rule mutation, and local user/group
changes. `New-ADHFinding` is excluded via a `(?!BP)` negative lookahead.

Rules of thumb when extending the audit path:

- Don't add `Set-*`/`New-*`/`Remove-*` calls to a `Test-*` even for "harmless"
  setup. If you need state, create it in the fix.
- Don't touch the registry directly via `Set-ItemProperty` from a check.
- The orchestrator's `New-Item` for the output directory is intentionally
  excluded from the scope (only audit-code-path files are scanned, not
  `Public/Invoke-ADHardening.ps1`).
- If you add a new audit helper, add its path to `$script:auditFiles` in
  the test.

---

## Reports directory

Each run writes to `Reports/<yyyy-MM-dd_HHmmss>/`:

```
audit.log           Timestamped INFO/CHECK/PASS/FAIL/WARN/ERROR/FIX/DEBUG lines
findings.jsonl      One JSON object per finding (compressed)
report.json         Full findings array (depth 10)
report.csv          Flattened (Evidence/AffectedObjects/References become JSON strings)
report.html         Self-contained report: one collapsed row per check, status
                    filter + sort, expand-all, dark/light toggle (dark default)
Locksmith <timestamp> ADCSIssues.CSV   Raw Locksmith AD CS findings — written into the
                    run dir by ADH-010 (Invoke-Locksmith -Mode 2) when Locksmith is
                    installed and a CA exists
changes.jsonl       Implement-phase only: one before/after record per fix invocation
implementation-summary.json   Implement-phase only: per-finding action/before/after results
implementation-report.html    Implement-phase only: what was applied/skipped, same
                    design system as report.html (one collapsed row per fix attempt)
```

NB: the implement phase writes its `implementation-*` artifacts into its
*own* `Reports/<timestamp>/` run directory, separate from the audit run it
consumed via `-ReportPath`.

Reports are local-only. There is no telemetry, no upload, no central server.

---

## What ships

- Module loader (`.psm1`), manifest (`.psd1`), banner, prerequisites.
- Orchestrator (`Invoke-ADHardening`) with `-Mode`, `-IncludeCheckIds` /
  `-ExcludeCheckIds`, `-OutputPath`, `-ReportPath`, `-NoBanner`, and `-Force`
  (forwarded to the implement phase on dispatch); audit phase; report exporter.
- All 10 `Test-*` checks (varying coverage — see file headers). ADH-004
  inspects the GPOs applied to the Domain Controllers OU via
  `Get-ADHGpoSettingForOu` (registry-policy probe → Security-Options XML
  fallback), so it reflects policy intent rather than each DC's live registry.
- 7 `Set-*` fixes (ADH-001/002/003/004/005/006/009):
  - ADH-005 (`Set-IPv6Mitm6Mitigated`) writes three Windows Firewall **Block**
    rules into the Invoke-ADHardening Hardening GPO via
    `New-NetFirewallRule -PolicyStore` (the write-mirror of how
    `Test-IPv6Mitm6` reads them): inbound DHCPv6 (UDP 546), inbound Router
    Advertisement (ICMPv6 134), and outbound DHCPv6 (UDP 546->547). The check
    returns **Pass** only when all three are present (switch-level RA/DHCPv6
    Guard remains the preferred, un-auditable mitigation).
  - ADH-009 (`Set-PasswordPolicyBaseline`) writes the account-policy baseline
    into the Invoke-ADHardening Hardening GPO as named `[System Access]`
    settings (via `Set-ADHGpoSystemAccess`) and links that GPO at the domain
    root **Enforced** so it wins over Default Domain Policy. Baseline: min
    length 15, complexity on, lockout 5 / 15 min / 15 min, and
    `MaxPasswordAge = 0` (never expire, written as `MaximumPasswordAge = -1`).
    `Test-PasswordPolicy` treats never-expire as compliant (NIST SP 800-63B)
    and fails `MaxPasswordAge` only when it exceeds 365 days.
- Implement phase — `Invoke-ADHImplementPhase` + `New-ADHImplementationReport`.
  The audit phase persists *every* finding to `findings.jsonl`, which is what
  the implement phase consumes. When a fix applies but the re-check isn't Pass,
  the reported note distinguishes "applied and verified Pass" from "applied but
  re-check still failing", and separates likely propagation delay (gpupdate /
  replication timing) from a fix that plainly didn't take effect, rather than
  implying false success either way.
- ADH-010 structured Locksmith capture — `Test-ADCSMisconfig` runs
  `Invoke-Locksmith -Mode 2 -OutputPath <run report dir>` and parses the
  produced `Locksmith <timestamp> ADCSIssues.CSV` (columns Forest, Technique,
  Name, Issue, Risk) for a row count. **Pass requires an affirmative 0-row
  CSV**; a scan that completes but captures no CSV (e.g. a Locksmith build
  without `-OutputPath`) returns Warning, never Pass. Fail reports the row
  count and points at the CSV in the run directory for full detail.
- Three optional network probes under `Private/Probes/`, not wired into any
  check.
- Test suite — 60 tests across 13 files, green under Pester 5.7 on both
  Windows PowerShell 5.1 and pwsh 7:
  - `Tests/AuditPhase.ReadOnly.Tests.ps1` — the read-only invariant (its
    `$script:auditFiles` list includes `Get-ADHGpoSettingForOu` and
    `Get-ADHReportAssets`).
  - `Tests/Checks/*.Tests.ps1` — per-check suite with mocked AD/GPO/NetSecurity
    cmdlets. Mocks live in each Context's `BeforeAll` (not Describe
    `BeforeEach`, which Pester re-applies *after* Context setup and would
    clobber throwing/error-path mocks). Shared cmdlet stubs in
    `Tests/TestStubs.ps1`. `Tests/Checks/Test-LDAPSigning.Tests.ps1` includes a
    two-GPO Context.
  - `Tests/Helpers/Get-ADHGpoSettingForOu.Tests.ps1` — exercises the real
    helper (not mocked) against two GPOs defining the same value, covering the
    effective-value / `[int]`-cast path.
  - `Tests/ImplementPhase.Tests.ps1` (fixture in `Tests/Fixtures/findings.jsonl`)
    — A/S/R/Q loop, `-Force`/`-WhatIf` gating, no-applicable, missing-fix.
  The unit tests stub AD/GroupPolicy/NetSecurity, so they run off-domain.
- `README.md` — install, audit/implement walkthrough, check table, repo layout,
  test instructions, credits, disclaimer.
- Sample artifacts — `lab/sample/` holds a captured audit run for docs and
  demos (`lab/sample.zip` is the zipped copy).

Working backlog — everything left is deliberately post-1.0, not unfinished
1.0 work:

- Wire the network probes (`Invoke-ADH*Probe`) in as opt-in behavioural
  confirmation for ADH-001/003/004, handling broadcast-domain scope and
  false negatives without pulling mutation into the read-only audit path.
- `Invoke-ADHRollback` — automated unwind from each fix's `BeforeState` in
  `changes.jsonl` (deliberately out of scope for the implement phase).
- Run `Invoke-ScriptAnalyzer -IncludeRule PSUseCompatibleCommands` over
  `Tests/` as well as `Public/`/`Private/`, for completeness.

---

## What not to build

- No agent on endpoints — everything reads from AD or DCs centrally.
- No telemetry or remote reporting — reports stay local.
- No GUI — PowerShell only.
- No auto-fix for ADH-007/-008/-010 (these need human judgment, and
  ADH-010 explicitly defers to Locksmith). ADH-005 *does* have an auto-fix
  (`Set-IPv6Mitm6Mitigated`, the GPO firewall-rule fallback) — but it
  deliberately does NOT disable IPv6 or touch switch-level RA/DHCPv6 Guard.
- Don't try to compete with PingCastle/Purple Knight on breadth — the 10
  guide items are the scope.
