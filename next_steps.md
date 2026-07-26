# Roadmap

Post-1.0 work. Everything here is genuinely future — deliberately out of
scope for the initial release, not a punch list of unfinished work.

## Wire the network probes as opt-in behavioural confirmation

`Invoke-ADHLlmnrProbe`, `Invoke-ADHSmbSigningProbe`, and
`Invoke-ADHLdapSigningProbe` (`Private/Probes/`) measure on-the-wire
behaviour rather than policy state. They are not called by any `Test-*`;
check evidence only mentions them as a roadmap item. Wire them in as an
**opt-in** confirmation step for ADH-001/003/004, handling:

- broadcast-domain scope (a probe run from one subnet doesn't prove the
  policy holds elsewhere),
- false negatives (absence of observed traffic during a short probe window
  isn't proof of absence of the behaviour),
- and, critically, must not pull any mutating behaviour into the read-only
  audit path — probes stay opt-in and outside `Invoke-ADHAuditPhase`'s
  default dispatch, and `Tests/AuditPhase.ReadOnly.Tests.ps1` must keep
  passing unchanged.

## `Invoke-ADHRollback`

Automated unwind from each fix's `BeforeState` in `changes.jsonl`. Every
`Set-*` fix already records a before/after change record; a rollback command
would replay those in reverse to return a domain to its pre-fix state
without requiring the operator to hand-unwind each change in GPMC/ADUC.
Deliberately out of scope for the implement phase itself — a separate
future milestone.

## Analyzer sweep over Tests/

Run `Invoke-ScriptAnalyzer -IncludeRule PSUseCompatibleCommands` over
`Tests/` in addition to `Public/` and `Private/` (the sweep currently covers
just the module code). Completeness only — no known issues, just unswept
ground.
