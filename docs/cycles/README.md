# Cycle Reports — Index

This directory holds the per-cycle development reports required by
Phase 149 (Development reporting) of the Final Remaining
Implementation spec. Before this directory existed, cycle outcomes
lived in chat transcripts and commit messages; the spec's §6 report
format is the standing shape for recording them in the repository.

## What a cycle is

A **cycle** is one bounded unit of work on LeakGuard: an
implementation batch, an audit, a platform change (new environment,
deploy-mechanism change), or a verification batch. A cycle ends when
its work is committed (or, for platform work, when the change is live
and its docs commit lands). Every cycle gets exactly one report file
in this directory.

## Rules

- **Same commit series.** An implementation cycle's report lands in
  the same commit series as the work it describes — written at
  closeout, committed alongside or immediately after the code, never
  reconstructed weeks later.
- **Every field, every time.** A report carries all 19 §6 fields, in
  order. A field that genuinely does not apply says so ("None",
  "Not applicable — documentation only", "not recorded" where the
  historical record is silent). A field is never omitted.
- **Evidence, not recollection.** Facts come from the repository
  record: `git log`, `PHASE_STATUS.md`, `CURRENT_STATE.md`,
  `MIGRATION_PLAN.md`, deploy records. Anything the record does not
  support is written as "not recorded" — never estimated, never
  rounded into existence.
- **No secrets, ever.** Reports never contain credential values,
  connection strings, or key material. Credential-adjacent facts are
  stated as counts, locations, and shapes only (the same discipline
  as `tests/test_secrets_hygiene.py`, whose guard scans these files
  once they are tracked).

## Naming convention

`YYYY-MM-DD-<slug>.md` — the cycle's closeout date (all cycles to
date are 2026-10-07) and a short lowercase hyphenated slug naming
the batch or program.

## The §6 template

Copy this skeleton for a new report and fill every field:

```markdown
# Cycle report — <name>

## CURRENT PHASE
<phase(s) / batch name>

## PRIORITY TIER
<P0 / P1 / P2 / P3, per phase>

## STATUS
<Complete / Partial / Audit only — outcome in one line>

## WHAT WAS AUDITED
<what was examined before changing anything>

## WHAT WAS IMPLEMENTED
<what shipped (for audit-only cycles: the audit deliverables)>

## WHAT WAS DELIBERATELY NOT IMPLEMENTED
<scope deliberately left out, and why>

## FILES CREATED
<new files, or None>

## FILES MODIFIED
<changed files, or None>

## DATABASE MIGRATIONS
<migration files, or None>

## API ROUTES
<routes added/changed, or None>

## TESTS ADDED
<test files / counts, or None>

## TESTS RUN
<suite runs and results>

## RESULTS
<outcome: statuses flipped, live verification, scoreboard>

## SECURITY CONTROLS
<controls added or verified, or None>

## PRIVACY CONTROLS
<controls added or verified, or None>

## DEPLOYMENT STATUS
<where the cycle's work runs now; deploy ids where recorded>

## KNOWN LIMITATIONS
<what remains limited, honestly>

## RISKS
<residual risks carried forward>

## NEXT PHASE
<what the program does next>
```

## Reports

| Date | Cycle | Commits | Outcome |
|---|---|---|---|
| 2026-10-07 | [Final-spec Batch A — transport security, SSRF guard, dependency lock, CI](2026-10-07-final-batch-a-transport-ssrf-lock-ci.md) | `5b14b08`, `77086ad` | HSTS, DNS-resolution SSRF guard, exact-pin lock, CI workflow; Phases 69/107 closed, 70 guarded with a documented rebinding residual |
| 2026-10-07 | [Final-spec Batch A.1 — migration-credential split](2026-10-07-final-batch-a1-migration-credential-split.md) | `2f3ec30` | Migrations moved to the owner-level connection; the app role serves DML-only; restore drill executed (Phases 73/78/170) |
| 2026-10-07 | [Final-spec Batch B — API v1, export re-auth, priority queue, flags, monitoring pause](2026-10-07-final-batch-b-api-v1-export-queue-flags.md) | `55f0a1c` | Phases 49/88/120/122/142/159 closed; migration 0009 |
| 2026-10-07 | [Final-spec Batch C — finding feedback, disputes, source sweep, security events, runbooks](2026-10-07-final-batch-c-feedback-sweep-runbooks.md) | `ece5f7c` | Phases 32/62/79/147/148/156/157 closed, 125 deepened; migration 0010; three runbooks + acceptance index written |
| 2026-10-07 | [Final-spec Batch D1 — passkeys](2026-10-07-final-batch-d1-passkeys.md) | `9c01b08` | Optional WebAuthn passkeys live (Phase 4); migration 0011 |
| 2026-10-07 | [Final-spec Batch D2 — policy analyzer, propagation, trust pages](2026-10-07-final-batch-d2-policy-propagation-pages.md) | `56c14e5` | Phases 82/83/102/104/126/128/129/152 closed; final code commit of the Final-spec program |
| 2026-10-07 | [Staging environment creation](2026-10-07-staging-environment.md) | platform work; docs `830a644` | `leakguard-staging` on its own Neon branch, manual deploys, own vault keys, no email lane (Phase 109) |
| 2026-10-07 | [Spec v2.1 live/repository reconciliation](2026-10-07-spec-v21-reconciliation.md) | `08a6d44` | Production commit pinned from the platform (`56c14e5`); no functional live↔repo discrepancy; Phases 173/180 closed |
| 2026-10-07 | [Owner-ordered audit re-issue](2026-10-07-audit-reissue.md) | `8c3b063` | Audit only, no implementation; PHASE_STATUS re-issued in the owner's 6-status taxonomy; approval gate recorded |
| 2026-10-07 | [Post-audit P0 program — SSRF pinning, evidence batch, cryptography remediation, rollback rehearsal](2026-10-07-post-audit-p0-program.md) | `7d391c1`, `0489cf8`, `b72a072` | Phases 70/1/74/107/174 closed; cryptography 45.0.7 → 50.0.2; all P0 phases closed (129 DONE) |
| 2026-10-07 | [P1-A verification batch — Privacy Center walk + mobile viewport check](2026-10-07-p1a-verification-48-97.md) | `5c2dabb` | Phases 48/97 verified and closed; CI-red hygiene self-flag found and fixed |
| 2026-10-07 | [Phase 149 — per-cycle development reporting system](2026-10-07-p149-cycle-reports.md) | (this closeout) | docs/cycles/ created: index, §6 template, 11 backfilled cycle reports, format guard test |
| 2026-10-07 | [P1-B — Phase 25 stored finding lifecycle state](2026-10-07-p1b-phase-25-lifecycle.md) | `d86afa7` | Migration 0012; single lifecycle writer; live two-cycle proof on staging (214 open → 214 resolved) |
| 2026-10-07 | [P2-A — verification records (Phases 80, 131, 132)](2026-10-07-p2a-records-80-131-132.md) | (docs closeout) | IR tabletop drill + runbook fixes; README 8 inaccuracies fixed; MIGRATION_PLAN annotated to shipped truth |
| 2026-10-08 | [P2-B — performance & scalability (Phases 115, 116)](2026-10-08-p2b-performance-115-116.md) | `1387fc4` | Set-based lifecycle writer (5 statements); batched in-app notifications + summary-only email (kills the 215-emails/cycle storm); benchmarks + documented single-instance ceiling; flips 10.5s, ledger 17.8s live |
| 2026-10-08 | [P2-C — observability & engineering alerts (Phases 76, 77)](2026-10-08-p2c-observability-76-77.md) | `f022399` | Error ledger (migration 0013, hash-only rollups, 30-day prune); admin metrics endpoint + overview block; four engineering alert rules on the scheduler tick with daily-deduped owner email; staging + production live-verified |
| 2026-10-08 | [P2-D — cost control & provider cost monitoring (Phases 66, 124)](2026-10-08-p2d-cost-66-124.md) | `3b89d0e` | Daily provider usage ledger (migration 0014); operator-set safety budgets with fail-open typed enforcement; admin provider metrics + provider_budget alert; Brevo honestly out of scope (binds the notification lane); staging + production live-verified |
| 2026-10-08 | [P2-E — scan budget engine & data-quality pipeline (Phases 158, 160)](2026-10-08-p2e-budgets-dq-158-160.md) | `3a56fb0` | Per-user daily scan budget (50/day, monitoring lane structurally exempt) + live budgets registry in admin metrics; DQ stage over stored findings (job-scoped duplicates, contract malformed checks, drift rollup — flag/record only, nothing deleted); first live DQ run: 1,498 findings, 0 issues; P2-B score-display watching brief explained (count-up animation) and closed |
| 2026-10-08 | [P2-F — broker depth (Phases 111, 162, 31, 137, 166)](2026-10-08-p2f-broker-depth-111-162-31-137-166.md) | `0d74ccb` | Fake-broker environment at the transport seam (production SSRF untouched, loopback still refused under test) + full E2E workflow harness (Spokeo/generic → verified_removed; persist/down/renamed/challenge negatives pinned); workflow_version stamped on every attempt (migration 0016) + case-detail endpoint; probe classification matrix (ambiguous → unknown); local-probe domain allowlist with route-level enforcement |
| 2026-10-08 | [P2-G — removal depth (Phases 153, 141, 119)](2026-10-08-p2g-removal-depth-153-141-119.md) | `5155044` | Versioned policy engine extracted from the engine (POLICY_VERSION 1; six embodied ambiguities preserved + pinned, regression suites unmodified); formal spec state mapping (needs_human→AWAITING_USER, blocked→REJECTED; AUTHORIZED/NOT_STARTED = consent-gated creation) as additive spec_status + docs/REMOVAL_STATES.md; admin dead-letter replay with per-lane consent re-check, typed refusals, audit rows, real-worker drain proofs |
| 2026-10-08 | [P2-H — surfaces (Phases 125, 40, 96, 67)](2026-10-08-p2h-surfaces-125-40-96-67.md) | `192ce5e` | Per-broker verification + workflow health in the admin dashboard; standalone search-exposure view (owner-scoped, masked, honest weak-confidence framing) with the discovery-cap review recorded (KEEP 6); accessibility pass (aria, skip link, live regions, focus-visible) + CI invariants + live a11y check PASS on staging and production; API no-store cache policy enforced at the response choke point and asserted |

All cycles through the P1 closeout are linked above.

The guard test `tests/test_cycle_reports.py` keeps this index
honest: every report linked here must exist, every report on disk
must be linked, and every report must carry all 19 §6 fields.
