# Cycle report — Post-audit P0 program: SSRF pinning, evidence batch, cryptography remediation, rollback rehearsal

Commits: `7d391c1` (Phase 70 fix), `0489cf8` (Phases 1/74/107
evidence + cryptography remediation), `b72a072` (Phase 174
record). Date: 2026-10-07. Executed after the owner approved
the audit re-issue and ordered: P0 first, Phase 70 first, no
AI, do not touch DONE phases unnecessarily.

## CURRENT PHASE

Post-audit P0 closure: Phase 70 (SSRF protection, INSECURE →
DONE), Phase 1 (Repository restructure, UNVERIFIED → DONE),
Phase 74 (Secrets, UNVERIFIED → DONE), Phase 107 (Dependency
security, UNVERIFIED → DONE), Phase 174 (Rollback plan,
UNVERIFIED → DONE). At this program's close, **no P0 phase
remains open**.

## PRIORITY TIER

P0 (all five phases).

## STATUS

Complete — all five phases closed with evidence, deployed
through the staging-first sequence, and verified live on
production.

## WHAT WAS AUDITED

- The rebinding window precisely: `core/ssrf.py` validated the
  resolved addresses, then callers fetched by hostname and the
  resolver answered again — a swapped second answer could
  reach a non-public address. Every guarded call site was
  inventoried (agent probe + form submit, remediation verify,
  source sweep, policy-analyzer fetch).
- The repository's import graph (Phase 1): which modules
  import which, and whether the claimed package boundaries are
  real.
- Secret hygiene (Phase 74): all tracked files and the full
  git history scanned for credential-shaped material;
  ignore-rule coverage for every known secret filename.
- Dependencies (Phase 107): the pinned set in
  `requirements.lock` and the ranges in `requirements.txt`,
  scanned with a real vulnerability tool for the first time.

## WHAT WAS IMPLEMENTED

**Phase 70 — connection pinning** (`7d391c1`). `core/ssrf.py`
gained pinned connection classes whose `connect()` resolves
the host once, validates *every* returned address as public
(any non-public answer fails closed before a socket opens),
and connects to a validated IP — while the Host header, TLS
server name and certificate verification keep the original
hostname. The pinned opener deliberately carries an empty
proxy handler: a proxy would resolve on its own side and
silently reopen the window. Redirects re-enter the pinned
handlers per hop. Call sites migrated: agent probe and form
submit, the remediation engine's fetcher, the source-sweep
fetcher, the policy analyzer's fetch opener. Callers' existing
pre-checks and error shapes are unchanged; pinning is the
decisive second layer. (One fetch deliberately not migrated:
the agent's relay probe targets a fixed, codebase-chosen
host.)

**Phase 1 — boundary verification** (`0489cf8`).
`tests/test_architecture.py` pins the import graph's real
invariants (fresh-subprocess import of every package;
`db`/`providers` import no project code; `vault` reaches only
`db`; `core` top level reaches only `db`, with its deferred
imports in `core/retention.py` confined by test). Two honest
irregularities recorded, not hidden: a `scanning` ↔
`monitoring` package-level cycle that never loops during
init, and `accounts` acting as a mid-layer hub.

**Phase 74 — secret-hygiene audit + guard** (`0489cf8`).
Recorded audit: 146 tracked files and the full 52-commit
history — zero credential-shaped findings; every known secret
filename verified ignored and never tracked. One hygiene gap
found and fixed: `.gitignore` did not cover the GitHub-token
filename pattern used by the owner's sibling tooling (the
file itself lives outside this repo and was never in its
history). `tests/test_secrets_hygiene.py` makes the audit
permanent: it fails if a secret-shaped string or an
un-ignored secret filename ever lands in tracked files or
history.

**Phase 107 — vulnerability scan + remediation**
(`0489cf8`). The first recorded scan (pip-audit 2.10.1)
found **7 advisories, all in the pinned cryptography
library, version 45.0.7** (PYSEC-2026-2141, PYSEC-2026-35,
PYSEC-2026-36, GHSA-537c-gmf6-5ccf, PYSEC-2026-3552,
PYSEC-2026-3553, PYSEC-2026-3554). Every fixed release was
blocked by the range cap in `requirements.txt` (the cap sat
below 46), so the range moved to admit the fully-fixed 50.x
line and the lock was regenerated at **50.0.2** — all other
pins unchanged. Re-scan of both files: no known
vulnerabilities. `tests/test_dependency_pins.py` guards the
invariant the scan depends on: the lock holds exact pins
only, and every ranged package appears in it.

**Phase 174 — rollback rehearsal** (`b72a072`). On staging:
deploy the previous commit (`7d391c1`, deploy
`dep-db36d91srm7s73c0v8j0`, Live, health ok), then redeploy
the current commit (`0489cf8`, deploy
`dep-db36dqm7bikc73bqooeg`, Live, health ok). The rehearsal
record was appended to `docs/ROLLBACK.md`, alongside the
existing database-side drill (Phase 170).

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- No rewrite of the SSRF call sites' error shapes, and no
  changes to phases already DONE — per the owner's order.
- The fixed-host relay probe stays on the ordinary fetch path
  (documented in the Phase 70 row): pinning protects
  data-driven fetches; a codebase-chosen host has no
  attacker-controlled resolution to pin against.
- No dependency upgrades beyond the vulnerable package: the
  scan was clean for everything else, and gratuitous pin churn
  is its own risk.

## FILES CREATED

- `tests/test_ssrf_pinning.py`
- `tests/test_architecture.py`
- `tests/test_secrets_hygiene.py`
- `tests/test_dependency_pins.py`

## FILES MODIFIED

- `core/ssrf.py` (pinning), `agent.py`,
  `remediation/engine.py`, `remediation/source_checks.py`,
  `dashboard/policy_analyzer.py` (call-site migration)
- `requirements.txt` (cryptography range), `requirements.lock`
  (regenerated), `.gitignore` (token filename pattern)
- `docs/ROLLBACK.md` (rehearsal record)
- `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

None.

## API ROUTES

None added or changed.

## TESTS ADDED

28 tests: `test_ssrf_pinning.py` (13 — rebinding with a
public-first/private-second resolver answer: resolver called
exactly once, private address never attempted; private-only
and mixed answers fail closed with zero connection attempts;
literal private IPs refused; redirect-to-private blocked at
the hop; redirect-to-public keeps per-hop Host headers; TLS
server name stays the hostname while connecting to the IP;
loopback plumbing success with only the address-class check
stubbed), `test_architecture.py` (8), `test_secrets_hygiene.py`
(5), `test_dependency_pins.py` (2).

## TESTS RUN

Full suite re-run by the parent agent at each step: 423
passed / 19 skipped after `7d391c1`; **438 passed /
19 skipped** at `0489cf8`.

## RESULTS

All five phases DONE. Scoreboard: 129 DONE / 31 PARTIAL /
1 MISSING / 0 INSECURE / 6 UNVERIFIED / 14 NOT APPLICABLE —
**zero P0 phases open**. Production verification after the
deploy (parent-run): health ok on both API spellings;
baselines unchanged (214 breaches, score 100, password-check
count 52,372,427); the agent probe fetched a broker page
through the new pinned path on production (reachable, HTTP
200); a throwaway register → login → delete cycle passed on
the upgraded cryptography build; HSTS intact.

## SECURITY CONTROLS

Connection pinning closes the time-of-check/time-of-use gap
in every data-driven fetch; the secrets guard converts a
one-off audit into a permanent tripwire; the dependency pins
guard keeps the scanned set equal to the deployed set;
the cryptography upgrade removes 7 known advisories from the
library that performs the vault's AES-256-GCM encryption.

## PRIVACY CONTROLS

None changed — no user-data behaviour moved in this program.
The secrets audit handled suspected material by file and line
only; no suspected value was reproduced anywhere, including
this report.

## DEPLOYMENT STATUS

Staging first, per the §9 sequence. `7d391c1`: staging deploy
`dep-db365v8m7kps73d5t040` (smoke incl. the pinned-fetch probe
against a live broker page). `0489cf8`: staging deploy
`dep-db36akvavr4c739u3s10` (build log confirms the 50.0.2
library installed; register/login/identifier/delete smoke
passed), then production deploy `dep-db36bvad0e5s73f97ta0`.
`b72a072` is documentation-only and was not deployed.
One incident in the pipeline, recorded honestly: GitHub
rejected all ref updates for the repo (server-side error,
including for an already-hosted known-good commit) for part
of the evening; production kept running `56c14e5` — with the
rebinding window still open — until the push landed via an
automatic retry and the deploys completed.

## KNOWN LIMITATIONS

Dependency scanning is a recorded manual cadence (on any
dependency change, and monthly), not a CI job — the workflow
file cannot be pushed with the repo credential. The secrets
guard scans tracked files; an untracked file is invisible to
it until staged (it bites at commit time, which is the point
of no return that matters).

## RISKS

Pinned connections depend on the resolver's answer set being
complete at connect time; an attacker who controls DNS for a
broker domain outright (not just rebinds) is out of this
control's scope — TLS verification is the layer that answers
that. Free-tier staging shares instance hours with
production, so rehearsals are scheduled, not continuous.

## NEXT PHASE

P1, in the owner's order: Phase 48 + Phase 97 verification
batch, then Phase 25, then Phase 149 (this report series).
