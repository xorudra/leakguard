# Cycle report — P1-B: Phase 25 stored finding lifecycle state

## CURRENT PHASE
Phase 25 (Exposure engine) — stored canonical lifecycle state

## PRIORITY TIER
P1

## STATUS
Complete — findings now carry a stored lifecycle state
(open / resolved / reappeared), written by a single writer and read
by every consumer that used to derive it. Phase 25 PARTIAL → DONE.

## WHAT WAS AUDITED
The pre-cycle state, per the audit taxonomy: `findings.status`
stayed 'open' forever, and lifecycle (is this exposure current,
gone, back?) was derived per-read from set differences in
`monitoring/diff.py` — recomputed on every view, owned by no
writer, and invisible to the API.

## WHAT WAS IMPLEMENTED
- Migration `0012_finding_lifecycle.sql` (additive):
  `findings.lifecycle_state` (TEXT, CHECK in
  open/resolved/reappeared, default 'open') and
  `findings.lifecycle_changed_at`. Backfill resolves only what is
  provable from stored rows: identities absent from the user's
  latest completed cycle, and findings matched to a
  `verified_removed` case by broker name/slug. Host-only matches
  deliberately start 'open' (recorded in the migration header).
- Single writer in `monitoring/diff.py`: `apply_lifecycle`
  (called from the scan-completion hook; completed jobs only;
  idempotent; refuses stale jobs) and `resolve_for_broker`
  (called from remediation verification). The stamp moves only
  when the state value changes. The broker↔finding matcher was
  unified into diff.py (events.py and dashboard/graph.py call it
  from there).
- Readers switched to the stored column: scan detail (which now
  also emits `lifecycle_state` and `lifecycle_changed_at` beside
  `status`) and Action Center counts. Finding feedback remains a
  separate axis, untouched.
- In the same commit, the Phase 74 secrets-hygiene guard was
  converted from pytest style to the suite's unittest style (see
  KNOWN LIMITATIONS of the P1-A cycle: CI runs unittest discovery
  without pytest installed; the guard also gained the two P1-A
  walk-fixture literals in its allowlist).

## WHAT WAS DELIBERATELY NOT IMPLEMENTED
- The notification diff in `monitoring/events.py` still
  set-compares to generate alerts — change detection in the same
  pass that writes the stored state, so the two cannot disagree.
- A set-based bulk writer: the writer updates per identity (see
  KNOWN LIMITATIONS). Correctness first; the optimization is a
  recorded P2 follow-up.

## FILES CREATED
- `db/migrations/0012_finding_lifecycle.sql`
- `tests/test_finding_lifecycle.py`
- `docs/cycles/2026-10-07-p1b-phase-25-lifecycle.md` (this report)

## FILES MODIFIED
- `monitoring/diff.py` (writer + unified matcher), `monitoring/events.py`
  (hook wiring), `monitoring/__init__.py` (docstring)
- `remediation/verify.py`, `remediation/service.py` (resolution path)
- `scanning/jobs.py` (scan detail emits the stored state)
- `dashboard/service.py` (Action Center counts), `dashboard/graph.py`
  (shared matcher)
- `tests/test_secrets_hygiene.py` (unittest conversion + allowlist)

## DATABASE MIGRATIONS
`0012_finding_lifecycle.sql` — applied at startup on staging and
production deploys of `ab05ab0`; verified behaviorally on both
(see RESULTS).

## API ROUTES
No new routes. Scan-detail finding objects gain two keys:
`lifecycle_state`, `lifecycle_changed_at`.

## TESTS ADDED
`tests/test_finding_lifecycle.py` — 9 tests: matcher units; the
full transition matrix across six real completion cycles (born
open+stamped → resolved → stamp frozen on no-change → reappeared
→ resolved again); failed-job and stale-job refusal; remediation
resolution and the reappearance case flip; migration backfill
classes on a 0001–0011 database; SQL-flip proof that readers serve
the stored column.

## TESTS RUN
Full suite under pytest: 450 passed, 19 skipped. Full suite under
an exact local replica of the CI runner (unittest discovery,
pytest import blocked, CI's dependency set): 440 tests, OK — the
first cycle verified green in both environments before deploy.

## RESULTS
- Staging (`dep-db37eoc9v7es73b7c6qg` on `ab05ab0`): live
  two-cycle proof with real providers — cycle 1 over
  test@example.com stored 214 findings, all 'open', all stamped;
  the identifier was then removed and cycle 2 ran over a clean
  identifier; the first cycle's 214 rows flipped to 'resolved'
  with stamps intact.
- Production (`dep-db37vonavr4c73a35t2g` on `ab05ab0`): deploy
  clean, health `db: "ok"`, baselines unchanged (214 / 100 /
  52,372,427), throwaway-account scan stored lifecycle state the
  same way.

## SECURITY CONTROLS
The writer is user-scoped by construction (every statement carries
the job owner's id), refuses to run for non-completed or stale
jobs, and never lets a remediation resolution leak across users —
the matcher resolves within the case owner's findings only.

## PRIVACY CONTROLS
No new data is collected or exposed: the state describes findings
the user already sees, and the API additions ride the existing
authenticated, user-scoped scan-detail response.

## DEPLOYMENT STATUS
Deployed to staging first (smoke: health, account E2E, two-cycle
lifecycle proof), then production (deploy above; live-verified).
Both services run `ab05ab0`.

## KNOWN LIMITATIONS
Convergence latency: the writer issues one UPDATE per identity
inside a single transaction, so over the Oregon→Singapore database
link a 214-identity cycle takes up to ~a minute to become visible
after the job shows 'done' (measured live on staging; reads inside
the window see the pre-hook state). States always converge to the
correct values. A set-based bulk write is the recorded fix.

## RISKS
The backfill's host-only class starts 'open' even where a removal
was verified — a conservative mislabel in the safe direction (an
exposure shown current that may be gone), corrected by the writer
on the next completed cycle.

## NEXT PHASE
P1 closeout (this report series) → P2 in priority order.
