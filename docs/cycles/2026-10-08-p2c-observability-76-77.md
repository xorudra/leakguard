# Cycle report — P2-C: observability & engineering alerts (Phases 76, 77)

## CURRENT PHASE
Phase 76 (Observability), Phase 77 (Engineering alerts).

## PRIORITY TIER
P2

## STATUS
Complete — both phases closed on implemented, tested, and
live-verified evidence. Scoreboard after this cycle: 140 DONE /
25 PARTIAL / 1 UNVERIFIED / 1 MISSING / 14 NOT APPLICABLE.

## WHAT WAS AUDITED
The observability surface as the audit left it: structured logs
with X-Request-Id, `/api/health`, `/api/providers/health`, and
the admin overview existed — but there was no metrics endpoint,
no error tracking (errors lived only in log lines), and no
alerting beyond UptimeRobot downtime email. Also audited: the
P2-A tabletop drill findings F3/F4 (no single control halts all
fetching; incident detection was human-paced), which named
76/77 as the fix, and the Phase 25 upgrade test's hard-coded
migration expectations, which any new migration must update
mechanically.

## WHAT WAS IMPLEMENTED
- **Error ledger** (Phase 76): migration
  `0013_error_events.sql` creates `error_events` (context,
  error class, sha256 `message_hash` — never the raw message —
  request id, occurrence rollups) and widens the notifications
  kind CHECK to admit `engineering_alert`. `core/error_ledger.py`
  records via one `INSERT … ON CONFLICT … DO UPDATE` per
  (context, class, hash, clock-hour bucket); it never raises
  (verified against a broken pool). Wired into
  `core/logging_setup.log_error` with no signature change, so
  all existing call sites gained tracking. Retention prunes
  rows older than 30 days in the daily pass.
- **Admin metrics** (Phase 76): `GET /api/admin/metrics`
  (same house 404 admin gate) plus a `metrics` block embedded
  in the admin overview, rendered as a compact grid in the
  admin UI: scan jobs by status; completed/failed/dead in the
  last 24h; median completed duration (percentile_cont);
  queue depth and oldest-queued age; remediation cases by
  status; notifications by status (24h); broker sources
  total / checked-24h / currently unreachable; security
  events by kind (24h, from the Phase 62 audit-trail view —
  this codebase has no separate security_events table);
  error-ledger distinct (context, class) pairs, total
  occurrences, and top-5 contexts (24h). All values come from
  real queries, asserted against seeded data in tests.
- **Engineering alerts** (Phase 77): `monitoring/alerts.py`
  `evaluate()` runs at the end of the scheduler tick (lazily
  imported, exception-guarded, flag-respecting via the tick's
  own early return). Four rules with named-constant
  thresholds: queue_buildup (≥10 active jobs OR oldest
  queued ≥900 s), worker_failures (≥3 dead jobs/24h OR ≥5
  failed remediation cases/24h), provider_outage (≥5 broker
  sources whose latest check is unreachable), error_spike
  (≥20 ledger occurrences in the trailing hour). On fire:
  one PII-free `engineering_alert` security-event row and an
  email to each admin via `create_notification` mode
  "always" (the owner/transactional lane), kind
  `engineering_alert` with a factual template, dedupe key
  `eng:<rule>:<UTC date>` — at most one per rule per admin
  per day.

## WHAT WAS DELIBERATELY NOT IMPLEMENTED
- The provider_outage "unreachable across its last 3 checks"
  leg: `broker_source_checks` keeps only the latest check per
  source (upsert by slug), so no check history exists to be
  honest about. The rule fires on ≥5 sources currently down;
  the limitation is stated in the module docstring. Adding a
  check-history table is a future schema decision, not a
  silent invention.
- Latency alerting (Phase 175's remaining leg) stays with
  P2-I, where post-launch monitoring is reviewed with
  production alert data in hand.

## FILES CREATED
- `db/migrations/0013_error_events.sql`, `core/error_ledger.py`,
  `monitoring/alerts.py`, `tests/test_observability_alerts.py`,
  `docs/cycles/2026-10-08-p2c-observability-76-77.md` (this)

## FILES MODIFIED
- `core/logging_setup.py` (ledger wiring), `core/retention.py`
  (30-day error-event prune), `accounts/admin.py` (metrics
  block, standalone route support, `admin_user_ids()`),
  `app.py` (metrics route), `monitoring/notify.py`
  (`engineering_alert` kind + template), `monitoring/scheduler.py`
  (tick invokes the evaluator), `static/app.js` (admin metrics
  grid), `tests/test_finding_lifecycle.py` (mechanical
  migration-list update: migrations-before-0012 wording +
  `0013` in the expected applied list; the 0012 backfill
  assertions are unchanged), `PHASE_STATUS.md` (76/77 DONE;
  counts 140/25; the not-at-DONE list refreshed — it also
  still named P2-A/P2-B/P1 closures as open, now corrected),
  `CURRENT_STATE.md` (dated production addendum; the 2026-10-07
  reconciliation block is untouched), `docs/cycles/README.md`
  (index row)

## DATABASE MIGRATIONS
`0013_error_events.sql` — `error_events` table + indexes;
notifications kind CHECK widened for `engineering_alert`.
Idempotent like all migrations; applied cleanly on staging
and production boots (health `db: "ok"` on both).

## API ROUTES
`GET /api/admin/metrics` (new, admin-gated with the house
404). The admin overview response gains a `metrics` block.

## TESTS ADDED
`tests/test_observability_alerts.py` — 11 tests: ledger write /
dedupe / hash-only storage / never-raises / log_error wiring,
retention prune, metrics admin gating (anon + non-admin → 404
`not_found`) and seeded values (median asserted ≈20 s from
10 s/30 s seeds) + overview embedding, all four alert rules
silent-below / fires-on-breach (both queue legs, both
worker-failure legs), daily dedupe (second evaluate leaves
exactly one row and one email), scheduler tick guard.

## TESTS RUN
pytest 471 passed / 19 skipped (baseline 460/19 + 11 new);
CI-replica unittest discovery (pytest blocked): 461 tests OK.
Secrets-hygiene guard green on the staged tree. GitHub CI
green on `f022399`.

## RESULTS
Staging (`f022399`, deploy dep-db3agp3tqb8s7384chp0): health
ok with 0013 applied; anonymous `/api/admin/metrics` and
`/api/admin/overview` both 404 `not_found` (corroborated in
Render logs by request id); baseline 214/100; throwaway E2E —
214 findings, one scan_summary notification, account deleted.
Production (`f022399`, deploy dep-db3ajprtqb8s7384mokg):
health ok; baselines 214/100 and password count 52,372,427;
anonymous gating 404 on both endpoints; E2E — 214 findings,
exactly ONE scan_summary in the notifications list, account
deleted. No alert has fired live yet: thresholds are untested
by reality, not by code — the rules are proven by tests and
the delivery path by the dedupe proof.

## SECURITY CONTROLS
Error storage is hash-only (a test asserts a unique marker
substring from a raw message appears in no stored column);
alerts and metric payloads are PII-free aggregates; the
metrics surface inherits the admin gate (404, not 401/403 —
existence is not disclosed); mode "always" email remains
reserved for owner/transactional mail, as documented in
notify.py.

## PRIVACY CONTROLS
No user data enters the error ledger (context + class + hash
only); metrics are counts and durations over system tables;
engineering alerts go only to ADMIN_EMAILS accounts.

## DEPLOYMENT STATUS
Production and staging both on `f022399`, live-verified.

## KNOWN LIMITATIONS
error_spike sums the ≤2 hourly rollup buckets overlapping the
trailing hour, restricted to rows last seen inside it — a
stated approximation inherent to rollup storage.
provider_outage reads latest-state only (see Deliberately Not
Implemented). Metric "failed jobs 24h" counts by `created_at`
because mid-retry jobs have no `finished_at` — noted in code.

## RISKS
Alert thresholds are first guesses (queue 10/900 s, dead 3,
failed cases 5, providers 5, errors 20/h): too quiet risks a
missed incident, too loud risks alert fatigue at one email
per rule per day maximum. The daily dedupe caps the worst
case at 4 emails/day; thresholds are named constants for
one-line tuning once production data exists (Phase 175).

## NEXT PHASE
P2-D — cost control + provider cost monitoring (Phases 66, 124).
