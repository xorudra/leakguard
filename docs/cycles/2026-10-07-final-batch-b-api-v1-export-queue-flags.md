# Cycle report — Final-spec Batch B: API v1, export re-auth, priority queue, flags, monitoring pause

Commit: `55f0a1c`. Date: 2026-10-07.

## CURRENT PHASE

Final Remaining Implementation — Batch B: Phase 88 (API
versioning), Phase 49 (Data export), Phase 142 (Final
monitoring), Phase 159 (Priority queue), Phase 120 (Emergency
controls), Phase 122 (Feature flags).

## PRIORITY TIER

P1 (Phases 88, 49, 142); P2 (Phases 159, 120); P3 (Phase 122).

## STATUS

Complete. `/api/v1` is the canonical API spelling, the privacy
export is POST-only behind password re-authentication, hand-started
scans outrank scheduled ones, kill switches exist per capability,
and monitoring can be paused without touching consent.

## WHAT WAS AUDITED

The pre-batch state: routes answered only unversioned; the
privacy export — the product's one plaintext exit — was a GET
behind the session alone; the scan worker claimed strictly FIFO,
so a user's hand-started scan queued behind monitoring jobs; no
per-capability off switch existed short of taking the site down;
and monitoring could only be stopped by withdrawing consent,
which conflates a pause with a legal act.

## WHAT WAS IMPLEMENTED

- API versioning (Phase 88): `app.py` normalizes a leading
  `/api/v1/` prefix at the routing layer, so every route answers
  under both spellings with the same handler; the unversioned
  spelling is a permanent alias of v1, and a future breaking
  change ships as `/api/v2` alongside. The browser extension
  moved to `/api/v1/...`.
- Export hardening (Phase 49): `POST /api/privacy/export` only
  (the old GET answers 404). Every attempt passes Argon2id
  password re-authentication and the credential rate limiter; a
  wrong password gets the login-identical 401; each success
  writes an audit row. JSON and CSV carry the same data (CSV
  flattened to section/record/field/value rows).
- Priority queue (Phase 159): the scan worker claims
  hand-started jobs before monitoring-scheduled ones (told apart
  by the scheduler's `monitor-` idempotency-key prefix), FIFO
  within each class; failed jobs still wait out their backoff.
- Kill switches and flags (Phases 120/122): `core/flags.py` —
  environment-driven flags for registration, account scans,
  removal runs and the monitoring scheduler, default on, read on
  every check. A gated capability answers a structured
  `503 feature_disabled`; the anonymous Quick Scan is never
  gated. The flag snapshot appears in `GET /api/admin/overview`.
- Monitoring pause (Phase 142): `user_settings.monitoring_paused`
  (migration 0009), exposed via `GET/PUT
  /api/monitoring/settings` with a Settings UI toggle. The
  scheduler excludes paused users; the append-only consent
  record is never touched by pause/resume (test-asserted).

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- No `/api/v2`: there is no breaking change to ship; the alias
  policy is the deliverable.
- No priority classes for the remediation queue: it has a single
  interactive class (cases come only from a user's run/retry;
  verification is synchronous in-request), so its FIFO claim is
  already the priority order (recorded in the Phase 159 row).

## FILES CREATED

- `core/flags.py`
- `db/migrations/0009_monitoring_pause.sql`
- `tests/test_batch_b.py`

## FILES MODIFIED

- `app.py` (versioned routing, flag enforcement, export route)
- `accounts/privacy.py` (re-auth, CSV), `accounts/admin.py`
  (flags snapshot)
- `scanning/worker.py`, `remediation/worker.py`
- `monitoring/service.py`, `monitoring/scheduler.py`
- `static/app.js`, `static/index.html`
- `extension/popup.js`, `extension/options.js`,
  `extension/dist/leakguard-extension.zip`
- `tests/test_accounts.py`, `tests/test_extensions.py`
- `README.md`, `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

`0009_monitoring_pause.sql` — adds `user_settings.monitoring_paused`
(additive, idempotent, applied at startup).

## API ROUTES

- All existing routes additionally answer under `/api/v1/*`.
- `POST /api/privacy/export` replaces the GET export (GET now 404).
- `GET/PUT /api/monitoring/settings` (pause/resume + cadence view).

## TESTS ADDED

`tests/test_batch_b.py` — 20 tests: v1/unversioned parity and
404 behaviour, export re-auth (success, wrong-password 401,
rate-limit counting, audit row, CSV parity), flag gates per
capability, priority claim order, pause semantics incl. consent
rows unchanged across pause/resume.

## TESTS RUN

Full suite run before deploy (per-batch totals not recorded; the
program-close suite was 410 passed, 19 skipped).

## RESULTS

Phases 49, 88, 120, 122, 142, 159 moved to DONE. Live parity
checks for health and providers under both API spellings were
re-verified in the v2.1 reconciliation.

## SECURITY CONTROLS

The one plaintext exit (export) now requires the account
password again, is rate-limited on the credential buckets, and
is audit-logged per success. Kill switches give an incident
off-ramp per capability without downtime.

## PRIVACY CONTROLS

Pause is separated from consent withdrawal: pausing stops the
scheduler for the user while the consent record — the legal
artifact — stays exactly as granted.

## DEPLOYMENT STATUS

Deployed to production in the Final-spec sequence (see Batch A
report); migration 0009 applied at startup on deploy.

## KNOWN LIMITATIONS

Flags are environment variables: flipping one means a Render
env edit and redeploy, not a runtime toggle. Priority is two
classes, not a weighted system — sufficient for one interactive
class plus one scheduled class.

## RISKS

The idempotency-key prefix is the priority signal; a future
job producer that forgets the prefix would silently join the
high-priority class (documented in the Phase 159 row).

## NEXT PHASE

Batch C — finding feedback + disputes, broker source sweep,
admin security events, runbooks.
