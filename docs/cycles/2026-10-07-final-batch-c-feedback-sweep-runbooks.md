# Cycle report — Final-spec Batch C: finding feedback, disputes, source sweep, security events, runbooks

Commit: `ece5f7c`. Date: 2026-10-07.

## CURRENT PHASE

Final Remaining Implementation — Batch C: Phase 156
(False-positive feedback), Phase 157 (Source dispute handling),
Phase 32 (Source change detection), Phase 125 (Source health
dashboard), Phase 62 (Security events), Phase 79 (Disaster
recovery), Phase 80 (Incident response), Phase 174 (Rollback
plan, document), Phases 147/148 (Final security / privacy
acceptance).

## PRIORITY TIER

P0 (Phases 62, 79, 147, 148); P2 (Phases 156, 157, 32, 125, 80).

## STATUS

Complete. Users can disown or confirm findings and get honest
dispute routing; broker opt-out pages are swept daily for
changes; the admin overview carries a security-events view;
the three runbooks and the acceptance index were written.
Phase 125 deepened (per-broker source health) but stayed
PARTIAL — verification-success rates remain open P2 depth.

## WHAT WAS AUDITED

Findings had no user verdict channel: a wrong match could only
be ignored, and it kept feeding notifications and reappearance
flips. Dispute guidance existed only implicitly. Broker opt-out
pages could change silently, invalidating playbooks. The admin
audit list mixed security events with everything else. And the
disaster-recovery, incident-response and rollback procedures
lived as per-stage practice, not documents.

## WHAT WAS IMPLEMENTED

- Finding feedback (Phase 156): a `finding_feedback` table
  (migration 0010) and one helper, `scanning/feedback.py`, that
  every surface consults. `POST /api/findings/feedback` (session
  + CSRF, owner-scoped, a foreign id answers 404) records
  `not_me` / `confirmed` / cleared. Scan rows carry the verdict
  with Undo; disowned findings render dimmed and are excluded
  from new-exposure notifications, summary counts and
  reappearance flips.
- Dispute handling (Phase 157): `scanning/disputes.py` gives
  every finding a dispute object with the honest route per
  source kind — breach database (the breached company is the
  data holder; the index only indexes), broker listing (the
  removal flow is the dispute route), search result (Google
  "Results about you").
- Source sweep (Phase 32): `remediation/source_checks.py`
  re-fetches every `brokers.json` opt-out URL daily through the
  SSRF guard, hashes the body (SHA-256, 64KB cap) and stores
  status/hash/state in `broker_source_checks` (migration 0010).
  A changed hash flags the broker for playbook review. Wired
  into the retention worker's daily loop.
- Security events + source health (Phases 62/125):
  `GET /api/admin/overview` gained `security_events` (the
  latest 20 audit rows in the auth/security action set,
  metadata only) and `source_health` (brokers by latest sweep
  state, changed/unreachable slug lists, last check time),
  both rendered in the Admin card.
- Runbooks (Phases 79/80/174): `docs/DISASTER_RECOVERY.md`
  (Neon PITR as the only backup, stated as such; RPO bounded by
  the console-visible window; the 2026-10-07 drill evidence;
  step-by-step restore), `docs/INCIDENT_RESPONSE.md` (severity
  ladder, first-30-minutes checklist, kill-switch table,
  credential rotation table), `docs/ROLLBACK.md` (Render
  redeploy of a prior commit; forward-fix database policy).
- Acceptance index (Phases 147/148): `docs/ACCEPTANCE.md`
  consolidates every security- and privacy-acceptance area to
  its existing evidence — no new claims.

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- No per-broker verification-success dashboard (Phase 125 stays
  PARTIAL): source reachability/change shipped; success rates
  need a longer run of verification history to mean anything.
- No incident-response *drill*: the runbook shipped in this
  batch; its rehearsal record is Phase 80's remaining
  verification (UNVERIFIED in the audit taxonomy).
- Rollback shipped as a document only; the rehearsal is
  Phase 174's remaining half, closed by the post-audit P0
  program.

## FILES CREATED

- `scanning/feedback.py`, `scanning/disputes.py`
- `remediation/source_checks.py`
- `db/migrations/0010_feedback_sources.sql`
- `docs/ACCEPTANCE.md`, `docs/DISASTER_RECOVERY.md`,
  `docs/INCIDENT_RESPONSE.md`, `docs/ROLLBACK.md`
- `tests/test_batch_c.py`

## FILES MODIFIED

- `app.py`, `accounts/admin.py`, `dashboard/service.py`
- `core/retention.py` (daily sweep wiring)
- `monitoring/events.py`, `scanning/jobs.py`
- `static/app.js`, `static/style.css`
- `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

`0010_feedback_sources.sql` — `finding_feedback` table and
`broker_source_checks` table (additive, idempotent).

## API ROUTES

- `POST /api/findings/feedback` (new).
- `GET /api/admin/overview` (response gained `security_events`
  and `source_health`; shape otherwise unchanged).

## TESTS ADDED

`tests/test_batch_c.py` — 14 tests: feedback owner-scoping and
notification exclusion, dispute routing per source kind (a test
asserts every URL the module names appears elsewhere in the
product), sweep state transitions, security-events filtering,
runbook presence.

## TESTS RUN

Full suite run before deploy (per-batch totals not recorded; the
program-close suite was 410 passed, 19 skipped).

## RESULTS

Phases 32, 62, 79, 147, 148, 156, 157 moved to DONE; Phase 125
deepened (PARTIAL); Phases 80 and 174 gained their documents
(their verification halves closed later: 174 in the P0 program;
80 still open as a drill record).

## SECURITY CONTROLS

Feedback is owner-scoped with foreign ids answering 404 (no
existence leak); the sweep fetches only through the SSRF guard;
the security-events view exposes metadata only (action, actor
kind, time) — the counts-only admin discipline is preserved.

## PRIVACY CONTROLS

A `not_me` verdict removes the identity from notification and
counting paths — the user's correction propagates everywhere
the finding did. Dispute copy never overclaims: it names the
actual data holder and the actual route.

## DEPLOYMENT STATUS

Deployed to production in the Final-spec sequence (see Batch A
report); migration 0010 applied at startup on deploy.

## KNOWN LIMITATIONS

The sweep sees what a datacenter fetch sees — a walled broker
page records as unreachable, which is itself the signal.
Acceptance documents index evidence; they do not re-test it.

## RISKS

Daily fetching of 40 broker pages is a small, steady load on
broker sites; the 64KB cap and once-daily cadence bound it.

## NEXT PHASE

Batch D1 — optional WebAuthn passkeys (Phase 4).
