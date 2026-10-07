# Documentation Review Records

*Standing record for the documentation-review phases (131, 132).
Each review is appended as its own dated section; documents are
fixed in place during the review, and this file is the checklist
evidence. Rule throughout: **code is the truth; docs move to
match — never the reverse.***

---

## Phase 131 — Documentation review (README.md, extension/README.md)

**Date:** 2026-10-07 · **Reviewer:** automated review (agent) ·
**Method:** every checkable claim in each document was compared
against the code as it exists today — the route table was
enumerated from `app.py` and diffed against every route the
documents name; environment variables were enumerated from
`os.environ` reads across the codebase and diffed against the
documents' Operations claims; behavior claims (export, deletion,
tokens, retention, password check) were read in their implementing
modules. Fixes were applied to the documents in this same pass and
are listed as FIX items.

### README.md

**API routes — PASS (with note).** Routes named anywhere in the
README: the rate-limit table (`/api/scan`, `/api/agent/probe`,
`/api/agent/submit`, `/api/auth/register`, `/api/auth/login`,
`/api/auth/forgot-password`, `/api/scans`,
`/api/remediation/run`), the token examples
(`/api/v1/action-center`, `/api/v1/scans`, `/api/v1/scans/<id>`,
`/api/v1/remediation/cases`, `/api/v1/notifications`,
`/api/v1/monitoring/timeline`), token management
(`GET`/`POST /api/tokens`, `DELETE /api/tokens/<id>`),
`GET /api/providers/health`, and the `/trust` page. **Every named
route exists** in `app.py`'s route set. Note: the README's API
section presents the versioning contract + examples, not an
exhaustive catalogue — the remaining account routes (consents,
identifiers, household, monitoring settings, graph, privacy
export, passkeys/TOTP, domains, findings feedback, admin, agent
plan, policy analyzer) are reachable from the UI and are not
claimed either way by the README, so no fix was needed.
Versioning claim verified in code: `/api/v1` is canonical and the
unversioned spelling is normalized to the same handler
(`app.py`).

**Rate limits — PASS.** Every number in the Operations table
matches `core/ratelimit.py` (30/h anon scan, 30/h agent probe and
submit, 10/h register, 5/h forgot-password, 10/h account scans,
6/h remediation run) and the credential limiter matches
`accounts/ratelimit.py` (10 attempts / 15 min, per IP and email).
Body-size claim (256 KB → 413) and the feature-flag table match
`core/flags.py` exactly (names, off values, 503
`feature_disabled`, Quick Scan never gated).

**Passkeys paragraph — PASS.** Attestation `none` only, ES256 /
RS256, user verification required, counter policy, no TOTP
stacking, and the `LEAKGUARD_WEBAUTHN_ORIGIN` /
`LEAKGUARD_WEBAUTHN_RP_ID` pins all match `accounts/webauthn.py`
and the environment reads.

**Retention table — PASS.** Sessions 7 days, reset tokens 7 days,
notifications 90 days, deleted accounts 30 days then hard purge,
audit trail kept — all match `core/retention.py`'s constants and
its deliberate exclusion of `audit_log`.

**Database connections — PASS.** The `DATABASE_URL` /
`MIGRATION_DATABASE_URL` privilege split and fallback match
`db/pool.py` + `db/migrate.py` (Batch A.1 behavior).

**Supply chain — PASS.** Three version-ranged runtime deps,
lock-as-snapshot, weekly CI — matches `requirements.txt`,
`requirements.lock`, and the workflow (as re-verified in the
Phase 107 cycle, including the cryptography 50.x remediation).

**FIX — hero + badges were pre-accounts copy.** The tagline said
"No accounts. No database. Nothing to install." and the badge
said "Dependencies: Zero". Both are false today (accounts + Neon
Postgres; three runtime deps). Tagline now scopes the no-account
claim to the Quick Scan; badge now reads "3 runtime".

**FIX — Agent Mode free-lane bullet described a removed
feature.** The bullet documented `LEAKGUARD_FREE_LANE_URL` /
`_KEY` / `_MODEL` configuration for an AI fallback. No such
environment variables exist anywhere in the code; `agent.py`'s
own header records the fallback "was removed in Stage S1" under
the owner's AI rule. Bullet replaced with the true statement (no
AI anywhere).

**FIX — password-check wording.** The Scan table said the
password "never leaves your device". In reality the password is
posted to the LeakGuard server, which hashes it and sends only
the 5-char SHA-1 prefix to HIBP (`providers/hibp_passwords.py`);
the password is never stored or logged, and account scan jobs
never carry passwords (`scanning/orchestrator.py`). Both the
table and the Privacy bullet now say exactly that.

**FIX — "Run it yourself" predated the data layer.** It claimed
zero dependencies and a bare `python3 app.py`. Now: install step,
the three deps named, and the database/vault-key environment the
account features need — including the true graceful-degradation
behavior (anonymous surface runs without a database).
**Deploy** line claimed "no build step"; it now names the real
build command from `render.yaml` and carries the
dashboard-stored-build-command caution.

**FIX — Privacy section + FAQ storage answers were false for
accounts.** "No accounts, no database, no server-side storage of
scans" and the FAQ's flat "No" described only the anonymous
surface while account scans/findings/cases are stored by design.
Both now split the answer honestly: anonymous = nothing stored;
account = vault-encrypted details + stored scans/cases, with the
export (JSON/CSV, password re-auth — verified in
`accounts/privacy.py` behavior and the P1 Privacy Center walk)
and the 30-day-soft-delete → hard-purge path. The FAQ's
"dependency-free" claim was corrected with the storage answer.

**FIX — Project layout listed 6 files for a 9-package tree.**
The table now covers the packages (`core/`, `accounts/`,
`vault/`, `db/`, `providers/`, `scanning/`, `remediation/`,
`monitoring/`, `dashboard/`), `static/`, `extension/`,
`tools/`, and `docs/` alongside the original files.

**FIX — Operations omitted the email-lane/admin environment.**
`BREVO_API_KEY`, `NOTIFY_FROM_EMAIL`, `NOTIFY_FROM_NAME`,
`ADMIN_EMAILS`, and `RESET_URL_BASE` are read by the code
(`monitoring/notify.py`, admin gating, reset flow) but were named
nowhere in Operations. A short "Email lane & admin" paragraph
now names them. (Noted, no fix: `LEAKGUARD_PROVIDERS` is a
test/dev provider switch, `LEAKGUARD_BROWSER_PROXY` /
`LEAKGUARD_NO_BROWSER` / `LEAKGUARD_CHROME` are already covered
by the run-locally notes.)

**FIX — Roadmap listed shipped work as future.** "Recurring
monitoring" shipped (scheduler, 7/14/30-day cadences, new-breach
and reappearance notifications — Phases 41–47 / S8). The roadmap
now records it as shipped and keeps the genuinely future items.

### extension/README.md

**PASS — no fixes.** Verified against `extension/manifest.json`
(Manifest V3; permissions exactly `storage` + the single
LeakGuard host permission), the files table against the folder's
actual contents, `tools/build_extension_zip.py` and
`tools/build_icons.py` (both exist), and the behavior claims
against the server: tokens are the Privacy Center's read-only API
tokens (hash-only storage, GET-only by construction —
`accounts/api_tokens.py`, `app.py` reader/session split), and the
popup's "one recommended next action" is the Action Center's
`next_action` field (`dashboard/service.py`), which `popup.js`
consumes. The Chrome Web Store fee explanation is an owner-policy
statement, not a code claim.

### Outcome

README.md: 8 FIX items (all applied above), the rest PASS.
extension/README.md: PASS in full. No code was changed; where a
document and the code disagreed, the document moved.

---

## Phase 132 — Migration documentation review (MIGRATION_PLAN.md)

**Date:** 2026-10-07 · **Reviewer:** automated review (agent) ·
**Method:** the stage map was walked stage by stage against
`git log` (every cited commit hash was confirmed present in the
repository), and the appended "Final Remaining Implementation"
plan (§§1–10 of that section) was compared item by item against
what the Final-spec batches and the post-audit P0/P1 programs
actually shipped (evidence: `PHASE_STATUS.md` rows +
`docs/cycles/` reports + the code). Corrections follow the file's
own convention: past facts that were true when written are kept
and annotated; present-tense claims that are false today are
corrected with a dated review note.

### Stage map (Sentinel program)

| Stage | Verdict | Evidence |
|---|---|---|
| S0 Audit | SHIPPED | `CURRENT_STATE.md` + the plan itself (Phase 0, `76565e0`) |
| S1 Foundations | SHIPPED | commit `c1845b5` present; packages + `core/ssrf.py` guard in tree |
| S2 Data | SHIPPED | `28e4a0f`; `db/`, `vault/`, migrations 0001+ in tree |
| S3 Accounts | SHIPPED | `ef2aa47`; `accounts/` incl. Privacy Center in tree |
| S4 Providers | SHIPPED | `938a9a2`; `providers/` registry in tree |
| S5 Scanning | SHIPPED | `70735ff`; `scanning/` orchestrator + queue in tree |
| S6 Identifiers | SHIPPED | `6f70a63`; identifier kinds incl. verified domains in tree |
| S7 Remediation v2 | SHIPPED | `c8a9718` (+ perf commits); verification/reappearance in tree |
| S8 Monitoring | SHIPPED | `72d4b77`; scheduler + Brevo lane live (per closeout record) |
| S9 Dashboard | SHIPPED | `3a10b0f`; `dashboard/` + Action Center in tree |
| S10 AI | CUT — correctly recorded | Owner AI rule; the free-lane hook's removal is confirmed in `agent.py`'s header |
| S11 Orgs & Admin | SHIPPED | `798d9b7`; orgs, admin overview, audit in tree |
| S12 Hardening | SHIPPED | `69ea6a0` + `56fb831`; rate-limit last-hop fix in tree |
| S13 Trust & API | SHIPPED | `7237780`; trust pages + subprocessors in tree |
| S14 Extensions | SHIPPED | `8c2ba6e`; `extension/`, graph, policy analyzer in tree |
| S15 Acceptance | SHIPPED with one false deliverable | Acceptance work shipped; the row's "Business model" (Phase 105) never shipped — CUT by owner rule. **Annotated on the row.** |

Two further stage-map-adjacent corrections: Guiding adaptation 4
still said the name decision was "pending" — it was made the same
day (Owner decisions §1); **annotated**. The Outcome section's
figures (275 tests, the baselines) are true-as-of-writing history
and were left as-is.

### The appended Final plan (§§1–10)

- **§1 Production/repository synchronization — STALE pin,
  annotated.** `8271c17` was the re-audit-time pin; production
  has since advanced (most recently `d86afa7`). The section's
  *rule* remains the operating rule and was annotated, not
  rewritten.
- **§2 P0 blockers — all ten SHIPPED, annotated as a block,**
  with four divergences recorded where the shipped work differs
  from the item's letter: HSTS shipped at full max-age (not
  conservative-first); Phase 70's resolve-and-check was
  **superseded by connection pinning** after the audit flagged
  the residual INSECURE; the dependency lock shipped **without
  artifact hashes** and the build does no hash checking;
  WebAuthn shipped as a hand-built stdlib implementation against
  the item's "document the deferral instead" fallback.
- **§3 P1 — all five SHIPPED, annotated.** (Batch B ×3,
  lifecycle in P1-B, report files in P1-C.)
- **§4 P2 — MIXED, annotated as a block.** Shipped: items 1, 2,
  3, 4, 7, 8, 9, 15-lite, 16. Recorded divergence: item 7's kill
  switches shipped under different variable names and semantics
  than proposed (`LEAKGUARD_FLAG_*`, route/scheduler gating);
  item 8's CI runs the suite but no merge-blocking is configured.
  The rest remain open at `PHASE_STATUS.md` depth.
- **§5 P3 — MIXED, annotated as a block.** Item 1 (organizations)
  is moot — S11 shipped them before this section existed. Items
  2, 4, 7, 8, 10, 11 shipped in substance; 3, 5-depth, 6-tooling,
  9 (localization — the program's one MISSING phase) and 12
  remain open.
- **§6 Migrations — annotated.** Three of four planned schema
  items shipped (`0009` — with the column named
  `monitoring_paused`, not `paused` as planned — `0010`,
  `0012`); the daily provider-usage counters table has not
  shipped (Phases 66/124 PARTIAL).
- **§7 Rollback — STALE, corrected by annotation.** The section
  called Phase 174 PARTIAL and the PITR path "untested"; both
  closed (restore drill passed; staging rollback rehearsal
  recorded in `docs/ROLLBACK.md`).
- **§8 Testing — STALE figures, annotated.** 302 tests / 16
  files was true when written; 454 passed / 19 skipped / 28 test
  files at the P1 closeout.
- **§9 Deployment — STALE conditional, annotated.** "When
  staging exists" — it does, and staging-first is now standing
  practice.
- **§10 Post-deploy verification — PASS.** The checklist is the
  one every later closeout actually used (health → providers →
  baseline parity → throwaway-account E2E → admin sanity →
  monitor), confirmed against the cycle reports.
- **v2.1 addendum — dated snapshot, annotated with a pointer**
  to the current scoreboard (its 135-DONE figure was superseded
  twice the same night).
- **Owner audit gate — STALE as a live instruction, annotated.**
  The gate was lifted on the owner's approval the same night;
  the P0/P1 programs ran under it. Kept as history.

### Outcome

Stage map: 14 SHIPPED, 1 CUT (correctly recorded), 1 false
deliverable claim annotated (S15/business model). Final plan:
§§2–3 fully shipped; §§4–5 mixed with the shipped items and
divergences now annotated; §§6–9 annotated/corrected where
stale; §10 PASS. No silent rewrites: every change to
MIGRATION_PLAN.md in this review is a dated, marked annotation or
correction, and `PHASE_STATUS.md` remains the live authority the
annotations point to.
