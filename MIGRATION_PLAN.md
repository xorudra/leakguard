# LeakGuard → Sentinel — Migration Plan (Phase 0 output)

*Companion to CURRENT_STATE.md · Source spec: "LeakGuard Sentinel Complete
Upgrade Master Prompt", Phases 0–180 (owner-supplied PDF, 2026-10-07).*

## Guiding adaptations (owner constraints override spec where they conflict)

*Owner additions, 2026-10-07 (not in the PDF — these outrank it):*
- **Free for the owner AND free for users.** No running costs, no paywalls, no
  pricing tiers anywhere until the owner explicitly says "make it paid".
  Spec Phase 105 (business model) is deferred until that order.
- **AI rule:** AI may be involved only if its token usage is free **and**
  unlimited. No such source exists (every free lane has quotas), so **AI is
  NOT involved**: spec Phases 51–56, 163–165 and the Phase 121 kill switch are
  cut, and the existing optional free-lane hook in the agent is removed in
  Stage 1. The platform is 100% deterministic scripts.
- **Standing go (2026-10-07):** owner ordered the whole upgrade — stages run
  back-to-back (DSRclone pattern), verified + pushed + reported per stage.

1. **₹0 forever:** Render free web service + **Neon or Supabase free Postgres**
   (owner picks; both have real free tiers, unlike Render's trial Postgres).
   Workers/scheduler run **in-process** in the modular monolith (spec rule 13
   allows this) — no paid worker services.
2. **Zero Claude tokens per run, ever** (see AI rule above).
3. **Incremental, always-live:** every stage ships to the same Render service and
   is verified on the live site before the next begins. Existing routes keep
   working until their replacement is proven (spec Phases 133–137).
4. **Name:** spec renames the platform "Sentinel" — *owner decision pending*;
   until decided, the product stays **LeakGuard** in UI, repo and URLs.
   *(Review annotation, 2026-10-07: decided the same day — see Owner
   decisions §1 below. The name is LeakGuard, permanently; "Sentinel"
   remains only the spec's codename.)*

## Stage map (spec phases grouped into shippable stages)

| Stage | Spec phases | Deliverable |
|---|---|---|
| **S0 — Audit** ✅ | 0 | CURRENT_STATE.md + this plan |
| **S1 — Foundations** ✅ `c1845b5`| 1, 86–89, 69–70, 75 | Modular restructure (api/domain/providers/remediation packages), structured errors, request IDs, security headers, SSRF hardening, secure logging — same behaviour, new skeleton |
| **S2 — Data** ✅ `28e4a0f`| 2, 73, 3 | Postgres (free host) + migrations; encrypted identifier vault (envelope encryption, HMAC lookup, masking) |
| **S3 — Accounts** ✅ `ef2aa47`| 4, 5, 6, 48–50 | Auth (Argon2id, sessions, reset, TOTP), authorization/IDOR guards, consent records, privacy center, export + account deletion |
| **S4 — Providers** ✅ `938a9a2`| 8, 9, 10, 110, 118 | Provider adapters + registry + health/circuit breaking; XposedOrNot & HIBP become the first two adapters; mock providers for tests |
| **S5 — Scanning** ✅ `70735ff`| 11, 12, 13, 14, 21–27 | Scan orchestrator + in-process job queue (retries, idempotency, DLQ), normalized findings, correlation, reliability, evidence, risk engine v2 |
| **S6 — Identifiers** ✅ `6f70a63`| 15–20 | Phone, username, name, address, domain (ownership-verified) monitoring + public-web discovery within terms/robots |
| **S7 — Remediation v2** ✅ `c8a9718` + perf `b54a167`/`adb9136`| 30–39, 153–157, 162, 167 | Broker registry + workflow versioning, remediation engine with idempotent attempts, **verification & reappearance** (never claim removal without evidence), human-review queue, CAPTCHA → HUMAN_ACTION_REQUIRED |
| **S8 — Monitoring** ✅ `72d4b77` (email lane proven live via Brevo)| 41–47, 158–160 | Continuous monitoring, scheduler, change detection, notifications with dedupe, history/timeline |
| **S9 — Dashboard** ✅ `3a10b0f`| 28, 29, 90–99, 138–143 | Full Protection dashboard + action center, final Quick Scan / Full Protection UX (Spotify theme language preserved), accessibility, mobile |
| **S10 — AI** | 51–56, 121, 163–165 | **CUT by the owner's AI rule** (free + unlimited tokens don't exist). Revisit only if that changes; prompt-injection defense principles still apply to all external content handling in S4–S8 |
| **S11 — Orgs & Admin** ✅ `798d9b7`| 57–62 | Organizations, domain verification, family profiles, admin panel, audit logging, security events |
| **S12 — Hardening** ✅ `69ea6a0` + `56fb831`| 63–68, 71, 72, 74, 76–80, 106–109, 115–120, 122–125 | Rate limiting, abuse/enumeration protection, cost control, caching, retention worker, observability, backups/DR, incident response, feature flags, emergency controls |
| **S13 — Trust & API** ✅ `7237780`| 81–85, 126–132 | Legal/privacy architecture, policy/terms/trust center, reports, support, subprocessors, data residency, documentation |
| **S14 — Extensions** ✅ `8c2ba6e`| 100–104 | Browser-extension foundation, mobile foundation, privacy-policy analyzer, exposure graph + propagation |
| **S15 — Acceptance** ✅ this commit| 105, 112–114, 145–152, 161, 166, 168–180 | Business model, full test matrices (functional/security/privacy/performance), contract + broker-workflow tests, final acceptance, readiness, rollback plan, limitations register, capability-claim review, cleanup + architecture review |
*(Review annotation, 2026-10-07: the S15 row's "Business model" deliverable
never shipped — Phase 105 was owner-deferred before S15 ran and is CUT
under the owner's rules (see the closing note of the Final section below).
S15 shipped the acceptance work without it.)*

## Sequencing rules

- S1→S3 must land before anything stores user data; consent (in S3) precedes all
  monitoring (S6/S8). Verification (S7) precedes any "removed" claim anywhere.
- Each stage: implement → local test → push → Manual Deploy → live verification →
  report, mirroring the workflow already used for v1–v2.5.
- Stages are independently valuable: stopping after any stage leaves a working,
  strictly better product.

## Owner decisions (all made 2026-10-07)

1. **Name: LeakGuard** — no rebrand; "Sentinel" survives only as the spec's
   codename in these docs.
2. **Database: Neon free** — account created by Muse on the owner's API email
   (same pattern as the other freemium providers); connection string lives in a
   600-permission file on the VM, never in git or chat.
3. **Go pattern: standing go** — stages run back-to-back, DSRclone pattern.
4. **Core UX law (owner, 2026-10-07):** the user enters their details ONCE →
   LeakGuard fetches their leaked data → the user gives ONE command
   ("remove all") → LeakGuard completes it. No stage may add manual chores
   (extra forms, per-item management, dashboards-as-homework) on top of that
   flow; accounts and monitoring exist to make that flow automatic
   (saved details → automatic re-scans → same one-command remediation),
   never to make the user operate the product.

## Outcome (2026-10-07)

All stages shipped and verified live on https://leakguard-hh8e.onrender.com
(Render free + Neon free + Brevo free; running cost ₹0). Every stage was
verified by the parent agent independently — own test-suite run plus a
production end-to-end check — never on the builder's word alone. Final
suite: 275 tests. Production baselines unchanged from the pre-upgrade
product: test@example.com → 214 breaches, exposure score 100; password
"password" → pwned 52,372,427×.

Known gaps (honest register):
1. ~~Per-broker verification search sources are not mapped yet, so the
   case-level Verify action answers "unknown" in production (never a
   guess).~~ **Closed after S15** by `verify_sources.json`, which maps
   all 40 brokers: 26 people-search brokers are verified against the
   search index (a `site:`-scoped DuckDuckGo query — their own sites
   are JS/bot-walled from servers, but their listing pages are
   publicly indexed), 2 brokers with confirmed server-rendered,
   name-addressable search (TruePeopleSearch, FastPeopleSearch) are
   checked directly on the broker's own search page, and the 12
   B2B/credit brokers are `none` — suppression-based removal with no
   public listing, unverifiable by design. Monitoring diffs already
   report findings appearing and disappearing across scans, and
   reappearance detection is wired. Every verification check now
   records its method (`search_index` / `broker_search` / `none`).
   Honest limit: search-index evidence is strong but indexes lag — a
   "gone" verdict means "no longer publicly indexed/listed as of this
   check", and a stale cached listing can keep a removed profile
   looking present until the index refreshes; ambiguous pages (walls,
   challenges, empty shells) still answer "unknown", never a guess.
2. Most people-search brokers wall datacenter IPs (27 of 40 cases in
   the production acceptance run classified blocked with reasons);
   those cases carry next steps, and the older local-agent path
   (user's own device/IP) remains the practical route for them.
3. Brevo free tier caps email at 300/day — ample now; the first
   scaling ceiling if the user base grows.
4. Render free sleeps when idle (~50s wake) and shares free hours
   across the owner's services.

---

## Final Remaining Implementation — order of work

*Appended 2026-10-07 by the Phase 0 re-audit under the "Final Remaining
Implementation" spec (181 phases, P0–P3 tiers). The Sentinel program above
shipped stages S0–S15; this section is the forward plan for everything the
re-audit found still open. Full evidence per phase: `PHASE_STATUS.md`
(DONE 101 / PARTIAL 50 / NOT_DONE 16 / CUT 11 / NA 3).*

### 1. Production/repository synchronization

Done and continuously maintained: production runs commit `8271c17` ==
repo HEAD; every stage was deployed manually on Render and verified live
before being declared done. Keep the rule: no stage is "done" until the
deployed commit matches the repo and a production check passes.
*(Review annotation, 2026-10-07: the `8271c17` pin was the state at the
Phase 0 re-audit. Production has since advanced through the Final-spec
batches and the post-audit P0/P1 programs — most recently `d86afa7`
(Phase 25), with the repo HEAD beyond it in documentation only. The
rule itself stands and is how every later closeout was run; current
pins live in `docs/cycles/` and `CURRENT_STATE.md`.)*

### 2. P0 blockers (do first, in this order)

None of these is an active production exposure; they are the
verification/documentation depth gaps in the P0 tier.

*(Review annotation, 2026-10-07: **all ten items below are closed.**
They landed through the Final-spec batches and the post-audit P0
program; per-item evidence is in `PHASE_STATUS.md` and
`docs/cycles/`. Divergences from this section's letter, recorded
honestly: item 3 (HSTS) shipped in Batch A at the full
`max-age=31536000; includeSubDomains`, not a conservative-first
value; item 4 (Phase 70) shipped first as the resolve-and-check
guard this section describes, and was then **superseded by
connection pinning** in the post-audit program — the
resolve-then-fetch version left a DNS-rebinding window the audit
later flagged INSECURE, and pinning is the fix that closed it;
item 6 (Phase 107) shipped the lock file as exact version pins
**without artifact hashes**, and the Render build does not perform
hash checking — the divergence is recorded in the phase's row;
item 8 (WebAuthn) shipped in Batch D1 as a hand-built stdlib
implementation (`accounts/webauthn.py`, `accounts/cbor.py`) with
no new dependency, contrary to this item's "document the deferral
instead of hand-rolling" fallback. Items 1, 2, 5, 7, 9 landed as
written; item 10's gate re-ran at the v2.1 reconciliation and
closed Phases 173/180.)*

1. **Restore test + backup/DR procedure** (Phases 170, 78, 79) —
   perform a Neon point-in-time restore into a scratch project, verify
   the app boots against it and vault data decrypts, then document
   RPO/RTO and the recovery procedure in README Operations.
   *Depends on: nothing. Blocks: 173, 180.*
2. **Written rollback plan** (Phase 174) — document app rollback
   (redeploy prior commit), configuration rollback (env var inventory
   + restore steps), and database rollback (restore-from-backup path,
   since migrations are additive-only by policy); rehearse the app
   path once.
3. **HSTS header** (Phase 69) — add `Strict-Transport-Security` in
   `core/security.py` with a conservative max-age first; test CSP
   suite stays green.
4. **DNS private-IP validation** (Phase 70) — resolve-and-check step in
   the shared outbound fetch path (`providers/base.py` + the agent
   fetcher): refuse private/loopback/link-local resolutions, re-check
   after redirects; add unit tests with hostile fixtures.
5. **Security-events view** (Phase 62) — an admin view over the
   existing `audit_log` filtered to auth failures, rate-limit hits and
   admin actions; no new data collection needed.
6. **Dependency lock file** (Phase 107) — pin the 3 runtime deps with
   hashes (`pip freeze` + hash checking in the Render build command);
   add a periodic manual review note to README Operations.
7. **Consolidated acceptance runbooks** (Phases 147, 148) — fold the
   per-stage security/privacy checks into two repeatable checklists in
   the repo, run them once end-to-end, record the run.
8. **WebAuthn/passkeys** (Phase 4) — optional second factor alongside
   TOTP; needs a vetted library decision (new dependency — owner rule:
   free only, stdlib-first; if no acceptable free library, document
   the deferral instead of hand-rolling WebAuthn crypto).
9. **Least-privilege DB role** (Phase 73) — a Neon role for the app
   without schema-ownership rights, if the free plan allows a second
   role; otherwise document the platform constraint.
10. **Re-run the Phase 180 final gate** once 1–9 land.

### 3. P1 core platform

1. **API versioning** (Phase 88) — introduce `/api/v1/...` aliases for
   the token read endpoints, keep unversioned routes working, publish
   a deprecation policy in README API. *Depends on: nothing.*
2. **Export hardening** (Phase 49) — password re-authentication before
   `GET /api/privacy/export` returns plaintext; add a CSV variant.
3. **Stored finding lifecycle** (Phase 25) — persist lifecycle state on
   findings (open/resolved/reappeared) written by the monitoring diff
   instead of deriving it per read; backfill from existing job history.
4. **Monitoring pause/resume** (Phase 142) — a paused flag in
   `user_settings`, separate from consent withdrawal; scheduler skips
   paused users.
5. **Per-cycle report files** (Phase 149) — land each implementation
   cycle's completion report under `docs/cycles/` going forward.

*(Review annotation, 2026-10-07: **all five P1 items are closed** —
items 1, 2 and 4 in Final Batch B (`55f0a1c`), item 3 in the P1-B
cycle (`d86afa7`, migration `0012_finding_lifecycle.sql`), item 5
in the P1-C cycle (`docs/cycles/`, 13 reports + format guard test).
See `docs/cycles/2026-10-07-p1b-phase-25-lifecycle.md` for item 3's
one recorded wart: lifecycle writes converge asynchronously, up to
~a minute after a large scan.)*

### 4. P2 remediation / intelligence / reliability

Ordered by user value, then risk reduction:

*(Review annotation, 2026-10-07: **mixed — this section is now
partly history.** Shipped since it was written: item 1 (source
change detection — the daily broker source sweep, Final Batch C),
items 2–3 (finding feedback + dispute guidance, Batch C), item 4
(scan priority queue, Batch B), item 7 (kill switches, Batch B —
**with different variable names than proposed here**: the shipped
controls are `LEAKGUARD_FLAG_REGISTRATION` /
`LEAKGUARD_FLAG_ACCOUNT_SCANS` / `LEAKGUARD_FLAG_REMOVAL_RUNS` /
`LEAKGUARD_FLAG_MONITORING_SCHEDULER` in `core/flags.py`, and they
gate routes + the scheduler tick rather than "route + worker
level"), item 8 (CI, Batch A — the workflow runs the suite on
push/PR and weekly; no merge-blocking is configured, and the
"static security pass" is the suite itself plus a frontend syntax
check), item 9 (staging environment, post-audit program), item 15
in lite form (per-broker source health in the admin overview),
item 16 (incident response runbook + tabletop drill — `docs/
INCIDENT_RESPONSE.md`, `docs/drills/`). The remaining items (5, 6,
10–14, 17–22) are still open at the depth `PHASE_STATUS.md`
records; that file, not this section, is the live authority.)*

1. **Source change detection** (Phase 32) — periodic hash/diff of
   broker opt-out pages + playbook flows at seed/scheduler level;
   changes raise an admin-visible review flag and pause auto-submit
   for that broker until reviewed. *Depends on: 123 (surface), 62
   (event plumbing) helpful but not blocking.*
2. **False-positive feedback** (Phase 156) — "This isn't me" on a
   finding → finding state `false_positive`, excluded from score and
   future alert dedupe; audited.
3. **Source dispute handling** (Phase 157) — disputed state on findings
   + a per-source dispute note in the broker registry; disputes feed
   reliability scoring. *Depends on: 156 (shared lifecycle states, P1
   item 3).*
4. **Priority queue** (Phase 159) — order worker claims by case/finding
   risk then age (`ORDER BY` change in both workers + tests); billing
   must never influence order (there is no billing — keep it that way).
5. **Scan budget engine** (Phase 158) — per-user daily provider-call
   budgets enforced in the orchestrator, surfaced in the Action Center
   when a scan is budget-limited. *Depends on: 124 (usage counters
   already exist in the HealthTracker).*
6. **Workflow-version capture** (Phase 31) — record
   `brokers.workflow_version` on each remediation attempt; bump rules
   documented in `remediation/registry_seed.py`.
7. **Emergency kill switches** (Phase 120) — env flags
   `LEAKGUARD_DISABLE_SCANS/REMEDIATION/NOTIFICATIONS` checked at the
   route + worker level, with an admin-visible banner when active.
8. **CI pipeline** (Phase 106) — run the full suite + a static
   security pass on every push (free tier of the repo host's CI);
   block merges on failure. *Depends on: nothing; do early if the
   repo host's free minutes suffice.*
9. **Staging environment** (Phase 109) — a second free Render service
   + Neon branch/project fed by the same repo; watch the shared
   free-hours budget (owner constraint: ₹0).
10. **Fake-broker harness** (Phases 111, 162) — a local stub broker
    server (form + wall + CAPTCHA fixtures) so remediation workflows
    regression-test end-to-end without touching real brokers.
11. **Dead-letter replay** (Phase 119) — admin action to requeue a
    dead job/case once, audited. *Depends on: 120 (guard rails).*
12. **Standalone policy engine** (Phase 153) — extract the remediation
    transition/consent/channel rules from `remediation/engine.py`
    into a versioned `remediation/policy.py` with its own tests;
    behavior must stay byte-identical (parity tests first).
13. **Data-quality stage** (Phase 160) — a worker pass over stored
    findings: duplicates, malformed URLs/timestamps, schema drift;
    reports counts to the admin overview, never silently rewrites.
14. **Metrics + engineering alerts** (Phases 76, 77) — counters for
    provider errors, queue depth, worker failures; alert via the
    existing Brevo lane to the owner when thresholds trip.
15. **Per-broker source-health dashboard** (Phase 125) — extend the
    admin overview with per-broker case outcomes + verification
    success rates from `verification_checks`.
16. **Incident response plan** (Phase 80) — a short written plan
    (breach, provider compromise, credential exposure, automation
    abuse, DB compromise) in the repo, with the security contact.
17. **Search-exposure view** (Phase 40) — a Privacy Center section
    listing discovery findings as their own view with limitations.
18. **Cost/quota tracking** (Phases 66, 124) — persist HealthTracker
    counters daily; show free-tier headroom (esp. Brevo 300/day) in
    the admin overview.
19. **Accessibility pass** (Phase 96) — ARIA landmarks/labels, focus
    order, contrast check on the Spotify theme; add a smoke test.
20. **Performance + load evidence** (Phases 115, 116) — a small
    repeatable benchmark script (scan latency, drain rates) run
    against staging once it exists. *Depends on: 109.*
21. **Browser-probe hardening** (Phases 137, 166) — domain allowlist
    enforcement in `browser_probe.py` beyond the playbooks.
22. **Legacy-surface decision** (Phase 178) — decide keep-or-remove
    for `local_agent.py` / `proxy_relay.py` (the local agent is the
    documented route for walled brokers — default keep, documented).

### 5. P3 advanced / optional

1. **Organizations** (Phases 57–59) — only if a real multi-user need
   appears; otherwise record the permanent decision here and close.
   Household labels cover the current family use case.
2. **Formal legal documents** (Phases 82, 83, 81) — standalone
   privacy-policy and terms pages generated from the *actual* data
   inventory (CURRENT_STATE §E), reviewed against the code; no
   template claims that the product doesn't implement.
3. **Report documents** (Phase 85) — a downloadable exposure/removal
   report (HTML/PDF) generated from the same data as the privacy
   export.
4. **Feature flags** (Phase 122) — a minimal env/DB-backed flag read
   for new risky features; only when a feature actually needs one.
5. **Admin health depth** (Phase 123) — queue depth + worker status.
   *Depends on: P2 item 14 (metrics).*
6. **Support workflow** (Phase 126) — a privacy-conscious, auditable
   support path (dedicated mailbox + triage doc) before any in-product
   tooling.
7. **Bug-bounty page** (Phase 128) — scope/safe-harbor text extending
   `security.txt`, only when the owner wants external researchers.
8. **Data residency** (Phase 129) — document current regions (Render
   Oregon, Neon Singapore) on /trust; design note for regional
   configuration if a residency requirement ever appears.
9. **Localization preparation** (Phase 98) — extract UI strings in
   `static/app.js`/`index.html` into a single catalog; no translation
   work yet.
10. **Privacy-policy analyzer** (Phase 102) — optional; only with
    facts/interpretation/uncertainty clearly separated, per spec.
11. **Propagation analysis** (Phases 104, 152) — only where evidence
    supports it (shared-source correlation exists); never claim
    causality the data doesn't show.
12. **Regional policy rules** (Phase 168) — promote the letter-law
    templates (Phase 81) into configurable per-region rules.

*(Review annotation, 2026-10-07: item 1 is **moot** — organizations
shipped in Stage S11 of the Sentinel program, before this section
was written, and remain PARTIAL in the audit taxonomy on depth,
not existence. Also shipped since: item 2's pages (privacy, terms,
support — Final Batch D2 and the S13 trust surface), item 4's flags
(the `core/flags.py` emergency controls, shipped via the P2 item 7
work), item 8's substance (regions documented on `/trust`), item 7's
`security.txt` (served at `/.well-known/security.txt`), item 10
(privacy-policy analyzer, Batch D2) and item 11 (propagation on
`/api/graph`, Batch D2). Still open: item 3 (report documents),
item 5's depth, item 6's in-product tooling, item 9 (localization
— Phase 98 is the program's one MISSING phase; not even the string
extraction has been done), item 12. `PHASE_STATUS.md` carries the
per-phase truth.)*

**Permanently closed by owner rules (not planned):** AI phases 51–56,
121, 163–165 (AI only if free *and* unlimited — no such tier exists)
and Phase 105 business model (monetization deferred until the owner
explicitly orders it). File uploads (71), webhooks (72), and containers
(108) are NA — those surfaces do not exist; if any is ever added, its
phase reopens automatically at P0/P3 as marked in `PHASE_STATUS.md`.

### 6. Migrations

No migrations are required by the audit itself. Planned schema work,
in order: stored finding lifecycle (P1 item 3 — new column + backfill,
additive), `user_settings.paused` (P1 item 4 — additive), false-positive/
dispute states (P2 items 2–3 — CHECK constraint widening, additive),
daily provider-usage counters (P2 item 18 — new table). Rules, unchanged
from the Sentinel program: migrations are additive and idempotent, run
at startup by `db/migrate.py`, and never rewrite history — a bad
migration is fixed forward, with the backup restore (§2 item 1) as the
safety net.
*(Review annotation, 2026-10-07: three of the four planned items
shipped — `0009_monitoring_pause.sql` (the pause column shipped
named `monitoring_paused`, not `paused`), `0010_feedback_sources.sql`
(feedback/dispute), `0012_finding_lifecycle.sql` (lifecycle state +
backfill). The daily provider-usage counters table has **not**
shipped; Phases 66/124 remain PARTIAL.)*

### 7. Rollback

Current state (Phase 174 PARTIAL): app rollback = manual deploy of a
prior commit on Render (the pattern used for every stage); env-var
rollback = edit in the Render dashboard; database rollback = Neon
point-in-time restore (owner-run, untested — P0 item 1 closes this).
Every future change must state its rollback in its cycle report, per
the spec's implementation loop.
*(Review correction, 2026-10-07: the paragraph above is stale.
Phase 174 is DONE: the point-in-time restore was drilled (a
point-in-time branch was restored, verified — 19 public tables /
40 brokers / migrations / users — and deleted), and the app
rollback path was rehearsed on staging (specific-commit deploy
back → health → forward). The standing document is
`docs/ROLLBACK.md`, including the rehearsal record.)*

### 8. Testing

The full suite (302 tests, 16 files) is the regression gate *(review
annotation, 2026-10-07: those were the figures at this section's
writing; at the P1 closeout the suite stands at 454 passed /
19 skipped across 28 test files, and CI runs it on every push)*:
security
matrix (`tests/test_hardening.py`, `tests/test_accounts.py`,
`tests/test_orgs_admin.py`, `tests/test_api_tokens.py`), privacy matrix
(`tests/test_vault.py`, `tests/test_monitoring.py`), provider contracts
(`tests/test_providers.py`), remediation + verification
(`tests/test_remediation.py`, `tests/test_verify_sources.py`). New work
adds tests in the same files' style (pgserver-backed, mock providers,
stub executors — never live brokers in tests). The two acceptance
runbooks (P0 item 7) formalize what is currently per-stage practice.

### 9. Deployment

Manual deploy on the existing Render service ("Manual Deploy → Deploy
latest commit" — auto-deploy does not fire for this service), latest
commit only, after the full suite passes locally. Env-var changes save
via "Save, rebuild, and deploy" (which also deploys the latest commit —
sequence accordingly). When staging exists (P2 item 9), deploy there
first, run the acceptance smoke, then promote the same commit.
*(Review annotation, 2026-10-07: staging exists — a second Render
service on a Neon branch, manual deploys only — and the
staging-first sequence in the last sentence is now the standing
practice every post-audit cycle followed.)*

### 10. Post-deploy verification

The per-stage checklist that produced today's state, kept verbatim:
health (`db: "ok"`) → providers health → anonymous baseline parity
(test@example.com → 214 breaches, score 100; "password" → pwned
52,372,427) → the stage's own production E2E (throwaway account,
self-deleted) → admin counts sanity → UptimeRobot confirmation. A
deploy that fails any step is rolled back per §7 before any report
goes out.

---

## v2.1 reconciliation addendum (2026-10-07, evening)

Spec v2.1 ("current live-production baseline") changed no phase and no
priority; it added one non-negotiable to Phase 0: a live/repository
reconciliation with the exact production commit identified from the
deployment platform. Executed the same day:

- Production commit pinned from the Render dashboard: `56c14e5`
  (deploy `dep-db34ec9srm7s73e32480`, live 18:50 IST); staging runs the
  same commit (deploy `dep-db34n9d9fdbs739vetc0`, 19:09 IST). Repository
  HEAD beyond production is documentation-only — production code and
  repository code are identical.
- Live feature sweep + throwaway-account E2E re-verified against
  production; full suite at HEAD: 410 passed, 19 skipped.
- Discrepancies found and resolved: audit-document drift (this file's
  companions `CURRENT_STATE.md` / `PHASE_STATUS.md` refreshed) and
  staging vault key files missing from `.gitignore` (fixed; never
  committed). No functional live↔repository discrepancy exists.
- Phases 173 (production readiness) and 180 (final command) closed on
  this evidence. Scoreboard: **135 DONE / 31 PARTIAL / 1 NOT_DONE /
  11 CUT / 3 NA**.
*(Review annotation, 2026-10-07: that scoreboard is a dated snapshot.
It was superseded the same night by the audit re-issue (124 DONE in
the owner's taxonomy) and then by the P0/P1 closeouts; the current
scoreboard lives in `PHASE_STATUS.md` — 133 DONE at the P1
closeout.)*

---

## Owner audit gate (2026-10-07, night)

The owner ordered the audit deliverables re-issued and placed an
explicit gate on this plan: **no remediation/implementation work under
this plan begins until the owner approves the audit results**
(`CURRENT_STATE.md`, this plan, and `PHASE_STATUS.md` in the owner's
audit taxonomy — DONE / PARTIAL / MISSING / INSECURE / UNVERIFIED /
NOT APPLICABLE, with per-phase dependencies, required next actions,
and required tests). The plan itself is unchanged by the audit; the
gate is procedural, not technical.
*(Review annotation, 2026-10-07: the gate was **lifted** — the owner
approved the audit the same night ("Approve the audit and start
implementing, P0 first"), and the post-audit P0 and P1 programs ran
under that approval and closed. This section is kept as the record
of the gate, not as a live instruction.)*
