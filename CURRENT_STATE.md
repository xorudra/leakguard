# LeakGuard Current State Audit

*Structure: the Final Remaining Implementation spec §3 (sections A–J).
Per-phase evidence for everything claimed here lives in `PHASE_STATUS.md`.
The pre-upgrade Phase 0 audit (v2.5) is preserved in git history at
commit `76565e0`; the Sentinel-era state file this replaces is in history
at `e31e016`.*

## A. Audit Metadata

- **Audit date:** 2026-10-07
- **Auditor:** Muse (Phase 0 auditor, Final Remaining Implementation program)
- **Repository commit:** `8271c17` (main, github.com/xorudra/leakguard)
- **Production deployment:** https://leakguard-hh8e.onrender.com — Render free web service `srv-db2rm6142hec73flnl90` (Oregon), manual deploy
- **Production commit/version:** `8271c17` — matches repository HEAD
- **Runtime:** Python 3.12, stdlib `http.server`; only three pip dependencies (`psycopg[binary]`, `cryptography`, `argon2-cffi`)
- **Deployment platform:** Render (free) + UptimeRobot free monitor (5-min, HEAD-safe)
- **Database:** Neon free PostgreSQL (project "leakguard", AWS ap-southeast-1 Singapore), pooled connection via `DATABASE_URL`
- **Queue/worker:** PostgreSQL-backed queues drained by in-process threads (scan worker, remediation worker, monitoring scheduler, retention worker) — no separate worker service
- **Frontend:** Vanilla JS single-page app + PWA (`static/`), Manifest V3 browser extension (`extension/`, sideload)
- **Backend:** Modular monolith — `core/`, `accounts/`, `providers/`, `scanning/`, `remediation/`, `monitoring/`, `dashboard/`, `db/`, `vault/`
- **AI provider configured:** NO — none exists in the product (owner rule: AI only if free *and* unlimited; no such tier exists)
- **Audit confidence:** High — every status in `PHASE_STATUS.md` was checked against the code (grep/read), the full suite was re-run by the auditor (302 tests, OK, 2 environment skips), and production behavior was end-to-end verified by the parent agent on 2026-10-07 for every shipped stage

## B. Production vs Repository

| Area | Repository | Production | Match? | Evidence | Action |
|---|---|---|---|---|---|
| Authentication | Argon2id, sessions, TOTP, reset (`accounts/`) | Live; register/login/TOTP/reset E2Es passed | YES | Stage S3/S8 production checks (parent-verified 2026-10-07) | None |
| Database | Migrations `0001`–`0008`, Neon Postgres (`db/`) | Live; health reports `db: "ok"` | YES | Production health + every account-stage E2E | None |
| Monitoring | Scheduler + diff + timeline (`monitoring/`) | Live; cadence settings + timeline verified | YES | Stage S8 production check | None |
| Notifications | Ledger + Brevo lane (`monitoring/notify.py`) | Live; real reset email delivered via Brevo and completed end-to-end | YES | Stage S8 email-lane proof (parent-verified) | None |
| Admin | Counts-only overview + audit (`accounts/admin.py`) | Live; non-admins get 404, admin sees counts only, no email strings in output | YES | Stage S11 production check (15/15) | None |
| Remediation | Engine + worker + verification (`remediation/`) | Live; 40-case runs settle; verification produces real `verified_removed` | YES | Stage S7/S7.1/S7.2 + verification drill (parent-verified) | None |
| API | Read-only Bearer tokens on six read endpoints (`accounts/api_tokens.py`) | Live; token read/mutation-wall/revoke drill passed | YES | Stage S13 production check (10/10) | None |
| Security | Rate limits, retention, headers, audit (`core/`, `accounts/audit.py`) | Live; 429 + Retry-After observed; X-Forwarded-For spoof bypass caught live and fixed (`56fb831`) | YES | Stage S12/S12.1 production checks | None |

## C. Architecture Inventory

- **Entry points:** `app.py` (HTTP server, all routes), `agent.py` (deterministic broker agent — the remediation core), `local_agent.py` (residential-IP runner for the user's own device), `browser_probe.py` (local Playwright probe), `proxy_relay.py` (dev-only egress relay for this VM)
- **Modules:** `core/` (errors, context/request-ids, security headers + CSRF, logging, rate limiter, retention, feature flags / emergency switches), `accounts/` (auth, sessions, totp, consents, identifiers, households, domains, admin, audit, api_tokens, privacy export, passwords), `providers/` (base HTTP client, registry, xposedornot, hibp_passwords, ddg_discovery, username_platforms, domain_intel, mock), `scanning/` (orchestrator, jobs, worker, normalize, correlation, risk), `remediation/` (engine, service, worker, verify, verify_sources, registry_seed, letters), `monitoring/` (scheduler, diff, events, notify, service), `dashboard/` (service = Action Center, graph), `db/` (pool, migrate), `vault/` (crypto, store)
- **Routes:** ~45 `/api/...` routes (every one also answering under the canonical `/api/v1/...` spelling — Phase 88) — anonymous (`/api/scan`, `/api/agent/*`, `/api/brokers`, `/api/providers/health`, `/api/health`), account (auth, consents, identifiers, domains, household, privacy export), scanning (`/api/scans`), remediation (`/api/remediation/run|cases|queue`), monitoring (`/api/monitoring/settings|timeline`, `/api/notifications`), dashboard (`/api/action-center`, `/api/graph`), tokens (`/api/tokens`), admin (`/api/admin/overview|audit`), plus `/trust`, `/reset`, `/.well-known/security.txt`, PWA assets (`/sw.js`, `/static/manifest.webmanifest`, icons)
- **Services:** in-process workers — scan worker (SKIP LOCKED, hand-started jobs claimed before scheduled ones, backoff, dead after 3 attempts), remediation worker (5 concurrent, 40s probe budget), monitoring scheduler (hourly tick, period-bucketed idempotency, paused users skipped), retention worker (daily)
- **Providers:** XposedOrNot (email breaches), HIBP Pwned Passwords (k-anonymity), DuckDuckGo discovery, username presence (13 platforms), domain intel (Cloudflare DoH + crt.sh); MockProvider behind `LEAKGUARD_PROVIDERS=mock`, always flagged
- **Database models:** users, sessions, consents, password_reset_tokens, identifiers, domains, scan_jobs, findings, brokers, remediation_cases, remediation_attempts, verification_checks, user_settings, notifications, households, household_members, audit_log, api_tokens
- **Migrations:** `db/migrations/0001_vault.sql` … `0008_api_tokens.sql`, applied by an idempotent runner at startup
- **Frontend pages:** one SPA — Quick Scan, Action Center (signed-in home), Privacy Center (identifiers, consents, household, monitoring, timeline, notifications, API tokens, exposure map, export, deletion), human queue, `/trust`, `/reset`
- **Browser automation:** Playwright probe locally only (`browser_probe.py`, subprocess-isolated); the server never runs a browser — walled brokers classify from HTTP evidence and the attempt trail records `browser: skipped on_server`
- **External dependencies:** Render, Neon, Brevo (email), XposedOrNot, Have I Been Pwned, DuckDuckGo, Cloudflare DoH, crt.sh, UptimeRobot
- **Deployment configuration:** `render.yaml` (build `pip install -r requirements.txt`, start `python3 app.py`); env vars on Render: `DATABASE_URL`, `VAULT_MASTER_KEY`, `VAULT_LOOKUP_KEY`, `BREVO_API_KEY`, `NOTIFY_FROM_EMAIL`, `NOTIFY_FROM_NAME`, `ADMIN_EMAILS`, `PYTHON_VERSION`. Deploys are manual (Render auto-deploy does not fire for this service)

## D. Security Inventory

- **Authentication:** Argon2id password hashes (`accounts/passwords.py`); password reset via single-use SHA-256-hashed tokens (1h expiry, enumeration-safe identical responses, all sessions revoked on reset); TOTP MFA (RFC 6238, verify-before-activate, replay protection). **No WebAuthn/passkeys** (Phase 4 PARTIAL)
- **Authorization:** every object owner-scoped; foreign ids → 404; API tokens are read-only by construction (mutation routes resolve the session only); admin gated by `ADMIN_EMAILS`, invisible (404) to everyone else
- **Session handling:** 30-day sliding sessions; cookie `lg_session` HttpOnly + Secure + SameSite=Lax; only SHA-256 digests stored
- **Encryption:** identifiers and account emails envelope-encrypted (per-record DEK, AES-256-GCM, env-only master key); lookups via HMAC-SHA256 with a *separate* env-only key; display always masked (e.g. `r•••@domain`)
- **Secrets:** Render env vars in production; mode-600 files locally; nothing secret in the repo; the GitHub PAT never appears in code or logs
- **CSRF:** `core/security.require_csrf` on account mutations (X-Requested-With or same-host Origin/Referer)
- **SSRF:** form-submit actions host-allowlisted against the broker registry; provider/broker fetches constrained to registry-defined endpoints; **DNS-resolution guard `core/ssrf.py`** on the data-driven fetch paths (submit, probe, direct verify) — hosts must resolve entirely to public addresses (Phase 70 DONE; resolve-then-fetch rebinding window documented in the module)
- **Rate limiting:** `core/ratelimit.py` per route class (anon scan 30/h/IP, register 10/h/IP, forgot-password 5/h/IP, user scans 10/h, removal runs 6/h) + login limiter (10/15min per IP+email); keys use the **last** X-Forwarded-For hop (a first-hop spoofing bypass was caught in production and fixed, `56fb831`); 429s carry Retry-After; rejected attempts don't extend lockouts
- **Enumeration:** forgot-password answers are byte-identical for known/unknown emails; login uses a dummy verify and one identical error; existence of identifiers/exposures is never revealed cross-account
- **Audit logs:** `audit_log` (migration `0007`) — auth, consent, identifier, scan, remediation, admin events; detail passes a PII filter; best-effort (an audit failure can never break the user action); a test serializes the whole table and asserts no email/identifier/token appears
- **Security headers:** CSP `default-src 'self'`, X-Frame-Options DENY, Referrer-Policy no-referrer, X-Request-Id on every response; **HSTS `max-age=31536000; includeSubDomains`** on every response (Phase 69 DONE; no `preload` — an owner decision not yet made)
- **Dependencies:** 3 runtime deps with version ranges in `requirements.txt` + **`requirements.lock`** exact-version snapshot (Phase 107 DONE); CI (`.github/workflows/tests.yml`, Phase 106 DONE) runs the full suite on push/PR and weekly; vulnerability scanning is not automated
- **Backups:** Neon platform point-in-time restore (owner-run from the Neon console; free-plan history limited); **restoration tested 2026-10-07** — PITR branch drill verified 19 public tables, 40 brokers, 8 migrations, 15 users (Phases 78, 170 DONE)

## E. Data Inventory

| Data class | What is stored | Where | Encryption | Lookup | Retention | Deletion | Export | Logging exposure | Provider sharing |
|---|---|---|---|---|---|---|---|---|---|
| Account email | HMAC + ciphertext + masked form — never plaintext | Neon `users` | AES-256-GCM envelope | HMAC-SHA256 (separate key) | Account lifetime + 30d | Soft delete → hard purge at 30d | Privacy export (owner-only, the only plaintext exit) | Never logged; admin sees counts only | Brevo receives it only as the recipient of the account's own emails |
| Identifiers (email/phone/name/username/address/domain) | Ciphertext + HMAC + masked form | Neon `identifiers` | AES-256-GCM envelope, per-record DEK | HMAC-SHA256 | Until user removes or account purge | Per-item delete; cascade on account purge | Privacy export | Masked forms only in API output | Sent only to the provider that checks that kind (e.g. breach lookup by email) |
| Passwords | Argon2id PHC hash only | Neon `users` | One-way hash | n/a | Account lifetime | With account purge | Never exported | Never logged | Never shared; password *checks* send only a 5-char SHA-1 prefix (k-anonymity) |
| Sessions / API tokens / reset tokens | SHA-256 digests (+ token display prefix) | Neon `sessions`, `api_tokens`, `password_reset_tokens` | One-way hash | Digest match | Sessions 30d sliding; expired/revoked rows purged after 7d | Revocation immediate; purge via retention worker | n/a | Never logged | Never shared |
| TOTP secrets | Ciphertext | Neon `users` | AES-256-GCM envelope | n/a | Until disabled/account purge | With account purge | Never exported | Never logged | Never shared |
| Findings | Provider, source name/URL, exposed field names, confidence, reliability, evidence hash — never the raw identifier value | Neon `findings` | Evidence is a SHA-256 over an HMAC-keyed payload | By job/user | Until account purge | Cascade on account purge | Privacy export + scan detail API | No identifier values in logs | Derived from provider responses |
| Remediation cases/attempts/checks | Broker slug, status, reason, method, outcome, evidence refs, generated letters | Neon (migration `0005` tables) | Letters contain the user's own details by necessity — owner-scoped access only | By case/user | Until account purge | Cascade on account purge | Privacy export | Reasons/statuses only | Letters are sent by the user from their own mailbox; form submits go to the broker's own endpoint |
| Notifications | Kind, status, minimal payload (reset URL only in the password_reset payload + the email itself; redacted from the API) | Neon `notifications` | n/a | By user | 90 days | Retention worker | In-app list | Status words only | Brevo transports the email body |
| Audit log | Actor id, action, target kind/id, PII-filtered detail (counts/enums only) | Neon `audit_log` | n/a | By time/actor | Survives account deletion by design (it contains no PII) | Not user-deletable | Admin view (owner) | It *is* the log — PII-free by construction + filter | Never shared |

## F. Feature Inventory

| Feature | Implemented? | Production verified? | Tested? | Secure? | Documented? | Evidence |
|---|---|---|---|---|---|---|
| Anonymous Quick Scan (breaches + password k-anonymity + score) | Yes | Yes — baselines identical to pre-upgrade (214 breaches / score 100 / pwned 52,372,427) | Yes | Yes — nothing stored | README, /trust | `app.py`, `providers/`; S15 acceptance |
| Accounts (register/login/TOTP/reset/delete) | Yes | Yes | Yes | Yes | README | `accounts/`; Stage S3/S8 E2Es |
| Encrypted identifier vault + consents | Yes | Yes | Yes | Yes | /trust, README Privacy | `vault/`, migration `0001`/`0002` |
| Account scanning (all identifier kinds) | Yes | Yes | Yes | Yes | README | `scanning/`; Stage S5/S6 E2Es |
| One-command remediation + human queue + letters | Yes | Yes — 40-case runs settle (2 submitted / 11 needs_human / 27 blocked in the acceptance run) | Yes | Yes — consent re-checked at execution | README | `remediation/`; Stage S7 E2Es |
| Removal verification + reappearance | Yes | Yes — Spokeo `gone` → `verified_removed` in production | Yes | Yes — `unknown` never guessed | CURRENT_STATE gaps, `verify_sources.json` notes | `remediation/verify.py`, `verify_sources.json` |
| Monitoring + change alerts (in-app + email) | Yes | Yes | Yes | Yes — consent-gated | README | `monitoring/`; Stage S8 E2E |
| Action Center (one next action) | Yes | Yes | Yes | Yes | Product copy | `dashboard/service.py`; Stage S9 E2E |
| Household grouping | Yes | Yes | Yes | Yes | Privacy Center copy | `accounts/households.py`; Stage S11 E2E |
| Owner admin (counts only) + audit log | Yes | Yes | Yes | Yes — no PII in output, test-asserted | README Operations | `accounts/admin.py`, `accounts/audit.py` |
| Read-only API tokens | Yes | Yes | Yes | Yes — structural read-only wall | README API | `accounts/api_tokens.py`; Stage S13 E2E |
| Trust center + security.txt | Yes | Yes | Yes | Yes | `/trust` itself | `static/index.html`, `/.well-known/security.txt` |
| Exposure map (graph) | Yes | Yes | Yes | Yes — masked labels only | Privacy Center copy | `dashboard/graph.py`; Stage S14 checks |
| Browser extension (sideload) | Yes | Packaged + statically verified; not store-published | Yes | Yes — token-only, single host permission | `extension/README.md` | `extension/`, `tools/build_extension_zip.py` |
| PWA (installable) | Yes | Yes — manifest/SW/icons serve 200 with correct types | Yes | Yes — SW caches shell only, never `/api/` | README | `static/manifest.webmanifest`, `static/sw.js` |
| AI features | **No — CUT by owner rule** | n/a | n/a | n/a | MIGRATION_PLAN owner rules | Phases 51–56, 121, 163–165 CUT |
| Organizations / multi-tenancy | No — households instead | n/a | n/a | n/a | PHASE_STATUS Phase 57 | Deliberate scope decision, Stage S11 |

## G. Phase Status

Full per-phase table: **`PHASE_STATUS.md`** (all 181 phases with tier, status,
evidence, and gap). Summary counts:

| Status | Count |
|---|---|
| DONE | 110 |
| PARTIAL | 45 |
| NOT_DONE | 12 |
| CUT (owner rule: AI phases + business model) | 11 |
| NA (surface does not exist: file uploads, webhooks, containers) | 3 |
| **Total** | **181** |

## H. Critical Risks

**No P0 production blocker is open.** Nothing in the open list exposes user
data, weakens authentication, or breaks deletion/retention today. The
P0-tier open items are depth and verification gaps, listed first per the
spec:

1. **Backup/DR procedure is not yet written down** (Phase 79 PARTIAL) —
   restores themselves are **tested** (drill 2026-10-07, Phases 78/170
   DONE); what remains is the written RPO/RTO procedure.
2. **Rollback is practised but not documented or rehearsed for the
   database** (Phases 174, 173 PARTIAL) — app rollback = redeploy a prior
   commit; configuration/DB rollback has no written plan.
3. **WebAuthn/passkeys absent** (Phase 4 PARTIAL) — TOTP is the strongest
   available factor.
4. **No distinct security-events view or anomaly alerting** (Phase 62
   PARTIAL); **no automated dependency vulnerability scanning**
   (the Phase 107 lock file exists; scanning does not);
   security/privacy acceptance evidence is per-stage rather than one
   consolidated runbook (Phases 147/148 PARTIAL).

Platform risks (not code defects): most people-search brokers wall
datacenter IPs — in the production acceptance run 27 of 40 cases
classified `blocked` with reasons (the residential-IP local agent is the
practical route for those); Brevo free caps email at 300/day; Render free
sleeps when idle (~50s wake) and shares free hours across the owner's
services; search-index verification lags the live web, so a `gone` verdict
means "no longer indexed as of the check".

## I. Recommended Implementation Order

Only genuinely open items, P0 → P3 (full detail in `PHASE_STATUS.md` and in
`MIGRATION_PLAN.md` → "Final Remaining Implementation — order of work"):

- **P0:** written backup/DR procedure (79) →
  written rollback plan incl. database/config (174, 173) → security-
  events view over the existing audit log (62) → consolidated security
  + privacy acceptance runbooks (147, 148)
  → WebAuthn/passkeys (4) → re-run the
  Phase 180 final gate. *(Batch A closed 69, 70, 106, 107; Batch A.1
  closed 73, 78, 170.)*
- **P1:** stored finding lifecycle states (25) → per-cycle report
  files in-repo (149). *(Batch B closed 88, 49, 142.)*
- **P2:** source change detection (32) → false-positive feedback (156) +
  source disputes (157) → scan budget engine
  (158) → workflow-version capture on attempts (31) → staging
  environment (109) →
  fake-broker harness (111, 162) → dead-letter replay (119) → standalone
  policy engine (153) → data-quality stage (160) → metrics + engineering
  alerts (76, 77) → per-broker source-health dashboard (125) → incident
  response plan (80) → search-exposure view (40) → cost/quota tracking
  (66, 124) → accessibility pass (96) → performance/load evidence
  (115, 116) → browser-probe allowlists (137, 166) → legacy-surface
  cleanup decision (178). *(Batch B closed 159, 120.)*
- **P3:** organizations or a documented permanent no (57–59) → formal
  privacy policy + terms documents (82, 83) → report documents (85) →
  admin health depth (123) → support workflow
  (126) → bug-bounty page (128) → data-residency note/design (129) →
  localization preparation (98) → privacy-policy analyzer (102) →
  propagation analysis (104, 152) → regional policy rules (168) → legal
  architecture hardening (81).

## J. Definition of Current Reality

**LeakGuard today CAN:**

- Scan an email anonymously against real breach data, check a password
  without ever sending or storing it (k-anonymity), and score exposure
  0–100 — storing nothing for anonymous users.
- Keep an account's details in an encrypted vault (the account email
  itself is never stored in plaintext) and scan every saved kind: email,
  phone, username, name, address, and ownership-verified domains.
- Run one-command removal across 40 brokers: auto-submit the fillable
  forms, generate legally-cited letters for email-channel brokers, and
  queue everything else with the exact reason and next step — never
  bypassing a CAPTCHA, login wall, or bot check.
- Verify removals with recorded evidence (search-index or direct
  checks; every check stores its method and outcome), detect
  reappearance, and monitor on a 7/14/30-day cadence with deduped
  in-app + email alerts.
- Show the user one next right action (Action Center), an exposure map,
  a household grouping, a full data export, and complete account
  deletion (hard-purged after 30 days) — all free, all deterministic,
  with zero AI anywhere in the product.

**LeakGuard today CANNOT:**

- Remove breach dumps already copied to Telegram, dark-web markets, or
  torrents — nobody can; the site says so plainly. Brokers,
  people-search sites, and Google results *can* be removed.
- Guarantee a broker removed anything: submission is tracked, removal
  is claimed only on verification evidence, and ambiguous evidence
  answers `unknown` — never a guess.
- Reach most people-search brokers' own websites from the server —
  they wall datacenter IPs (27/40 cases in the acceptance run); those
  cases carry reasons and next steps, and the local agent on the
  user's own device/IP is the working route.
- Claim exhaustive internet coverage: discovery is DuckDuckGo-index
  based and username presence covers 13 platforms; findings are
  labelled exact/probable/weak and weak correlation is never upgraded
  to fact.
- Serve organizations/multi-tenant workspaces, offer passkeys, produce
  generated report documents, or run a staging environment — see
  `PHASE_STATUS.md` for the full open list.
- Send more than 300 emails/day (Brevo free) or stay awake while idle
  (Render free sleeps; ~50s wake).
