# LeakGuard Current State Audit

*Structure: the Final Remaining Implementation spec §3 (sections A–J).
Per-phase evidence for everything claimed here lives in `PHASE_STATUS.md`.
The pre-upgrade Phase 0 audit (v2.5) is preserved in git history at
commit `76565e0`; the Sentinel-era state file this replaces is in history
at `e31e016`.*

***Owner-ordered audit issue — 2026-10-07 (night).** The owner directed
a standalone audit pass and an explicit gate: the three deliverables
(this file, `MIGRATION_PLAN.md`, `PHASE_STATUS.md`) are produced from
the production inspection and reconciliation below, and **no phase
implementation proceeds until the owner approves these audit results**.
`PHASE_STATUS.md` is re-issued in the owner's audit taxonomy
(DONE / PARTIAL / MISSING / INSECURE / UNVERIFIED / NOT APPLICABLE)
with per-phase evidence, source files, gap, dependencies, required
next action, and required tests. No functionality was rewritten or
deleted during the audit; the deterministic zero-AI Agent Mode, broker
playbooks, browser probing, and Quick Scan are preserved as-is, and no
AI dependency was introduced.*

***v2.1 reconciliation refresh — 2026-10-07 (evening).** Spec v2.1 added
a non-negotiable live/repository reconciliation to Phase 0. It was run
the same day: the exact production commit was read from the Render
dashboard, the live public surface and a throwaway-account end-to-end
journey were re-verified against production, the full suite was re-run
at repository HEAD, and every discrepancy found is recorded in §B and
resolved there. Sections A, B, F, G, H, I, J below reflect the
reconciled state; nothing in this file rests on UI copy alone.*

## A. Audit Metadata

- **Audit date:** 2026-10-07 (v2.1 reconciliation refresh, evening)
- **Auditor:** Muse (Phase 0 auditor, Final Remaining Implementation program)
- **Repository commit:** `830a644` (main, github.com/xorudra/leakguard) — docs-only on top of the production code commit
- **Production deployment:** https://leakguard-hh8e.onrender.com — Render free web service `srv-db2rm6142hec73flnl90` (Oregon), manual deploy
- **Production commit/version:** `56c14e53bda472d6eb1d8a6c9391d626442ac655` — read from the Render dashboard on 2026-10-07 (deploy `dep-db34ec9srm7s73e32480`, "Deploy succeeded | Live", deployed 18:50 IST; full SHA verified via the dashboard's GitHub commit link). The only repository commits beyond it (`830a644`) change documentation files only (`git diff 56c14e5..830a644` touches `CURRENT_STATE.md` + `PHASE_STATUS.md`, no executable code), so production code and repository code are identical. Staging (`leakguard-staging`, `srv-db34g7vlk1mc739dgp9g`) runs the same commit `56c14e5` (deploy `dep-db34n9d9fdbs739vetc0`, live 19:09 IST) on its own Neon branch
- **Runtime:** Python 3.12, stdlib `http.server`; only three pip dependencies (`psycopg[binary]`, `cryptography`, `argon2-cffi`)
- **Deployment platform:** Render (free) + UptimeRobot free monitor (5-min, HEAD-safe)
- **Database:** Neon free PostgreSQL (project "leakguard", AWS ap-southeast-1 Singapore), pooled connection via `DATABASE_URL`
- **Queue/worker:** PostgreSQL-backed queues drained by in-process threads (scan worker, remediation worker, monitoring scheduler, retention worker) — no separate worker service
- **Frontend:** Vanilla JS single-page app + PWA (`static/`), Manifest V3 browser extension (`extension/`, sideload)
- **Backend:** Modular monolith — `core/`, `accounts/`, `providers/`, `scanning/`, `remediation/`, `monitoring/`, `dashboard/`, `db/`, `vault/`
- **AI provider configured:** NO — none exists in the product (owner rule: AI only if free *and* unlimited; no such tier exists)
- **Audit confidence:** High — every status in `PHASE_STATUS.md` was checked against the code (grep/read), the full suite was re-run at repository HEAD (410 passed, 19 skipped, 2026-10-07), production behavior was end-to-end verified by the parent agent on 2026-10-07 for every shipped stage, and the v2.1 reconciliation pinned the production commit from the deployment platform itself (spec §0 rule 6 satisfied with platform evidence, not inference)

- **Addendum 2026-10-08 (P2-B / P2-C closeouts):** production has advanced beyond the §A pin above, which remains the 2026-10-07 reconciliation record and is not rewritten. Production ran `1387fc4` (P2-B performance & scalability, deploy `dep-db3a1b0m7kps73dik75g`) and now runs `f022399` (P2-C observability & engineering alerts, deploy `dep-db3ajprtqb8s7384mokg`, live-verified 2026-10-08 ~01:58 IST: health `db: "ok"` with migration 0013 applied, baselines 214 breaches / score 100 and password count 52,372,427, anonymous admin endpoints 404, throwaway-account E2E with exactly one scan_summary notification and account deletion). Staging runs the same commit `f022399` (deploy `dep-db3agp3tqb8s7384chp0`).
- **Addendum 2026-10-08 (P2-D closeout):** production advanced to `3b89d0e` (P2-D cost control & provider cost monitoring, deploy `dep-db3b2o59fdbs73aigjlg`, live-verified 2026-10-08 ~02:29 IST: health `db: "ok"` with migration 0014 applied, baselines 214/100 + 52,372,427, admin gating, throwaway-account E2E with exactly one scan_summary and account deletion). Staging runs the same commit `3b89d0e` (deploy `dep-db3b03flot8c73f6vp7g`).
- **Addendum 2026-10-08 (P2-E closeout):** production advanced to `3a56fb0` (P2-E scan budget engine & data-quality pipeline, deploy `dep-db3bimajnfac739b18pg`, live-verified 2026-10-08 ~03:03 IST: health `db: "ok"` with migration 0015 applied, baselines 214/100 + 52,372,427, admin gating, fresh-user E2E unrefused by the new budget with exactly one scan_summary and account deletion). Staging runs the same commit `3a56fb0` (deploy `dep-db3bg77lk1mc73a2ojeg`); its deploy log records the data-quality stage's first live run — 1,498 stored findings scanned, 0 duplicates, 0 malformed.
- **Addendum 2026-10-08 (P2-F closeout):** production advanced to `0d74ccb` (P2-F broker depth, deploy `dep-db3ca12j9qps73f19j20`, live-verified 2026-10-08 ~03:53 IST: health `db: "ok"` with migration 0016 applied, baselines 214/100 + 52,372,427, admin + case-endpoint gating, throwaway-account E2E with exactly one scan_summary and account deletion). Staging runs the same commit `0d74ccb` (deploy `dep-db3c72ij9qps73f0v690`).
- **Addendum 2026-10-08 (P2-G closeout):** production advanced to `5155044` (P2-G removal depth, deploy `dep-db3ct5btqb8s73dfkj00`, live-verified 2026-10-08 ~04:35 IST: health `db: "ok"`, baselines 214/100 + 52,372,427, admin + replay-endpoint gating, throwaway-account E2E with exactly one scan_summary and account deletion). Staging runs the same commit `5155044` (deploy `dep-db3copom7kps73e4nd2g`). No migration in this batch.
- **Addendum 2026-10-08 (P2-H closeout):** production advanced to `192ce5e` (P2-H surfaces, deploy `dep-db3e3vflk1mc73br9osg`, live-verified 2026-10-08 ~06:01 IST: health `db: "ok"` with `Cache-Control: no-store` confirmed on the API response, baselines 214/100 + 52,372,427, admin + search-exposure gating, throwaway-account E2E with exactly one scan_summary and account deletion, and the live accessibility check passing all 6 pages against production directly). Staging runs the same commit `192ce5e` (deploy `dep-db3dfnd9fdbs73dajulg`). No migration in this batch.
- **Addendum 2026-10-08 (P2-I closeout — P2 PROGRAM COMPLETE):** production advanced to `41cfcf7` (P2-I closeout batch, deploy `dep-db3epm6i0phs739sh8a0`, live-verified 2026-10-08 ~06:42 IST: health `db: "ok"`, baselines 214/100 + 52,372,427, admin gating, throwaway-account E2E with exactly one scan_summary and account deletion). Staging runs the same commit `41cfcf7` (deploy `dep-db3emkegekts73efi9eg`). No migration in this batch. **All 25 P2 phases are DONE; final scoreboard 158 DONE / 7 PARTIAL / 1 UNVERIFIED / 1 MISSING / 14 NOT APPLICABLE — every not-at-DONE phase is P3 scope.**
- **Addendum 2026-10-08 (P3 closeout — implemented in the repository, PRE-DEPLOY):** the owner approved a bounded P3 closeout roadmap (production freeze otherwise maintained; production still runs `41cfcf7` — deployment follows the staging-first pattern and a further addendum will record it). Phase 85 DONE in code: `GET /api/report` renders a masked-only, on-demand, never-persisted exposure & removal report (the Privacy Center links it). Phase 123 closed by verification only — the admin metrics block shipped in P2-C and the row's gap text was stale; no new code and no duplicate health surface. Phase 176 DONE on the limitations-register review (`docs/reviews/2026-10-08-limitations-register-review.md`: 28 claims checked — 25 ACCURATE, 2 STALE-superseded including §J's report-documents line overtaken by Phase 85, 1 WRONG copy item fixed on /trust). Phases 57/58 are NOT APPLICABLE by owner decision (LeakGuard remains individual/household-focused); 59/81/98/168 are unchanged, each with its owner-recorded build trigger. No migration in this batch. **Scoreboard: 161 DONE / 3 PARTIAL / 1 MISSING / 0 UNVERIFIED / 16 NOT APPLICABLE.**
- **Addendum 2026-10-08 (P3 closeout — DEPLOYED + LIVE-VERIFIED):** commit `30c5741` deployed staging-first (staging dep-db3jjg60tbcc73fqeg80; production dep-db3jkll9fdbs73e3h2m0) — production and staging now both run `30c5741`. Staging smoke: anonymous `GET /api/report` -> 401 `unauthenticated`; a throwaway staging account's signed-in report returned 200 `text/html` with `Cache-Control: no-store`, the account's masked email present and its plaintext absent; `/api/v1/report` gated identically; /trust serves the corrected "JSON or CSV" copy. Production live verification: health ok/db ok; anonymous `/api/report` -> 401 with `no-store`; `/api/admin/metrics` signed-out -> 404; baselines exact (test@example.com -> 214 breaches, exposure score 100; password_pwned_count 52,372,427); /trust copy fix live. Suites at the deployed commit: pytest 611 passed / 19 skipped; CI-parity discovery Ran 599 OK; GitHub CI success. No migration. **The production freeze resumes, re-anchored at `30c5741`.** Remaining P3 scope is trigger-gated only (59, 81, 168 PARTIAL; 98 MISSING).

## B. Production vs Repository

| Area | Repository | Production | Match? | Evidence | Action |
|---|---|---|---|---|---|
| Authentication | Argon2id, sessions, TOTP, reset, passkeys (`accounts/`) | Live; register/login/TOTP/reset E2Es passed; passkey sign-in options live (challenge, rpId `leakguard-hh8e.onrender.com`, UV required, empty allowCredentials); v2.1 reconciliation E2E (register → login → me → delete) passed 2026-10-07 | YES | Stage S3/S8 production checks + Batch D1 live check + v2.1 reconciliation sweep (parent-verified 2026-10-07) | None |
| Database | Migrations `0001`–`0012`, Neon Postgres (`db/`) | Live; health reports `db: "ok"` on production and staging; app connects as least-privilege role `leakguard_app`, migrations via `MIGRATION_DATABASE_URL` | YES | Production health + every account-stage E2E + Batch A.1 deploy logs | None |
| Monitoring | Scheduler + diff + timeline (`monitoring/`) | Live; cadence settings + timeline verified | YES | Stage S8 production check | None |
| Notifications | Ledger + Brevo lane (`monitoring/notify.py`) | Live; real reset email delivered via Brevo and completed end-to-end | YES | Stage S8 email-lane proof (parent-verified) | None |
| Admin | Counts-only overview + audit (`accounts/admin.py`) | Live; non-admins get 404, admin sees counts only, no email strings in output | YES | Stage S11 production check (15/15) | None |
| Remediation | Engine + worker + verification (`remediation/`) | Live; 40-case runs settle; verification produces real `verified_removed` | YES | Stage S7/S7.1/S7.2 + verification drill (parent-verified) | None |
| API | `/api/v1/*` canonical + unversioned v1 alias; read-only Bearer tokens on six read endpoints (`accounts/api_tokens.py`) | Live; v1/unversioned parity verified for health + providers; token read/mutation-wall/revoke drill passed | YES | Stage S13 production check (10/10) + Batch B and v2.1 reconciliation live parity checks | None |
| Security | Rate limits, retention, headers, audit (`core/`, `accounts/audit.py`) | Live; 429 + Retry-After observed; X-Forwarded-For spoof bypass caught live and fixed (`56fb831`); HSTS `max-age=31536000; includeSubDomains`, CSP, X-Frame-Options DENY, X-Request-Id on responses (v2.1 sweep) | YES | Stage S12/S12.1 production checks + v2.1 reconciliation header sweep | None |
| Pages | `/privacy`, `/terms`, `/support`, `/trust`, `/reset`, `/.well-known/security.txt` (`static/`) | Live; all return 200 (v2.1 sweep) | YES | Batch D2 live check + v2.1 reconciliation sweep | None |
| Environments | Production + staging services, staging on its own Neon branch with its own vault keys, no email lane on staging | Live; both services on commit `56c14e5` (dashboard-verified); staging health `db: "ok"` | YES | Phase 109 build + v2.1 reconciliation (dashboard + health, 2026-10-07) | None |

**Discrepancies found by the v2.1 reconciliation (all resolved):**

1. **Audit-document drift (documentation only, no code impact).** This
   file and `PHASE_STATUS.md` still cited the superseded audit commit
   `8271c17`, migrations `0001`–`0010`, a two-item NOT_DONE count, and
   pre-staging risk text, and Phases 173/180 still listed CI (106),
   restore tests (170), and staging (109) as open after all three had
   closed. Corrected in this refresh; Phases 173 and 180 re-scored on
   the evidence in `PHASE_STATUS.md`.
2. **Staging vault keys were not git-ignored.** `.staging-vault-master-key`
   / `.staging-vault-lookup-key` sat untracked but un-ignored in the
   working tree — one `git add -A` away from a public commit. They were
   never committed (verified: not in git history); `.gitignore` now
   covers `.staging-vault-*`.
3. **No functional live↔repository discrepancy was found.** Every live
   behavior probed in the reconciliation (health, v1 parity, provider
   health, baselines, passkey options, export re-auth, account E2E,
   headers, page availability, 40-broker registry) traces to source at
   production commit `56c14e5` and to the test suite at HEAD (410
   passed, 19 skipped). No feature exists in production that is absent
   from the repository, and no repository feature is missing from
   production.

## C. Architecture Inventory

- **Entry points:** `app.py` (HTTP server, all routes), `agent.py` (deterministic broker agent — the remediation core), `local_agent.py` (residential-IP runner for the user's own device), `browser_probe.py` (local Playwright probe), `proxy_relay.py` (dev-only egress relay for this VM)
- **Modules:** `core/` (errors, context/request-ids, security headers + CSRF, logging, rate limiter, retention, feature flags / emergency switches), `accounts/` (auth, sessions, totp, webauthn + cbor, consents, identifiers, households, domains, admin, audit, api_tokens, privacy export, passwords), `providers/` (base HTTP client, registry, xposedornot, hibp_passwords, ddg_discovery, username_platforms, domain_intel, mock), `scanning/` (orchestrator, jobs, worker, normalize, correlation, risk, feedback, disputes), `remediation/` (engine, service, worker, verify, verify_sources, registry_seed, letters, source_checks), `monitoring/` (scheduler, diff, events, notify, service), `dashboard/` (service = Action Center, graph, policy_analyzer), `db/` (pool, migrate), `vault/` (crypto, store)
- **Routes:** ~45 `/api/...` routes (every one also answering under the canonical `/api/v1/...` spelling — Phase 88) — anonymous (`/api/scan`, `/api/agent/*`, `/api/brokers`, `/api/providers/health`, `/api/health`), account (auth, consents, identifiers, domains, household, privacy export), scanning (`/api/scans`), remediation (`/api/remediation/run|cases|queue`), monitoring (`/api/monitoring/settings|timeline`, `/api/notifications`), dashboard (`/api/action-center`, `/api/graph`), tools (`/api/tools/policy-analyzer`), tokens (`/api/tokens`), admin (`/api/admin/overview|audit`), plus `/trust`, `/privacy`, `/terms`, `/support`, `/reset`, `/.well-known/security.txt`, PWA assets (`/sw.js`, `/static/manifest.webmanifest`, icons)
- **Services:** in-process workers — scan worker (SKIP LOCKED, hand-started jobs claimed before scheduled ones, backoff, dead after 3 attempts), remediation worker (5 concurrent, 40s probe budget), monitoring scheduler (hourly tick, period-bucketed idempotency, paused users skipped), retention worker (daily; its loop also hosts the broker source sweep — SSRF-guarded re-fetch + hash compare of every broker opt-out page, `remediation/source_checks.py`)
- **Providers:** XposedOrNot (email breaches), HIBP Pwned Passwords (k-anonymity), DuckDuckGo discovery, username presence (13 platforms), domain intel (Cloudflare DoH + crt.sh); MockProvider behind `LEAKGUARD_PROVIDERS=mock`, always flagged
- **Database models:** users, sessions, consents, password_reset_tokens, identifiers, domains, scan_jobs, findings, finding_feedback, broker_source_checks, brokers, remediation_cases, remediation_attempts, verification_checks, user_settings, notifications, households, household_members, audit_log, api_tokens, passkey_credentials, webauthn_challenges
- **Migrations:** `db/migrations/0001_vault.sql` … `0011_passkeys.sql`, `0012_finding_lifecycle.sql`, applied by an idempotent runner at startup
- **Frontend pages:** one SPA — Quick Scan, Action Center (signed-in home), Privacy Center (identifiers, consents, household, monitoring, timeline, notifications, API tokens, exposure map, export, deletion), human queue, `/trust`, `/reset`
- **Browser automation:** Playwright probe locally only (`browser_probe.py`, subprocess-isolated); the server never runs a browser — walled brokers classify from HTTP evidence and the attempt trail records `browser: skipped on_server`
- **External dependencies:** Render, Neon, Brevo (email), XposedOrNot, Have I Been Pwned, DuckDuckGo, Cloudflare DoH, crt.sh, UptimeRobot
- **Deployment configuration:** `render.yaml` (build `pip install -r requirements.txt`, start `python3 app.py`); env vars on Render: `DATABASE_URL`, `MIGRATION_DATABASE_URL`, `VAULT_MASTER_KEY`, `VAULT_LOOKUP_KEY`, `BREVO_API_KEY`, `NOTIFY_FROM_EMAIL`, `NOTIFY_FROM_NAME`, `ADMIN_EMAILS`, `PYTHON_VERSION`. Deploys are manual (Render auto-deploy does not fire for this service). A second service, `leakguard-staging`, mirrors the configuration against the Neon `staging` branch with its own vault keys and deliberately no Brevo/email variables

## D. Security Inventory

- **Authentication:** Argon2id password hashes (`accounts/passwords.py`); password reset via single-use SHA-256-hashed tokens (1h expiry, enumeration-safe identical responses, all sessions revoked on reset); TOTP MFA (RFC 6238, verify-before-activate, replay protection); WebAuthn passkeys (optional, Batch D1: attestation `none` only, ES256/RS256, UV-required discoverable sign-in, single-use DB challenges, counter clone detection; only public keys stored)
- **Authorization:** every object owner-scoped; foreign ids → 404; API tokens are read-only by construction (mutation routes resolve the session only); admin gated by `ADMIN_EMAILS`, invisible (404) to everyone else
- **Session handling:** 30-day sliding sessions; cookie `lg_session` HttpOnly + Secure + SameSite=Lax; only SHA-256 digests stored
- **Encryption:** identifiers and account emails envelope-encrypted (per-record DEK, AES-256-GCM, env-only master key); lookups via HMAC-SHA256 with a *separate* env-only key; display always masked (e.g. `r•••@domain`)
- **Secrets:** Render env vars in production; mode-600 files locally; nothing secret in the repo; the GitHub PAT never appears in code or logs
- **CSRF:** `core/security.require_csrf` on account mutations (X-Requested-With or same-host Origin/Referer)
- **SSRF:** form-submit actions host-allowlisted against the broker registry; provider/broker fetches constrained to registry-defined endpoints; **DNS-resolution guard + connection pinning `core/ssrf.py`** on every data-driven fetch path (agent submit + probe, remediation direct verify, broker source sweep, policy-analyzer fetch) — hosts must resolve entirely to public addresses, and the pinned connection resolves once inside `connect()` and connects to a validated IP (Host header + TLS SNI/cert checks keep the hostname), so the former resolve-then-fetch DNS-rebinding window is closed (Phase 70 DONE; regression suite `tests/test_ssrf_pinning.py`)
- **Rate limiting:** `core/ratelimit.py` per route class (anon scan 30/h/IP, register 10/h/IP, forgot-password 5/h/IP, user scans 10/h, removal runs 6/h) + login limiter (10/15min per IP+email); keys use the **last** X-Forwarded-For hop (a first-hop spoofing bypass was caught in production and fixed, `56fb831`); 429s carry Retry-After; rejected attempts don't extend lockouts
- **Enumeration:** forgot-password answers are byte-identical for known/unknown emails; login uses a dummy verify and one identical error; existence of identifiers/exposures is never revealed cross-account
- **Audit logs:** `audit_log` (migration `0007`) — auth, consent, identifier, scan, remediation, admin events; detail passes a PII filter; best-effort (an audit failure can never break the user action); a test serializes the whole table and asserts no email/identifier/token appears
- **Security headers:** CSP `default-src 'self'`, X-Frame-Options DENY, Referrer-Policy no-referrer, X-Request-Id on every response; **HSTS `max-age=31536000; includeSubDomains`** on every response (Phase 69 DONE; no `preload` — an owner decision not yet made)
- **Dependencies:** 3 runtime deps with version ranges in `requirements.txt` + **`requirements.lock`** exact-version snapshot (Phase 107 DONE); CI (`.github/workflows/tests.yml`, Phase 106 DONE) runs the full suite on push/PR and weekly; vulnerability scanning runs on a recorded manual cadence (pip-audit on dependency change + monthly) — the first recorded scan (2026-10-07) found 7 advisories in `cryptography==45.0.7`, remediated the same night to 50.0.2 with a clean re-scan (Phase 107)
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
| Passkeys (WebAuthn sign-in + management) | Yes | Yes — live since Batch D1; sign-in options re-verified in the v2.1 sweep (challenge issued, rpId correct, UV required, empty allowCredentials, unauthenticated passkey list 401) | Yes — software-authenticator ceremonies incl. every failure mode | Yes — public keys only, attestation `none` only, UV required, one generic sign-in failure | README Operations, Privacy Center copy | `accounts/webauthn.py`, `accounts/cbor.py`, migration `0011`; `tests/test_webauthn.py` |
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
| Privacy policy analyzer (keyword checklist) | Yes | Yes — live since Batch D2; unauthenticated call rejected (403) in the D2 live check | Yes — fixture/control/SSRF tests | Yes — session-gated, SSRF-guarded fetch, nothing stored | Privacy Center copy + disclaimer | `dashboard/policy_analyzer.py`; `tests/test_batch_d2.py` |
| Privacy / Terms / Support pages + propagation list | Yes | Yes — live since Batch D2; all pages return 200 in the v2.1 sweep | Yes | Yes — masked labels only, matcher-only associations | `/privacy`, `/terms`, `/support`, `/trust` additions | `static/index.html`, `dashboard/graph.py` (`propagation`) |
| Exposure map (graph) | Yes | Yes | Yes | Yes — masked labels only | Privacy Center copy | `dashboard/graph.py`; Stage S14 checks |
| Browser extension (sideload) | Yes | Packaged + statically verified; not store-published | Yes | Yes — token-only, single host permission | `extension/README.md` | `extension/`, `tools/build_extension_zip.py` |
| PWA (installable) | Yes | Yes — manifest/SW/icons serve 200 with correct types | Yes | Yes — SW caches shell only, never `/api/` | README | `static/manifest.webmanifest`, `static/sw.js` |
| AI features | **No — CUT by owner rule** | n/a | n/a | n/a | MIGRATION_PLAN owner rules | Phases 51–56, 121, 163–165 CUT |
| Organizations / multi-tenancy | No — households instead | n/a | n/a | n/a | PHASE_STATUS Phase 57 | Deliberate scope decision, Stage S11 |

## G. Phase Status

Full per-phase table: **`PHASE_STATUS.md`** (all 181 phases with tier,
status, evidence, source files, gap, dependencies, required next
action, and required tests). Summary counts, in the owner's audit
taxonomy (owner-ordered audit issue, 2026-10-07):

| Status | Count |
|---|---|
| DONE | 138 |
| PARTIAL | 27 |
| MISSING | 1 |
| INSECURE | 0 |
| UNVERIFIED | 1 |
| NOT APPLICABLE | 14 |
| **Total** | **181** |

*(How this differs from the pre-audit vocabulary: the 11 owner-CUT
phases and 3 surface-NA phases are grouped as NOT APPLICABLE (14);
Phase 98 is MISSING; Phase 70 (SSRF) is INSECURE on its own documented
DNS-rebinding residual; and 10 phases whose record contains no test
and no live check — documentation, review-record, and rehearsal gaps,
listed in `PHASE_STATUS.md` — are UNVERIFIED rather than DONE. The
v2.1 reconciliation earlier the same day moved Phases 173 and 180
PARTIAL → DONE on the gate evidence: dashboard-pinned production
commit, full-suite pass at HEAD, and a fresh live verification pass.)*

## H. Critical Risks

**No P0 production blocker is open.** Nothing in the open list exposes user
data, weakens authentication, or breaks deletion/retention today. The
audit's one INSECURE finding (Phase 70, item 4 below) was a narrow,
documented residual in a defense-in-depth control; it was closed the
same night (2026-10-07) and no INSECURE item remains open. The remaining
P0-tier open items are depth and verification gaps, listed first per the
spec:

1. **Disaster recovery rests on one platform mechanism** (Phase 79 DONE —
   `docs/DISASTER_RECOVERY.md`; `docs/ROLLBACK.md` exists but Phase 174
   was UNVERIFIED at audit time; the application rollback rehearsal
   has since been performed on staging, 2026-10-07 — Phase 174 DONE) —
   restores are **tested** (drill 2026-10-07, Phases 78/170 DONE) and
   the procedure is written, but the only backup is Neon free-plan PITR:
   its console-visible history window bounds the RPO, and there is no
   second copy.
2. **One production service on a free tier.** Production readiness and
   the final gate are closed (Phases 173, 180 DONE — staging exists,
   Phase 109, and the v2.1 reconciliation verified the gate criteria
   live), but production remains a single free Render instance that
   sleeps when idle and shares the account's free instance hours with
   staging; there is no redundancy if Render or Neon has an outage.
3. **No anomaly alerting; dependency scanning is manual-cadence** —
   the security-events *view* exists (Phase 62 DONE) and acceptance
   evidence is consolidated (`docs/ACCEPTANCE.md`, Phases 147/148
   DONE), but nothing watches the view. Dependency vulnerability
   scanning is no longer unscanned (Phase 107 DONE — first pip-audit
   run 2026-10-07 found and fixed 7 advisories in `cryptography`), but
   it runs on a recorded manual cadence, not in CI.
4. **SSRF DNS-rebinding residual — CLOSED 2026-10-07 (Phase 70).**
   The audit's one INSECURE finding (resolve-then-fetch let a swapped
   DNS answer reach a non-public address) was fixed the same night
   with connection pinning in `core/ssrf.py`: resolution, validation,
   and connection now happen once, inside `connect()`, and the socket
   connects to a validated IP while TLS keeps the hostname. Covered
   by `tests/test_ssrf_pinning.py` (rebinding, redirect-to-private,
   fail-closed mixes). No residual is carried for this item.

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

- **P0:** — none open. *(Batch A closed 69, 70,
  106, 107; Batch A.1 closed 73, 78, 170; Batch C closed 79, 174,
  62, 147, 148; Batch D1 closed 4; the v2.1 reconciliation closed
  173 and 180.)*
- **P1:** stored finding lifecycle states (25) → per-cycle report
  files in-repo (149). *(Batch B closed 88, 49, 142.)*
- **P2:** scan budget engine
  (158) → workflow-version capture on attempts (31) →
  fake-broker harness (111, 162) → dead-letter replay (119) → standalone
  policy engine (153) → data-quality stage (160) → metrics + engineering
  alerts (76, 77) → per-broker verification-success dashboard (125 —
  source reachability/change shipped in Batch C) → search-exposure
  view (40) → cost/quota tracking
  (66, 124) → accessibility pass (96) → performance/load evidence
  (115, 116) → browser-probe allowlists (137, 166) → legacy-surface
  cleanup decision (178). *(Batch B closed 159, 120; Batch C closed
  32, 156, 157, 80.)*
- **P3:** organizations or a documented permanent no (57–59) → report
  documents (85) → admin health depth (123) → localization preparation
  (98) → regional policy rules (168) → legal architecture hardening
  (81). *(Batch D1 closed 4; Batch D2 closed 82, 83, 102, 104, 126,
  128, 129, 152.)*

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
- Serve organizations/multi-tenant workspaces or produce generated
  report documents — see `PHASE_STATUS.md` for the full open list.
  (A staging environment *does* exist — `leakguard-staging` on its own
  Neon branch — but it serves rehearsals, not users.)
- Send more than 300 emails/day (Brevo free) or stay awake while idle
  (Render free sleeps; ~50s wake).
- Addendum (2026-10-08, RWV Wave 1 fix loop, post-deploy): the claims audit's 8 PARTIAL wording fixes shipped as commit eda0e35 (production deploy dep-db3lk0mgekts73f9la9g; staging dep-db3lj0nlk1mc73c1npv0), live-verified: corrected footer/stat/Agent-Mode/password-hint copy present, old overstatements absent, baselines intact (214 breaches / score 100 / password count 52,372,427; anon /api/report 401, admin metrics 404). Regression guards: tests/test_public_copy.py. Suites at eda0e35: pytest 619 passed / 19 skipped; CI-parity discovery Ran 607 OK (skipped=2); GitHub CI green. Production code anchor moves 30c5741 -> eda0e35; the feature freeze is unchanged (this release is validation-driven copy correction under the Real-World Validation program, not new scope).
- Addendum (2026-10-08, Real-World Validation program complete): all six waves executed against production commit eda0e35 (staging-first for the one fix). Full evidence: REAL_WORLD_VALIDATION.md (repo root). Headlines: claims audit 26/8/0 with all 8 wording fixes live; real-world account journey + 40-broker run completed with honest outcomes (2 submitted / 11 needs_human / 27 blocked, 0 falsely successful); black-box security assessment — no finding above Informational; performance measured to 10 concurrent with no errors and no scalability claim beyond it; reliability idempotency proven live. Open items recorded in the report: F1 (9 stale broker opt-out URLs — data refresh pass recommended, not yet done), L1-L6 limitations, and the explicit Not-validated list. Production anchor remains eda0e35; the feature freeze is unchanged.
- Addendum (2026-10-08, F1 broker-data refresh, owner-authorized): the 9 stale (404) broker opt-out addresses in brokers.json were replaced with verified current destinations (each traced from the broker's own site/privacy policy; AdvancedBackgroundChecks' first candidate was caught still-404ing on staging and corrected to the broker's own /opt-out form page before production). Commits 461ef91 + e6738ba; production deploy dep-db3q57ui0phs73b5uftg, staging dep-db3q23mi0phs73b5kg20. Full 40-broker runs on staging (x2) and production: http_404 outcomes 9 -> 0; totals 2/11/27 -> 3 submitted / 15 needs_human / 22 blocked (the new submission is AdvancedBackgroundChecks through its corrected form); other 31 brokers unchanged; baselines intact (214 / 100 / 52,372,427). Data-only change; production code anchor remains eda0e35 in behavior, data anchor now e6738ba; feature freeze unchanged. Detail: REAL_WORLD_VALIDATION.md F1 addendum.
