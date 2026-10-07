# LeakGuard — Phase Status (Phases 0–180)

*Audit: 2026-10-07 · Repo HEAD `8271c17` · Evidence basis: direct code inspection
(grep/read) + full test suite run by the auditor (302 tests, OK, 2 skipped) +
production end-to-end checks run by the parent agent on 2026-10-07 for every
shipped stage (cited as "production (parent-verified 2026-10-07)").*

*Tier derivation: spec §1 topic lists — P0 = production blockers / security /
data integrity; P1 = core platform; P2 = remediation / intelligence /
reliability; P3 = advanced / optional. CUT = removed by a standing owner
rule: (a) AI phases — owner's rule "AI only if free AND unlimited, otherwise
do not involve" (no such tier exists; the spec itself makes AI optional);
(b) Phase 105 — owner deferred all paid/monetization until he says otherwise.
NA = the surface the phase governs does not exist in this deployment.*

| Phase | Tier | Status | Evidence | Gap |
|---|---|---|---|---|
| 0 — Repository & production audit | P0 | DONE | CURRENT_STATE.md + MIGRATION_PLAN.md (S0, commit `76565e0`); this refresh | |
| 1 — Repository restructure | P0 | DONE | Packages `core/`, `accounts/`, `providers/`, `scanning/`, `remediation/`, `monitoring/`, `dashboard/`, `db/`, `vault/`; legacy `agent.py` wrapped, not rewritten | |
| 2 — PostgreSQL persistence | P1 | DONE | `db/migrate.py`, `db/migrations/0001`–`0008`; Neon Postgres; health `db:"ok"` in production (parent-verified) | |
| 3 — Secure identifier vault | P0 | DONE | `vault/crypto.py` (AES-256-GCM envelope, per-record DEK), `vault/store.py` (HMAC lookup, separate key, masking); `tests/test_vault.py` | |
| 4 — Authentication | P0 | DONE | `accounts/passwords.py` (Argon2id), `accounts/sessions.py`, reset flow, `accounts/totp.py` (TOTP MFA), `accounts/webauthn.py` + `accounts/cbor.py` (WebAuthn passkeys: DB challenges, attestation `none` only, ES256/RS256, UV-required discoverable sign-in, counter clone policy; migration `0011_passkeys.sql`; tests `tests/test_webauthn.py`) | |
| 5 — Authorization | P0 | DONE | Owner-scoped services; foreign ids → 404; IDOR tests in `tests/test_orgs_admin.py`, `tests/test_api_tokens.py`; production (parent-verified) | |
| 6 — Consent management | P0 | DONE | `accounts/consents.py` — append-only versioned consents (migration `0002`) for scanning/monitoring/automated_remediation/notifications; gates enforced in scanning, remediation, monitoring | |
| 7 — Anonymous Quick Scan | P1 | DONE | `POST /api/scan` (no account, nothing stored); production baselines unchanged (parent-verified) | |
| 8 — Provider abstraction | P1 | DONE | `providers/base.py` HttpClient (timeouts, ≤2 retries, circuit breaker); provider metadata incl. cost model + privacy note | |
| 9 — Provider registry | P1 | DONE | `providers/registry.py`; `GET /api/providers/health` | |
| 10 — Provider health | P1 | DONE | In-memory HealthTracker + circuit breaking in `providers/base.py`; degraded per-identifier outcomes reported, never hidden | |
| 11 — Scan orchestrator | P1 | DONE | `scanning/orchestrator.py`, `scanning/jobs.py` (idempotency keys, partial results per identifier) | |
| 12 — Background jobs | P1 | DONE | `scanning/worker.py`, `remediation/worker.py` (SKIP LOCKED claims, backoff, dead after 3 attempts), `monitoring/scheduler.py`, `core/retention.py` | |
| 13 — Email exposure | P1 | DONE | `providers/xposedornot.py`; production: test@example.com → 214 breaches (parent-verified) | |
| 14 — Password exposure | P1 | DONE | `providers/hibp_passwords.py` k-anonymity; `tests/test_providers.py` asserts only the 5-char prefix leaves the server | |
| 15 — Phone monitoring | P1 | DONE | `scanning/orchestrator.py` — normalized quoted public-web discovery query for phone identifiers; weak confidence, honestly labelled | |
| 16 — Username monitoring | P1 | DONE | `providers/username_platforms.py` — 13 platforms, probable/weak semantics, "not proof of identity" notes | |
| 17 — Name monitoring | P1 | DONE | `scanning/orchestrator.py` name discovery query with conservative weak confidence | |
| 18 — Address monitoring | P1 | DONE | `scanning/orchestrator.py` address discovery query; addresses vault-stored and masked | |
| 19 — Domain monitoring | P1 | DONE | `providers/domain_intel.py` (Cloudflare DoH + crt.sh); TXT-token ownership verification; migration `0004` | |
| 20 — Public web discovery | P1 | DONE | `providers/ddg_discovery.py` (DuckDuckGo); findings labelled weak; no exhaustive-coverage claims anywhere in UI copy | |
| 21 — Normalization | P1 | DONE | `scanning/normalize.py`; canonical findings schema in migration `0003` | |
| 22 — Identity correlation | P1 | DONE | `scanning/correlation.py` — clusters + shared-source notes; confidence 'probable' is never upgraded to fact | |
| 23 — Source reliability | P2 | DONE | `findings.reliability` (high/medium/low) independent of confidence (migration `0003`); rubric in `scanning/risk.py` | |
| 24 — Evidence engine | P1 | DONE | `findings.evidence_ref` = SHA-256 over HMAC-keyed payload (migration `0003`); `verification_checks` evidence rows (migration `0005`) | |
| 25 — Exposure engine | P1 | PARTIAL | Lifecycle derived by `monitoring/diff.py` (new/resolved/continuing) and the timeline | No stored canonical lifecycle state — `findings.status` itself stays 'open' |
| 26 — Exposure clustering | P2 | DONE | `scanning/correlation.py` clustering; findings deduplicated on (identifier, provider, source) | |
| 27 — Risk engine | P1 | DONE | `scanning/risk.py` v2 with plain-language explanations; 378-combination parity matrix vs the legacy scorer (`tests/test_scanning.py`) | |
| 28 — Dashboard | P1 | DONE | `dashboard/service.py`; Action Center home in `static/index.html` | |
| 29 — Action Center | P1 | DONE | `GET /api/action-center` server-computed next_action priority; `tests/test_action_center.py` covers every branch | |
| 30 — Broker registry | P2 | DONE | `brokers` table (migration `0005`) seeded from brokers.json by `remediation/registry_seed.py`; `GET /api/brokers` DB-backed with file fallback | |
| 31 — Broker workflow versioning | P2 | PARTIAL | `brokers.workflow_version` column (migration `0005`); seed preserves it — it moves only on deliberate re-mapping (`remediation/registry_seed.py` docstring) | Attempts don't record the workflow version used; no per-version field/consent/failure-mode tracking |
| 32 — Source change detection | P2 | DONE | `remediation/source_checks.py` (Batch C, 2026-10-07): a daily sweep re-fetches every brokers.json opt-out URL through the SSRF guard (`core/ssrf.py`), hashes the body (SHA-256, 64KB cap) and stores status/hash/state in `broker_source_checks` (migration `0010`); a changed hash flags the broker for playbook review in the admin overview's `source_health`. Wired into the retention worker's daily loop (`core/retention.py` `_run_source_sweep`), armed only when the worker is started, self-gated to one sweep per 24h by the checks table itself; unreachable keeps the last-seen hash. Tests: `tests/test_batch_c.py` (ok/changed/unreachable, gate, hash retention) | |
| 33 — Remediation engine | P2 | DONE | `remediation/engine.py` + `remediation/service.py` — executor-injected engine wrapping the deterministic `agent.py` | |
| 34 — User authorization | P0 | DONE | Removal runs require the automated_remediation consent, re-checked at execution; withdrawn consent = zero external calls (`tests/test_remediation.py`) | |
| 35 — Automated removal | P2 | DONE | Form submits + server-generated email letters (`remediation/engine.py`); CAPTCHA/login walls → needs_human, never bypassed | |
| 36 — Idempotent removal | P2 | DONE | Partial unique LIVE case per (user, broker) (migration `0005`); production re-run created 0 duplicate cases (parent-verified) | |
| 37 — Removal attempts | P2 | DONE | `remediation_attempts` audit table (migration `0005`) — action, result, detail, timestamps per attempt | |
| 38 — Removal verification | P2 | DONE | `remediation/verify.py` + `verify_sources.json` (26 search_index / 2 direct / 12 none); production drill: Spokeo check `gone` → case `verified_removed` (parent-verified) | |
| 39 — Reappearance | P2 | DONE | `monitoring/events.py` wires `remediation.verify.mark_reappeared()` into scan completion; reappeared status + notification | |
| 40 — Search engine exposure | P2 | PARTIAL | DuckDuckGo discovery findings tracked with weak confidence inside scans (`providers/ddg_discovery.py`) | No standalone search-exposure view/report; discovery capped at 6 queries per job |
| 41 — Continuous monitoring | P1 | DONE | `monitoring/scheduler.py` — cadence re-scans only for users with monitoring consent (migration `0006`) | |
| 42 — Scheduler | P1 | DONE | Hourly monitoring tick (`monitoring/scheduler.py`), daily retention (`core/retention.py`), in-process workers started guarded in `app.py` main | |
| 43 — Change detection | P2 | DONE | `monitoring/diff.py` — new/resolved/continuing findings + score delta; alerts only on change | |
| 44 — Notifications | P1 | DONE | `monitoring/notify.py` ledger + Brevo email lane; in-app list at `GET /api/notifications` | |
| 45 — Notification deduplication | P1 | DONE | 7-day dedupe window → repeat notifications recorded `suppressed`; ≤5 new-finding alerts + one summary (migration `0006`, `tests/test_monitoring.py`) | |
| 46 — Exposure history | P1 | DONE | Findings retained per job; `monitoring/service.py` timeline derives appearances, changes, disappearances, returns | |
| 47 — Timeline | P1 | DONE | `GET /api/monitoring/timeline` — read model over scan jobs, findings, remediation cases | |
| 48 — Privacy Center | P1 | DONE | Privacy Center in `static/index.html`: identifiers, consents, monitoring, timeline, notifications, export, deletion, household, API tokens | |
| 49 — Data export | P1 | DONE | `POST /api/privacy/export` (`accounts/privacy.py` `export_document`) — owner-only export, the only plaintext exit, now behind Argon2id password re-authentication; every attempt is counted by the credential rate limiter (`accounts/ratelimit.py`, the login buckets), a wrong password answers the login-identical 401, and each success writes an audit row (`privacy_export`, with format). Two formats carry the same data: JSON and CSV (flattened `section,record,field,value` rows, `render_csv`). The old GET route is removed — a download this sensitive is never one stray link away (Batch B, 2026-10-07; `tests/test_batch_b.py`, `tests/test_accounts.py`) | |
| 50 — Account deletion | P1 | DONE | Delete-account cascade + soft delete; `core/retention.py` hard-purges after 30 days | |
| 51 — Optional AI assistant | P3 | CUT | Owner rule: AI only if free AND unlimited (does not exist); spec §0.17–19 makes AI optional and core must not depend on it — no AI exists in the codebase | |
| 52 — Optional AI tool layer | P3 | CUT | Same owner rule as Phase 51 | |
| 53 — Optional AI remediation assistance | P3 | CUT | Same owner rule as Phase 51 | |
| 54 — AI confirmation | P3 | CUT | Same owner rule as Phase 51 | |
| 55 — AI prompt-injection defense | P3 | CUT | Same owner rule as Phase 51 (the underlying principle — external content is untrusted data — is applied in provider/broker handling) | |
| 56 — AI audit | P3 | CUT | Same owner rule as Phase 51 | |
| 57 — Organizations | P3 | PARTIAL | `accounts/households.py` — label-based household grouping shipped instead (Stage S11 decision) | No multi-tenant organizations/workspaces or tenant model |
| 58 — Domain verification | P3 | PARTIAL | TXT-token domain ownership verification exists for user domains (`accounts/domains.py`, migration `0004`) | No organization-level domain verification (no orgs — see Phase 57) |
| 59 — Household profiles | P3 | PARTIAL | Household members as owner-managed labels (migration `0007`); deleting a member keeps identifiers (SET NULL) | Members have no separate consent or ownership of their own |
| 60 — Admin panel | P3 | DONE | `accounts/admin.py` counts-only overview + audit view; `ADMIN_EMAILS` gate, non-admins get 404; production (parent-verified) | |
| 61 — Audit logging | P0 | DONE | `accounts/audit.py` + `audit_log` (migration `0007`) — auth, consent, identifiers, scans, remediation, admin; PII filter drops identifier-shaped keys; whole-table PII-absence test (`tests/test_orgs_admin.py`) | |
| 62 — Security events | P0 | DONE | Distinct security-events view (Batch C, 2026-10-07): `GET /api/admin/overview` carries `security_events` — the latest 20 `audit_log` rows in the auth/security action set (`auth.login*`, `auth.password_reset*`, `auth.totp*`, `account.deleted*`, `api_token.*`, `privacy_export`), meta only (action, actor_kind, time), surfaced in the Admin card (`accounts/admin.py`); the full audit list remains at `GET /api/admin/audit`. Tests: `tests/test_batch_c.py` (security action appears, non-security action does not, non-admin 404) | Anomaly *detection*/alerting on top of the view is still absent — the view is the record, not an alarm |
| 63 — Rate limiting | P0 | DONE | `core/ratelimit.py` wired per route class (anon scan 30/h/IP, register 10/h/IP, forgot-password 5/h/IP, user scans 10/h, removal runs 6/h) + S3 login limiter; 429 + Retry-After; production (parent-verified) | |
| 64 — Abuse prevention | P0 | DONE | Rate limits, discovery budget (6 queries/job), enumeration-safe responses, CAPTCHA never bypassed, 256 KB body cap → 413 | |
| 65 — Enumeration protection | P0 | DONE | Forgot-password answers identical 200 for known/unknown emails (production, parent-verified); login uses dummy verify + one identical `invalid_credentials` error; identifiers masked everywhere | |
| 66 — Cost control | P2 | PARTIAL | All providers free by owner rule (registry `cost_model` metadata, `providers/base.py`); discovery + probe budgets; rate limits | No per-user/provider budget or quota tracking |
| 67 — Caching | P2 | PARTIAL | `static/sw.js` caches the app shell only; per-request session cache in `app.py` | No server-side response caching — deliberate for privacy: API responses are never cached |
| 68 — Retention worker | P0 | DONE | `core/retention.py` — sessions/reset tokens purged 7d after expiry/revocation, notifications at 90d, deleted accounts hard-purged at 30d across 14 tables | |
| 69 — Security headers | P0 | DONE | `core/security.py` — CSP `default-src 'self'`, X-Frame-Options DENY, Referrer-Policy no-referrer, CSRF (`core/security.require_csrf`), Secure/HttpOnly/SameSite=Lax session cookie; **HSTS `max-age=31536000; includeSubDomains`** in the central `SECURITY_HEADERS` (Batch A, 2026-10-07) — no `preload` (owner has not made that browser-vendor commitment) | Proven on a 200, a 404 and an API error response (`tests/test_batch_a.py`) |
| 70 — SSRF protection | P0 | DONE | Form-submit actions host-allowlisted against the broker registry (`remediation/engine.py`); provider/broker fetches constrained to registry-defined endpoints; **DNS-resolution guard `core/ssrf.py`** (Batch A): http/https only, host must resolve entirely to public addresses (private/loopback/link-local/multicast/reserved/unspecified rejected, literal IPs checked without resolving), enforced at `agent.submit_form`, `agent.probe_broker` and the remediation direct-verify fetch | Residual documented in the module: resolve-then-fetch leaves a DNS-rebinding window — the guard kills the internal-target class, it is not connection pinning |
| 71 — File security | P0 | NA | No upload route exists in `app.py`; nothing accepts file uploads | Not applicable — no file-upload surface |
| 72 — Webhook security | P0 | NA | No webhooks (inbound or outbound) exist anywhere in the codebase | Not applicable — no webhook surface |
| 73 — Database security | P0 | DONE | Parameterized queries throughout (psycopg bound parameters); DB credentials env-only; Neon pooled TLS endpoint; **least-privilege `leakguard_app` role live in production 2026-10-07** (DML only, no DDL) — DML proven by production register/scan/delete E2E; migrations split onto the owner-level `MIGRATION_DATABASE_URL` (`db/pool.py` migration_dsn, `db/migrate.py`, app boot; `tests/test_migration_split.py` incl. pgserver reproduction of the restricted-role DDL refusal) | |
| 74 — Secrets | P0 | DONE | Secrets only in Render env vars / mode-600 local files; none in repo; vault master + lookup keys are env-only (`db/pool.py`, `vault/`) | |
| 75 — Secure logging | P0 | DONE | `core/logging_setup.py` structured PII-free logs (exception class names only); audit detail PII filter (`accounts/audit.py`) | |
| 76 — Observability | P2 | PARTIAL | Structured logs, X-Request-Id, `/api/health`, `/api/providers/health`, admin overview | No metrics endpoint or error-tracking service |
| 77 — Engineering alerts | P2 | PARTIAL | UptimeRobot downtime email alerts on the production URL | No alerting for provider outages, queue buildup, or worker failures |
| 78 — Backups | P0 | DONE | Backups are Neon platform point-in-time restore, described honestly in README Operations; **restore tested 2026-10-07** (see Phase 170) | |
| 79 — Disaster recovery | P0 | DONE | `docs/DISASTER_RECOVERY.md` (Batch C, 2026-10-07): what backs up where (Neon free-plan PITR — the only database backup, stated as such), RPO phrased as bounded by the console-visible free-plan PITR window, RTO as the drill observation (under an hour end-to-end), the 2026-10-07 drill evidence (19 tables / 40 brokers / 8 migrations / 15 users), and a step-by-step restore procedure (freeze writes → branch from PITR → verify counts → repoint `DATABASE_URL` + `MIGRATION_DATABASE_URL` → redeploy → verify → unfreeze) | |
| 80 — Incident response | P2 | DONE | `docs/INCIDENT_RESPONSE.md` (Batch C, 2026-10-07): severity ladder SEV-1..4, first-30-minutes checklist, the Batch B kill switches with their variables and restore step, a rotation table (vault keys as a planned re-encryption maintenance — no automated tooling, stated plainly; DB role passwords; Brevo key; GitHub PAT; user passwords via the product flow only), the product's honesty rules applied to incident comms (never claim an unevidenced removal or breach scope), and a post-incident review step | |
| 81 — Legal/privacy architecture | P3 | PARTIAL | `remediation/letters.py` cites DPDP §12 / GDPR Art. 17 / CCPA from per-law templates | Jurisdiction behavior is letter templates, not configurable regional rules (see Phase 168) |
| 82 — Privacy policy | P3 | PARTIAL | `/trust` page states actual collection, providers, retention, deletion (in `static/index.html`) | No standalone formal privacy-policy document/route |
| 83 — Terms | P3 | PARTIAL | Honest-limits copy in the product and on `/trust` matches actual capabilities | No standalone Terms document/route |
| 84 — Trust center | P3 | DONE | `/trust` route; every claim traceable to code; no certification claims (claim-reviewed in Stages S13/S15) | |
| 85 — Reporting | P3 | PARTIAL | Privacy export, timeline, admin aggregates | No generated exposure/remediation report documents |
| 86 — API | P1 | DONE | `accounts/api_tokens.py` — read-only Bearer tokens (migration `0008`) accepted on six read endpoints only; README API section; production (parent-verified) | |
| 87 — Structured errors | P0 | DONE | `core/errors.py` — every API error is `{error:{code,message,request_id}}` | |
| 88 — API versioning | P1 | DONE | `/api/v1` is the canonical version: `app.py` `_versioned_route()` normalizes a leading `/api/v1/` prefix to `/api/` at the routing layer before dispatch, so every route answers under both spellings with the SAME handler; the unversioned spelling is a permanent alias of v1, and a future breaking change ships as `/api/v2` alongside (policy in README → API). The browser extension calls `/api/v1/...` (Batch B, 2026-10-07; parity + 404 tests in `tests/test_batch_b.py`) | |
| 89 — Request IDs | P0 | DONE | `core/context.py` request ids; `X-Request-Id` response header; id echoed in error bodies | |
| 90 — Frontend pages | P1 | DONE | Single-page app (`static/index.html`): scan, Action Center, Privacy Center, monitoring, trust, reset | |
| 91 — Dashboard UX | P1 | DONE | Dashboard leads with exposure score + the one server-chosen next action (`dashboard/service.py`) | |
| 92 — Exposure detail | P1 | DONE | `GET /api/scans/<id>` returns findings with confidence, reliability, evidence_ref, exposed fields | |
| 93 — Removal detail | P2 | DONE | `GET /api/remediation/cases` + `GET /api/remediation/queue` — state, reason, next steps; letters attached to email cases | |
| 94 — Monitoring page | P1 | DONE | Monitoring block: cadence select, last/next scan (`monitoring/service.py`); provider health via `GET /api/providers/health` | |
| 95 — Settings | P1 | DONE | Privacy Center settings: password change, TOTP, consents, monitoring cadence, API tokens, export, account deletion | |
| 96 — Accessibility | P2 | PARTIAL | Semantic HTML with real `<label>` elements; responsive layout | Zero `aria-*` attributes in `static/index.html`; no accessibility audit or tests |
| 97 — Responsive mobile | P1 | DONE | Responsive theme (`@media (max-width: 640px)` in `static/style.css`); installable PWA | |
| 98 — Localization | P3 | NOT_DONE | UI is single-language; no i18n hooks in `static/` | Localization architecture not prepared |
| 99 — Notification emails | P1 | DONE | `monitoring/notify.py` plain-text templates carry minimal content (no identifier values); production reset-email round trip (parent-verified) | |
| 100 — Browser extension foundation | P3 | DONE | `extension/` Manifest V3 — storage permission only, single host permission, token-only auth; deterministic zip via `tools/build_extension_zip.py` | |
| 101 — Mobile foundation | P3 | DONE | `static/manifest.webmanifest` + `static/sw.js` (shell-only caching); token API reusable by future clients; no native app claimed | |
| 102 — Privacy policy analyzer | P3 | NOT_DONE | No analyzer exists in the codebase | Not implemented (optional P3) |
| 103 — Exposure graph | P3 | DONE | `GET /api/graph` + `dashboard/graph.py` — masked identifier → source → broker nodes/edges from real rows only | |
| 104 — Source propagation | P3 | NOT_DONE | Graph edges are `found_in` and `removal` only (`dashboard/graph.py`) | Propagation analysis absent; cross-source causality deliberately not claimed |
| 105 — Business model | P3 | CUT | Owner deferred all paid/monetization until he explicitly says otherwise ("free for me, free for users until I say to make paid") | |
| 106 — CI/CD | P2 | DONE | `.github/workflows/tests.yml` (Batch A): push + PR + weekly scheduled run — Python 3.12, `pip install -r requirements.txt pgserver`, `node --check static/app.js`, full unittest discovery; migrations auto-run at startup (`db/migrate.py`) | Deploys remain manual via the Render dashboard (deliberate — Render auto-deploy does not fire reliably); no dependency-scanning automation (see 107) |
| 107 — Dependency security | P0 | DONE | `requirements.txt` — 3 runtime deps, version-ranged; stdlib-first minimizes surface; **`requirements.lock`** (Batch A): exact-version snapshot of requirements.txt + pgserver's resolution (12 packages), generated in a throwaway venv via `pip freeze`, with the regeneration procedure in its header and README's Supply chain note | The lock pins versions, not artifact hashes; automated vulnerability scanning is not wired (the weekly CI run surfaces resolution drift) |
| 108 — Container security | P3 | NA | No Dockerfile or container usage anywhere; Render native Python runtime | Not applicable — no container surface |
| 109 — Environments | P2 | NOT_DONE | One Render service + one Neon project (`render.yaml`) | No staging environment |
| 110 — Mock providers | P2 | DONE | `providers/mock.py` behind `LEAKGUARD_PROVIDERS=mock`, always visibly flagged in health output; mock contract tests (`tests/test_providers.py`) | |
| 111 — Fake broker | P2 | PARTIAL | `StubExecutor` test doubles (`tests/test_remediation.py`) exercise full case workflows | No standalone fake-broker server environment |
| 112 — Testing | P1 | DONE | 302 tests in 16 files (unit/integration/API/worker/provider/remediation/security/privacy); auditor re-ran the suite 2026-10-07: OK (2 environment skips) | |
| 113 — Security test matrix | P0 | DONE | `tests/test_hardening.py`, `tests/test_accounts.py`, `tests/test_orgs_admin.py`, `tests/test_api_tokens.py` — IDOR, CSRF, rate limits, enumeration, token walls; live X-Forwarded-For spoof regression pinned after a production catch | |
| 114 — Privacy test matrix | P0 | DONE | `tests/test_vault.py`, `tests/test_accounts.py`, `tests/test_monitoring.py`, `tests/test_hardening.py` — encryption, masking, retention, deletion, export, consent, PII-free logging/audit | |
| 115 — Performance | P2 | PARTIAL | 40s probe budget + worker-concurrency proofs (`tests/test_remediation.py`); per-stage measurements recorded in commit messages | No performance test suite or benchmarks |
| 116 — Scalability | P2 | PARTIAL | Postgres-backed queues, indexes, in-process workers fit the free tier's single instance | No load testing; horizontal scaling unproven |
| 117 — Data consistency | P0 | DONE | Transactions throughout; partial unique indexes (live identifiers, live cases, live user emails); `UNIQUE(user_id, idempotency_key)` on scan jobs; SKIP LOCKED claims | |
| 118 — Retry/circuit breaker | P2 | DONE | `providers/base.py` — ≤2 retries (never on 4xx), circuit opens after 3 failures, half-open after 60s; worker backoff 30s/120s | |
| 119 — Dead-letter queue | P2 | PARTIAL | Jobs/cases reach a persisted dead/failed state after 3 attempts, with stale-running recovery (migration `0003`, `scanning/worker.py`) | No dead-letter replay tooling |
| 120 — Emergency controls | P2 | DONE | Scoped kill switches in `core/flags.py` (Batch B, 2026-10-07): `LEAKGUARD_FLAG_REGISTRATION` / `_ACCOUNT_SCANS` / `_REMOVAL_RUNS` make the gated POSTs answer a structured `503 feature_disabled`, and `_MONITORING_SCHEDULER` makes the scheduler's tick a no-op — each capability stops without taking the site, or the never-gated anonymous Quick Scan, down. Plus the earlier switches: `LEAKGUARD_PROVIDERS=mock` provider switch; workers are DB-guarded (site stays up without a database); email lane dormant without `BREVO_API_KEY`. Emergency procedure documented in README → Operations | |
| 121 — AI kill switch | P3 | CUT | Same owner rule as Phase 51 — no AI exists to switch off; core never depended on it | |
| 122 — Feature flags | P3 | DONE | `core/flags.py` (Batch B, 2026-10-07): env-driven flags (`registration`, `account_scans`, `removal_runs`, `monitoring_scheduler`), default ON, `0/false/off/no` = off, read from the environment on every check; the current snapshot is reported in `GET /api/admin/overview` (`flags`) and every flag + the emergency procedure is documented in README → Operations. Enforcement points in `app.py` (register/scans/removal) and `monitoring/scheduler.py` | |
| 123 — Admin system health | P3 | PARTIAL | `GET /api/admin/overview` — counts by status, provider health, db status (`accounts/admin.py`) | No queue-depth, latency, or worker-health metrics |
| 124 — Provider cost monitoring | P2 | PARTIAL | HealthTracker counts successes/failures/latency per provider (`providers/base.py`); all providers are free | No quota/budget tracking or spend alerting (spend is ₹0 by owner rule) |
| 125 — Source health dashboard | P2 | PARTIAL | `GET /api/providers/health`; admin overview carries case counts by status — plus per-broker source health (Batch C, 2026-10-07): `source_health` in `GET /api/admin/overview` (brokers by latest sweep state, changed/unreachable slug lists, last_checked_at, from `remediation/source_checks.py`), rendered in the Admin card | No per-broker *verification-success* or workflow-health dashboard yet — what exists is opt-out-page reachability/change, not per-broker removal-outcome rates |
| 126 — Support | P3 | NOT_DONE | No support workflow or tooling in the repo | Support is the owner's mailbox only; nothing auditable in-product |
| 127 — Security disclosure | P3 | DONE | `/.well-known/security.txt` served (Contact, Expires 2027-10-07, Canonical); security contact also on `/trust`; production (parent-verified) | |
| 128 — Bug bounty foundation | P3 | NOT_DONE | `security.txt` covers disclosure only | No bug-bounty documentation prepared |
| 129 — Data residency | P3 | NOT_DONE | Regions are fixed platform choices (Render Oregon; Neon ap-southeast-1 Singapore) | No data-residency configuration or design |
| 130 — Subprocessors | P3 | DONE | `/trust` lists every processor: Render, Neon, Brevo, XposedOrNot, Have I Been Pwned, DuckDuckGo, Cloudflare DoH, crt.sh | |
| 131 — Documentation | P2 | DONE | `README.md` (Operations, API, layout, Privacy, FAQ), `CURRENT_STATE.md`, `MIGRATION_PLAN.md`, `extension/README.md` | |
| 132 — Migration documentation | P2 | DONE | `MIGRATION_PLAN.md` — stage map, owner rules, outcome section, gaps register | |
| 133 — Backward compatibility | P2 | DONE | Legacy routes and shapes preserved (`/api/scan`, `/api/agent/*`, `/api/brokers` byte-identical file fallback); regression-pinned in `tests/test_providers.py` / `tests/test_remediation.py` | |
| 134 — Broker data migration | P2 | DONE | brokers.json/playbooks.json → DB registry with no workflow loss (`remediation/registry_seed.py`) | |
| 135 — Score migration | P1 | DONE | Risk v2 parity: 378-combination matrix; production baselines byte-identical to the pre-upgrade product (parent-verified) | |
| 136 — Agent migration | P2 | DONE | Deterministic `agent.py` wrapped by `remediation/engine.py` (executor injection); not replaced | |
| 137 — Browser probe migration | P2 | PARTIAL | `browser_probe.py` preserved (Playwright, subprocess-isolated) for local runs | Browser probing cannot run on Render; the server classifies from HTTP evidence instead — recorded per-attempt in `probe_trail` |
| 138 — Final Quick Scan + Full Protection UX | P1 | DONE | "Quick Scan" / "Full Protection" labelled flows in `static/index.html`; production (parent-verified) | |
| 139 — Final dashboard | P1 | DONE | Action Center: current score, open cases by status, urgent next action, recent activity | |
| 140 — Final exposure experience | P1 | DONE | Finding detail (confidence, evidence, history via timeline) + exposure map (`dashboard/graph.py`) | |
| 141 — Final removal experience | P2 | PARTIAL | Case states: queued/running/submitted/needs_human/blocked/verified_removed/reappeared/failed (CHECK in migration `0005`) | State set differs from the spec's names (needs_human ≈ AWAITING_USER, blocked ≈ REJECTED); no distinct AUTHORIZED/NOT_STARTED states — authorization is consent-gated case creation |
| 142 — Final monitoring | P1 | DONE | Cadence, last/next run, consent on/off (`monitoring/service.py`) — plus a dedicated pause/resume state (Batch B, 2026-10-07): `user_settings.monitoring_paused` (migration `0009_monitoring_pause.sql`), exposed by GET/PUT `/api/monitoring/settings`, with a Pause/Resume toggle in the Settings UI. The scheduler's candidate query excludes paused users, and pausing never touches the append-only consent record — pause ≠ withdrawal (test-asserted, consent rows unchanged across pause/resume in `tests/test_batch_b.py`) | |
| 143 — Final reappearance | P2 | DONE | Reappeared cases + dedupe-aware notifications (`monitoring/events.py`, `remediation/verify.py`) | |
| 144 — Privacy principle | P0 | DONE | Minimization throughout: masked storage, k-anonymity, evidence hashes instead of payloads, search snippets never stored (`providers/ddg_discovery.py`), audit PII filter | |
| 145 — Definition of done | P1 | DONE | DoD applied every stage S1–S15: implementation + tests + docs + independent production verification (see `MIGRATION_PLAN.md` outcome) | |
| 146 — Final acceptance test | P1 | DONE | Full journey exercised in production across stage E2Es: register → consent → scan → removal run → verify → delete (parent-verified 2026-10-07) | |
| 147 — Final security acceptance | P0 | DONE | Consolidated in `docs/ACCEPTANCE.md` (Batch C, 2026-10-07): an index from every security-acceptance area (auth, IDOR, encryption, SSRF, headers, rate limits, least-privilege DB role, tested restore, dependency pinning + CI, kill switches, regression suite) to its existing evidence — code, tests, PHASE_STATUS rows and the 2026-10-07 production checks. No new claims; the per-stage checks it indexes are the ones already recorded | |
| 148 — Final privacy acceptance | P0 | DONE | Consolidated in `docs/ACCEPTANCE.md` (Batch C, 2026-10-07): an index from every privacy-acceptance area (anonymous scan stores nothing, masked-only output, k-anonymity, HMAC-keyed evidence, owner-only rechecked export, deletion cascade + purge, consent gates, counts-only admin, claim discipline, regression suite) to its existing evidence, plus the production baselines (214 breaches / score 100 / pwned 52,372,427). No new claims | |
| 149 — Development reporting | P1 | PARTIAL | Per-stage completion reports, descriptive commits, `MIGRATION_PLAN.md` outcome section | Reports live in chat/git history, not per-cycle report files in the repo |
| 150 — Final implementation rule | P1 | DONE | Completion was never declared from UI/docs alone — every stage is evidenced by code, tests, and production checks (this table cites them) | |
| 151 — Exposure graph implementation | P3 | DONE | `GET /api/graph` owner/Bearer-scoped with masked labels only (`tests/test_extensions.py`) | |
| 152 — Propagation analysis | P3 | NOT_DONE | Same state as Phase 104 | Propagation analysis absent; unsupported causality deliberately not claimed |
| 153 — Removal policy engine | P2 | PARTIAL | Deterministic policy embodied in `remediation/engine.py` probe transitions, consent re-checks, and channel derivation (`remediation/registry_seed.py`) | No standalone versioned policy-engine module |
| 154 — Human review queue | P2 | DONE | `GET /api/remediation/queue` — needs_human cases with exact reasons, next steps, and ready-to-send letters | |
| 155 — Verification evidence | P2 | DONE | `verification_checks` (migration `0005`) stores method + outcome + evidence_ref for every check, including `unknown` | |
| 156 — False-positive feedback | P2 | DONE | `finding_feedback` (migration `0010`) + `scanning/feedback.py` — the ONE helper every surface consults: `POST /api/findings/feedback` (session + CSRF, owner-scoped, foreign id → 404; 'not_me'/'confirmed'/'none'-clears). Scan view rows carry the verdict + Undo and render disowned findings dimmed; monitoring's scan-completion hook excludes 'not_me' identities from new-exposure notifications, summary counts and reappearance flips (`monitoring/events.py`); Action Center finding counts exclude them (`dashboard/service.py`). Tests: `tests/test_batch_c.py` | |
| 157 — Source dispute handling | P2 | DONE | `scanning/disputes.py` (Batch C, 2026-10-07): per-finding `dispute` object in the scan view with a 'Dispute or correct this' panel — breach_database (the breached company is the data holder; the index only indexes — stated verbatim), broker_listing (the removal flow IS the dispute route), search_result (Google 'Results about you' — the one URL, already linked from `static/index.html`; a test asserts every URL in the module appears elsewhere in the repo), generic honest steps otherwise. Tests: `tests/test_batch_c.py` | |
| 158 — Scan budget engine | P2 | PARTIAL | Discovery budget of 6 queries/job, 40s per-case probe budget, route rate limits | No per-user/org/provider scan budget engine |
| 159 — Priority queue | P2 | DONE | `scanning/worker.py` claim (Batch B, 2026-10-07): hand-started jobs are claimed before monitoring-scheduled ones — told apart by the scheduler's `monitor-` idempotency-key prefix (scan_jobs has no source column) — FIFO (`created_at, id`) within each class; failed jobs still wait out their backoff. Remediation checked: its queue has a single, interactive class (cases come only from the user's run/retry; verification is synchronous in-request, `remediation/verify.py`), so its FIFO claim is the priority order by construction (documented in `remediation/worker.py`) | |
| 160 — Data-quality pipeline | P2 | PARTIAL | `scanning/normalize.py` + DB CHECK constraints (confidence/reliability enums) + adapter parse guards | No data-quality stage over stored findings (dedupe/drift/malformed detection) |
| 161 — Provider contract tests | P2 | DONE | `tests/test_providers.py` — success, timeout, retry, 4xx/5xx, malformed JSON, circuit-breaker states, mock contract | |
| 162 — Broker workflow regression tests | P2 | PARTIAL | `tests/test_remediation.py` + `tests/test_verify_sources.py` regression-cover workflows via stub executors | No fake-broker end-to-end regression harness (see Phase 111) |
| 163 — AI policy gate | P3 | CUT | Same owner rule as Phase 51 | |
| 164 — AI output validation | P3 | CUT | Same owner rule as Phase 51 | |
| 165 — AI data minimization | P3 | CUT | Same owner rule as Phase 51 | |
| 166 — Secure browser context | P2 | PARTIAL | `browser_probe.py` runs subprocess-isolated locally; the server never runs a browser | Local probe has no domain allowlist beyond the playbooks; no server-side browser contexts exist (by design) |
| 167 — CAPTCHA handling | P0 | DONE | CAPTCHA/login walls classify to needs_human with the exact reason; bypass is never attempted (`remediation/engine.py` transitions; production cases carry the reasons) | |
| 168 — Regional policy rules | P3 | PARTIAL | Letters exist for DPDP/GDPR/CCPA (`remediation/letters.py`, `DEFAULT_LAW = "dpdp"`) | Law is a letter template/default, not configurable regional policy rules |
| 169 — Retention enforcement tests | P0 | DONE | `tests/test_hardening.py` — account deleted 29d ago untouched; at 31d purged from all 14 tables; expired sessions/tokens/notifications removed | |
| 170 — Restore tests | P0 | DONE | **Restore drill 2026-10-07**: a branch created from Neon's point-in-time restore showed 19 public tables, 40 brokers, 8 migrations, 15 users; the drill branch was deleted after verification | |
| 171 — Security regression suite | P0 | DONE | Security tests are part of the full suite, run before every deploy (302 tests; per-stage runs by parent and auditor) | |
| 172 — Privacy regression suite | P0 | DONE | Privacy tests likewise (`tests/test_vault.py`, `tests/test_accounts.py`, `tests/test_hardening.py` PII-absence assertions) | |
| 173 — Production readiness | P0 | PARTIAL | Per-deploy readiness checks ran: health, db status, provider health, baseline scans | Restore tests (170) and staging (109) keep full readiness open |
| 174 — Rollback plan | P0 | DONE | `docs/ROLLBACK.md` (Batch C, 2026-10-07): code rollback (Render redeploy of a prior commit; `git revert` path — never a force-pushed rewrite), a configuration table of every env var (what it does + where its value's source of truth lives — **no values**), and the database policy: migrations are additive, rollback is forward-fix, and data damage escapes via the PITR procedure in `docs/DISASTER_RECOVERY.md` | |
| 175 — Post-launch monitoring | P2 | PARTIAL | UptimeRobot uptime monitoring + per-deploy live verification + admin overview | No error/latency alerting; post-launch monitoring is uptime + manual checks |
| 176 — Limitations register | P3 | DONE | `CURRENT_STATE.md` §Known gaps + `MIGRATION_PLAN.md` gaps register + honest-limits copy on `/trust` and the home page | |
| 177 — Capability-claim review | P3 | DONE | Claims audited in Stages S13/S15: `/trust` statements traceable to code; README honest limits; no certification claims | |
| 178 — Codebase cleanup | P2 | PARTIAL | The free-lane AI hook was fully removed in Stage S1 (repo grepped clean); legacy agent retained deliberately as the remediation core | `local_agent.py` / `proxy_relay.py` / `browser_probe.py` remain as documented local-only surface |
| 179 — Final architecture review | P2 | DONE | Stage S15 architecture review + this Phase 0 re-audit (`CURRENT_STATE.md`, this file) | |
| 180 — Final command | P0 | PARTIAL | Most final criteria verified live on 2026-10-07: production matches repo (commit `8271c17`), tests pass, security/privacy checks pass, monitoring/remediation/verification/reappearance work | Restore tests (170), staging (109), and CI (106) still open — the final gate is not fully met |

## Counts

| Status | Count |
|---|---|
| DONE | 124 |
| PARTIAL | 35 |
| NOT_DONE | 8 |
| CUT (owner rule) | 11 |
| NA (surface does not exist) | 3 |
| **Total** | **181** |

Open by tier — **P0:** 173, 180 (all PARTIAL — none is an active production exposure; they are depth gaps: production-readiness evidence and the final gate). **P1:** 25, 149. **P2:** 31, 40, 66, 67, 76, 77, 96, 109, 111, 115, 116, 119, 124, 125, 137, 141, 153, 158, 160, 162, 166, 175, 178. **P3:** 57, 58, 59, 81, 82, 83, 85, 98, 102, 104, 123, 126, 128, 129, 152, 168.
