<div align="center">

# 🛡️ LeakGuard

### Your data got leaked. Find it. Remove it.

### 🌐 Live Website: [leakguard-hh8e.onrender.com](https://leakguard-hh8e.onrender.com)

[![Live Demo](https://img.shields.io/badge/▶_Live_Demo-leakguard--hh8e.onrender.com-2ea043?style=for-the-badge)](https://leakguard-hh8e.onrender.com)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-3_runtime-important?style=for-the-badge)
![Cost](https://img.shields.io/badge/Cost-₹0_Free-success?style=for-the-badge)

**Scan → Score → Remove.** A free web tool that finds your leaked personal data and walks you through erasing it — built on India's **DPDP Act**, **GDPR** and **CCPA** erasure rights. The anonymous Quick Scan needs no account; a free account adds saved details, automatic monitoring and one-command removal.

</div>

---

## ✨ What it does

| Step | What happens |
|---|---|
| 🔍 **Scan** | Enter your email — LeakGuard checks real breach databases ([XposedOrNot](https://xposedornot.com), free, no API key) and lists exactly which breaches contain you and what data types leaked. Optional password check via [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using k-anonymity — the server hashes your password and only the first 5 characters of the hash ever leave the server; the password itself is never stored or logged. |
| 📊 **Score** | An exposure score from **0–100** with a clear risk label, so you know how bad it is at a glance. |
| 🧹 **Remove** | A Removal Centre covering **40 data brokers & people-search sites** (Spokeo, Whitepages, BeenVerified, Acxiom, Epsilon, LexisNexis and more): opt-out links, step-by-step flows, a progress tracker, and a one-click **erasure-request letter generator** citing DPDP Act §12, GDPR Art. 17, or CCPA. |
| 🌐 **Google** | Builds the searches a stranger would run on you, and links Google's own *Results about you* removal tool. |

## 🤖 Agent Mode — zero tokens, by design

The agent does the boring work with plain deterministic scripts. **No AI tokens are burned, ever.**

- 🗺️ **Personal plan** — per-broker playbooks (16 hand-mapped, all 40 covered) turned into a removal plan for your details.
- 🛰️ **Live probe, in layers** — for each broker the agent inspects the real opt-out page:

  | Layer | What it does |
  |---|---|
  | HTTP | Fetches the page directly and parses its real form |
  | Relay reader | Retries via a different network when the site blocks servers |
  | Real browser | Headless Chromium for JavaScript-walled pages (optional install; on the hosted service the deep pass uses HTTP + relay, and says so when a page would need a real browser) |

  It pre-fills the form payload with your details and honestly reports blockers — CAPTCHA, login walls, bot protection — instead of pretending they aren't there.
- ✉️ **Email channels** — some sites (e.g. BeenVerified, Nuwber) wall their web forms off from datacenter networks entirely. LeakGuard surfaces their official opt-out **email addresses**, which work from anywhere.
- 🔒 **Guarded submit** — a run starts only from your explicit confirmation (one press confirms the run); every submission call still requires the confirm flag, and submissions only ever go to the broker's own host.
- 🚫 **No AI anywhere** — an earlier optional AI fallback for cryptic form fields was removed in Stage S1 and never came back: every step above is deterministic code, so there is nothing to configure and nothing that can hallucinate a result.

## ⚖️ The honest limits

> - ✅ **Can be removed:** data brokers, people-search sites, Google search results — they must answer a legal erasure request.
> - ❌ **Cannot be removed:** a breach dump already copied to Telegram, dark-web forums or torrents. No tool can delete every copy — anyone promising that is lying. The defence there is changing compromised passwords and turning on 2FA.
> - 🧑 CAPTCHA, email-confirmation and phone-verification steps always need you. By design — they're proof you're a human removing *your own* data.

## 🚀 Run it yourself

Three small runtime dependencies (a Postgres driver, AES-GCM, Argon2 — see `requirements.txt` for why each exists); everything else is the Python 3.12 standard library.

```bash
pip install -r requirements.txt
python3 app.py
# open http://localhost:8000
```

Environment: `PORT` (default 8000) · `HOST` (default 0.0.0.0). For the account features, also set `DATABASE_URL` (Postgres), `VAULT_MASTER_KEY` and `VAULT_LOOKUP_KEY` (base64-encoded 32-byte keys — see Operations → Database connections). Without a database configured, the account features answer unavailable and the anonymous surface (Quick Scan, Removal Centre, Agent Mode) still runs.

**📱 On your own device** (recommended for walled sites): `python3 local_agent.py` runs the same engine under your home IP, where broker sites behave normally. It probes, prints the plan, and can open opt-out pages in your browser — it never submits anything automatically.

**🧩 Optional browser probe layer:** `pip install -r requirements-optional.txt` plus any Chromium/Chrome. On proxy-locked networks run `python3 proxy_relay.py` and set `LEAKGUARD_BROWSER_PROXY=http://127.0.0.1:8899`. Disable with `LEAKGUARD_NO_BROWSER=1`.

**☁️ Deploy:** `render.yaml` is included — create a Web Service from this repo on Render's free tier (or use Blueprint). Build command `pip install -r requirements.txt`, start command `python3 app.py` (both already in `render.yaml`). Note: Render keeps the dashboard-stored build command — if a deploy behaves like an old configuration, check Settings → Build & Deploy on the service itself.

## ⚙️ Operations

**Rate limits** (in-memory, per process; excess requests answer a structured `429 rate_limited` with a real `Retry-After`):

| Route | Limit | Keyed by |
|---|---|---|
| `POST /api/scan` (anonymous quick scan) | 30 / hour | client IP |
| `POST /api/agent/probe`, `POST /api/agent/submit` | 30 / hour each | client IP |
| `POST /api/auth/register` | 10 / hour (plus the credential limiter below) | client IP |
| `POST /api/auth/login`, `POST /api/auth/register` | 10 attempts / 15 min | client IP **and** account email |
| `POST /api/auth/forgot-password` | 5 / hour | client IP |
| `POST /api/scans` | 10 / hour | account |
| `POST /api/remediation/run` | 6 / hour | account |

JSON request bodies over **256 KB** are rejected with `413 body_too_large`. Read (GET) endpoints are unlimited.

**Feature flags & emergency controls** (environment variables; every flag defaults to ON, and a flag takes effect when the service restarts — on Render: set the variable under Environment, then **Save, rebuild, and deploy**):

| Variable | When set to `off` |
|---|---|
| `LEAKGUARD_FLAG_REGISTRATION` | `POST /api/auth/register` answers `503 feature_disabled` — no new accounts; existing users are unaffected |
| `LEAKGUARD_FLAG_ACCOUNT_SCANS` | `POST /api/scans` answers `503 feature_disabled` — account full scans pause; **the anonymous Quick Scan is never gated** |
| `LEAKGUARD_FLAG_REMOVAL_RUNS` | `POST /api/remediation/run` answers `503 feature_disabled` — no new removal runs start (cases already queued are untouched) |
| `LEAKGUARD_FLAG_MONITORING_SCHEDULER` | The hourly monitoring scheduler enqueues nothing |

Accepted off values are `0`, `false`, `off`, `no` (case-insensitive); unset means on. The current state of every flag is visible to the owner in the Admin overview (`flags`) and lives in `core/flags.py`. Emergency procedure: set the one variable for the misbehaving capability, redeploy, confirm the gated route answers `503 feature_disabled`, fix the cause, then remove the variable (or set it back to `on`) and redeploy again. Nothing else needs to change — flags are read from the environment, never stored in the database.

**Passkeys (WebAuthn):** sign-in with a password is always available; a passkey is an optional extra managed in the Privacy Center (adding or removing one asks for the account password once more). Only the credential's **public** key is stored — nothing server-side can sign in as the user. Deliberate limits, all enforced server-side: attestation format **`none` only** (other formats are rejected by name, never silently trusted); algorithms **ES256** (P-256) and **RS256** (RSA ≥ 2048-bit); sign-in requires the authenticator to verify the user (fingerprint / face / PIN) on every ceremony, and a signature counter that goes backwards fails the sign-in (authenticators that always report 0 are accepted). A passkey sign-in does not additionally demand a TOTP code — the user-verified ceremony is possession + verification in one step. The relying-party id and expected origin are derived from the request's validated origin; pin them explicitly with `LEAKGUARD_WEBAUTHN_ORIGIN` / `LEAKGUARD_WEBAUTHN_RP_ID` if a deployment ever needs fixed values.

**Retention** (an in-process worker runs one pass daily; every purge is audit-logged with counts only):

| Data | Kept for |
|---|---|
| Sessions | deleted once expired or revoked for more than 7 days |
| Password-reset tokens | deleted once used or expired for more than 7 days |
| Notifications | 90 days |
| Deleted accounts | soft-deleted for 30 days (recoverable by support), then hard-purged with everything the account owns — identifiers, scans, findings, removal cases, settings, household, passkeys. The PII-free audit trail (counts and actions, never values) is kept. |

**Database connections:** two environment variables, split by privilege. `DATABASE_URL` is the runtime connection and should be a **least-privilege role** (SELECT/INSERT/UPDATE/DELETE only — no DDL); everything the running app does goes through it. `MIGRATION_DATABASE_URL` is an **owner-level** connection used only by the boot-time migration step, which needs DDL; it is never used to serve requests. When `MIGRATION_DATABASE_URL` is unset, migrations fall back to `DATABASE_URL` (the pre-split behavior — convenient for local development and tests, where one connection does both jobs).

**Email lane & admin:** transactional email (password resets, monitoring alerts) goes through Brevo's free tier — set `BREVO_API_KEY`, `NOTIFY_FROM_EMAIL` and `NOTIFY_FROM_NAME`. `ADMIN_EMAILS` lists the account emails that get the admin overview (comma-separated). `RESET_URL_BASE` pins the public base URL used in password-reset links when it cannot be derived from the request.

**Backups:** the database lives on Neon's free plan. Point-in-time restore is a Neon platform feature and restores are run by the owner from the Neon console; the free plan's restore history is limited, and LeakGuard keeps no second backup copy — the encrypted vault means a database copy alone exposes no identifier values (the master key lives only in the server environment).

**Supply chain:** runtime installs use `requirements.txt` (three version-ranged dependencies; everything else is the Python standard library). `requirements.lock` is the audited snapshot: the exact versions that file — plus `pgserver`, the test-only Postgres — resolved to when last generated, produced by `pip freeze` from a clean throwaway venv so the tested dependency set is reviewable and reproducible. The lock is a snapshot, not the install source; refresh it after any `requirements.txt` change by following the regeneration commands in its header, and expect the weekly CI run (`.github/workflows/tests.yml`) to surface resolution drift in between.

## 🔌 API

**Versioning:** the current API version is **v1**. Every route answers under its canonical `/api/v1/...` spelling, and the unversioned `/api/...` spelling is a **permanent alias of v1** — both reach the same handler, so existing integrations (including the browser UI) cannot break. If a breaking change is ever needed, it ships as `/api/v2/...` alongside v1; v1 is not silently changed or removed.

Accounts can mint a personal **API token** (Privacy Center → **API access**) for scripting reads of their own data. The raw token (`lg_…`) is shown **exactly once**, at creation — the server stores only its SHA-256 hash plus a short display prefix, so it cannot be recovered later; revoke it and mint a fresh one instead.

Tokens are **read-only by construction**: they authenticate `GET` requests only, and never authorize any change — every create/update/delete route requires a browser session, token or not.

```bash
TOKEN="lg_REPLACE_WITH_YOUR_TOKEN"
BASE="https://leakguard-hh8e.onrender.com"

curl -H "Authorization: Bearer $TOKEN" $BASE/api/v1/action-center
curl -H "Authorization: Bearer $TOKEN" $BASE/api/v1/scans
curl -H "Authorization: Bearer $TOKEN" $BASE/api/v1/scans/<job-id>
curl -H "Authorization: Bearer $TOKEN" $BASE/api/v1/remediation/cases
curl -H "Authorization: Bearer $TOKEN" $BASE/api/v1/notifications
curl -H "Authorization: Bearer $TOKEN" $BASE/api/v1/monitoring/timeline
```

Token management itself is session-only (`GET`/`POST /api/tokens`, `DELETE /api/tokens/<id>` from the Privacy Center). A revoked or unknown token answers the same `401` as being signed out. `GET /api/providers/health` stays public. What the platform stores, who processes data, and how long anything is kept: **[Trust & security](https://leakguard-hh8e.onrender.com/trust)**.

## 🗂️ Project layout

| Path | Role |
|---|---|
| `app.py` | The web server: stdlib HTTP, the route table, and the composition root that wires every package together |
| `agent.py` | Zero-token Agent Mode engine — plans, probes, guarded submit |
| `core/` | Cross-cutting platform code: SSRF guard + connection pinning, security headers, rate limits, feature flags / emergency controls, retention worker, logging |
| `accounts/` | Accounts: Argon2id auth, sessions, TOTP, passkeys (WebAuthn), consents, identifiers, households, API tokens, audit, admin |
| `vault/` | The encrypted identifier vault (AES-256-GCM envelope encryption, HMAC lookup, masking) |
| `db/` | Postgres pool + the idempotent migration runner and `db/migrations/` |
| `providers/` | Breach-data provider adapters (XposedOrNot, HIBP Pwned Passwords, username/domain checks) behind a registry with health tracking |
| `scanning/` | Scan orchestrator + in-process job queue, findings, risk scoring, scan priority |
| `remediation/` | Removal engine: broker cases, guarded submission, verification & reappearance, the daily broker source sweep |
| `monitoring/` | Continuous monitoring: scheduler, change diff + stored finding lifecycle, timeline, notifications (Brevo email lane) |
| `dashboard/` | Action Center / exposure graph + propagation, privacy-policy analyzer |
| `static/` | The browser UI (SPA) |
| `extension/` | The read-only browser extension (see `extension/README.md`) |
| `browser_probe.py` | Headless-Chromium probe for JavaScript-walled pages |
| `local_agent.py` | Run the engine on your own device/IP |
| `tools/` | Operator utilities (extension packaging, mobile viewport check) |
| `docs/` | Runbooks (incident response, disaster recovery, rollback), acceptance evidence, per-cycle reports (`docs/cycles/`) |
| `brokers.json` | The 40-broker removal directory |
| `playbooks.json` | Hand-mapped removal flows per broker |

## 🔐 Privacy

- **Anonymous Quick Scan:** no account and **no server-side storage** — the scan runs per request and is gone when the response is.
- **Accounts (optional):** the details you save are stored encrypted in the vault (AES-256-GCM; lookups by HMAC, never plaintext), and your scans, findings and removal cases are stored — that storage is what makes monitoring, the Action Center and one-command removal possible. You can export everything from the Privacy Center (JSON or CSV, password re-auth required); the Privacy Center also renders a printable exposure & removal report on demand — masked values only, generated in the moment and never stored — and you can delete the account at any time: deletion is a 30-day soft delete, then a hard purge of everything the account owns; the PII-free audit trail (counts and actions, never values) is kept.
- Removal progress for anonymous use lives only in the visitor's browser (`localStorage`).
- Password checks use k-anonymity — only the first 5 characters of the SHA-1 hash ever leave the server, and passwords are never stored or logged.

## ❓ FAQ

**Is it really free?** Yes — the breach APIs are free, the code has only three small runtime dependencies, and it runs on Render's and Neon's free tiers. ₹0.

**Does LeakGuard store my email or scan results?** For the anonymous Quick Scan, no — it is per-request and nothing is kept. If you create an account, yes: your saved details (encrypted), scans and removal cases are stored so monitoring and one-command removal work — and the Privacy Center gives you a full export and a delete that purges them.

**Why can't it remove data from Telegram / the dark web?** Once a breach dump is copied a thousand times, no request can reach every copy — that's true for every tool, including paid ones. What *can* be removed is what's publicly listed: brokers, people-search sites and Google results.

**Why do some removals go by email?** A few brokers block all datacenter traffic to their web forms. Their official opt-out email channels accept the same legal request and work from any network — so LeakGuard gives you the address and the letter.

## 🗺️ Roadmap

- **Shipped since this list was first written:** recurring monitoring — automatic re-scans on a 7/14/30-day cadence, with alerts when your email appears in a *new* breach or a broker re-lists you
- **v3:** 150+ brokers
- Browser form *filling* for rendered opt-out forms · email-confirmation tracking

---

<div align="center">

**© 2026 Rudra Singh — All rights reserved** · Made as a sister project to [SiteGuard](https://github.com/xorudra/siteguard)

</div>
