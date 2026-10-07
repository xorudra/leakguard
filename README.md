<div align="center">

# 🛡️ LeakGuard

### Your data got leaked. Find it. Remove it.

### 🌐 Live Website: [leakguard-hh8e.onrender.com](https://leakguard-hh8e.onrender.com)

[![Live Demo](https://img.shields.io/badge/▶_Live_Demo-leakguard--hh8e.onrender.com-2ea043?style=for-the-badge)](https://leakguard-hh8e.onrender.com)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-important?style=for-the-badge)
![Cost](https://img.shields.io/badge/Cost-₹0_Free-success?style=for-the-badge)

**Scan → Score → Remove.** A free web tool that finds your leaked personal data and walks you through erasing it — built on India's **DPDP Act**, **GDPR** and **CCPA** erasure rights. No accounts. No database. Nothing to install.

</div>

---

## ✨ What it does

| Step | What happens |
|---|---|
| 🔍 **Scan** | Enter your email — LeakGuard checks real breach databases ([XposedOrNot](https://xposedornot.com), free, no API key) and lists exactly which breaches contain you and what data types leaked. Optional password check via [Have I Been Pwned](https://haveibeenpwned.com/Passwords) using k-anonymity — the password itself never leaves your device. |
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
  | Real browser | Headless Chromium for JavaScript-walled pages |

  It pre-fills the form payload with your details and honestly reports blockers — CAPTCHA, login walls, bot protection — instead of pretending they aren't there.
- ✉️ **Email channels** — some sites (e.g. BeenVerified, Nuwber) wall their web forms off from datacenter networks entirely. LeakGuard surfaces their official opt-out **email addresses**, which work from anywhere.
- 🔒 **Guarded submit** — submission only behind your explicit per-broker confirmation, and only to the broker's own host.
- ⚡ **Optional free-lane fallback** — cryptic form fields can be classified by *your own* FreeLLMAPI gateway (`LEAKGUARD_FREE_LANE_URL` / `LEAKGUARD_FREE_LANE_KEY` / `LEAKGUARD_FREE_LANE_MODEL`, e.g. `openai/gpt-oss-20b`, `gemini-3.5-flash-lite`). Off by default; only your gateway's free tiers.

## ⚖️ The honest limits

> - ✅ **Can be removed:** data brokers, people-search sites, Google search results — they must answer a legal erasure request.
> - ❌ **Cannot be removed:** a breach dump already copied to Telegram, dark-web forums or torrents. No tool can delete every copy — anyone promising that is lying. The defence there is changing compromised passwords and turning on 2FA.
> - 🧑 CAPTCHA, email-confirmation and phone-verification steps always need you. By design — they're proof you're a human removing *your own* data.

## 🚀 Run it yourself

Zero dependencies — Python 3 standard library only.

```bash
python3 app.py
# open http://localhost:8000
```

Environment: `PORT` (default 8000) · `HOST` (default 0.0.0.0)

**📱 On your own device** (recommended for walled sites): `python3 local_agent.py` runs the same engine under your home IP, where broker sites behave normally. It probes, prints the plan, and can open opt-out pages in your browser — it never submits anything automatically.

**🧩 Optional browser probe layer:** `pip install -r requirements-optional.txt` plus any Chromium/Chrome. On proxy-locked networks run `python3 proxy_relay.py` and set `LEAKGUARD_BROWSER_PROXY=http://127.0.0.1:8899`. Disable with `LEAKGUARD_NO_BROWSER=1`.

**☁️ Deploy:** `render.yaml` is included — create a Web Service from this repo on Render's free tier (or use Blueprint). Start command `python3 app.py`, no build step.

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

**Retention** (an in-process worker runs one pass daily; every purge is audit-logged with counts only):

| Data | Kept for |
|---|---|
| Sessions | deleted once expired or revoked for more than 7 days |
| Password-reset tokens | deleted once used or expired for more than 7 days |
| Notifications | 90 days |
| Deleted accounts | soft-deleted for 30 days (recoverable by support), then hard-purged with everything the account owns — identifiers, scans, findings, removal cases, settings, household. The PII-free audit trail (counts and actions, never values) is kept. |

**Database connections:** two environment variables, split by privilege. `DATABASE_URL` is the runtime connection and should be a **least-privilege role** (SELECT/INSERT/UPDATE/DELETE only — no DDL); everything the running app does goes through it. `MIGRATION_DATABASE_URL` is an **owner-level** connection used only by the boot-time migration step, which needs DDL; it is never used to serve requests. When `MIGRATION_DATABASE_URL` is unset, migrations fall back to `DATABASE_URL` (the pre-split behavior — convenient for local development and tests, where one connection does both jobs).

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

| File | Role |
|---|---|
| `app.py` | The web server + GUI (stdlib only) |
| `agent.py` | Zero-token Agent Mode engine — plans, probes, guarded submit |
| `browser_probe.py` | Headless-Chromium probe for JavaScript-walled pages |
| `local_agent.py` | Run the engine on your own device/IP |
| `brokers.json` | The 40-broker removal directory |
| `playbooks.json` | Hand-mapped removal flows per broker |

## 🔐 Privacy

- No accounts, no database, **no server-side storage of scans**.
- Removal progress lives only in the visitor's browser (`localStorage`).
- Password checks use k-anonymity — only the first 5 characters of the SHA-1 hash ever leave, and passwords are never logged.

## ❓ FAQ

**Is it really free?** Yes — the breach APIs are free, the code is dependency-free, and it runs on Render's free tier. ₹0.

**Does LeakGuard store my email or scan results?** No. Scans happen per-request and are never stored server-side.

**Why can't it remove data from Telegram / the dark web?** Once a breach dump is copied a thousand times, no request can reach every copy — that's true for every tool, including paid ones. What *can* be removed is what's publicly listed: brokers, people-search sites and Google results.

**Why do some removals go by email?** A few brokers block all datacenter traffic to their web forms. Their official opt-out email channels accept the same legal request and work from any network — so LeakGuard gives you the address and the letter.

## 🗺️ Roadmap

- **v3:** 150+ brokers · recurring monitoring — monthly re-scans with alerts when your email appears in a *new* breach or a broker re-lists you
- Browser form *filling* for rendered opt-out forms · email-confirmation tracking

---

<div align="center">

**© 2026 Rudra Singh — All rights reserved** · Made as a sister project to [SiteGuard](https://github.com/xorudra/siteguard)

</div>
