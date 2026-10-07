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

**Retention** (an in-process worker runs one pass daily; every purge is audit-logged with counts only):

| Data | Kept for |
|---|---|
| Sessions | deleted once expired or revoked for more than 7 days |
| Password-reset tokens | deleted once used or expired for more than 7 days |
| Notifications | 90 days |
| Deleted accounts | soft-deleted for 30 days (recoverable by support), then hard-purged with everything the account owns — identifiers, scans, findings, removal cases, settings, household. The PII-free audit trail (counts and actions, never values) is kept. |

**Backups:** the database lives on Neon's free plan. Point-in-time restore is a Neon platform feature and restores are run by the owner from the Neon console; the free plan's restore history is limited, and LeakGuard keeps no second backup copy — the encrypted vault means a database copy alone exposes no identifier values (the master key lives only in the server environment).

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
