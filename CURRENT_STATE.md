# LeakGuard — Current State (Phase 0 Audit)

*Audit date: 2026-10-07 · Repo: github.com/xorudra/leakguard · Live: https://leakguard-hh8e.onrender.com (Render free, commit 6aae0f6, v2.5 Zero-touch) · Monitored by UptimeRobot (5-min, HEAD-safe).*

## 1. What the product is today

A single-file-stack, zero-dependency Python web app that (a) scans an email against
breach data and scores exposure 0–100, (b) checks passwords via k-anonymity, and
(c) runs a deterministic removal agent over 40 data brokers — probing their live
opt-out forms and, since v2.5, submitting automatically behind one user press.

## 2. Architecture inventory

| Component | File(s) | Lines | Notes |
|---|---|---|---|
| HTTP server + API | `app.py` | 327 | Python 3.12 stdlib `http.server` only; `do_GET/do_POST/do_HEAD`; JSON body parsing; SSRF guard on submit |
| Removal agent engine | `agent.py` | 458 | Playbook plan builder, HTTP probe, relay-reader probe, browser-fallback orchestration, submit, optional free-lane field classification |
| Browser probe | `browser_probe.py` | 142 | Playwright + system Chromium, subprocess-isolated; NOT available on Render (no Playwright there) |
| Local runner | `local_agent.py` | 80 | Zero-dep script for the user's own device/IP (residential-IP brokers); never auto-submits |
| Proxy relay (dev) | `proxy_relay.py` | 95 | Local CONNECT relay for this VM's egress quirk; dev-only |
| Broker registry data | `brokers.json` | 286 | 40 brokers: name, category, region, opt-out URL, search URL, method notes, contact emails (3) |
| Playbooks | `playbooks.json` | 213 | 16 hand-mapped broker flows + generic flow |
| Frontend | `static/index.html` / `app.js` / `style.css` | 193 / 676 / 178 | Vanilla JS, no build step; Spotify-style theme; progress in browser localStorage only |
| Deploy | `render.yaml` | 10 | Render free web service, `python3 app.py`, no build |

**Routes:** `GET /` (SPA), `GET /static/*`, `GET /api/health`, `GET /api/brokers`,
`POST /api/scan` (XposedOrNot email breaches + HIBP Pwned Passwords k-anonymity +
exposure score), `POST /api/agent/plan`, `POST /api/agent/probe` (fast + deep),
`POST /api/agent/submit` (explicit `confirm:true` + known-broker-host SSRF guard).

## 3. Feature map (verified live, 2026-10-07)

- Anonymous quick scan: email breaches, data-types exposed, exposure score + label,
  password pwned count, next-step guidance, scan-to-scan delta (browser-local).
- Agent Mode zero-touch run: batch probe (fast pass ~12 s; deep pass via relay +
  alternate URLs), auto-submit of fillable forms, erasure-letter generation
  (DPDP §12 / GDPR Art. 17 / CCPA), mailto drafts for email-channel brokers,
  downloadable letters pack + run report.
- Removal Centre (Advanced): 40-broker manual list, status tracker (localStorage),
  per-broker letters; Google exposure searches + "Results about you" link.
- Verified live run (test profile): 3 auto-submitted (Spokeo, PeopleLooker,
  Data Axle — HTTP 200), 2 email drafts (BeenVerified, Nuwber), 35 blocked with
  exact reasons (403 bot walls, JS-only forms, CAPTCHA).

## 4. What does NOT exist (vs the Sentinel specification)

No persistence of any kind (no database, no accounts) · no auth/authz · no consent
records · no provider abstraction/registry/health layer (integrations are direct
calls in `app.py`/`agent.py`) · no job queue or scheduler (runs are synchronous
in-request) · no continuous monitoring, notifications, history or timeline ·
no phone/username/name/address/domain monitoring · no identity correlation,
evidence engine or removal verification/reappearance detection · no admin,
organizations, family profiles · no API versioning, request IDs, structured
errors · no tests in-repo · no CI/CD · no backups/DR · no privacy/trust center
beyond honest-limits copy.

## 5. Constraints that shape the migration

- **₹0 budget (owner rule):** free tiers only. Render free web = no persistent
  disk, no free background workers, Postgres on Render is trial-only → durable
  Postgres must come from a free external host (Neon or Supabase free tier).
- **Zero-token rule:** product runs must never consume Claude tokens; any AI
  features must route through the owner's free-lane gateway (FreeLLMAPI), off by
  default, with kill switch (spec Phases 51–56, 121, 163–165 align).
- **Honesty rules already in product copy** match spec rules 6–9: never fabricate
  results, never claim removal from submission alone, never bypass CAPTCHA/auth.
- **Working assets to preserve (spec rule 15):** brokers.json, playbooks,
  probe layers, scoring, letter generator, zero-touch UX, Spotify theme.
- **Known platform gaps:** Playwright unavailable on Render (browser probe is
  VM/local-only); Render free sleeps when idle (~50 s wake); free relay
  (allorigins) is intermittent.

## 6. Top risks

1. Scope: 181 phases is a multi-week program — needs phased value delivery, not
   a big-bang rewrite (spec rule 3/5 agree).
2. Free-tier ceilings: external Postgres free limits, Render sleep, no workers →
   scheduler/workers must run in-process in the modular monolith (spec rule 13).
3. Storing identifiers (Phase 3 vault) raises the security bar sharply: envelope
   encryption + HMAC lookups must land before any monitoring feature stores data.
4. Legal surface grows with monitoring/orgs/family — consent (Phase 6) must
   precede those features, not follow them.
