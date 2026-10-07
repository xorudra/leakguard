# LeakGuard — Current State

*Refreshed: 2026-10-07 (post-Sentinel acceptance) · Repo: github.com/xorudra/leakguard · Live: https://leakguard-hh8e.onrender.com (Render free) · Database: Neon free (Postgres) · Email: Brevo free (300/day) · Monitored by UptimeRobot (5-min, HEAD-safe). Running cost: ₹0.*

> The original Phase 0 audit (pre-upgrade state, v2.5) is preserved in git
> history at commit `76565e0`. This file describes the product as it stands
> after the Sentinel upgrade (stages S0–S15; see MIGRATION_PLAN.md).

## 1. What the product is

LeakGuard finds leaked personal data and removes what can honestly be
removed. Two modes:

- **Quick Scan** (anonymous, nothing stored): email breach scan
  (XposedOrNot), password check via HIBP k-anonymity (the password is never
  sent or stored), exposure score 0–100, plus the deterministic broker
  agent (probe/submit over 40 brokers) and erasure-letter generator.
- **Full Protection** (free account): saved details in an encrypted vault,
  one-click scans, one-command removal runs with a human queue, continuous
  monitoring with change alerts (in-app + email), a household grouping,
  an Action Center whose single button is the next right action, a public
  /trust page, read-only API tokens, an exposure map, a browser extension
  (sideload), and an installable PWA.

Honest limit, unchanged since v1 and stated on the site: brokers,
people-search sites and Google results CAN be removed; breach dumps
already copied to Telegram/dark web/torrents CANNOT.

## 2. Architecture

Modular Python (stdlib HTTP server; only three pip deps: `psycopg[binary]`,
`cryptography`, `argon2-cffi`):

| Area | Package | Notes |
|---|---|---|
| Core | `core/` | Structured errors + request ids, security headers/CSP, PII-free logging, sliding-window rate limiter, retention worker |
| Data | `db/`, `vault/` | Migration runner (0001–0008); envelope encryption (per-record DEK, AES-256-GCM), HMAC lookup with a separate key, masking |
| Accounts | `accounts/` | Argon2id, 30-day sliding sessions (SHA-256 at rest), TOTP 2FA, versioned consents, households, API tokens, PII-filtered audit log, owner admin (counts only) |
| Providers | `providers/` | One HTTP client (timeouts, ≤2 retries, circuit breakers), adapters: XposedOrNot, HIBP, DuckDuckGo discovery, username presence (13 platforms), domain intel (DoH + crt.sh, TXT-verified ownership) |
| Scanning | `scanning/` | Postgres job queue (SKIP LOCKED, idempotency, backoff, dead-letter), findings with confidence/evidence hashes, risk engine v2 (byte-parity with the legacy scorer) |
| Remediation | `remediation/` | Broker registry in DB, one-command runs, 5-wide worker with a 40s probe budget (relay only when no page was fetched), verification + reappearance, human queue with ready-to-send letters |
| Monitoring | `monitoring/` | Cadence scheduler (consent-gated), scan diffing, notification ledger with dedupe (Brevo lane; statuses honest — `sent` only on provider 2xx), timeline |
| Dashboard | `dashboard/` | Action Center aggregate + next-action engine, exposure graph read model |
| Legacy agent | `agent.py`, `playbooks.json` | The v2 deterministic engine, wrapped by the remediation executor |

Workers run in-process (Render free has no paid workers): scan worker,
remediation worker, monitoring scheduler, retention worker — all guarded
so a database failure can never take the anonymous site down (health
reports `db: ok|disabled|error` honestly).

## 3. Verified state (acceptance, 2026-10-07)

- Test suite: **275 tests**, all passing (2 environment skips).
- Production baselines identical to the pre-upgrade product:
  test@example.com → 214 breaches, exposure 100; "password" → 52,372,427.
- Every stage S1–S14 has a parent-run production end-to-end check on
  record (accounts/TOTP, scanning, remediation 40-case run, monitoring,
  Brevo password-reset email round-trip, Action Center, households,
  admin counts-only, rate limits + the X-Forwarded-For fix, API tokens,
  graph/PWA).

## 4. Known gaps

1. Per-broker verification search sources unmapped → case-level Verify
   answers "unknown" in production (never guessed); monitoring diffs
   cover appearance/disappearance, reappearance wiring is live.
2. Datacenter-IP walls: 27/40 production cases classify blocked with
   reasons + next steps; the residential-IP local agent remains the
   practical route for those brokers.
3. Brevo free cap 300 emails/day; Render free sleeps when idle (~50s
   wake) and shares free hours across the owner's services.
4. Browser extension is sideload-only (Web Store publishing needs a
   paid developer account — against the free rule).
