# Claims audit — WORKING FILE (2026-10-08)

Read-only audit companion to the Phase 176 limitations review
(`docs/reviews/2026-10-08-limitations-register-review.md`).
That review verified 28 limitation claims in CURRENT_STATE.md,
MIGRATION_PLAN.md, /trust (its §C) and the home page's #honest /
Quick-Scan-hint / privacy sections (its §D). This audit does NOT
re-verify those 28; it covers the claim surface they did not:
numeric/performance claims, monitoring cadence, the "40
brokers" framing, Agent Mode capability wording, security
wording outside /trust, removal-success wording, pricing/free
claims, and the README (HEAD 165da84).

## Sources and method

- Live site fetched 2026-10-08: `/`, `/trust`, `/privacy`,
  `/terms`, `/support`, `/reset` all return 200 with the same
  47,669-byte SPA shell; the shell is byte-identical to the
  repo's `static/index.html` (production commit 30c5741).
  `/.well-known/security.txt` fetched live (200). No live page
  failed to fetch; the service was already awake.
- Ground truth: the repo working tree (== deployed code),
  `static/app.js` (dynamic copy), `brokers.json`,
  `playbooks.json`, `requirements.txt`, and the code paths
  cited per row.
- Verdicts: DEMONSTRATED (implementation evidence at the cited
  location), PARTIAL (real but narrower than the words),
  UNSUPPORTED (no implementation evidence).

## A. DEMONSTRATED — keep (one line each)

| # | Claim (location) | Evidence |
|---|---|---|
| A1 | "40 brokers covered" (index.html hero stat; README Removal Centre) | `brokers.json` counted: exactly 40 entries. README states the depth honestly in the same breath — 16 hand-mapped playbooks, generic coverage for all 40 (`playbooks.json` counted: 16) |
| A2 | Exposure score "0–100" with a risk label (hero stat; README Score row) | `scanning/risk.py:15,64` — score clamped 0..100; label bands rendered in `static/app.js:49-51` |
| A3 | Agent Mode burns "0 tokens", is "pure scripts", "no AI" (hero stat; #agent heading; README "No AI anywhere") | `agent.py:5-7` docstring (deterministic, former AI fallback removed); zero LLM/FreeLLMAPI references in any served `.py`; plan endpoint self-describes "no AI involved" (`app.py` /api/agent/plan) |
| A4 | Hero pill "SCANS STORE NOTHING" (scoped by its own pill context to the no-sign-up Quick Scan) | Anonymous scan writes nothing server-side (176 review D2); the browser-side last-scan summary in localStorage is disclosed in the privacy policy section |
| A5 | Monitoring re-checks on a 7/14/30-day schedule (Privacy Center Monitoring; README roadmap "Shipped") | `monitoring/scheduler.py:47` hourly tick (TICK_SECONDS=3600); cadence read from `user_settings.monitor_cadence_days` (default 7); the UI offers exactly 7/14/30 |
| A6 | Monitoring email is "the check's summary" in the inbox, only with Notifications permission on (Privacy Center Monitoring) | `monitoring/notify.py:28,62,179` — per-cycle email is the single `scan_summary` digest via create_notification; per-finding notices are in-app only (`create_notifications_batch`, :368-379) |
| A7 | Domains: "Monitoring only starts after you prove the domain is yours… Until then the domain is never looked at" (Privacy Center, My domains) | `scanning/orchestrator.py:18-21` — domains scanned ONLY when verified; unverified domains produce outcome `domain_unverified` and are never scanned |
| A8 | Household: members are "just a name label… we store nothing about them beyond the label you type" (Privacy Center, My household) | `accounts/households.py:78` inserts only (household_id, label); :52 selects id/label/created_at. No member accounts exist (Phase 59 record agrees) |
| A9 | Identifier-kind coverage + "a mention… is a lead — never proof" (Privacy Center, My saved details) | `scanning/orchestrator.py` kind routing (email→breach DBs; phone/name/address→web mentions; username→platform profiles + mentions; domain→verified-only); confidence vocabulary enforced by schema CHECK (176 review A4) |
| A10 | Full scan: unchecked kinds are reported as "no checks available yet", "never as safe" (Privacy Center, Full scan) | Orchestrator outcome `no_provider_yet` (`scanning/orchestrator.py:22`); UI renders "no checks available for this kind of detail yet" (`static/app.js:2329`) |
| A11 | TOTP: "Codes are single-use — a code that worked once never works again" (Privacy Center, 2FA) | `accounts/totp.py:6-10` — verify() refuses any step not strictly newer than the last accepted step; callers persist the step |
| A12 | Passkeys: only the public half stored; UV (fingerprint/face/PIN) required at sign-in; ES256/RS256 only; attestation `none` only; counter rollback fails sign-in (README Operations; Privacy Center) | `accounts/webauthn.py:24,27-34,91,326,332` — `_FLAG_UV` enforced via `require_uv` at sign-in; only COSE -7/-257 (RSA ≥2048) accepted; counter regression returns 401. (The absolute phrasing "cannot be phished or leaked" is P8 below) |
| A13 | API tokens are "read-only — they can never change, submit or delete anything", hash-only storage, shown exactly once (Privacy Center, API access; README API section) | `app.py:334-362` — Bearer tokens authenticate GET reads; every POST route passes `_require_user` (session only), "so a Bearer token alone" cannot mutate; `accounts/api_tokens.py` stores SHA-256 + prefix |
| A14 | Account Removal: "One tap opens a removal case with every data broker in the registry" (Privacy Center, Removal) | `remediation/service.py:88` iterates the registry brokers in order when a run starts; the paired "only says Removed after re-check" sentence is 176 review A2/C1 evidence |
| A15 | Exposure map "drawn only from real scan findings and real cases, never guessed" (Privacy Center, Exposure map) | `dashboard/graph.py:5,75` — built from the latest completed scan job's findings and their remediation cases; honestly empty when neither exists |
| A16 | Privacy policy: findings record "an evidence hash — not the raw saved detail" | `db/migrations/0003_scans.sql:10,61` — `evidence_ref` is a SHA-256 over a canonical payload |
| A17 | README rate-limit table — all seven route limits, credential limiter "10 attempts / 15 min, IP and account email", and the 256 KB body cap → 413 | `core/ratelimit.py:37-44` matches every number (30/30/30/5/10/10/6 per hour); `accounts/ratelimit.py:21-22` MAX_ATTEMPTS=10, WINDOW=15 min; `app.py:89,673` MAX_BODY=256×1024 → `body_too_large` |
| A18 | README: "only three small runtime dependencies" + Dependencies badge | `requirements.txt` — exactly psycopg[binary], cryptography, argon2-cffi |
| A19 | README roadmap "Shipped": monitoring alerts "when your email appears in a new breach or a broker re-lists you" | `monitoring/diff.py` lifecycle writer + `monitoring/notify.py:62` kinds include `new_finding` and `reappeared` |
| A20 | Support page: findings can be disputed / marked "Not me" | `POST /api/findings/feedback` exists in the route inventory (`app.py`) and the POST route list |
| A21 | README (Run it yourself): `local_agent.py` "never submits anything automatically" | `local_agent.py:23` — submission happens by the user in their own browser |
| A22 | security.txt: contact + canonical URL, expiry in the future | Fetched live 2026-10-08: Contact mailto present, Canonical matches the live URL, `Expires: 2027-10-07` |
| A23 | Privacy policy checker is "a fixed keyword checklist, not a legal verdict" (Privacy Center) | Self-limiting copy matches the implementation: `dashboard/policy_analyzer.py` is a fixed keyword checklist; the copy's caveats are accurate |
| A24 | Consent: "Switching off is instant and recorded" (Privacy Center, My permissions) | `accounts/consents.py` records every change (history surfaces in the data export, `accounts/privacy.py` build_export); consent is re-checked at case/replay time (`remediation/policy.py`, Phase 119 record) |
| A25 | README: without a database, "the account features answer unavailable and the anonymous surface… still runs" | `db/pool.py` graceful degradation (also `requirements.txt:9-10`); consistent with the recorded pre-Neon live behavior (health honestly reported db error while the anonymous surface served) |
| A26 | Terms: "No guarantee of removal", service "may sleep when idle" | Self-limiting and accurate (176 review A8/B4 platform record); no action |

## B. PARTIAL — rewrite recommended

| # | Claim (location) | Verdict basis | Recommended action + suggested wording |
|---|---|---|---|
| P1 | "₹0 — free forever" (hero stat, index.html) and "Free forever, like everything here" (account hint) | PARTIAL — the present tense is demonstrated (₹0, no payment surface anywhere, free tiers; 176 review C4). "Forever" is an unconditional promise about the future that no code can demonstrate; it silently depends on Render/Neon/Brevo free tiers continuing to exist | REWRITE: hero stat label → "₹0 · free — no card, no paid tier"; account hint → "Free, like everything here." Drop "forever" in both places; the ₹0 fact stands on its own |
| P2 | Agent Mode: "You watch it work; there is nothing else for you to do" (index.html #agent intro) | PARTIAL — the run does probe all 40 and auto-submit fillable forms (`static/app.js:522-640`), but the same page contradicts the sentence twice: email-broker letters open in the user's mail app ("your only job there is pressing Send", #draftHint) and CAPTCHA/sign-in brokers are handed back with manual steps (run summary + account Removal copy) | REWRITE → "You watch it work. The only steps ever handed back to you are the ones no tool can honestly do for you: pressing Send on the email-broker letters, and any broker hiding behind a CAPTCHA or sign-in — each listed with the exact step to finish." |
| P3 | README: "Guarded submit — submission only behind your explicit per-broker confirmation" | PARTIAL — the API contract is real (`/api/agent/submit` refuses without `confirm: true` per call, broker-host SSRF guard, `app.py` agent/submit handler), but the shipped UX is ONE press confirming the whole 40-broker run (the page sets confirm:true per call, `static/app.js` autoSubmit/autoBtn). "Per-broker confirmation" tells a reader they confirm each broker individually — stricter than what ships | REWRITE → "Guarded submit — a run starts only from your explicit confirmation (one press confirms the run); every submission call still requires the confirm flag, and submissions only ever go to the broker's own host." |
| P4 | Footer: "No scan data is stored on this server" (index.html footer, site-wide) | PARTIAL — true only for the anonymous Quick Scan. For account holders, scan results and findings ARE stored server-side — the site's own /trust page and privacy policy say so explicitly. As a blanket footer line it contradicts the site's own trust copy | REWRITE → "Anonymous Quick Scan stores nothing on this server." |
| P5 | Password hint: "Your password never leaves this page in plain form and is never stored" (index.html #scan; same family as the /trust "never sent" wording) | PARTIAL — the protection is real but the boundary is misstated. `static/app.js:30` POSTs the plaintext password to LeakGuard's own server over HTTPS; `app.py:773` reads it and hashes server-side (`app.py:127-133`); only sha1[:5] ever leaves the server, and it is never stored or logged. Note: the 176 review's D2 verdicted this hint ACCURATE on the HIBP-leg evidence; this audit flags the browser→server leg that review did not examine, and the README already carries the precise wording | REWRITE the hint to the README's own accurate sentence → "Checked safely with Have I Been Pwned k-anonymity: your password is hashed on our server, only the first 5 characters of the hash ever leave it, and the password is never stored or logged." |
| P6 | README Agent Mode probe table: "Real browser — Headless Chromium for JavaScript-walled pages" listed as a standing layer | PARTIAL — the layer exists in the engine (`agent.py:319` probe_with_browser_fallback) but Playwright is NOT installed on the hosted deployment (it lives in `requirements-optional.txt` only); there the deep pass is HTTP + relay and the probe honestly reports "Playwright not installed on this server" (`browser_probe.py:31-32,237`). The table presents the layer without that qualifier (the qualifier exists, but only in the Run-it-yourself section) | REWRITE the table row → "Real browser — Headless Chromium for JavaScript-walled pages (optional install; on the hosted service the deep pass uses HTTP + relay and says so when a page would need a real browser)" |
| P7 | Quick Scan: "type one email address and see its breaches in seconds" (index.html #scan hint) | PARTIAL (minor) — true on a warm instance (one XposedOrNot lookup); the free service sleeps when idle with a ~50 s wake (disclosed in Terms and the 176 review A8), so a first visit after idle is not "in seconds" | REWRITE (soften) → "…see its breaches in seconds — if the free server was asleep, the first check can take about a minute while it wakes." |
| P8 | Passkeys "cannot be phished or leaked" (index.html, Privacy Center passkey hint) | PARTIAL (minor) — the mechanism genuinely is phishing-resistant (origin-bound WebAuthn, UV enforced at sign-in, only the public half stored — A12). But "cannot be leaked" as an absolute also covers the device-side private key, which LeakGuard does not control, and no implementation can demonstrate an absolute negative | REWRITE → "…and it is phishing-resistant by design — there is no password to phish or leak: LeakGuard stores only the passkey's public half, never anything that could sign in as you." |

## C. UNSUPPORTED

None found. Every material claim on the live pages and in the
README traced to implementation evidence; the gaps are all
overstatement-by-wording (Section B), not missing features.

## D. Notes for the parent

- The single sharpest item is **P4**: the footer contradicts
  the site's own /trust page in the same visitor's session.
- **P5** is the only place this audit's verdict differs in
  direction from the 176 review (its D2). The difference is
  scope, not evidence: D2 checked the server→HIBP leg
  (sha1[:5], accurate); the browser→server leg (plaintext
  password in the /api/scan JSON body, `static/app.js:30`)
  makes the literal sentence broader than the implementation.
  Aligning the copy to the README's wording resolves both.
- Everything else on the home page and README that sounds
  like marketing ("Find it. Remove it.", "FULL PROTECTION",
  the Action Center's "one most useful thing to do next")
  either traces to a mechanism above or is headline puffery
  immediately qualified by the honest-limits copy beside it.
- Pages fetched live, all successfully: /, /trust, /privacy,
  /terms, /support, /reset (one shared SPA shell),
  /.well-known/security.txt.
