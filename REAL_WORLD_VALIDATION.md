# LeakGuard — Real-World Validation Report

Program ordered by the owner 2026-10-08 (~13:53 IST) after the
feature scope was declared complete. Rules held throughout:
feature-complete scope frozen (phases 59/81/98/168 not implemented,
no new features); zero-AI deterministic Agent Mode preserved; no
production change without staging verification; every fix carries a
regression test; non-destructive, low-volume testing against
production only.

Production under test: commit `eda0e35` (deployed 2026-10-08,
deploy dep-db3lk0mgekts73f9la9g; staging dep-db3lj0nlk1mc73c1npv0).
Test identities: two throwaway accounts on example.com addresses
(`rwv-a-20261008@…`, `rwv-b-20261008@…`; B deleted during testing,
A retained for the monitoring cycle). All measurements from this
operator VM's network path unless an environment says otherwise —
that path adds proxy latency and rotates egress IPs, and is labelled
where it matters.

**Scope statement (read first):** this report validates what its
evidence covers — the workflows, probes, and loads actually run
below. It does not declare LeakGuard "fully production validated":
the items under *Not validated* at the end remain open, by name.

---

## Wave 1 — Documentation / claims audit

Method: every material public claim on the live site (/, /trust,
/privacy, /terms, /support, SPA copy) and README compared against
the implementation, building on the Phase 176 review (28 claims).
Full table: `docs/reviews/2026-10-08-claims-audit-working.md`.

| | |
|---|---|
| Claims audited this wave | 34 |
| Demonstrated | 26 |
| Partial (wording overstates the implementation) | 8 |
| Unsupported | 0 |

The 8 partials — all wording, no missing features — and their fixes
(shipped in `eda0e35`, regression-guarded by
`tests/test_public_copy.py`):

1. Footer "No scan data is stored on this server" — true only for
   the anonymous Quick Scan; contradicted the /trust page.
   → "Anonymous Quick Scan stores nothing on this server."
2. "₹0 — free forever" / "Free forever, like everything here" — ₹0
   is present fact; "forever" promises a future resting on
   third-party free tiers. → "free — no card, no paid tier" /
   "Free, like everything here."
3. Agent Mode "there is nothing else for you to do" — the page
   itself hands back two steps. → copy now names them: pressing
   Send on email-broker letters, and CAPTCHA/sign-in brokers, each
   with its finishing step.
4. Password hint "never leaves this page in plain form" — the
   password is posted to LeakGuard's own server over HTTPS; the
   protection is server-side hashing + k-anonymity. → hint now
   states that boundary exactly.
5. README "explicit per-broker confirmation" — the shipped UX is
   one press for the run; the per-call confirm flag is an API
   contract. → README corrected.
6. README probe table listed the headless-browser layer without
   noting it is not installed on the hosted service. → qualifier
   added (the hosted deep pass is HTTP + relay and says so).
7. "breaches in seconds" — gained the sleeping-server caveat
   (~a minute on first wake).
8. Passkeys "cannot be phished or leaked" → "phishing-resistant
   by design — there is no password to phish or leak: LeakGuard
   stores only the passkey's public half…".

Verification: suites at `eda0e35` — pytest 619 passed / 19 skipped;
CI-parity discovery Ran 607, OK (skipped=2); GitHub CI green;
staging smoke and production live checks confirmed the corrected
copy serving and the old strings absent. Severity of the class:
Low (honesty/trust), except the footer line: Medium (it misstated
data storage on a privacy product).

## Wave 2 — Real-world validation (production)

| Test | Result | Evidence |
|---|---|---|
| Quick Scan, known-breach address | PASS | `test@example.com` → 214 breaches, score 100 |
| Quick Scan, password check | PASS | "password" → 52,372,427 (HIBP k-anonymity) |
| Quick Scan, zero-result address | PASS | fresh address → 0 breaches, score 0, `breach_error: null` — honest empty, nothing invented |
| Quick Scan, malformed / missing email | PASS | typed `invalid_email` error, no 500 |
| Full saved-detail scan (account A) | PASS | register → 4 consents → identifier (masked `t•••@example.com` everywhere) → job `a6e2982f` done in **10.3 s**, **214 findings**, `degraded: false`, summary clusters per identifier |
| Action Center | PASS | score 100 "Critical exposure", findings_total 214, monitoring_on true, next action = one-tap removal |
| Notifications | PASS | exactly **1** in-app `scan_summary` for the cycle (by design; per-finding notices are in-app only). Email leg not exercised — the test address is example.com, undeliverable by construction; the Brevo lane itself was proven in earlier phases |
| Dispute / false-positive flow | PASS | `POST /api/findings/feedback {verdict: not_me}` → recorded |
| Monitoring | PASS | consent on, cadence 7 d, `last_scan_at` = scan finish, `next_scan_at` = **2026-10-15T08:56Z** exactly +7 d; settings update via PUT verified |
| Downloadable report (Phase 85) | PASS | signed-in 200 `text/html`, `Cache-Control: no-store`, masked `p•••@example.com` present, plaintext absent (staging smoke + production gating 401 for anonymous) |
| Agent Mode — one-command removal run, all 40 brokers | COMPLETED with honest outcomes | 40 cases created 09:01:54Z, queue drained by 09:07:21Z (~5.5 min). **2 submitted · 11 needs_human · 27 blocked · 0 falsely successful** |
| Removal → verification | PENDING BY DESIGN | verification runs on the follow-up cycle; `verified_removed` = 0 at report time for the test identity. One historical production `verified_removed` exists (Spokeo, Sentinel era) |
| Removal → reappearance | NOT RUN | requires a verified removal first (see Not validated) |

Broker outcome rates (test identity with no real listings, probes
from the production datacenter host — rates for a real user on a
residential connection will differ, mainly on the 403 line):

| Outcome | Count | Detail |
|---|---|---|
| submitted | 2 (5%) | forms accepted |
| needs_human — browser_required | 5 | needs a real browser session |
| needs_human — email_send_required | 3 | letter prepared; user presses Send |
| needs_human — captcha | 2 | human-attestation wall (never automated through) |
| needs_human — manual_only | 1 | broker offers no automated channel |
| blocked — http_403 | 16 | broker bot-walls refuse the datacenter host |
| blocked — http_404 | 9 | **stale opt-out addresses in the broker data** (Finding F1) |
| blocked — unreachable | 1 | broker site down/unreachable |
| blocked — form_not_fillable | 1 | form present, not safely fillable |

Every non-success carries its machine-readable reason on the case;
nothing was recorded as removed without evidence. This matches the
product's published honest limits.

## Wave 3 — Security validation (production, black-box, non-destructive)

| Test | Result | Evidence |
|---|---|---|
| Security headers | PASS | CSP `default-src 'self'` + `frame-ancestors 'none'` + `base-uri 'none'`; HSTS 1 y incl. subdomains; `nosniff`; `X-Frame-Options: DENY`; `Referrer-Policy: no-referrer` |
| Session cookie | PASS | HttpOnly + Secure + SameSite=Lax, Path=/, 30 d |
| CSRF | PASS | POST with no Origin → `csrf_failed`; foreign Origin → `csrf_failed` |
| Login enumeration | PASS | existing-account/wrong-password and nonexistent account return identical `invalid_credentials` |
| Forgot-password enumeration | PASS | identical `200 {"ok": true}` for real and ghost addresses (IP-rate-limited) |
| Registration enumeration | INFORMATIONAL | duplicate registration answers `email_taken` — standard registration UX; recorded as F2, not a vulnerability (login/reset surfaces are safe) |
| IDOR / BOLA (B against A's objects) | PASS | A's scan → 404 "Scan not found"; A's finding dispute → 404; A's removal case → 404. No existence leak |
| Report isolation | PASS | B's report contains zero references to A's data |
| Consent enforcement | PASS | consentless B: removal run → `consent_required`; full scan (with idempotency key) → `consent_required` |
| SSRF | PASS | no user-controlled arbitrary-URL fetch exists server-side; the one URL-input feature (policy analyzer) refuses non-public targets (`policy_url_not_public` for 169.254.169.254); agent probe keys on broker identity, not URLs; connection pinning verified in P0 (Phase 70) |
| Session invalidation | PASS | logout → old cookie returns `unauthenticated` |
| Login rate limiting | PASS | 429 `rate_limited` at the 6th consecutive failed attempt |
| TOTP lifecycle | PASS (live) | enroll → activate with computed code → login without code returns `totp_required` and **no session** → fresh-step code logs in → **replaying the same code → `invalid_credentials`** (single-use enforced) |
| Passkeys | PARTIAL | code-audited (UV enforced at sign-in, ES256/RS256, attestation none — claims audit A12) + full unit coverage; live browser ceremony not completed (Wave 5 harness limitation, L4) |
| API tokens | PASS | created (raw shown once) → reads via `/api/v1/*` Bearer work → token-only mutation → `unauthenticated` (read-only enforced) → revoke → reuse → `unauthenticated` |
| Data export | PASS | POST-only, **password step-up required** (no GET variant); JSON 200 (account/consents/domains/identifiers sections); CSV 200 `text/csv` with the same sections; export password attempts count against the credential limiter (observed live) |
| Account deletion | PASS | password-confirmed deletion → `{"ok": true}`; the deleted account's session immediately `unauthenticated`; login impossible |
| Leakage via errors/paths | PASS | malformed JSON → typed `invalid_json`, no stack traces; `/.env`, `/.git/config`, `/app.py`, `/server.py`, `/wp-admin` → 404; every API response carries `Cache-Control: no-store` (P2-I, re-verified on /api/report) |
| File handling | N/A by design | the product has no upload surface; nothing to test |

No security finding above Informational was found.

## Wave 4 — Performance / load validation

Workload profile (from Waves 2–3 + admin metrics design): the
realistic load is Quick Scans (one provider round-trip), occasional
full scans (per-identifier provider calls + persistence), an hourly
monitoring scheduler, and a queued removal worker.

| Measurement | Environment | Result |
|---|---|---|
| Health latency, warm ×5 | production | 0.49–0.98 s (first hit 2.34 s) |
| Quick Scan latency ×3 | production | 0.67–0.76 s end-to-end incl. provider |
| Homepage | production | 48 KB, TTFB 0.42 s, total 0.48 s |
| Full scan, 214 findings | production | 10.3 s |
| Removal worker throughput | production | 40 brokers in ~5.5 min ≈ 8.2 s/broker |
| Cold start (asleep → health 200) | staging | **55.7 s** — the free-tier sleep, disclosed in Terms |
| 10 concurrent Quick Scans | staging | **10/10 HTTP 200**, 4.5–5.0 s each (vs ~0.7 s solo) |
| 10 concurrent health | staging | 10/10 200, slowest 3.17 s |

Capacity statement: the deployment is a **single Render free
instance**; at 10-way concurrency it answers everything correctly
with roughly linear latency inflation and no errors. No horizontal
scaling exists and none is claimed. The practical ceiling is the
free instance's CPU/memory plus provider rate limits; a load test
beyond 10 concurrent was not run against the live services (owner's
no-high-volume rule for production; staging shares the account's
free hours).

## Wave 5 — UX validation (mobile, production, real browser)

Environment: Chromium, 412×915 Android viewport, via the operator
VM's local relay (the only browser path off this VM).

| Check | Result |
|---|---|
| Page load + title | PASS |
| Horizontal overflow | PASS — scrollWidth == innerWidth (412) |
| Corrected footer copy live in browser | PASS |
| Quick Scan journey in the UI | PASS — results render, 214 shown |
| Sign-in reachability | PASS — visible "Sign in" call-to-action, 1 tap reveals the account form |
| Report controls present | PASS — "Open my report", "Download full report (.txt)" |
| Tap targets | PASS — 48 visible buttons, **0** under 32 px tall |
| Console errors | PASS — only the expected anonymous-session 401 probe |
| Signed-in browser legs (report open, passkey ceremony) | NOT COMPLETED — the operator VM's relay intermittently drops the login POST/response (the identical credentials returned 200 via API repeatedly, before and after; a direct browser path off this VM does not exist — `ERR_TUNNEL_CONNECTION_FAILED`). Recorded as a test-environment limitation (L4), not a product defect |

No UX defect was found in what could be exercised; per the program
rules, nothing was redesigned.

## Wave 6 — Reliability validation

| Test | Environment | Result |
|---|---|---|
| Duplicate full scan (same idempotency key) | production | PASS — the **same job** returned, no duplicate |
| Duplicate removal run | production | PASS — `cases_created: 0`, total stays 40, statuses unchanged |
| Broker site changes | production | PASS — the 9 moved opt-out pages (404) and 16 bot-walls (403) were recorded as `blocked` with reasons; **never** as submitted/removed |
| Provider outage honesty | local suite | PASS — provider-outage and worker-failure classes green in the full-suite runs at `eda0e35` (outage alerting, degraded scans surface `error_kind`; a scan with a dead source completes honestly degraded, findings never fabricated) |
| SSRF fail-closed | local suite | PASS — `TestFailClosed` green standalone |
| Dead letters / replay | suite (P2-G) | covered by the admin replay implementation + tests; not re-run live (needs the owner's admin login, L5) |
| Notification failure | design + suite | in-app records are written in the same transaction family as the events; the email lane failing cannot lose the in-app record (P2-B semantics, suite-covered) |
| Stale jobs / retries | suite | job retry + attempts fields exercised across the suite; the Wave 2 job shows `attempts` tracked on the record |

## Findings register

| # | Finding | Severity | Fix | Regression test |
|---|---|---|---|---|
| F1 | 9 of 40 broker opt-out addresses in `playbooks.json` answered 404 during the live run — stale broker data | Low (user impact: those brokers land in `blocked` with an honest reason; the data should be refreshed) | **Not fixed in this program.** Recommended: a broker-data refresh pass (re-probe all 40 opt-out URLs, update moved addresses), staging-first, as its own cycle | the refresh pass should re-run the live probe table from Wave 2 and diff outcomes |
| F2 | Duplicate registration discloses account existence (`email_taken`) | Informational — standard registration UX; login and reset surfaces are enumeration-safe | none (by design) | — |
| F3 | Scan-detail payload is ~130 KB for a 214-finding scan (full findings inline) | Informational — acceptable at current scale; a pagination opportunity if finding counts grow | none now | — |
| F4 | (Wave 1) 8 public claims overstated the implementation | Low–Medium | fixed in `eda0e35` (see Wave 1) | `tests/test_public_copy.py` (8 tests) |

## Limitations register — additions (2026-10-08)

- L1: Removal **verification** for the 2 submitted test cases
  resolves on the follow-up verification cycle; at report time
  `verified_removed` for the test identity is 0. The lifecycle's
  final leg (reappearance) is unvalidated for a real listing.
- L2: Monitoring's first real production cycle for the test
  account lands 2026-10-15 (7-day cadence) — scheduling is proven;
  the cycle's execution will be observable then, not before.
- L3: Email delivery was not exercised in this program (test
  addresses are example.com). The Brevo lane and digest semantics
  were proven in earlier phases.
- L4: Signed-in **browser** legs (report open, passkey ceremony)
  could not be completed through the operator VM's relay; both are
  proven at API level (report) and code+suite level (passkeys).
  A clean-path browser run remains the way to close this.
- L5: Admin surfaces (metrics, replay UI) were not live-tested in
  this program — they require the owner's admin login; their
  gating was verified anonymously (404) and their implementation
  is suite-covered.
- L6: Load validated to 10 concurrent requests. Beyond that is
  unmeasured, and no scalability claim is made.

## Not validated (explicit)

- Removal → verification → reappearance for a genuine personal
  listing (the test identity has none; submitting removals for a
  real person's data was out of scope for a test identity).
- Email delivery to a real inbox within this program (L3).
- Passkey sign-in ceremony in a live browser (L4).
- Load beyond 10 concurrent; multi-instance behavior (there is
  one instance).
- The monitoring cycle's execution on 2026-10-15 (L2) — scheduled
  and observable, not yet occurred.

---

## Addendum — F1 resolved (2026-10-08, owner-authorized maintenance)

The 9 stale opt-out addresses (in `brokers.json`, the broker registry) were
refreshed in a dedicated staging-first cycle. Every replacement was verified
as the broker's own official opt-out destination, traced from the broker's
own site or privacy policy — no address was invented, and every one of the 9
brokers still operates an online route, so none had to be marked unavailable.

| Broker | Before | After (verified destination) | Live outcome after fix (production) |
|---|---|---|---|
| NeighborWho | neighborwho.com/opt-out (404) | beenverified.com/svc/optout/search/optouts (NeighborWho's own FAQ/footer flow redirects to its sister brand's portal; same removal system) | blocked / http_403 (portal bot wall — page exists) |
| AdvancedBackgroundChecks | /optout (404) | /opt-out (the site's own /do-not-sell notice page links it; live form on the page) | **submitted** |
| InfoTracer | members.infotracer.com/optout.aspx (404) | infotracer.com/optout/ | blocked / form_not_fillable |
| SearchQuarry | /removal-request (404) | searchquarry.com/opt-out-new/ | needs_human / browser_required |
| LexisNexis Risk Solutions | /consumerDisclosurePortal (404) | consumer.risk.lexisnexis.com/request | needs_human / captcha |
| Experian | experian.com/privacy/opt-out (404) | consumerprivacy.experian.com (per Experian's own US Consumer Data Privacy Policy) | needs_human / browser_required |
| Equifax | /privacy-statement/opt-out (404) | myprivacy.equifax.com/opt-in-opt-out/personal-info/ (per Equifax's own Privacy Statement) | needs_human / browser_required |
| CoreLogic | corelogic.com/privacy/opt-out (404) | cotality.com/privacy.aspx (company rebranded to Cotality; privacy page links the request portal; method text now states the GLBA/FCRA limits honestly) | blocked / form_not_fillable |
| LiveRamp | /privacy/your-privacy-choices (404) | liveramp.com/privacy/my-privacy-choices | blocked / form_not_fillable |

Validation: commits `461ef91` + `e6738ba` (the second corrects the first
AdvancedBackgroundChecks candidate, /removal, which staging validation
showed still answering 404 — replaced with the broker's own /opt-out form
page before production ever saw it). Suites: pytest 619 passed / 19 skipped
(two runs), CI-parity discovery Ran 607 OK, GitHub CI green on both commits.
Full 40-broker runs executed on staging (twice) and production (fresh test
account): **http_404 outcomes went 9 → 0 in both environments**; totals moved
2 submitted / 11 needs_human / 27 blocked → **3 / 15 / 22**; the only new
submission is AdvancedBackgroundChecks through its corrected form; the other
31 brokers' statuses are unchanged versus the Wave 2 run; baselines intact
(214 / 100 / 52,372,427). No code, workflow, channel, or scope changes —
`brokers.json` data only.

### Addendum (2026-10-08, owner live-run report): false "unreachable" verdicts in Agent Mode — FIXED

The owner ran Agent Mode ("Remove my data everywhere") on production and
reported the results (screenshots). Outcomes were 4 submitted / 2 letters /
34 blocked; the blocked set contained verdicts that were **not true**, all
in the Agent Mode probe path (the account remediation flow was not
implicated):

1. **CoreLogic, LiveRamp, Epsilon (Conversant)** were reported
   "unreachable from the server right now". All three are reachable —
   before the fix and after — in single probes and in a 10-way
   concurrent burst (HTTP 200). Root cause, found in the code: that
   sentence was the browser client's catch-all for its own 120-second
   abort of the deep probe, while the server's deep chain could
   legitimately run ~160s (direct 15s + relay 3 attempts x 45s +
   backoff + browser layer). Slow chains were cut off mid-flight and
   the abort was misreported as a server verdict.
2. **ClustrMaps** was refused by the SSRF guard ("did not pass the
   outbound safety check"). Verified via public DNS (dns.google,
   controls resolving normally): **clustrmaps.com deliberately
   publishes a loopback A record (127.0.0.1)** for these networks —
   the guard's refusal is correct; only the wording was jargon.
3. Contributing factor: a single transient network failure hardened
   into a permanent "Page unreachable" verdict (no retry anywhere in
   the direct fetch).

Fix (commit `053b1d5`, staging-first, production deploy
dep-db3s3djncjis73bjjh50, live 2026-10-08 21:46 IST): the relay layer is
bounded to 2 attempts x 30s; the client windows are widened (fast 40s,
deep 150s); a client-side timeout now honestly reports that the check
timed out before a verdict; the direct fetch retries exactly once on
transient failures (HTTP answers are verdicts, never retried); the
non-public-resolution refusal now explains in plain words that the
broker's site deliberately refuses server networks. Regression tests:
`tests/test_agent_probe_resilience.py`. Suites: pytest 625 passed /
22 skipped; CI-parity discovery OK (skipped=2); GitHub CI green.
Post-deploy evidence, both environments: deep probes for CoreLogic
and LiveRamp return reachable / HTTP 200 / 1 form in ~44s (inside the
window with wide margin); ClustrMaps serves the new plain-language
blocker; Epsilon (Conversant) reports its true CAPTCHA wall and
InfoTracer its true JavaScript-form wall; baselines intact
(214 / 100). No broker outcome became a success that was not one
before — the remaining blocked set is the brokers' documented
anti-bot wall (403 / CAPTCHA / login / JavaScript), unchanged.

### Addendum (2026-10-08, owner request): email route for every broker that publishes one

The owner asked for LeakGuard to "do email to every brokers". At the
time only 3 of 40 brokers (BeenVerified, PeopleLooker, Nuwber) had a
recorded email route. All 37 others were researched against the
broker's OWN site (privacy policy / opt-out page / help centre) or its
official California data-broker registry entry — pattern-guessed
addresses were never used, and six initially unverifiable addresses
were confirmed character-for-character in a live browser (including
Spokeo's privacy@spokeo.com on its own opt-out page and Social
Catfish's privacyrequests@socialcatfish.com, its published
Delete/Opt-Out address).

Result (commit `0b93b26`): 20 brokers gained a verified
`contact_email` — **23 of 40 brokers now have an email route**.
Deliberately not added: addresses a source scopes away from consumer
removal (Equifax, TransUnion, USPhoneBook, FamilyTreeNow, Oracle,
Neustar) and brokers publishing no usable email (incl. ClustrMaps,
FastPeopleSearch, SearchPeopleFree, LiveRamp, Radaris, ThatsThem,
VoterRecords, AdvancedBackgroundChecks, PeekYou, PublicRecordsNow).

Channel honesty: `remediation/policy.py` gained a narrow exception —
Spokeo, CheckPeople and Data Axle keep the FORM channel (their forms
are production-proven to submit; `policy._FORM_CHANNEL_BROKERS`,
replay-pinned in tests) and use the email only as the Agent Mode
letter fallback. Everywhere else the email channel replaces a wall,
never a working submission.

Validation (staging dep-db3t3ou7bikc73aaahhg, then production
dep-db3t74s9v7es738arang, live 2026-10-08 23:03 IST), full 40-broker
account runs on fresh accounts in BOTH environments, compared
broker-by-broker against the F1 runs: totals 3 submitted /
15 needs_human / 22 blocked → **3 / 23 / 14**; the submitted three
are identical (Spokeo, AdvancedBackgroundChecks, Data Axle); all 17
changed cases moved from blocked (http_403, form_not_fillable) or
dead-end reasons (browser_required, captcha, manual_only) to
needs_human/email_send_required — a ready-to-send letter. Notably,
Social Catfish's and LexisNexis's CAPTCHA walls and Epsilon
(Conversant)'s CAPTCHA are bypassed by the brokers' own published
email channels. Agent Mode plan on production: 23 email routes.
Baselines intact (214 / 100). Suites: pytest 625 passed / 22
skipped; CI-parity discovery OK (skipped=2); GitHub CI green.
