# Limitations register review — 2026-10-08 (Phase 176)

The verification record Phase 176's row required: every
limitation claimed in the register sources, checked against the
current implementation. Performed as part of the owner-approved
P3 closeout (2026-10-08). No product behavior was changed by
this review; the single wrong copy found was fixed in place
(item C7).

## Sources and method

Register sources, as the phase row names them:

- `CURRENT_STATE.md` — the file has no section literally titled
  "Known gaps"; its limitations live in §J ("LeakGuard today
  CANNOT"), §H (Critical Risks, including the platform-risks
  paragraph) and the §F inventory rows. All were enumerated.
  §J/§H are part of the dated 2026-10-07 reconciliation record:
  under this file's own discipline the record is never rewritten
  and later truth arrives as dated §A addenda — so a claim that
  was accurate at its date and has since been overtaken is
  verdicted STALE-superseded here, not edited in place.
- `MIGRATION_PLAN.md` — the "Known gaps (honest register)" list
  (4 items, one already marked closed by the register itself).
- `/trust` — served by app.py as `static/index.html` with the
  `#trust` section unhidden; the copy reviewed is the static
  source of exactly what the route serves.
- The home page — the same `static/index.html` (`#honest`
  section, the Quick Scan hints, and the privacy-policy section
  served at /privacy).

Method: each claim was checked against code (file:line),
schema, data files (counted programmatically where a claim is
numeric), or tests. Claims whose truth rests on platform state
rather than code (hosting tier, email-plan cap, regions,
historical acceptance-run figures) are verdicted against the
standing platform records — `CURRENT_STATE.md` §A and
`POST_P2_RELEASE_AUDIT.md` (2026-10-08) — and are listed at the
end as resting on those records; this review ran no fresh
production probe.

Verdicts: **ACCURATE** (holds against the current
implementation), **STALE** (was accurate, has been overtaken —
supersession recorded, frozen text untouched), **WRONG**
(incorrect as written — copy fixed in this cycle).

## A. CURRENT_STATE.md (§J CANNOT, §H, §F)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| A1 | Breach dumps copied to Telegram / dark-web markets / torrents cannot be removed; brokers, people-search sites and Google results can | ACCURATE | The removal surface is the 40-broker registry only (`brokers.json`, `remediation/registry_seed.py`); erasure letters cite DPDP §12 / GDPR Art. 17 / CCPA (`remediation/letters.py`). No mechanism anywhere claims dump removal |
| A2 | No guarantee a broker removed anything; removal is claimed only on verification evidence; ambiguous evidence answers `unknown`, never a guess | ACCURATE | `remediation/verify.py` outcome vocabulary (`still_present` / `gone` / `unknown`, line 32) with "a check is not a guess" transitions; `tests/test_verify_sources.py::TestVerifyClassificationMatrix` pins ambiguous → unknown |
| A3 | Most people-search brokers wall datacenter IPs (27/40 cases blocked in the acceptance run); those cases carry reasons + next steps; the local agent on the user's device/IP is the working route | ACCURATE | The 27/40 figure is the dated acceptance-run record (restated in §F's remediation row: 2 submitted / 11 needs_human / 27 blocked). The mechanism is in code: blocked classifications with reasons in `remediation/engine.py`; `local_agent.py` exists and is the documented route (Phase 178 KEEP decision, `docs/DOC_REVIEW.md`) |
| A4 | Coverage is not exhaustive: discovery is DuckDuckGo-index based; username presence covers 13 platforms; findings are labelled exact/probable/weak and weak is never upgraded to fact | ACCURATE | `providers/ddg_discovery.py`; `providers/username_platforms.py` PLATFORMS tuple = 13 entries (counted); the confidence vocabulary is a schema CHECK (`db/migrations/0003_scans.sql`: `confidence IN ('exact','probable','weak')`), and `scanning/correlation.py` never silently upgrades a signal — its single inferred note type is labelled `probable` and described in its docstring as an inference, not a fact |
| A5 | Cannot serve organizations / multi-tenant workspaces (§J + §F "Organizations: No — households instead") | ACCURATE | No tenant model exists; `accounts/households.py` is the grouping that shipped. As of this closeout the absence is also an explicit owner decision (Phase 57 → NOT APPLICABLE, 2026-10-08) |
| A6 | Cannot "produce generated report documents" (§J, same bullet as A5) | **STALE** | Accurate on 2026-10-07; overtaken by this closeout: Phase 85 ships `GET /api/report` (`dashboard/report.py`). The frozen §J text is not rewritten (the file's addendum discipline); the supersession is recorded here and in the §A addendum for this cycle |
| A7 | Cannot send more than 300 emails/day (Brevo free) | ACCURATE | The notification lane is Brevo (`monitoring/notify.py`); 300/day is Brevo's published free tier, recorded as a published figure — not an operator estimate — in `docs/MONITORING.md`. Platform-plan fact; rests on the standing platform record (see end) |
| A8 | Cannot stay awake while idle (Render free sleeps; ~50 s wake) | ACCURATE | Platform behavior of the single free service (`render.yaml`); the app carries the standard mitigations (UptimeRobot 5-min monitor; `do_HEAD` in app.py so its probes answer 200). Platform fact; rests on the standing platform record |
| A9 | Disaster recovery rests on one mechanism: Neon free-plan PITR; history window bounds the RPO; no second copy (§H.1) | ACCURATE | `docs/DISASTER_RECOVERY.md` + `docs/ROLLBACK.md` describe exactly one restore mechanism; the PITR drill passed 2026-10-07 (Phases 78/170 DONE). No second backup exists anywhere in the repo or runbooks |
| A10 | One production service on a free tier; sleeps when idle; shares free instance hours with staging; no redundancy (§H.2) | ACCURATE | One production service + one staging service (CURRENT_STATE §A/§C); `POST_P2_RELEASE_AUDIT.md` re-verified the single-service production state 2026-10-08. Platform fact |
| A11 | "No anomaly alerting … nothing watches the [security-events] view" (§H.3, first half) | **STALE** | Accurate at the record date; overtaken 2026-10-08 by P2-C (Phases 76/77: error ledger + six engineering alert rules on the scheduler tick, admin-emailed) and P2-I (Phase 175 scan_latency rule) — all recorded in the §A addenda and `docs/MONITORING.md`. Frozen text untouched per the file's discipline |
| A12 | Dependency vulnerability scanning runs on a recorded manual cadence, not in CI (§H.3, second half) | ACCURATE | Phase 107's record stands: pip-audit on dependency change + monthly, no CI scanning job (`.github/workflows/tests.yml` runs the suite only) |
| A13 | Search-index verification lags the live web; a `gone` verdict means "no longer indexed as of the check" (§H platform paragraph) | ACCURATE | `verify_sources.json` maps 26 of 40 brokers to `search_index` (see B1); the lag caveat is inherent to the method and is also stated in `MIGRATION_PLAN.md`'s register |

## B. MIGRATION_PLAN.md — "Known gaps (honest register)"

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| B1 | Item 1 (marked closed by the register itself): verification sources are mapped for all 40 brokers — 26 search-index, 2 direct, 12 none; every check records its method; index-lag limit stands | ACCURATE | `verify_sources.json` counted programmatically in this review: 40 entries — 26 `search_index`, 2 `direct`, 12 `none`, exactly as claimed. Method is stored per check (`verification_checks`, `remediation/verify.py`) |
| B2 | Item 2: most people-search brokers wall datacenter IPs (27/40 blocked in the acceptance run); cases carry next steps; the local-agent path remains the practical route | ACCURATE | Same evidence as A3 |
| B3 | Item 3: Brevo free tier caps email at 300/day — "ample now; the first scaling ceiling" | ACCURATE | Same evidence as A7 |
| B4 | Item 4: Render free sleeps when idle (~50 s wake) and shares free hours across the owner's services | ACCURATE | Same evidence as A8/A10 |

## C. /trust page (static/index.html, #trust)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| C1 | "Can be removed: brokers, people-search sites, Google results — a removal only counts as done after verification that the listing is gone" | ACCURATE | Same evidence as A1/A2 |
| C2 | "Cannot be removed: a breach dump already copied to Telegram, dark-web forums or torrents. No tool can delete every copy" | ACCURATE | Same evidence as A1 |
| C3 | Retention: sessions deleted 7 days after expiry/revoke; reset tokens after 7 days; notifications 90 days; a deleted account is hard-deleted 30 days after deletion, count-only audit kept | ACCURATE | `core/retention.py` constants match the copy exactly: `SESSION_GRACE_DAYS = 7`, `RESET_TOKEN_GRACE_DAYS = 7`, `NOTIFICATION_TTL_DAYS = 90`, `DELETED_USER_GRACE_DAYS = 30` (lines 50–54); the audit log carries no PII by construction + filter (CURRENT_STATE §D) |
| C4 | Storage/crypto: AES-256-GCM envelope encryption with a per-record key under an env-only master key; account email via HMAC lookup, stored encrypted, displayed masked only; account passwords Argon2id hashes; sessions/API tokens stored as SHA-256 digests; checked passwords use k-anonymity (5-char SHA-1 prefix, matched locally, never sent/stored/logged); no payment details held (no payments) | ACCURATE | `vault/crypto.py` + `vault/store.py`; `accounts/passwords.py` (Argon2id); `accounts/sessions.py` `_token_hash` = SHA-256 (line 31); app.py `check_password_pwned` sends `sha1[:5]` only (line 132); no payment surface exists in the app.py route inventory |
| C5 | Locations: the app runs on Render in Oregon (US); the database is Neon in AWS ap-southeast-1 (Singapore) | ACCURATE | Platform record (CURRENT_STATE §A: service in Oregon; Neon project AWS ap-southeast-1). Rests on the standing platform record |
| C6 | Processors: Render, Neon, Brevo, XposedOrNot, Have I Been Pwned, DuckDuckGo, Cloudflare (DNS), crt.sh, and the checked platforms themselves; no advertising/analytics/selling | ACCURATE | Matches the provider registry (`providers/`) and CURRENT_STATE §C's external-dependencies list; no analytics or ads code exists in `static/` or app.py |
| C7 | "See everything: Privacy Center → 'Download my data' exports all of it as one JSON file" | **WRONG — fixed in this cycle** | The export has offered JSON **or CSV** since Batch B (`accounts/privacy.py`: `FORMATS = ("json", "csv")`; the Privacy Center UI offers both). Copy corrected in this review to "as one file (JSON or CSV)" — a static-text fix only, no behavior change |

## D. Home page (static/index.html — #honest, Quick Scan, /privacy section)

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| D1 | #honest: "Can be removed: data brokers, people-search sites, Google search results — they must answer a legal erasure request" / "Cannot be removed: a breach dump already copied to Telegram, dark-web forums or torrents. No tool on earth can delete every copy" | ACCURATE | Same evidence as A1/A2 |
| D2 | Quick Scan hint: the same can/cannot limits; password check sends only the first 5 characters of the SHA-1 hash, the password never leaves the page in plain form and is never stored | ACCURATE | app.py line 132 (`sha1[:5]`); the anonymous scan stores nothing (no writes on the /api/scan path — providers are queried per request) |
| D3 | Privacy policy section: "Copies of breach data already spread to Telegram, dark-web forums, torrents or private collections cannot be recalled by LeakGuard" | ACCURATE | Same evidence as A1 |

## Tally

28 claims reviewed: **25 ACCURATE · 2 STALE · 1 WRONG**.

- The 2 STALE claims (A6, A11) were accurate at their record
  date and were overtaken by shipped work (Phase 85; Phases
  76/77/175); both supersessions are recorded in dated addenda
  and in this review — the frozen 2026-10-07 record itself is
  not rewritten, per CURRENT_STATE.md's own discipline.
- The 1 WRONG claim (C7) was a copy inaccuracy about the
  export's formats; the copy is fixed in this cycle.
- No limitation claim was found that overstates what the
  product cannot do in order to hide a defect, and no
  capability claim in the reviewed copy overstates the
  implementation.

## Claims resting on platform records (for the parent's live confirmation)

These verdicts rest on platform state, not code, and stand on
the standing records named; the parent's closeout deploy pass
re-confirms the production ones as part of the staging →
production verification:

- A7/B3 — Brevo's published 300/day free-tier cap (external
  plan fact).
- A8/A10/B4 — Render free-tier behavior: single production
  instance, sleep-on-idle (~50 s wake), free hours shared with
  staging (re-verified 2026-10-08 in POST_P2_RELEASE_AUDIT.md).
- A3/B2 — the 27/40 blocked figure is a historical
  acceptance-run record, not re-derivable from code.
- C5 — hosting regions (Render Oregon; Neon ap-southeast-1),
  per the platform dashboards as recorded in CURRENT_STATE §A.
