# Incident Response — Tabletop Drill Record

*Phase 80 verification artifact. Drill date: 2026-10-07. Type:
**tabletop** (walked against the runbook and the code; no live
flag was flipped and no production action was taken). Companion:
`docs/INCIDENT_RESPONSE.md` — every step below names the runbook
section it exercises. Steps are marked **[code]** (verified
against the repository as of this date), **[platform]** (a Render
/ Neon dashboard action, not executable from the repo), or
**[prior drill]** (a platform action already rehearsed for real
in an earlier drill, cited).*

## Scenario (SEV-2)

> **A broker's infrastructure starts answering from non-public
> addresses.** The daily broker source sweep flips one large
> people-search broker to `unreachable`, and two users' removal
> cases record verification outcomes that look wrong (a case that
> should still be listed reports evidence the operator does not
> trust). The working hypothesis is hostile or broken DNS at the
> broker: its hostnames intermittently resolve to private /
> loopback addresses — a DNS-rebinding pattern — so every fetch
> the platform aims at that broker is suspect until proven
> otherwise. Per the runbook's severity ladder this is SEV-2 ("a
> core protection is down or lying"); it escalates to SEV-1 only
> if evidence shows fetches actually reached a non-public address
> or data crossed accounts.

Why this scenario: it exercises the exact layers changed most
recently — `core/ssrf.py` connection pinning (Phase 70), the kill
switches (`core/flags.py`), the source sweep
(`remediation/source_checks.py`), remediation verification
(`remediation/engine.py`, `remediation/verify.py`) — and it has a
containment answer that is *mostly* a flag flip, which is what
the first-30-minutes lane assumes.

## Ground truth established before the walk (all [code])

- Every data-driven outbound fetch in the verification path goes
  through the pinned fetcher: `remediation/source_checks.py`
  (`assert_public_url` pre-check + `ssrf.pinned_urlopen`) and
  `remediation/engine.py` (`ssrf.pinned_urlopen`). The pinned
  connection resolves **once**, inside `connect()`, validates
  every returned address as public, and connects to a validated
  IP while Host header and TLS `server_hostname` keep the
  original hostname. A resolution that turns private between any
  check and the fetch is refused inside `connect()` — the fetch
  raises, and the caller records a failure/`unreachable`, never a
  page fetched from a private address. Regression proof:
  `tests/test_ssrf_pinning.py` (13 tests).
- The four kill switches exist exactly as the runbook's table
  lists them — `core/flags.py` `FLAGS`, consulted at
  `app.py` (register / scans / remediation run routes, each
  answering `503 feature_disabled` when off) and
  `monitoring/scheduler.py` (tick returns no work when off). The
  admin overview (`accounts/admin.py::overview`) embeds
  `flags.snapshot()`. The anonymous Quick Scan (`POST /api/scan`)
  has no gate anywhere. **[code]**
- The daily source sweep runs from the retention tick
  (`core/retention.py` → `source_checks.maybe_run()`, armed at
  worker startup, at most once per 24h) and is **not** flag-gated.
  Queued remediation cases drain through `remediation/worker.py`
  independently of the `removal_runs` flag, which gates only
  `POST /api/remediation/run`. **[code]** — this shaped steps 4
  and 6 below and produced drill findings F2/F3.

## The walk

### First 30 minutes (timed lane, per runbook § "First 30 minutes")

| Clock | Runbook step | Responder action (exact) | Expected observable |
|---|---|---|---|
| T+0–3 | Severity call | Declare SEV-2 from the sweep flip + suspect verification outcomes; start the plain-text timeline (runbook step 5, done from minute zero). | Timeline file open; severity recorded. **[code]** — the ladder's SEV-2 example "removals submitting to the wrong place" covers this shape. |
| T+3–8 | 1 — Stop the bleeding | Render → leakguard service → Environment → set `LEAKGUARD_FLAG_REMOVAL_RUNS=off` → **Save, rebuild, and deploy**. This stops *new* removal runs (and with them, new user-triggered verification work) without touching scans, registration, or the Quick Scan. | Deploy succeeds on the current commit; `POST /api/remediation/run` answers `503` with code `feature_disabled`. **[platform]** for the dashboard action; **[code]** for the gated route + response shape (`app.py`, `core/errors.py::unavailable` → HTTP 503). |
| T+8–12 | 1 (confirm) | Open the admin overview; check the `flags` object shows `removal_runs: false`. | Flag state visible and matching the intent. **[code]** — `flags.snapshot()` is embedded in the overview payload. |
| T+8–15 | 2 — Snapshot the evidence | Note the time (IST); pull the request ids from the structured logs for the suspect verification checks (`X-Request-Id` is set on every response — `app.py` sends it in the common response path); copy the relevant `audit_log` rows via Admin → audit (`/api/admin/audit`) into the timeline. | Evidence bundle in the timeline: times, request ids, audit rows (PII-free by construction — `accounts/audit.py` filters detail to scalars and drops secret-shaped keys). **[code]** |
| T+12–20 | 3 — Blast radius | In the admin overview: read `remediation_cases_by_status` (how many cases are mid-flight), the **source_health** block (which brokers the sweep flags `unreachable`/`changed` — is it one broker or many?), and **security_events** (auth/account actions — confirm the anomaly is broker-shaped, not account-shaped). | One broker flagged ⇒ broker-side DNS problem; many brokers flagged at once ⇒ suspect the platform's own resolver/egress instead, and widen the incident. **[code]** — all three views exist in `overview()` today. |
| T+20–30 | 4 — Containment vs continuity decision | Decide: (a) if pinning evidence holds (step 5 below), keep the flag off, leave scans/registration/Quick Scan up, and work the broker problem; (b) if any evidence shows a fetch *reached* a non-public address, escalate to SEV-1 and move to the rotation table (the exposed thing would be the platform's fetch path, so also treat broker-supplied content as hostile). | Decision + rationale written in the timeline. **[code]** for the decision inputs; the call itself is the owner's. |

### After the first 30 minutes

| Step | Action | Expected observable / verification |
|---|---|---|
| 5. Prove the pinning held | From the recorded verification checks for the affected broker: pinning refusals surface as fetch failures — source sweep records the broker `unreachable`; case verification records an unknown/failed check, never a result page. Cross-check against `tests/test_ssrf_pinning.py` semantics: a rebinding resolution is refused inside `connect()` before any socket opens to the private address. | No verification outcome in the window is based on content fetched from a non-public address. Outcomes recorded during the window are treated as *unknown*, per the product's honesty rule — never as proof of removal or of presence. **[code]** |
| 6. Bound the un-gated surfaces | Acknowledge in the timeline what the flag did **not** stop: (a) already-queued cases keep draining through the remediation worker — bounded by the current queue (read the count at T+12–20), and their verification fetches use the same pinned fetcher, so the residual risk is wasted work, not SSRF; (b) the daily source sweep may run once more before any code change — its targets are the fixed broker-registry hosts, through `assert_public_url` + pinning; (c) Agent Mode probe/submit are not flag-gated — they carry their own host allowlist (`unknown_broker_host` rejection in `app.py`) and the same pinned fetch, and are rate-limited per IP. | Residual exposure is enumerated, bounded, and accepted in writing — or, if not acceptable, step 7 becomes mandatory instead of optional. **[code]** |
| 7. (If needed) Deactivate the broker | Set the broker's row inactive (`brokers.active = false`) via the owner DB connection so no surface targets it while its DNS is suspect. | Admin overview broker count drops by one; no new cases/probes for that broker. **[platform]** — a database action; there is deliberately no admin-UI toggle today. Not rehearsed live in this drill. |
| 8. Fix / wait out the cause | Broker-side DNS is outside the platform: the fix is the broker repairing its zone, or a code change if the platform mishandled a legitimate broker change (e.g. a moved opt-out URL — the sweep's `changed` state exists for exactly this). Any code change follows the normal cycle: suite → staging deploy → smoke → production deploy. | Cause named in the timeline with evidence, not vibes. **[prior drill]** — the staging-first deploy sequence is the standing practice recorded in the cycle reports (`docs/cycles/`). |
| 9. Restore (runbook § "After the incident" 1–2) | Remove `LEAKGUARD_FLAG_REMOVAL_RUNS` (or set it to a non-off value) → Save, rebuild, and deploy → admin overview shows `removal_runs: true` → verify the basics: `/api/health` reports `db: "ok"`, sign-in works, one scan runs, one verification cycle for the recovered broker records a sane outcome. | Service fully restored; the suspect window's verification outcomes stay marked unknown in case histories (they are never rewritten into verdicts). **[platform]** for the env change; **[code]** for health shape. |
| 10. Close out (runbook § "After the incident" 3–4) | Post-incident review within a few days: timeline, root cause, what monitoring caught (the sweep flip caught this — that is the detection working) and what it did not (no alert fires on a single broker flip; the owner noticed from the overview), filed as work items. | Review exists; work items filed. This drill record is the template. |

### Escalation branch (not walked in full)

If step 5 had shown a fetch reaching a non-public address, or
step 3 had shown account-shaped anomalies, the incident becomes
SEV-1 and the runbook's rotation table governs. Verified against
the code during this drill's preparation: vault keys
(`VAULT_MASTER_KEY`, `VAULT_LOOKUP_KEY`) load env-only in
`vault/store.py` as standard-base64 32-byte keys; account emails
and identifiers are vault-encrypted and lookups are HMACs under
the lookup key, so both rotation rows' premises are true. The
app DB role (`DATABASE_URL`) and owner connection
(`MIGRATION_DATABASE_URL`, boot-time migrations only —
`db/migrate.py`) are separate credentials, as the table says.
The Brevo key is read from the environment by
`monitoring/notify.py`. The GitHub PAT row names locations only
(GitHub settings + the operator's stored copy), as does this
record. Password resets revoke **all** of the account's sessions
(`accounts/auth.py` reset completion), and there is no
platform-wide session revoke — both as the runbook states.
**[code]**

Platform recovery actions referenced by the runbook were
rehearsed for real in earlier drills and are cited, not
re-executed, here: the application rollback rehearsal on staging
(previous commit → health → current commit, recorded in
`docs/ROLLBACK.md` and `docs/cycles/2026-10-07-post-audit-p0-program.md`)
and the Neon point-in-time restore drill (recorded in
`docs/DISASTER_RECOVERY.md` / the Phase 170 record). **[prior
drill]**

## Drill findings

- **F1 — Runbook wording (fixed during this drill).** "First 30
  minutes" step 2 implied audit rows must be copied "before
  retention can age anything out." `core/retention.py`
  deliberately never touches `audit_log`; the wording now says
  so and gives the real reason to snapshot (platform log
  retention, evidence in one place).
- **F2 — Runbook disclosure gap (fixed during this drill).** The
  kill-switch section did not state the flags' limits: queued
  cases keep draining, user-triggered verification is synchronous
  in-request, and the daily source sweep has no flag. A responder
  could have believed a flag flip froze all fetching. The
  runbook now carries a "What the flags do NOT stop" paragraph,
  and the vault-key rotation row no longer claims flags "freeze
  writes."
- **F3 — Accepted residual (no doc change needed beyond F2).**
  There is no single control that halts *every* fetching surface
  (sweep, queued-case drain, agent probe/submit) at once; the
  containment design deliberately leans on the fetch path's own
  guards (pinning, allowlists, rate limits). The drill judges
  this acceptable for the SEV-2 shape — pinning makes the
  dangerous outcome (a fetch landing on a private address) the
  one thing that cannot happen quietly — and step 7 covers the
  single-broker case. Revisit if a future surface fetches
  user-supplied hosts without the pinned path.
- **F4 — Detection is human-paced.** The sweep flip is visible
  in the admin overview but nothing pages the owner on it
  (consistent with the known Phase 76/77 metrics/alerts gap).
  The drill's T+0 assumed the owner noticed; a real incident
  clock starts at notice, not at the flip.
- **No impossible steps found.** Every switch, route, view, and
  mechanism the runbook names exists as named. The two wording
  fixes above are the drill's only runbook corrections.

## Verification basis (summary)

Code read for this drill: `docs/INCIDENT_RESPONSE.md`,
`core/flags.py`, `core/ssrf.py`, `core/retention.py`,
`core/errors.py`, `app.py` (flag gates, agent host allowlist,
request-id header, admin routes), `accounts/admin.py` (overview,
security events, flags snapshot), `accounts/audit.py`,
`accounts/auth.py` (reset session revocation), `vault/store.py`,
`db/migrate.py`, `monitoring/scheduler.py`,
`monitoring/notify.py`, `remediation/source_checks.py`,
`remediation/engine.py`, `remediation/worker.py`. Test evidence:
`tests/test_ssrf_pinning.py`. Prior drills cited:
`docs/ROLLBACK.md`, `docs/DISASTER_RECOVERY.md`,
`docs/cycles/2026-10-07-post-audit-p0-program.md`.
