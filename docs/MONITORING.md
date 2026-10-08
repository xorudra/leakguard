# Post-Launch Monitoring — How LeakGuard Is Watched

*Standing summary (Phase 175). One answer to "how is LeakGuard
watched?", in one place. Everything below runs on free tiers and
in-product machinery — no paid APM, no pager service. Detail
lives in the modules and records named per section; this page is
the map, not a copy.*

## 1. Uptime — external, always on

UptimeRobot (free plan) checks the production URL every 5
minutes and emails the owner on downtime. The app implements
`do_HEAD`, so the monitor's default HEAD probe is answered like
a GET with the body suppressed (a stdlib `http.server` app
without `do_HEAD` reports a false DOWN). This is the only layer
that watches from outside the platform — deliberately, because
every in-product layer below stops when the single free
instance spins down (see §7).

## 2. Errors — the error ledger (Phase 76)

`core/error_ledger.py` persists one rollup row per distinct
error per clock hour in `error_events`: context, exception
class, and the **sha256 of the message — never the raw
message** (messages can sit next to user data; the hash is all
dedupe needs). `core/logging_setup.log_error` mirrors into the
ledger, so every existing `log_error` call site is tracked with
no signature change. Recording is best-effort and never raises.
Retention prunes rows older than 30 days
(`core/retention.py`). The admin metrics surface shows the
trailing-24h picture: distinct (context, class) pairs, total
occurrences, top contexts.

## 3. Alerting — engineering alerts (Phases 77, 175)

`monitoring/alerts.py::evaluate()` runs at the tail of the
hourly monitoring scheduler tick (`TICK_SECONDS = 3600`),
behind the `monitoring_scheduler` feature flag and guarded so
an alerts failure can never break the tick. Rules (thresholds
are the module constants; all are operator judgment, stated in
the module docstring — none is a vendor SLO):

| Rule | Fires when |
|---|---|
| `queue_buildup` | queued+running scan jobs ≥ 10, OR oldest queued job waiting ≥ 900 s |
| `worker_failures` | scan jobs reaching `dead` in 24 h ≥ 3, OR remediation cases reaching `failed` in 24 h ≥ 5 |
| `provider_outage` | ≥ 5 distinct broker sources whose latest sweep state is `unreachable` |
| `error_spike` | error-ledger occurrences in the trailing hour ≥ 20 |
| `provider_budget` | any provider's calls today reached its daily budget (§5) |
| `scan_latency` | median completed-scan duration over the trailing 24 h ≥ 120 s, across ≥ 10 completed jobs (Phase 175 — arithmetic in the module docstring) |

Delivery, identical for every rule: an audit row
(`action = 'engineering_alert'`, actor `system`, counts/names
only — visible in the admin panel's security-events view) plus
one notification per admin account (`ADMIN_EMAILS`) via
`notify.create_notification` in mode `always` — the owner's
operational mail, like a password reset; user consent settings
do not govern it. Dedupe key `eng:<rule>:<UTC date>` caps it at
**one email per rule per admin per day**; same-day repeats land
as `suppressed` ledger rows.

## 4. Latency — what "slow" means here (Phase 175)

The latency rule watches the same number the admin metrics
publish (`median_completed_duration_seconds_last_24h`):
`percentile_cont(0.5)` over `finished_at - started_at` for
`status = 'done'` jobs completed in the trailing 24 h — worker
execution time, one definition everywhere. The healthy band
(P2-B measurements, `docs/PERFORMANCE.md`, and live deploys)
is seconds per job; 120 s is ≥ 2× the worst healthy figure
ever recorded, and the ≥ 10-jobs sample floor keeps a quiet
system from firing on one slow job. The median is deliberate:
a few legitimately huge profiles cannot fire it.

## 5. Provider budgets — the cost watch (Phases 66, 124)

`providers/usage.py` keeps per-provider daily call counts
(persisted in `provider_usage_daily`) against **operator-set
safety budgets** — none of the keyless APIs publishes a numeric
daily quota, and the budgets are labeled as operator judgment
in the code, never as vendor quotas: XposedOrNot 5,000/day,
HIBP Pwned Passwords 5,000/day, DuckDuckGo discovery
1,000/day, username platforms 20,000/day, domain intel
10,000/day. At 100% the provider refuses with a typed
`budget_exhausted` result (fail-open design: refusals degrade
the scan honestly, they never crash it), and the
`provider_budget` alert fires once that day. The one
published quota in the system is Brevo's 300 emails/day free
tier, which binds the notification lane: per-finding notices
are in-app only, email is the once-per-cycle `scan_summary`
digest (Phase 115/116 semantics, P2-B) — a 214-finding cycle
sends one email, not 214. Total running cost of all of the
above: ₹0.

## 6. Per-deploy live verification

Monitoring is only half the watch; every change is verified
live before it counts as shipped: deploy staging first →
acceptance smoke (health `db: "ok"`, anonymous baselines —
`test@example.com` → 214 breaches / score 100, password check
→ 52,372,427 — admin surfaces 404 to anonymous, throwaway-
account end-to-end with exactly one scan-summary notification,
account deleted) → promote the **same commit** to production →
repeat the verification there. Each batch's record lives in
`docs/cycles/`.

## 7. Honest limits

- **Detection latency.** Alerts evaluate on the hourly tick;
  a breach can wait up to ~an hour for its email (the audit
  row and metrics are visible in the admin panel as soon as
  the tick runs).
- **Sleep.** The scheduler, workers, and alert evaluator run
  in-process on one free instance that spins down when idle.
  While it sleeps, nothing evaluates — UptimeRobot (§1) is
  the always-on layer, and its check wakes the instance.
- **Stall vs slowness.** A total worker stall produces no
  completed jobs, so `scan_latency` stays silent by design;
  that failure shape belongs to `queue_buildup` /
  `worker_failures`.
- **Thresholds are judgment, not SLOs.** There is no error-
  budget policy behind the numbers; they are set so a fire
  means "a human should look", and the drill record
  (`docs/drills/2026-10-08-latency-alert-drill.md`) shows
  one firing end to end.
- **Kill switch.** `LEAKGUARD_FLAG_MONITORING_SCHEDULER=off`
  stops the tick — monitoring enqueues *and* alert
  evaluation — as one emergency lever (`core/flags.py`).
