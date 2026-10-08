# Engineering Alert — Latency Rule Drill Record

*Phase 175 verification artifact. Drill date: 2026-10-08. Type:
**seeded test-environment walk** (the rule fired end to end
against a local pgserver database provisioned by the test
harness; the email lane was a recording fake). No staging or
production action was taken and none is claimed — live deploy
verification for this batch is the per-deploy smoke recorded
in the P2-I cycle report. Companion: `docs/MONITORING.md`
(the standing monitoring summary) and `monitoring/alerts.py`
(the rule engine). Steps are marked **[code]** (verified
against the repository), **[test]** (executed by the named
test), or **[gap]** (a known limit, stated not smoothed).*

## Scenario

> **Scans get slow without failing.** A provider degrades (or
> the Neon link congests): jobs still complete, no errors
> spike, no queue builds — but a full scan that took seconds
> now takes minutes. Before Phase 175 nothing watched this
> shape: uptime is green (the site answers), the error rules
> are silent (nothing is erroring), and the only evidence is
> the median in the admin metrics, which nobody stares at.
> The `scan_latency` rule exists for exactly this gap.

Rule under drill (`monitoring/alerts.py::_scan_latency`):
median completed-scan duration over the trailing 24 h —
`percentile_cont(0.5)` over `finished_at - started_at` for
`status = 'done'`, the same figure the admin metrics publish —
**≥ 120 s**, across **≥ 10 completed jobs**. Threshold
arithmetic is recorded in the module docstring (healthy band
is seconds per job; 120 s is ≥ 2× the worst healthy figure
ever recorded; the sample floor keeps a quiet system from
firing on one slow job).

## Ground truth established before the walk (all [code])

- The rule is one entry in `alerts._RULES`, appended after the
  five P2-C/P2-D rules, whose behavior is unchanged. It is
  evaluated by the same `evaluate()` — failure-isolated per
  rule (a broken query skips that rule, never the pass), same
  `_deliver()` path: audit row (`engineering_alert`,
  PII-free flat scalars) + `notify.create_notification`
  mode `always`, dedupe key `eng:scan_latency:<UTC date>`.
- `evaluate()` runs only from `monitoring/scheduler.py::tick()`,
  after the enqueue work, behind the `monitoring_scheduler`
  flag (the tick returns early when the flag is off) and
  exception-guarded so an alerts failure cannot break the tick.
- The rule's `extra` detail carries `completed_jobs_24h` as a
  flat scalar — it rides both the audit row and the
  notification payload (the audit writer drops non-scalars).

## The walk (executed in tests/test_observability_alerts.py)

| Step | Action (exact) | Observed |
|---|---|---|
| 1. Quiet system, extreme jobs | Seed 3 `done` jobs with 3,600 s durations. Run `alerts.evaluate()`. **[test]** `TestAlertScanLatencySampleFloorDb` | **No fire, no notification rows at all.** The sample floor (3 < 10) holds even against absurd durations — one slow afternoon on a quiet system cannot page the owner. |
| 2. Healthy band, full sample | Seed 12 `done` jobs at 10 s each. Run `evaluate()`. **[test]** `TestAlertScanLatencyFastDb` | **No fire.** Above the floor, below the threshold: the healthy band stays silent. |
| 3. Breach, approaching the floor | Seed 9 `done` jobs at 180 s. Run `evaluate()`. **[test]** `TestAlertScanLatencyDb` | **No fire yet** — median is 180 s but the sample is 9. The floor is a real leg of the rule, not decoration. |
| 4. Breach, sample complete | Seed a 10th `done` job at 180 s. Run `evaluate()`. **[test]** same class | **Rule fires**: `{"rule": "scan_latency", "metric": "median_scan_duration_seconds_24h", "observed": 180, "threshold": 120}`. Exactly one non-suppressed `engineering_alert` notification for the admin; exactly one email through the (fake) lane; the audit row's detail carries `completed_jobs_24h = 10`. |
| 5. Same-day repeat | Run `evaluate()` again with the breach still seeded. **[test]** same class | Rule fires again (the condition still holds) but **no second email**: the repeat notification lands `status = 'suppressed'` under the dedupe key. One email per rule per admin per day — the P2-C discipline, unchanged. |
| 6. Flag respect | Re-seed the breach; set `LEAKGUARD_FLAG_MONITORING_SCHEDULER=off`; wrap `alerts.evaluate` in a counter; call `scheduler.tick()`. Then clear the flag; call `tick()` again. **[test]** `TestAlertScanLatencyFlagDb` | Flag off: tick returns `[]`, the evaluator was **never called**, zero notifications. Flag on: the same tick evaluates and the alert is delivered exactly once. The owner's emergency stop covers the new rule with no rule-specific code. |

## What the admin sees

- **Email** (one, that day): an `engineering_alert`
  notification for rule `scan_latency` with the observed
  median (180), the threshold (120), and the sample size
  (10 completed jobs) — enough to act on without opening a
  dashboard.
- **Admin panel**: the audit row in the security-events view
  (`engineering_alert` / `scan_latency`, actor `system`),
  and the metrics block's
  `median_completed_duration_seconds_last_24h` showing the
  same 180 the rule fired on — the alert and the surface
  cannot disagree, because they are the same query shape.
- **Nothing user-facing changes**: no user notification kind
  was added; users' scan-summary semantics are untouched.

## Acknowledge / resolve path (honest)

There is **no ack button and no ack state** — by design, and
stated plainly rather than dressed up. The daily dedupe *is*
the acknowledgement mechanism: the owner reads the one email,
and the platform will not repeat it that day whether or not
anyone acts. Resolution is operational, not a click: find the
cause via the admin metrics (which providers are slow, queue
state, error top-contexts), fix or wait it out, and confirm
the trailing-24 h median falling back under 120 s in the
metrics. If the condition still holds tomorrow, the rule
emails again tomorrow — one per day, every day it holds.
An owner who wants silence *now* has the kill switch:
`LEAKGUARD_FLAG_MONITORING_SCHEDULER=off` stops the tick
(and therefore evaluation) entirely — at the cost of also
stopping monitoring enqueues, which is why it is an
emergency lever, not a mute button. **[code]**

## Drill findings (gaps, stated)

- **G1 — Detection latency is up to one tick (~1 h).** The
  evaluator rides the hourly scheduler tick; a degradation
  that starts just after a tick waits for the next one. The
  audit row/metrics are immediate once the tick runs, but
  nothing evaluates between ticks. Accepted for a free-tier,
  in-process design; a tighter cadence is a config change
  (`TICK_SECONDS`), not new machinery. **[gap]**
- **G2 — A sleeping instance evaluates nothing.** The
  scheduler is an in-process thread; when the free instance
  spins down, ticks stop. UptimeRobot's external check
  (5 min) is the always-on layer and its traffic wakes the
  instance — but a latency degradation that begins while the
  instance sleeps is only measured once it wakes and jobs
  complete. **[gap]**
- **G3 — Stall ≠ slowness.** If the worker stalls outright,
  no jobs complete, the sample never forms, and this rule
  correctly stays silent — that shape is covered by
  `queue_buildup` (the queue grows / ages) and
  `worker_failures` (jobs go `dead`). The rules partition
  the failure shapes; no single rule sees all of them. **[code]**
- **G4 — Median only, by choice.** A degrading p95 with a
  healthy median (most scans fine, the largest profiles
  suffering) does not fire. The median was chosen so
  legitimately huge profiles cannot false-fire the rule;
  a p95 companion rule is a possible future addition, not
  a silent omission. **[gap]**
- **No impossible steps found.** Every mechanism named above
  — the rule, the dedupe, the fake-lane email count, the
  audit row, the flag gate — executed as named in the tests
  cited.

## Verification basis (summary)

Code read for this drill: `monitoring/alerts.py`,
`monitoring/scheduler.py`, `monitoring/notify.py`,
`accounts/admin.py` (the metrics median this rule mirrors),
`accounts/audit.py`, `core/flags.py`, `docs/PERFORMANCE.md`
(the P2-B healthy band), `docs/MONITORING.md`. Test evidence:
`tests/test_observability_alerts.py` —
`TestAlertScanLatencyDb`, `TestAlertScanLatencySampleFloorDb`,
`TestAlertScanLatencyFastDb`, `TestAlertScanLatencyFlagDb`
(4 tests, all passing at drill time; full-suite figures in
the P2-I cycle report).
