# Performance & Scalability Record (Phases 115, 116; P2-B)

Benchmarks run **2026-10-07** with `tools/bench.py` (rerunnable:
`python3 tools/bench.py`). All numbers below are that run's actual
output, pasted unrounded from the script.

## Environment — read this before quoting any number

* This VM (Linux, Python 3.12), app served in-process by the
  stdlib `ThreadingHTTPServer`, exactly as the test harness runs
  it.
* Database: **pgserver-bundled PostgreSQL on local disk** — not
  Neon, not over a network. Production is a Render free instance
  in Oregon talking to Neon in Singapore (~200 ms round trip);
  production latencies for DB-touching paths are strictly worse
  than everything measured here. These numbers characterize
  LeakGuard's own code and SQL, nothing else.
* Providers: **mock** (`LEAKGUARD_PROVIDERS=mock`). No network
  calls; real provider latency is excluded by design.
* Rate limits: production configuration, in force throughout
  (the load phase notes where a limit is the measured ceiling).

## Phase 115 — benchmark results

### Cold migration run (empty database)

| Metric | Value |
|---|---|
| Migrations applied | 12 (0001–0012) |
| Wall time | 0.28 s |

### (a) Anonymous Quick Scan handler — POST /api/scan, mock providers

Sample kept inside the production `anon_scan` budget (30/hour/IP)
so the handler, not the limiter, is measured.

| n | mean | p50 | p95 | min | max |
|---|---|---|---|---|---|
| 25 | 1.83 ms | 1.71 ms | 3.31 ms | 0.89 ms | 3.76 ms |

### (b) Authenticated API reads (account with 2 identifiers, 1 completed job, 3 findings)

| Endpoint | n | mean | p50 | p95 | min | max |
|---|---|---|---|---|---|---|
| GET /api/scans/\<id\> | 30 | 16.75 ms | 14.82 ms | 26.86 ms | 13.93 ms | 27.21 ms |
| GET /api/action-center | 30 | 41.25 ms | 39.54 ms | 54.79 ms | 37.79 ms | 57.11 ms |
| GET /api/monitoring/timeline | 30 | 18.37 ms | 17.44 ms | 23.02 ms | 16.80 ms | 25.76 ms |

The action center is the heaviest read (it aggregates exposure,
cases, and identifier state per request).

### (c) Scan-worker throughput (mock providers, end-to-end)

Measured through the full pipeline — API job creation, status
polling, the in-process worker's `run_once` — on one account
re-scanning two identifiers (3 finding rows per job):

| Jobs | Wall time | Jobs/sec | Finding rows | Findings/sec |
|---|---|---|---|---|
| 9 | 1.24 s | 7.27 | 27 | 21.8 |

### (d) apply_lifecycle vs identity count — the bulk-write proof

The lifecycle writer's cost per completed cycle, direct call,
median of 3 runs. Each point mixes all transition classes
(continuing, births, resolutions):

| Identities touched | Median | Runs |
|---|---|---|
| 10 | 12.09 ms | 10.94, 12.09, 17.41 |
| 100 | 25.25 ms | 24.03, 25.25, 30.29 |
| 500 | 200.82 ms | 186.99, 200.82, 224.93 |

Statement count is the structural result behind this table:
the writer issues **5 SQL statements per cycle regardless of
identity count** (3 reads + 1 transitions UPDATE + 1
continuing-carry UPDATE), pinned by
`tests/test_lifecycle_query_count.py` — measured 5 statements at
45 identities and 5 at 90. The previous implementation issued
3 + N statements (one UPDATE per identity): for the production
214-identity cycle that was 217 round trips and up to ~a minute
to converge over the Oregon→Singapore link (measured live,
docs/cycles/2026-10-07-p1b-phase-25-lifecycle.md). Locally the
remaining growth (100 → 500 identities) is row volume inside a
constant number of statements — wider VALUES lists and larger
joins — not round trips.

### (f1) Load: anonymous scans, 20 threads × 5 (fresh rate-limit window)

| Attempts | Wall time | Overall rate | 200 | 429 | 5xx | Transport resets |
|---|---|---|---|---|---|---|
| 100 | 2.08 s | 48.1 req/s | 30 | 69 | 0 | 1 |

Successful scans: p50 16.82 ms, p95 25.06 ms.

The 30 successes are exactly the production per-IP budget
(30 anonymous scans/hour): **the rate limiter is the binding
ceiling for single-IP scan load, by design**, and it sheds the
excess with clean 429s — zero 5xx. One attempt in 100 was reset
at transport level during the initial burst.

### (f2) Load: authenticated reads, 8 threads × 25 (action-center / timeline mix)

| Requests | Wall time | Throughput | p50 | p95 | 5xx | Transport resets |
|---|---|---|---|---|---|---|
| 200 | 5.52 s | 36.2 req/s | 232.48 ms | 371.58 ms | 0 | 0 |

Zero errors, but per-request latency inflates ~6× versus the
sequential reads in (b) at only 8 concurrent readers. The
contention is structural: one process (Python threads), and a
fresh database connection opened per operation. This is a local
measurement against pgserver; it identifies the pressure point,
not a production figure.

## Phase 116 — scalability: shape, ceiling, upgrade path

### Architecture shape

* The HTTP application is **stateless**: every durable thing —
  accounts, vault ciphertext, jobs, findings, sessions — lives
  in PostgreSQL. Any request can in principle be served by any
  instance.
* Background work is **in-process**: the scan worker loop and
  the monitoring scheduler run as threads inside the web
  process. This is the coupling point for scaling out (below).
* Database access uses short-lived connections, opened per
  operation and closed after (db/pool.py) — designed for Neon's
  pooler (PgBouncer), so connection count tracks concurrent
  operations, not process count.

### Documented ceiling of the CURRENT deployment

**Ceiling: one Render free instance, and it is not proven beyond
that.** Horizontal scaling is NOT claimed anywhere in this
document — it has never been run with more than one instance.

What bounds the current deployment, in the order it is expected
to bite (reasoned from the measurements above, not load-proven
in production):

1. **The single instance itself.** Render's free plan runs one
   instance (which also spins down when idle). Request handling,
   the scan worker, and the scheduler share its CPU: a scan burst
   steals capacity from requests, and (f2) shows latency
   inflating under even mild concurrency.
2. **Connection churn.** Every operation opens a fresh database
   connection, so request rate converts directly into connection
   rate against the Neon pooler, and every round trip pays the
   trans-Pacific latency. Per-operation round trips are the
   scarce resource — the reason the lifecycle writer is now
   set-based (5 statements per cycle, above).
3. **Neon free-plan limits** — pooled connection caps and
   compute autosuspend (cold wakes add seconds to the first
   query after idle; the pool already allows a 15 s connect
   timeout for this).
4. **Designed product ceilings**, independent of hardware:
   per-IP and per-user rate limits (30 anonymous scans/hour/IP,
   10 account scans/hour/user) cap abusive load before it can
   become an availability problem.

### Upgrade path (NOT implemented, NOT proven)

In order of increasing change: a paid Render instance (more
CPU/RAM, no spin-down) raises ceiling #1 without code changes →
running multiple instances requires moving the worker/scheduler
out of the web process (or adding leader election) and is
**untested** — job claiming and scheduler ticks are currently
single-process assumptions → a separate worker process lets
scanning scale independently of request serving → connection
strategy revisited (pooler transaction mode, fewer round trips
per request) and, only if reads dominate, a read replica. Each
step past the first is a project, not a config flip, and none is
claimed as done.
