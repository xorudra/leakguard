"""Scan budget engine (spec Phase 158) — the one policy home for
every budget that bounds scanning work.

WHY THIS MODULE. Before Phase 158 the budgets were scattered
fixed constants, each enforced where it was born and documented
nowhere together: a per-job discovery cap in the orchestrator, a
per-case probe budget in the remediation engine, per-provider
daily budgets from P2-D, route rate limits in core. The audited
gap was the missing tier — no per-USER budget at all — and no
single place that lists the whole policy. This module is that
place: it owns the one new enforcement (the per-user daily
full-scan budget) and REGISTERS every other budget by reference
(budgets_snapshot() reads the live constants from their homes;
nothing is copied, so the snapshot cannot drift from the
enforcement).

THE BUDGETS.

* Per-user daily full scans — USER_DAILY_SCAN_BUDGET, enforced
  HERE (enforce_manual_budget, called by scanning/jobs.py when a
  signed-in user creates a job by hand). See the lane decision
  below for what counts.
* Per-job discovery queries — scanning/orchestrator.py
  DISCOVERY_BUDGET (6 quoted public-web queries per scan job;
  platform and DNS checks do not consume it), enforced by the
  orchestrator's _DiscoveryBudget.
* Per-case probe seconds — remediation/engine.py
  AgentExecutor(probe_budget_seconds=40.0): a soft budget on
  broker probing per removal case, enforced by the engine.
* Per-provider daily calls — providers/usage.py BUDGETS,
  enforced in the provider transport (Phase 66/124): the free
  tiers are the finite resource those budgets protect.
* Route rate limits — core/ratelimit.py DEFAULT_LIMITS
  (per-IP for anonymous routes, per-user for account routes,
  including the 10/hour 'user_scans' burst cap on POST
  /api/scans). The daily budget below complements that hourly
  cap: the limiter stops bursts, the budget stops a slow
  runaway that stays under every hourly window all day.

THE ORG TIER IS EMPTY — DELIBERATELY. The spec's budget tiers
are per-user / per-org / per-provider. This product has no
organizations or teams: an account is one person, and
"households" (migration 0007) are member LABELS inside one
account (family members cannot sign in and own nothing) — not
budget principals. Budgets therefore attach to the account
(user_id), a household shares its owner's budget exactly as it
shares the owner's identifiers, and no org tier is invented.

THE SCHEDULED LANE. Monitoring-scheduler jobs do NOT count
against the per-user manual budget and are never refused by it.
A scheduled job is inserted directly by monitoring/scheduler.py
(never through jobs.create_job) under the idempotency key
'monitor-<user_id>-<period_start>', authorized by the user's
'monitoring' consent and already bounded to at most one job per
cadence period by that deterministic key. The manual budget
therefore counts only hand-started jobs — scan_jobs rows whose
idempotency key lacks the monitor prefix (the durable marker
scanning/worker.py documents) — because a user who hand-scans
enthusiastically must not silently starve the scheduled
monitoring the product exists to do, and a monitoring cycle
must not eat the allowance the user spends by hand. Each lane
is bounded by its own control: cadence for the scheduled lane,
this budget (+ the hourly rate limit) for the manual lane.

FAILURE MODE. The check is a COUNT inside the same transaction
as the job insert (scanning/jobs.py), so it has no failure mode
of its own: a database failure fails job creation exactly as it
did before this phase (infrastructure errors propagate to the
worker's retry policy). There is no cached or in-memory count
to go stale.
"""

import inspect

from core import errors, ratelimit
from providers import usage as provider_usage
from scanning import orchestrator

# Hand-started full scans per signed-in user per UTC day.
# OPERATOR-SET safety budget (the Phase 66/124 pattern: chosen
# from the product's arithmetic, not copied from any published
# quota — there is none). The arithmetic: a monitoring user
# hand-scans a few times a day at most (after an alert, after
# saving a new detail); the 'user_scans' rate limit already
# caps bursts at 10/hour, so 50/day only binds sustained
# all-day automation — roughly two scans an hour around the
# clock — which is exactly the slow runaway the hourly window
# cannot see. A fresh user is nowhere near it: their first
# scans always fit.
USER_DAILY_SCAN_BUDGET = 50

# The scheduler's idempotency-key prefix — the durable marker
# that separates scheduled jobs from hand-started ones (jobs
# carry no source column). Mirrors monitoring/scheduler.py's
# monitor_key() and scanning/worker.py's MONITOR_KEY_PREFIX;
# kept as a literal here so this module stays importable
# without the scheduler.
MONITOR_KEY_PREFIX = "monitor-"

# Start of the current UTC day (the same expression the admin
# metrics and the usage ledger bucket by).
_UTC_DAY_START = ("(date_trunc('day', now() AT TIME ZONE 'UTC')"
                  " AT TIME ZONE 'UTC')")


def manual_jobs_today(conn, user_id):
    """How many of the user's HAND-STARTED scan jobs were
    created in the current UTC day. Scheduled monitoring jobs
    (monitor- idempotency keys) are the other lane and are not
    counted — see the module docstring."""
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM scan_jobs"
        " WHERE user_id = %s AND created_at >= " + _UTC_DAY_START
        + " AND idempotency_key NOT LIKE %s",
        (user_id, MONITOR_KEY_PREFIX + "%"),
    ).fetchone()
    return int(row["n"])


def enforce_manual_budget(conn, user_id):
    """Refuse a NEW hand-started job once the user is at today's
    budget. Raises the house typed error (an ApiError the API
    layer renders as the standard error body) — the refusal is
    plain and says when the budget resets; nothing is queued
    silently. Callers invoke this only for genuinely new jobs:
    an idempotent retry of an existing job must never be refused
    (scanning/jobs.py checks for the existing row first)."""
    if manual_jobs_today(conn, user_id) >= USER_DAILY_SCAN_BUDGET:
        raise errors.ApiError(
            429, "scan_budget_exhausted",
            "You've reached today's full-scan budget "
            "(%d scans per day). It resets at midnight UTC — "
            "scheduled monitoring scans are not affected."
            % USER_DAILY_SCAN_BUDGET)


def _probe_budget_seconds():
    """The remediation engine's per-case probe budget, read from
    the live default (deferred import: remediation sits beside
    scanning in the graph, and this snapshot is the only place
    the two meet). None when the engine cannot be read — the
    snapshot is informational and must not fail over it."""
    try:
        from remediation.engine import AgentExecutor

        return float(inspect.signature(
            AgentExecutor.__init__).parameters[
                "probe_budget_seconds"].default)
    except Exception:
        return None


def budgets_snapshot():
    """The whole scan-budget policy in one JSON-safe dict — the
    registry view the admin metrics show. Every value is read
    from the constant that enforces it (named in "source"), so
    the view cannot drift from the enforcement."""
    return {
        "per_user_daily_full_scans": {
            "limit": USER_DAILY_SCAN_BUDGET,
            "unit": "scan jobs",
            "window": "UTC day",
            "scope": ("signed-in user, hand-started jobs only — "
                      "the scheduled monitoring lane is separate "
                      "and never counted or refused"),
            "source": "scanning/budgets.py USER_DAILY_SCAN_BUDGET",
        },
        "per_job_discovery_queries": {
            "limit": orchestrator.DISCOVERY_BUDGET,
            "unit": "public-web discovery queries",
            "window": "per scan job",
            "scope": "all identifiers in the job combined",
            "source": "scanning/orchestrator.py DISCOVERY_BUDGET",
        },
        "per_case_probe_seconds": {
            "limit": _probe_budget_seconds(),
            "unit": "seconds of broker probing",
            "window": "per remediation case",
            "scope": "one removal case's verification probing",
            "source": ("remediation/engine.py "
                       "AgentExecutor.probe_budget_seconds"),
        },
        "per_provider_daily_calls": {
            "limits": dict(provider_usage.BUDGETS),
            "unit": "provider calls",
            "window": "UTC day",
            "scope": "per provider, product-wide",
            "source": "providers/usage.py BUDGETS",
        },
        "route_rate_limits": {
            "limits": {
                name: {"limit": limit, "window_seconds": window}
                for name, (limit, window)
                in ratelimit.DEFAULT_LIMITS.items()
            },
            "unit": "requests",
            "window": "per route class (see window_seconds)",
            "scope": "per IP (anonymous routes) or per user "
                     "(account routes)",
            "source": "core/ratelimit.py DEFAULT_LIMITS",
        },
    }
