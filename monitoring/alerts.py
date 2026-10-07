"""Engineering alerts (spec Phase 77).

The product's own tripwires, evaluated in-product from the same
tables the admin metrics read (Phase 76) — no external pager or
APM service, everything free-tier and in-product. The evaluator
rides the hourly monitoring scheduler tick (monitoring/scheduler.py
calls evaluate() after its enqueue work, guarded so an alerts
failure can never break the tick, and behind the same
monitoring_scheduler feature flag as the rest of the tick).

Rules (thresholds are the module constants below):

* queue_buildup     — queued+running scan jobs >= 10, OR the
                      oldest queued job has waited >= 900 s.
* worker_failures   — scan jobs reaching 'dead' in the last 24 h
                      >= 3, OR remediation cases reaching 'failed'
                      in the last 24 h >= 5.
* provider_outage   — broker sources whose LATEST sweep state is
                      'unreachable' >= 5 distinct sources.
                      (broker_source_checks keeps only the latest
                      check per broker — there is no check history
                      to count "3 unreachable checks in a row"
                      against, so the rule is distinct sources
                      currently down, nothing more.)
* error_spike       — error-ledger occurrences in the last hour
                      >= 20. The ledger rolls up by clock hour
                      (error_events.bucket_start), so the count
                      sums the (at most two) hour buckets that
                      overlap the trailing hour, restricted to
                      rows actually seen inside it — a close,
                      stated approximation, not a per-event log.
* provider_budget   — any provider's calls today reached its
                      daily call budget (Phases 66/124: the
                      usage ledger provider_usage_daily vs the
                      operator-set budgets in providers/usage.py).
                      Observed = how many providers are
                      exhausted; the audit detail also names the
                      first exhausted provider and the full list.
                      One alert per day for the rule as a whole —
                      never one email per provider.

On a trigger, for each fired rule:
* an audit row (actor_kind 'system', action 'engineering_alert',
  detail = rule / metric / observed / threshold — counts and
  names only, PII-free by the audit writer's construction), which
  is also how the alert surfaces in the admin panel's
  security-events view; and
* one notification per admin account (ADMIN_EMAILS), via
  notify.create_notification with mode "always" — the owner's
  operational mail, like password reset: the 'notifications'
  consent governs user alerts, not the platform telling its owner
  it is unhealthy. dedupe_key 'eng:<rule>:<UTC date>' caps it at
  one email per rule per admin per day; repeats the same day land
  as 'suppressed' ledger rows.
"""

from datetime import datetime, timezone

from accounts import admin as admin_service
from accounts import audit
from core import logging_setup
from db import pool
from monitoring import notify

QUEUE_ACTIVE_THRESHOLD = 10
QUEUE_OLDEST_AGE_SECONDS = 900
DEAD_JOBS_24H_THRESHOLD = 3
FAILED_CASES_24H_THRESHOLD = 5
UNREACHABLE_SOURCES_THRESHOLD = 5
ERROR_OCCURRENCES_1H_THRESHOLD = 20


def _queue_buildup(conn):
    row = conn.execute(
        "SELECT"
        " COUNT(*) FILTER (WHERE status IN ('queued', 'running'))"
        " AS active,"
        " EXTRACT(EPOCH FROM (now() - MIN(created_at)"
        "   FILTER (WHERE status = 'queued'))) AS oldest_age"
        " FROM scan_jobs",
    ).fetchone()
    active = int(row["active"])
    if active >= QUEUE_ACTIVE_THRESHOLD:
        return {"rule": "queue_buildup", "metric": "active_jobs",
                "observed": active,
                "threshold": QUEUE_ACTIVE_THRESHOLD}
    age = row["oldest_age"]
    if age is not None and float(age) >= QUEUE_OLDEST_AGE_SECONDS:
        return {"rule": "queue_buildup",
                "metric": "oldest_queued_age_seconds",
                "observed": int(float(age)),
                "threshold": QUEUE_OLDEST_AGE_SECONDS}
    return None


def _worker_failures(conn):
    dead = conn.execute(
        "SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'dead'"
        " AND COALESCE(finished_at, created_at)"
        " >= now() - interval '24 hours'",
    ).fetchone()["n"]
    if int(dead) >= DEAD_JOBS_24H_THRESHOLD:
        return {"rule": "worker_failures", "metric": "dead_jobs_24h",
                "observed": int(dead),
                "threshold": DEAD_JOBS_24H_THRESHOLD}
    failed = conn.execute(
        "SELECT COUNT(*) AS n FROM remediation_cases"
        " WHERE status = 'failed'"
        " AND updated_at >= now() - interval '24 hours'",
    ).fetchone()["n"]
    if int(failed) >= FAILED_CASES_24H_THRESHOLD:
        return {"rule": "worker_failures",
                "metric": "failed_cases_24h",
                "observed": int(failed),
                "threshold": FAILED_CASES_24H_THRESHOLD}
    return None


def _provider_outage(conn):
    unreachable = conn.execute(
        "SELECT COUNT(*) AS n FROM broker_source_checks"
        " WHERE state = 'unreachable'",
    ).fetchone()["n"]
    if int(unreachable) >= UNREACHABLE_SOURCES_THRESHOLD:
        return {"rule": "provider_outage",
                "metric": "unreachable_sources",
                "observed": int(unreachable),
                "threshold": UNREACHABLE_SOURCES_THRESHOLD}
    return None


def _provider_budget(conn):
    from providers import usage

    # The evaluator reads the ledger table, so flush this
    # process's in-memory counts first (best-effort, never raises)
    # — otherwise the rule would lag the batch by up to a flush.
    usage.flush()
    rows = conn.execute(
        "SELECT provider, calls FROM provider_usage_daily"
        " WHERE day = (now() AT TIME ZONE 'UTC')::date",
    ).fetchall()
    exhausted = sorted(
        row["provider"] for row in rows
        if usage.budget_for(row["provider"]) is not None
        and int(row["calls"]) >= usage.budget_for(row["provider"]))
    if not exhausted:
        return None
    return {"rule": "provider_budget",
            "metric": "provider_daily_budget",
            "observed": len(exhausted),
            "threshold": 1,
            # Flat scalars only: the audit writer drops non-scalar
            # detail values by design (flat facts, not payloads).
            "extra": {"provider": exhausted[0],
                      "exhausted_providers": ", ".join(exhausted)}}


def _error_spike(conn):
    total = conn.execute(
        "SELECT COALESCE(SUM(occurrence_count), 0) AS n"
        " FROM error_events"
        " WHERE bucket_start >= date_trunc('hour',"
        " now() - interval '1 hour')"
        " AND last_seen_at >= now() - interval '1 hour'",
    ).fetchone()["n"]
    if int(total) >= ERROR_OCCURRENCES_1H_THRESHOLD:
        return {"rule": "error_spike",
                "metric": "error_occurrences_1h",
                "observed": int(total),
                "threshold": ERROR_OCCURRENCES_1H_THRESHOLD}
    return None


_RULES = (_queue_buildup, _worker_failures, _provider_outage,
          _error_spike, _provider_budget)


def _deliver(fired):
    """Audit row + one owner notification per fired rule. The
    notification dedupe key makes repeats inside a day land
    'suppressed', so this is safe to run every tick."""
    day = datetime.now(timezone.utc).date().isoformat()
    detail = {
        "rule": fired["rule"],
        "metric": fired["metric"],
        "observed": fired["observed"],
        "threshold": fired["threshold"],
    }
    # A rule may attach rule-specific facts (provider_budget names
    # the exhausted provider(s)); they ride both the audit detail
    # and the notification payload, keys never colliding with the
    # four base fields.
    detail.update(fired.get("extra") or {})
    audit.record(None, "system", "engineering_alert", "alert_rule",
                 fired["rule"], detail)
    for admin_id in admin_service.admin_user_ids():
        notify.create_notification(
            admin_id, "engineering_alert", detail,
            dedupe_key="eng:%s:%s" % (fired["rule"], day),
            mode="always")


def evaluate():
    """One evaluation pass. Returns the list of fired rules
    ({"rule", "metric", "observed", "threshold"} dicts) — empty
    when the platform is within every threshold. Each rule is
    failure-isolated (a broken query skips that rule, never the
    pass), and each delivery is isolated too: a failed alert
    channel must not silence the other rules. Delivery failures
    are the only thing logged — via log_error, which also feeds
    the error ledger this module watches."""
    with pool.connection() as conn:
        fired = []
        for rule_fn in _RULES:
            try:
                hit = rule_fn(conn)
            except Exception as exc:
                logging_setup.log_error(
                    None, "engineering alert rule failed: "
                    + type(exc).__name__)
                continue
            if hit is not None:
                fired.append(hit)
    for hit in fired:
        try:
            _deliver(hit)
        except Exception as exc:
            logging_setup.log_error(
                None, "engineering alert delivery failed: "
                + type(exc).__name__)
    if fired:
        logging_setup.get_logger().info(
            "engineering_alerts fired=%s"
            % ",".join(hit["rule"] for hit in fired))
    return fired
