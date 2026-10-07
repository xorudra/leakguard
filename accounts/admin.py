"""Admin — the product owner's operational view (Stage S11, spec
Phases 106–114).

There is exactly ONE admin concept in this product: the owner.
Access is gated by the ADMIN_EMAILS environment variable
(comma-separated addresses, matched against the account email via
the same vault decryption the owner-only export uses — emails are
never stored in plaintext, so the check decrypts in memory and
compares; nothing is logged or returned).

PRIVACY CONTRACT: the admin sees AGGREGATES ONLY — platform counts,
status breakdowns, provider health and the PII-free audit trail.
Never another user's identifiers, emails, findings or letters: this
module's queries count rows and group them; no per-user row ever
leaves it. Non-admins cannot even tell the routes exist — the
handlers answer 404, not 403.
"""

import os

from accounts import audit
from accounts import auth as auth_service
from accounts.auth import _iso
from core import flags
from db import pool as db_pool
from providers import registry as providers_registry


def _admin_emails():
    """The configured admin addresses, normalized with the vault's
    email recipe so the comparison matches how accounts are stored."""
    configured = set()
    for part in os.environ.get("ADMIN_EMAILS", "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            configured.add(auth_service.normalize_email(part))
        except Exception:
            configured.add(part.lower())
    return configured


def is_admin(user_id):
    """True when the account's email is in ADMIN_EMAILS. With no
    addresses configured, nobody is an admin — the panel stays dark
    until the owner opts in on the server."""
    configured = _admin_emails()
    if not configured or user_id is None:
        return False
    row = auth_service._get_user_by_id(user_id)
    if row is None:
        return False
    try:
        email = auth_service.reveal_email(row)
    except Exception:
        return False
    return auth_service.normalize_email(email) in configured


def admin_user_ids():
    """The user ids of every live account whose email is in
    ADMIN_EMAILS — the recipients of owner-only operational mail
    (Phase 77 engineering alerts). Empty when ADMIN_EMAILS is
    unset: with no owner configured there is nobody to alert."""
    if not _admin_emails():
        return []
    with db_pool.connection() as conn:
        rows = conn.execute(
            "SELECT id FROM users WHERE deleted_at IS NULL",
        ).fetchall()
    return [str(row["id"]) for row in rows
            if is_admin(str(row["id"]))]


# The security-events view (spec Phase 62): audit actions that are
# about authentication and account security, matched by prefix so
# the family stays complete as actions are added ('auth.login'
# covers 'auth.login' and 'auth.login_failed'). Only meta is ever
# exposed — action, actor kind, time; the audit detail (PII-free as
# it is) stays in the full audit view.
_SECURITY_ACTION_PATTERNS = (
    "auth.login%",
    "auth.passkey%",
    "auth.password_reset%",
    "auth.totp%",
    "account.deleted%",
    "api_token.%",
    "privacy_export",
    # Phase 77 engineering alerts land in the same trail (written by
    # monitoring/alerts.py via the audit writer) so the owner sees a
    # fired rule next to the sign-in events it sits alongside.
    "engineering_alert",
)
_SECURITY_EVENTS_LIMIT = 20


def _security_events(conn):
    rows = conn.execute(
        "SELECT action, actor_kind, created_at FROM audit_log"
        " WHERE action LIKE ANY(%s)"
        " ORDER BY created_at DESC, id DESC LIMIT %s",
        (list(_SECURITY_ACTION_PATTERNS), _SECURITY_EVENTS_LIMIT),
    ).fetchall()
    return [{
        "action": row["action"],
        "actor_kind": row["actor_kind"],
        "created_at": _iso(row["created_at"]),
    } for row in rows]


def _counts_by(conn, table, column, where=""):
    rows = conn.execute(
        "SELECT " + column + " AS k, COUNT(*) AS n FROM " + table
        + where + " GROUP BY " + column,
    ).fetchall()
    return {row["k"]: int(row["n"]) for row in rows}


_DAY = "interval '24 hours'"


def _metrics_block(conn):
    """Operational metrics (spec Phase 76): live queue state plus
    trailing-24h throughput/failure numbers, all computed from the
    product's own tables — no external monitoring service. Every
    windowed figure is labeled in its key; counts only, per the
    module's privacy contract.

    Window notes: a completed (done) or dead job is counted in the
    24h window by finished_at (both terminal paths stamp it); a
    'failed' job is mid-retry and has no finished_at yet, so it is
    counted by created_at. Error-event figures aggregate the
    ledger's hour-bucket rollups (error_events.bucket_start inside
    the window), so occurrence totals carry at most one partial
    bucket of edge at the window boundary."""
    scan_by_status = _counts_by(conn, "scan_jobs", "status")
    terminal = conn.execute(
        "SELECT"
        " COUNT(*) FILTER (WHERE status = 'done') AS completed,"
        " COUNT(*) FILTER (WHERE status = 'dead') AS dead"
        " FROM scan_jobs"
        " WHERE finished_at >= now() - " + _DAY,
    ).fetchone()
    failed_24h = conn.execute(
        "SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'failed'"
        " AND created_at >= now() - " + _DAY,
    ).fetchone()["n"]
    median = conn.execute(
        "SELECT percentile_cont(0.5) WITHIN GROUP"
        " (ORDER BY EXTRACT(EPOCH FROM (finished_at - started_at)))"
        " AS med FROM scan_jobs"
        " WHERE status = 'done' AND started_at IS NOT NULL"
        " AND finished_at >= now() - " + _DAY,
    ).fetchone()["med"]
    queue = conn.execute(
        "SELECT"
        " COUNT(*) FILTER (WHERE status = 'queued') AS queued,"
        " COUNT(*) FILTER (WHERE status = 'running') AS running,"
        " EXTRACT(EPOCH FROM (now() - MIN(created_at)"
        "   FILTER (WHERE status = 'queued'))) AS oldest_age"
        " FROM scan_jobs WHERE status IN ('queued', 'running')",
    ).fetchone()
    cases_by_status = _counts_by(conn, "remediation_cases", "status")
    notifications_24h = _counts_by(
        conn, "notifications", "status",
        " WHERE created_at >= now() - " + _DAY)
    sources = conn.execute(
        "SELECT COUNT(*) AS total,"
        " COUNT(*) FILTER (WHERE checked_at >= now() - " + _DAY
        + ") AS checked_24h,"
        " COUNT(*) FILTER (WHERE state = 'unreachable')"
        " AS unreachable"
        " FROM broker_source_checks",
    ).fetchone()
    security_rows = conn.execute(
        "SELECT action AS k, COUNT(*) AS n FROM audit_log"
        " WHERE action LIKE ANY(%s)"
        " AND created_at >= now() - " + _DAY
        + " GROUP BY action",
        (list(_SECURITY_ACTION_PATTERNS),),
    ).fetchall()
    security_by_kind = {row["k"]: int(row["n"]) for row in security_rows}
    error_pairs = conn.execute(
        "SELECT COUNT(*) AS pairs FROM"
        " (SELECT 1 FROM error_events"
        " WHERE bucket_start >= now() - " + _DAY
        + " GROUP BY context, error_class) AS d",
    ).fetchone()["pairs"]
    error_total = conn.execute(
        "SELECT COALESCE(SUM(occurrence_count), 0) AS total"
        " FROM error_events WHERE bucket_start >= now() - " + _DAY,
    ).fetchone()["total"]
    top_rows = conn.execute(
        "SELECT context, error_class,"
        " SUM(occurrence_count) AS n FROM error_events"
        " WHERE bucket_start >= now() - " + _DAY
        + " GROUP BY context, error_class"
        " ORDER BY n DESC, context, error_class LIMIT 5",
    ).fetchall()
    return {
        "scan_jobs": {
            "by_status": scan_by_status,
            "last_24h": {
                "completed": int(terminal["completed"]),
                "failed": int(failed_24h),
                "dead": int(terminal["dead"]),
            },
            "median_completed_duration_seconds_last_24h": (
                float(median) if median is not None else None),
        },
        "queue": {
            "queued": int(queue["queued"]),
            "running": int(queue["running"]),
            "active": int(queue["queued"]) + int(queue["running"]),
            "oldest_queued_age_seconds": (
                float(queue["oldest_age"])
                if queue["oldest_age"] is not None else None),
        },
        "remediation_cases_by_status": cases_by_status,
        "notifications_by_status_last_24h": notifications_24h,
        "broker_sources": {
            "total": int(sources["total"]),
            "checked_last_24h": int(sources["checked_24h"]),
            "unreachable": int(sources["unreachable"]),
        },
        "security_events_by_kind_last_24h": security_by_kind,
        "errors_last_24h": {
            "distinct_context_class_pairs": int(error_pairs),
            "total_occurrences": int(error_total),
            "top": [{
                "context": row["context"],
                "error_class": row["error_class"],
                "occurrences": int(row["n"]),
            } for row in top_rows],
        },
    }


def metrics(admin_user_id):
    """The metrics block on its own (GET /api/admin/metrics) —
    the same object overview() embeds under "metrics"."""
    with db_pool.connection() as conn:
        block = _metrics_block(conn)
    audit.record(admin_user_id, "admin", "admin.metrics_viewed")
    return block


def overview(admin_user_id):
    """Platform aggregates for the owner. Counts only — see the
    module docstring's privacy contract."""
    with db_pool.connection() as conn:
        users_total = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL",
        ).fetchone()["n"]
        users_last_30d = conn.execute(
            "SELECT COUNT(*) AS n FROM users"
            " WHERE deleted_at IS NULL"
            " AND created_at >= now() - interval '30 days'",
        ).fetchone()["n"]
        identifiers_by_kind = _counts_by(
            conn, "identifiers", "kind", " WHERE deleted_at IS NULL")
        scan_jobs_by_status = _counts_by(conn, "scan_jobs", "status")
        cases_by_status = _counts_by(
            conn, "remediation_cases", "status")
        notifications_by_status = _counts_by(
            conn, "notifications", "status")
        brokers = conn.execute(
            "SELECT COUNT(*) AS n FROM brokers WHERE active = true",
        ).fetchone()["n"]
        security_events = _security_events(conn)
        metrics_block = _metrics_block(conn)
    from remediation import source_checks

    result = {
        "users": {
            "total": int(users_total),
            "registered_last_30d": int(users_last_30d),
        },
        "identifiers_by_kind": identifiers_by_kind,
        "scan_jobs_by_status": scan_jobs_by_status,
        "remediation_cases_by_status": cases_by_status,
        "notifications_by_status": notifications_by_status,
        "brokers": int(brokers),
        "providers": providers_registry.get_registry().summary(),
        "db": db_pool.db_status(),
        # The emergency controls' current state (core/flags.py,
        # spec Phases 120/122): booleans only, so the owner can see
        # at a glance which capabilities a flag has switched off.
        "flags": flags.snapshot(),
        # Per-broker source health (Phases 32/125-lite): the daily
        # sweep's latest state per broker opt-out page — counts +
        # flagged slugs only, from remediation/source_checks.py.
        "source_health": source_checks.source_health(),
        # The security-events view (Phase 62): the latest auth /
        # account-security audit rows, meta only.
        "security_events": security_events,
        # Operational metrics (Phase 76): live queue state +
        # trailing-24h throughput and failure numbers. The same
        # block is served standalone at GET /api/admin/metrics.
        "metrics": metrics_block,
    }
    audit.record(admin_user_id, "admin", "admin.overview_viewed")
    return result


def _public_audit_row(row):
    return {
        "id": int(row["id"]),
        "actor_user_id": (str(row["actor_user_id"])
                          if row["actor_user_id"] else None),
        "actor_kind": row["actor_kind"],
        "action": row["action"],
        "target_kind": row["target_kind"],
        "target_id": row["target_id"],
        "detail": row["detail"] if isinstance(row["detail"], dict)
        else {},
        "created_at": _iso(row["created_at"]),
    }


def list_audit(admin_user_id, limit=100):
    """The most recent audit rows, newest first. Detail is PII-free
    by construction (accounts/audit.py) — safe to show as-is."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))
    with db_pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, actor_user_id, actor_kind, action, target_kind,"
            " target_id, detail, created_at FROM audit_log"
            " ORDER BY created_at DESC, id DESC LIMIT %s",
            (limit,),
        ).fetchall()
    entries = [_public_audit_row(row) for row in rows]
    # Recorded AFTER the read, so a view never lists itself.
    audit.record(admin_user_id, "admin", "admin.audit_viewed",
                 detail={"limit": limit})
    return entries
