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


# The security-events view (spec Phase 62): audit actions that are
# about authentication and account security, matched by prefix so
# the family stays complete as actions are added ('auth.login'
# covers 'auth.login' and 'auth.login_failed'). Only meta is ever
# exposed — action, actor kind, time; the audit detail (PII-free as
# it is) stays in the full audit view.
_SECURITY_ACTION_PATTERNS = (
    "auth.login%",
    "auth.password_reset%",
    "auth.totp%",
    "account.deleted%",
    "api_token.%",
    "privacy_export",
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
