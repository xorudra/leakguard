"""Consent records (spec Phase 6).

Append-only: registration seeds version 1 (granted = false) for every
purpose; every later grant or withdrawal appends the next version.
Nothing is ever updated or deleted, so the history IS the audit
trail, and the current state is simply the highest version per
purpose. The Privacy Center's data export includes the full history.

Consent precedes capability in this product (migration-plan
sequencing rule): monitoring, automated remediation and
notifications all check the current state before acting.
"""

from core import errors
from db import pool

PURPOSES = ("scanning", "monitoring", "automated_remediation", "notifications")


def seed_defaults(conn, user_id):
    """Insert the version-1 defaults (all purposes off) for a new
    user. Runs inside the caller's transaction/connection."""
    for purpose in PURPOSES:
        conn.execute(
            "INSERT INTO consents (user_id, purpose, version, granted)"
            " VALUES (%s, %s, 1, false) ON CONFLICT DO NOTHING",
            (user_id, purpose),
        )


def _public(row):
    from accounts.auth import _iso

    return {
        "purpose": row["purpose"],
        "granted": bool(row["granted"]),
        "version": int(row["version"]),
        "updated_at": _iso(row["created_at"]),
    }


def current_consents(user_id):
    """Current state per purpose: the latest version of each, in the
    canonical PURPOSES order. A purpose with no rows (should not
    happen — registration seeds them) reports granted=false,
    version=0."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT DISTINCT ON (purpose) purpose, granted, version,"
            " created_at FROM consents WHERE user_id = %s"
            " ORDER BY purpose, version DESC",
            (user_id,),
        ).fetchall()
    by_purpose = {row["purpose"]: _public(row) for row in rows}
    state = []
    for purpose in PURPOSES:
        state.append(by_purpose.get(purpose, {
            "purpose": purpose,
            "granted": False,
            "version": 0,
            "updated_at": None,
        }))
    return state


def history(user_id):
    """The full append-only history (data export)."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT purpose, granted, version, created_at FROM consents"
            " WHERE user_id = %s ORDER BY created_at, purpose, version",
            (user_id,),
        ).fetchall()
    return [_public(row) for row in rows]


def set_consent(user_id, purpose, granted):
    """Append the next version for one purpose and return the full
    new current state. Unknown purposes are a hard 400 — a client bug
    must never silently create a purpose nobody defined."""
    if purpose not in PURPOSES:
        raise errors.bad_request(
            "unknown_purpose", "Unknown consent purpose")
    if not isinstance(granted, bool):
        raise errors.bad_request(
            "invalid_consent", "granted must be true or false")
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(version), 0) AS v FROM consents"
            " WHERE user_id = %s AND purpose = %s",
            (user_id, purpose),
        ).fetchone()
        conn.execute(
            "INSERT INTO consents (user_id, purpose, version, granted)"
            " VALUES (%s, %s, %s, %s)",
            (user_id, purpose, int(row["v"]) + 1, granted),
        )
    return current_consents(user_id)
