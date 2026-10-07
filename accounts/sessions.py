"""Server-side sessions (spec Phase 4).

The cookie carries a random token (secrets.token_urlsafe(32)); the
database stores only its SHA-256 digest, so a database leak does not
leak usable sessions and a session can be revoked server-side at any
time. Sessions live 30 days with sliding renewal: an actively used
session whose expiry drifts near is extended instead of logging the
user out mid-task (UX law — fewer chores, same security).

Validation joins the users table and refuses sessions whose user is
soft-deleted, so account deletion kills every session immediately.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from db import pool

COOKIE_NAME = "lg_session"
SESSION_DAYS = 30
_RENEW_WHEN_REMAINING = timedelta(days=15)
_TOUCH_INTERVAL_SECONDS = 60


def _now():
    return datetime.now(timezone.utc)


def _token_hash(token):
    return hashlib.sha256(str(token).encode("utf-8")).digest()


def cookie_header(token):
    """Set-Cookie value for a live session token."""
    return (
        "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Lax"
        % (COOKIE_NAME, token, SESSION_DAYS * 24 * 3600)
    )


def clear_cookie_header():
    """Set-Cookie value that deletes the session cookie."""
    return "%s=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax" % COOKIE_NAME


def create_session(user_id):
    """Create a session for a user. Returns the RAW token (shown to
    the user once, as the cookie; only its digest is stored)."""
    token = secrets.token_urlsafe(32)
    now = _now()
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at)"
            " VALUES (%s, %s, %s)",
            (_token_hash(token), user_id, now + timedelta(days=SESSION_DAYS)),
        )
    return token


def _public_user(row):
    from accounts.auth import public_user

    return public_user(row)


def validate_session(token):
    """Resolve a cookie token to its live user (public dict) or None.

    None for: missing/unknown token, revoked session, expired session,
    or a user who has been soft-deleted. Applies sliding renewal and
    last-seen bookkeeping as side effects.
    """
    if not token:
        return None
    digest = _token_hash(token)
    now = _now()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT s.expires_at, s.last_seen_at,"
            " u.id, u.email_masked, u.totp_enabled, u.created_at,"
            " u.deleted_at AS user_deleted_at"
            " FROM sessions s JOIN users u ON u.id = s.user_id"
            " WHERE s.token_hash = %s AND s.revoked_at IS NULL",
            (digest,),
        ).fetchone()
        if row is None or row["user_deleted_at"] is not None:
            return None
        if row["expires_at"] <= now:
            return None
        # Sliding renewal + last-seen touch (throttled writes).
        last_seen = row["last_seen_at"]
        stale_touch = (
            last_seen is None
            or (now - last_seen).total_seconds() > _TOUCH_INTERVAL_SECONDS
        )
        renew = row["expires_at"] - now < _RENEW_WHEN_REMAINING
        if stale_touch or renew:
            expires = (
                now + timedelta(days=SESSION_DAYS) if renew else row["expires_at"]
            )
            conn.execute(
                "UPDATE sessions SET last_seen_at = %s, expires_at = %s"
                " WHERE token_hash = %s",
                (now, expires, digest),
            )
    return _public_user(row)


def revoke_session(token):
    """Revoke one session by its raw token (logout)."""
    if not token:
        return
    with pool.connection() as conn:
        conn.execute(
            "UPDATE sessions SET revoked_at = now()"
            " WHERE token_hash = %s AND revoked_at IS NULL",
            (_token_hash(token),),
        )


def revoke_all_sessions(user_id, except_token=None):
    """Revoke every session of a user (password change, deletion).
    `except_token` keeps the caller's current session alive."""
    with pool.connection() as conn:
        if except_token:
            conn.execute(
                "UPDATE sessions SET revoked_at = now()"
                " WHERE user_id = %s AND revoked_at IS NULL"
                " AND token_hash <> %s",
                (user_id, _token_hash(except_token)),
            )
        else:
            conn.execute(
                "UPDATE sessions SET revoked_at = now()"
                " WHERE user_id = %s AND revoked_at IS NULL",
                (user_id,),
            )
