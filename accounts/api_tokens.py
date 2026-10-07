"""Personal API tokens (Stage S13, spec Phases 126–132).

A token lets the owner's own scripts READ their LeakGuard data —
action center, scan jobs, removal cases, notifications, timeline —
without a browser session. The safety contract:

* READ-ONLY BY CONSTRUCTION. Tokens are resolved only by the read
  routes (see app.py's `_require_reader`); every mutation route
  resolves the session cookie instead, so a request carrying a
  Bearer token and no session answers 401 no matter how valid the
  token is. `scopes` records that ('read' is the only scope).
* HASH AT REST, like sessions (accounts/sessions.py): the database
  stores only the SHA-256 digest of the raw token. The raw value
  (`lg_` + token_urlsafe(32)) is returned exactly once, at
  creation; afterwards only its 8-character display prefix is ever
  shown again.
* Revocation is a timestamp, checked on every use; validation
  joins the users table and refuses tokens whose owner has been
  soft-deleted, exactly like session validation.
* Nothing about a token — raw, digest or prefix beyond the stored
  display column — is ever logged, and the audit rows for create /
  revoke carry no token material (accounts/audit.py's filter is
  the second line of defence).
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from accounts import audit
from accounts.auth import _iso
from core import errors
from db import pool

TOKEN_MARKER = "lg_"
_PREFIX_LEN = 8  # marker (3) + 5 chars: display only, never auth
MAX_NAME_LENGTH = 60
SCOPES = ["read"]
_TOUCH_INTERVAL = timedelta(minutes=5)


def _now():
    return datetime.now(timezone.utc)


def _token_hash(token):
    return hashlib.sha256(str(token).encode("utf-8")).digest()


def _public_token(row):
    """The only token shape the API ever returns after creation:
    metadata and the display prefix — never the raw value, never
    the digest."""
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "prefix": row["prefix"],
        "scopes": list(row["scopes"] or []),
        "created_at": _iso(row["created_at"]),
        "last_used_at": _iso(row["last_used_at"]),
        "revoked_at": _iso(row["revoked_at"]),
    }


def create_token(user_id, name):
    """Create a token for the caller. The response carries the raw
    token exactly once; only its digest + display prefix persist."""
    if not isinstance(name, str):
        raise errors.bad_request(
            "invalid_name", "Give the token a short name")
    name = name.strip()
    if not 1 <= len(name) <= MAX_NAME_LENGTH:
        raise errors.bad_request(
            "invalid_name",
            "Token names are 1 to %d characters" % MAX_NAME_LENGTH)
    raw = TOKEN_MARKER + secrets.token_urlsafe(32)
    with pool.connection() as conn:
        row = conn.execute(
            "INSERT INTO api_tokens"
            " (user_id, name, token_hash, prefix, scopes)"
            " VALUES (%s, %s, %s, %s, %s)"
            " RETURNING id, name, prefix, scopes, created_at,"
            " last_used_at, revoked_at",
            (user_id, name, _token_hash(raw), raw[:_PREFIX_LEN], SCOPES),
        ).fetchone()
    audit.record(user_id, "user", "api_token.created", "api_token",
                 row["id"], {"label": name, "scopes": "read"})
    return {"token": raw, "record": _public_token(row)}


def list_tokens(user_id):
    """The caller's tokens, newest first — metadata only."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, name, prefix, scopes, created_at,"
            " last_used_at, revoked_at FROM api_tokens"
            " WHERE user_id = %s ORDER BY created_at DESC, id",
            (user_id,),
        ).fetchall()
    return [_public_token(row) for row in rows]


def revoke_token(user_id, token_id):
    """Revoke one of the caller's tokens. A foreign or unknown id
    answers the same 404 as a nonexistent one (Stage S3 pattern);
    revoking an already-revoked token is likewise a 404 — it is
    already inert, and pretending otherwise would leak its state."""
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE api_tokens SET revoked_at = now()"
            " WHERE id = %s AND user_id = %s AND revoked_at IS NULL"
            " RETURNING id",
            (token_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("API token not found")
    audit.record(user_id, "user", "api_token.revoked", "api_token",
                 token_id)
    return {"deleted": True, "id": str(token_id)}


def authenticate_token(raw):
    """Resolve a raw Bearer token to its owner's public user dict,
    or None. None for: malformed token, unknown digest, revoked
    token, or a soft-deleted owner — callers turn every one of
    those into the same 401 as being signed out.

    Side effect: last_used_at bookkeeping, throttled to one write
    per token per 5 minutes (mirrors sessions' touch throttle).
    """
    if not isinstance(raw, str) or not raw.startswith(TOKEN_MARKER):
        return None
    digest = _token_hash(raw)
    now = _now()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT t.id AS token_id, t.last_used_at,"
            " u.id, u.email_masked, u.totp_enabled, u.created_at,"
            " u.deleted_at AS user_deleted_at"
            " FROM api_tokens t JOIN users u ON u.id = t.user_id"
            " WHERE t.token_hash = %s AND t.revoked_at IS NULL",
            (digest,),
        ).fetchone()
        if row is None or row["user_deleted_at"] is not None:
            return None
        last_used = row["last_used_at"]
        if last_used is None or now - last_used > _TOUCH_INTERVAL:
            conn.execute(
                "UPDATE api_tokens SET last_used_at = %s WHERE id = %s",
                (now, row["token_id"]),
            )
    from accounts.auth import public_user

    return public_user(row)
