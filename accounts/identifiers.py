"""User-owned identifiers (Stage S3 wiring of the Stage S2 vault).

The vault (vault/store.py) owns storage: normalization, HMAC lookup,
envelope encryption, masking. This module owns AUTHORIZATION: every
operation is scoped to the authenticated user, list views only ever
see the caller's rows, and deleting someone else's identifier id
answers the same 404 as a nonexistent id (never a 403 leak).

One vault invariant shapes add(): a live (kind, value) pair exists at
most once globally (0001's partial unique index). Re-adding your own
identifier is idempotent. A legacy unowned row (user_id NULL, from
the pre-accounts vault) is claimed by the first account that adds it.
A row owned by a DIFFERENT user cannot be taken over — that is a 409,
and the other user's data stays untouched.
"""

from core import errors
from db import pool
from vault import store as vault_store

_COLUMNS = "id, user_id, kind, masked, created_at, updated_at"


def _public(row):
    from accounts.auth import _iso

    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]) if row.get("user_id") else None,
        "kind": row["kind"],
        "masked": row["masked"],
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
    }


def add_identifier(user_id, kind, value):
    """Add (or idempotently re-add) an identifier for this user.
    Returns the masked public record — never plaintext."""
    try:
        record = vault_store.put(kind, value, user_id=user_id)
    except ValueError:
        raise errors.bad_request(
            "invalid_identifier",
            "Pick a valid kind and a non-empty value")
    if record is None:  # pragma: no cover - put() always returns a row
        raise errors.internal_error()
    # The vault's record carries raw datetimes; normalize to the API
    # shape (ISO strings) before it goes anywhere near a response.
    record = _public(record)
    if record["user_id"] == str(user_id):
        return record
    if record["user_id"] is None:
        # Claim a legacy unowned vault row for this account.
        with pool.connection() as conn:
            conn.execute(
                "UPDATE identifiers SET user_id = %s, updated_at = now()"
                " WHERE id = %s AND user_id IS NULL AND deleted_at IS NULL",
                (user_id, record["id"]),
            )
        record["user_id"] = str(user_id)
        return record
    raise errors.conflict(
        "identifier_taken",
        "That identifier is already saved on another account")


def list_identifiers(user_id):
    """The caller's live identifiers, masked, oldest first."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT " + _COLUMNS + " FROM identifiers"
            " WHERE user_id = %s AND deleted_at IS NULL"
            " ORDER BY created_at, id",
            (user_id,),
        ).fetchall()
    return [_public(row) for row in rows]


def delete_identifier(user_id, identifier_id):
    """Soft-delete one of the caller's identifiers by id. Foreign or
    unknown ids raise the same 404 (IDOR-safe by construction)."""
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE identifiers SET deleted_at = now(), updated_at = now()"
            " WHERE id = %s AND user_id = %s AND deleted_at IS NULL"
            " RETURNING id",
            (identifier_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("Identifier not found")
    return {"deleted": True, "id": str(identifier_id)}
