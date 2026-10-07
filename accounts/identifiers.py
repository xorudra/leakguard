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

import uuid

from accounts import audit
from core import errors
from db import pool
from vault import store as vault_store

_COLUMNS = "id, user_id, kind, masked, member_id, created_at, updated_at"


def _public(row):
    from accounts.auth import _iso

    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]) if row.get("user_id") else None,
        "kind": row["kind"],
        "masked": row["masked"],
        "member_id": str(row["member_id"]) if row.get("member_id") else None,
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
    }


def _validate_member(user_id, member_id):
    """Normalize an optional member assignment. None means "no
    assignment given" and passes through. Anything else must be a
    member of the CALLER's household — a foreign or malformed id
    raises the same 404, so membership in someone else's household
    is never revealed."""
    if member_id is None:
        return None
    try:
        member_id = str(uuid.UUID(str(member_id)))
    except (ValueError, AttributeError, TypeError):
        raise errors.not_found("Household member not found")
    from accounts import households as households_service

    if not households_service.member_belongs_to(user_id, member_id):
        raise errors.not_found("Household member not found")
    return member_id


def add_identifier(user_id, kind, value, member_id=None):
    """Add (or idempotently re-add) an identifier for this user.
    Returns the masked public record — never plaintext. An optional
    member_id assigns the identifier to one of the caller's
    household members (whose detail this is); without one, a re-add
    keeps whatever assignment the row already has."""
    member_id = _validate_member(user_id, member_id)
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
    if record["user_id"] is None:
        # Claim a legacy unowned vault row for this account.
        with pool.connection() as conn:
            conn.execute(
                "UPDATE identifiers SET user_id = %s, updated_at = now()"
                " WHERE id = %s AND user_id IS NULL AND deleted_at IS NULL",
                (user_id, record["id"]),
            )
        record["user_id"] = str(user_id)
    elif record["user_id"] != str(user_id):
        raise errors.conflict(
            "identifier_taken",
            "That identifier is already saved on another account")
    # The row is the caller's now. Apply a requested member
    # assignment, and report the assignment the row actually has
    # (the vault's own record shape predates members).
    with pool.connection() as conn:
        if member_id is not None:
            conn.execute(
                "UPDATE identifiers SET member_id = %s,"
                " updated_at = now()"
                " WHERE id = %s AND user_id = %s AND deleted_at IS NULL",
                (member_id, record["id"], user_id),
            )
        row = conn.execute(
            "SELECT member_id FROM identifiers WHERE id = %s",
            (record["id"],),
        ).fetchone()
    record["member_id"] = (
        str(row["member_id"]) if row and row["member_id"] else None)
    audit.record(user_id, "user", "identifier.added",
                 "identifier", record["id"], {"kind": record["kind"]})
    return record


def update_identifier_member(user_id, identifier_id, member_id):
    """Set (or clear, with member_id=None) the household member one
    of the caller's identifiers belongs to. Foreign identifiers and
    foreign members both answer 404."""
    member_id = _validate_member(user_id, member_id)
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE identifiers SET member_id = %s, updated_at = now()"
            " WHERE id = %s AND user_id = %s AND deleted_at IS NULL"
            " RETURNING " + _COLUMNS,
            (member_id, identifier_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("Identifier not found")
    return _public(row)


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
            " RETURNING id, kind",
            (identifier_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("Identifier not found")
    audit.record(user_id, "user", "identifier.removed",
                 "identifier", identifier_id, {"kind": row["kind"]})
    return {"deleted": True, "id": str(identifier_id)}
