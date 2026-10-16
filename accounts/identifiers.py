"""User-owned identifiers (Stage S3 wiring of the Stage S2 vault).

The vault (vault/store.py) owns storage: normalization, HMAC lookup,
envelope encryption, masking. This module owns AUTHORIZATION: every
operation is scoped to the authenticated user, list views only ever
see the caller's rows, and deleting someone else's identifier id
answers the same 404 as a nonexistent id (never a 403 leak).

One vault invariant shapes add(): since migration 0021 a live
(kind, value) pair is unique PER USER, never globally — the old
global index made this endpoint a cross-account existence oracle
and let a squatter block the real owner (audit 2026-10-16,
identifier-existence-oracle-and-squatting-409). Re-adding your own
identifier is idempotent, and whether or not another account
holds the same value is neither revealed nor blocking. A legacy
unowned row (user_id NULL, from the pre-accounts vault) is
claimed by the first account that adds it. A per-user count cap
and the route's per-user rate limit bound bulk probing.
"""

# The per-account ceiling on live identifiers: generous for a
# person plus household members (a handful of kinds each), small
# enough that scripted squatting/probing runs out of room fast.
MAX_IDENTIFIERS_PER_USER = 100

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
    with pool.connection() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM identifiers"
            " WHERE user_id = %s AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()
    if count["n"] >= MAX_IDENTIFIERS_PER_USER:
        raise errors.bad_request(
            "identifier_limit_reached",
            "You have saved the maximum of %d details — remove one "
            "before adding another" % MAX_IDENTIFIERS_PER_USER)
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
            claimed = conn.execute(
                "UPDATE identifiers SET user_id = %s, updated_at = now()"
                " WHERE id = %s AND user_id IS NULL AND deleted_at IS NULL"
                " RETURNING id",
                (user_id, record["id"]),
            ).fetchone()
        if claimed is None:
            # Run-2 hunt: the claim raced another account and
            # LOST — the old code set user_id on the response
            # anyway, telling (and audit-logging) this user that
            # they own a row they do not; their value would never
            # be scanned for them. Fall through to put(): under
            # migration 0021 it now inserts the caller's OWN row
            # for the same value.
            record = _public(vault_store.put(kind, value,
                                             user_id=user_id))
        else:
            record["user_id"] = str(user_id)
    # No foreign-owner branch remains: put() scopes to the caller,
    # so a value another account holds simply creates the caller's
    # own row — the response is identical either way (audit
    # 2026-10-16: no existence oracle, no squatting block).
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
