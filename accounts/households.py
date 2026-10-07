"""Households — family profiles (Stage S11, spec Phases 57–62).

A household groups the people whose details ONE account protects.
A member is a LABEL the owner types ("Mum", "Dad") — never an
identifier value, never an email, never credentials. Members cannot
log in and hold no data of their own; they exist so an identifier
can say whose it is (identifiers.member_id; NULL = the owner).

Authorization follows the Stage S3 pattern: every operation is
scoped by the session's user id through the household's owner, and a
foreign member id answers the same 404 as a nonexistent one.

The household itself is created lazily on first access — an account
that never groups anyone never grows a row it doesn't need.
"""

from accounts.auth import _iso
from core import errors
from db import pool

MAX_LABEL_LENGTH = 60


def _public_member(row):
    return {
        "id": str(row["id"]),
        "label": row["label"],
        "created_at": _iso(row["created_at"]),
    }


def _ensure_household(conn, user_id):
    """The caller's household row, created on first use."""
    conn.execute(
        "INSERT INTO households (owner_user_id) VALUES (%s)"
        " ON CONFLICT (owner_user_id) DO NOTHING",
        (user_id,),
    )
    return conn.execute(
        "SELECT id, name, created_at FROM households"
        " WHERE owner_user_id = %s",
        (user_id,),
    ).fetchone()


def get_household(user_id):
    """The caller's household (lazily created) + its members,
    oldest first."""
    with pool.connection() as conn:
        household = _ensure_household(conn, user_id)
        members = conn.execute(
            "SELECT id, label, created_at FROM household_members"
            " WHERE household_id = %s ORDER BY created_at, id",
            (household["id"],),
        ).fetchall()
    return {
        "id": str(household["id"]),
        "name": household["name"],
        "members": [_public_member(row) for row in members],
    }


def add_member(user_id, label):
    """Add a member label to the caller's household. Labels are
    display text only — duplicates are allowed, because two people
    can share a name and a label is not an identity."""
    if not isinstance(label, str):
        raise errors.bad_request(
            "invalid_label", "Give the person a short name or label")
    label = label.strip()
    if not 1 <= len(label) <= MAX_LABEL_LENGTH:
        raise errors.bad_request(
            "invalid_label",
            "Labels are 1 to %d characters" % MAX_LABEL_LENGTH)
    with pool.connection() as conn:
        household = _ensure_household(conn, user_id)
        row = conn.execute(
            "INSERT INTO household_members (household_id, label)"
            " VALUES (%s, %s) RETURNING id, label, created_at",
            (household["id"], label),
        ).fetchone()
    return _public_member(row)


def delete_member(user_id, member_id):
    """Remove one of the caller's members. The member's identifiers
    keep existing — the identifiers.member_id foreign key sets them
    back to NULL (the owner themself) via ON DELETE SET NULL."""
    with pool.connection() as conn:
        row = conn.execute(
            "DELETE FROM household_members m"
            " USING households h"
            " WHERE m.id = %s AND m.household_id = h.id"
            " AND h.owner_user_id = %s"
            " RETURNING m.id",
            (member_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("Household member not found")
    return {"deleted": True, "id": str(member_id)}


def member_belongs_to(user_id, member_id):
    """True only when the member sits in the CALLER's household —
    the check identifiers use before accepting a member_id, so a
    foreign id is indistinguishable from a nonexistent one."""
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT 1 AS ok FROM household_members m"
            " JOIN households h ON h.id = m.household_id"
            " WHERE m.id = %s AND h.owner_user_id = %s",
            (member_id, user_id),
        ).fetchone()
    return row is not None
