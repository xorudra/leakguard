"""Identifier vault storage (spec Phase 3).

Write/read API over the `identifiers` table (see db/migrations/
0001_vault.sql). Rules this module enforces:

* Plaintext values are normalized for lookup, masked for display and
  envelope-encrypted for storage. Plaintext is never written to the
  database and never logged.
* Plaintext leaves the vault only through reveal() (by value) and
  reveal_by_id() (by row id, for the Stage S5 scan worker acting for
  the account owner). Everything else returns the masked form.
* Lookups are by HMAC only: get_by_lookup(kind, value) recomputes the
  lookup HMAC and finds the row without the database ever seeing the
  value.
* put() is idempotent per (kind, value): re-adding the same identifier
  returns the existing live record instead of creating a duplicate
  (the partial unique index in the schema backs this up).
* Soft delete only: soft_delete() stamps deleted_at; the row leaves
  every lookup immediately and the identifier can be re-added later.

Configuration (environment only): DATABASE_URL, VAULT_MASTER_KEY,
VAULT_LOOKUP_KEY. When unconfigured, every operation raises
VaultNotConfiguredError and the rest of the app is unaffected.
"""

import hashlib
import hmac as hmac_mod
import re

from db import pool
from vault import crypto

KINDS = ("email", "phone", "name", "address", "username")

_BULLET = "•"
_WS_RE = re.compile(r"\s+")
_NON_DIGIT_RE = re.compile(r"\D+")


class VaultNotConfiguredError(Exception):
    """DATABASE_URL / vault keys are not configured in the environment."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def vault_configured():
    """True when the DB and both vault keys are present and well-formed."""
    if not pool.configured():
        return False
    try:
        crypto.load_key_from_env("VAULT_MASTER_KEY")
        crypto.load_key_from_env("VAULT_LOOKUP_KEY")
    except crypto.VaultKeyError:
        return False
    return True


def _require_configured():
    if not pool.configured():
        raise VaultNotConfiguredError("DATABASE_URL is not configured")
    try:
        master = crypto.load_key_from_env("VAULT_MASTER_KEY")
        lookup = crypto.load_key_from_env("VAULT_LOOKUP_KEY")
    except crypto.VaultKeyError as exc:
        raise VaultNotConfiguredError(str(exc))
    return master, lookup


# ---------------------------------------------------------------------------
# Normalization, lookup HMAC, masking (pure functions — offline testable)
# ---------------------------------------------------------------------------

def _check_kind(kind):
    kind = str(kind or "").strip().lower()
    if kind not in KINDS:
        raise ValueError("unknown identifier kind: %r" % kind)
    return kind


def normalize(kind, value):
    """Canonical form used for lookup HMACs (NOT for display/storage).

    email:    trim + lowercase
    phone:    digits only; a leading international "00" prefix is
              dropped (country-agnostic; no country is assumed)
    others:   trim, collapse internal whitespace, casefold
    """
    kind = _check_kind(kind)
    value = "" if value is None else str(value)
    if kind == "email":
        return value.strip().lower()
    if kind == "phone":
        digits = _NON_DIGIT_RE.sub("", value)
        if digits.startswith("00"):
            digits = digits[2:]
        return digits
    return _WS_RE.sub(" ", value.strip()).casefold()


def hmac_with_label(label, normalized_value, lookup_key=None):
    """HMAC-SHA256 digest (bytes) over an arbitrary label + an
    ALREADY-normalized value: HMAC(key, label + "\\x00" + value).

    This is the vault's single MAC recipe. lookup_hmac() uses it with
    the identifier kind as the label; accounts (Stage S3) use it with
    the label "account_email" so account emails are looked up by the
    same keyed-HMAC scheme without becoming vault identifiers.
    """
    if lookup_key is None:
        lookup_key = crypto.load_key_from_env("VAULT_LOOKUP_KEY")
    lookup_key = crypto.validate_key(lookup_key, "lookup key")
    msg = (str(label) + "\x00" + str(normalized_value)).encode("utf-8")
    return hmac_mod.new(lookup_key, msg, hashlib.sha256).digest()


def lookup_hmac(kind, value, lookup_key=None):
    """HMAC-SHA256 digest (bytes) over kind + normalized value.

    Deterministic, so equal identifiers always find their row; the kind
    is part of the MAC input, so the same string stored as an email and
    as a username can never collide.
    """
    kind = _check_kind(kind)
    return hmac_with_label(kind, normalize(kind, value), lookup_key)


def mask(kind, value):
    """Display-safe rendering, computed at write time so list views
    never need to decrypt.

    email:   first char of the local part + ••• + @domain  (r•••@x.com)
    phone:   ••• + last 2 digits
    others:  first character + •••
    """
    kind = _check_kind(kind)
    if kind == "email":
        normalized = normalize(kind, value)
        local, sep, domain = normalized.partition("@")
        if sep and local:
            return local[0] + _BULLET * 3 + "@" + domain
        return (normalized[:1] or "") + _BULLET * 3
    if kind == "phone":
        digits = normalize(kind, value)
        return _BULLET * 3 + digits[-2:] if len(digits) >= 2 else _BULLET * 3
    stripped = "" if value is None else str(value).strip()
    return (stripped[:1] or "") + _BULLET * 3


# ---------------------------------------------------------------------------
# Storage operations
# ---------------------------------------------------------------------------

_PUBLIC_COLUMNS = "id, user_id, kind, masked, created_at, updated_at"


def _public(row):
    if row is None:
        return None
    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]) if row.get("user_id") else None,
        "kind": row["kind"],
        "masked": row["masked"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def put(kind, value, user_id=None):
    """Store an identifier (idempotently). Returns the public record
    (masked — never plaintext). Re-adding a live identifier returns the
    existing record. Raises VaultNotConfiguredError when unconfigured,
    ValueError for an empty value or unknown kind."""
    kind = _check_kind(kind)
    master_key, lookup_key = _require_configured()
    if value is None or not str(value).strip():
        raise ValueError("value must not be empty")
    if not normalize(kind, value):
        raise ValueError("value must not be empty")
    digest = lookup_hmac(kind, value, lookup_key)
    stored_value = str(value).strip()
    blob = crypto.encrypt_value(master_key, stored_value)
    masked = mask(kind, value)
    with pool.connection() as conn:
        row = conn.execute(
            "INSERT INTO identifiers (user_id, kind, hmac_lookup, ciphertext, masked)"
            " VALUES (%s, %s, %s, %s, %s)"
            " ON CONFLICT (kind, hmac_lookup) WHERE deleted_at IS NULL"
            " DO NOTHING RETURNING " + _PUBLIC_COLUMNS,
            (user_id, kind, digest, blob, masked),
        ).fetchone()
        if row is None:  # already present — return the live record
            row = conn.execute(
                "SELECT " + _PUBLIC_COLUMNS + " FROM identifiers"
                " WHERE kind = %s AND hmac_lookup = %s AND deleted_at IS NULL",
                (kind, digest),
            ).fetchone()
    return _public(row)


def get_by_lookup(kind, value):
    """Find the live record for an identifier, by HMAC only. Returns
    the public (masked) record or None. Never returns plaintext."""
    kind = _check_kind(kind)
    _master, lookup_key = _require_configured()
    digest = lookup_hmac(kind, value, lookup_key)
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT " + _PUBLIC_COLUMNS + " FROM identifiers"
            " WHERE kind = %s AND hmac_lookup = %s AND deleted_at IS NULL",
            (kind, digest),
        ).fetchone()
    return _public(row)


def reveal(kind, value):
    """Return the plaintext for an identifier, or None if not stored.

    This is the ONLY plaintext exit from the vault. It exists for
    future authorized flows (Stage S3+: an account owner acting on
    their own identifiers); callers must enforce authorization before
    calling it. Never log the return value.
    """
    kind = _check_kind(kind)
    master_key, lookup_key = _require_configured()
    digest = lookup_hmac(kind, value, lookup_key)
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT ciphertext FROM identifiers"
            " WHERE kind = %s AND hmac_lookup = %s AND deleted_at IS NULL",
            (kind, digest),
        ).fetchone()
    if row is None:
        return None
    return crypto.decrypt_value(master_key, bytes(row["ciphertext"]))


def reveal_by_id(identifier_id, user_id=None):
    """Return the plaintext for a stored identifier ROW, or None.

    The second plaintext exit from the vault, added for the scan
    worker (Stage S5): the worker runs server-side on behalf of the
    account owner (who consented to scanning), so it resolves rows by
    id instead of by value. When user_id is given the row must belong
    to that user — a mismatched owner reads as "not found". Callers
    must enforce authorization before calling; never log the result.
    """
    master_key, _lookup_key = _require_configured()
    with pool.connection() as conn:
        if user_id is None:
            row = conn.execute(
                "SELECT ciphertext FROM identifiers"
                " WHERE id = %s AND deleted_at IS NULL",
                (identifier_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT ciphertext FROM identifiers"
                " WHERE id = %s AND user_id = %s AND deleted_at IS NULL",
                (identifier_id, user_id),
            ).fetchone()
    if row is None:
        return None
    return crypto.decrypt_value(master_key, bytes(row["ciphertext"]))


def soft_delete(kind, value):
    """Soft-delete the live record for an identifier. Returns True if a
    live record was deleted, False if none existed. The identifier can
    be re-added afterwards (put creates a fresh row)."""
    kind = _check_kind(kind)
    _master, lookup_key = _require_configured()
    digest = lookup_hmac(kind, value, lookup_key)
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE identifiers SET deleted_at = now(), updated_at = now()"
            " WHERE kind = %s AND hmac_lookup = %s AND deleted_at IS NULL"
            " RETURNING id",
            (kind, digest),
        ).fetchone()
    return row is not None
