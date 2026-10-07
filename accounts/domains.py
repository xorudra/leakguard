"""User domains + ownership verification (Stage S6, spec 19/58).

Flow:
  add_domain()     — validates + normalizes the domain, saves it as a
                     vault identifier (kind 'domain', so scans pick
                     it up like every other saved detail) and creates
                     the verification row with a fresh random token.
                     Idempotent: re-adding a live domain returns the
                     existing row (and its existing token).
  verify_domain()  — reads the TXT records of _leakguard.<domain>
                     through the domain_dns provider (DNS-over-
                     HTTPS) and compares against the stored token in
                     constant time. A match flips verified on; no
                     match leaves the domain pending. A DNS outage is
                     a 503 — never a silent "not verified".
  list_domains()   — the caller's live domains, full domain text
                     (domains are public, not secret) + status.
  delete_domain()  — soft-deletes the verification row only. The
                     vault identifier STAYS (it is a saved detail the
                     user manages in the usual list); without a live
                     verified row the orchestrator simply reports the
                     domain unverified again.

Authorization mirrors identifiers.py: everything is scoped by the
session's user id, and a foreign or unknown domain id answers the
same 404 as a nonexistent one.
"""

import hmac as hmac_mod
import re
import secrets

from accounts import identifiers as identifiers_service
from core import errors
from db import pool
from providers import registry as providers_registry
from vault import store as vault_store

TOKEN_PREFIX = "leakguard-verify="
TXT_NAME_PREFIX = "_leakguard."
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,60}[a-z0-9])$")

_COLUMNS = ("id, user_id, domain, verify_token, verified, verified_at,"
            " created_at")


def _public(row):
    from accounts.auth import _iso

    return {
        "id": str(row["id"]),
        "domain": row["domain"],
        "verified": bool(row["verified"]),
        "verified_at": _iso(row["verified_at"]),
        "created_at": _iso(row["created_at"]),
        "txt_name": TXT_NAME_PREFIX + row["domain"],
        "txt_value": row["verify_token"],
    }


def normalize_and_validate(raw):
    """Normalize a user-supplied domain and validate its shape.
    Raises the API's 400 invalid_domain for anything else."""
    domain = vault_store.normalize("domain", raw or "")
    if not domain or not _DOMAIN_RE.match(domain):
        raise errors.bad_request(
            "invalid_domain",
            "Enter a domain like example.com")
    return domain


def add_domain(user_id, raw_domain):
    """Create (or idempotently return) the caller's domain row and
    its verification token. Also saves the domain as a vault
    identifier so full scans see it."""
    domain = normalize_and_validate(raw_domain)
    # The vault save enforces the one-owner-per-identifier rule and
    # raises its own 409 when another account already saved it.
    identifiers_service.add_identifier(user_id, "domain", domain)
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT " + _COLUMNS + " FROM domains"
            " WHERE user_id = %s AND domain = %s AND deleted_at IS NULL",
            (user_id, domain),
        ).fetchone()
        if row is None:
            token = TOKEN_PREFIX + secrets.token_hex(16)
            row = conn.execute(
                "INSERT INTO domains (user_id, domain, verify_token)"
                " VALUES (%s, %s, %s) RETURNING " + _COLUMNS,
                (user_id, domain, token),
            ).fetchone()
    return _public(row)


def list_domains(user_id):
    """The caller's live domains, oldest first."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT " + _COLUMNS + " FROM domains"
            " WHERE user_id = %s AND deleted_at IS NULL"
            " ORDER BY created_at, id",
            (user_id,),
        ).fetchall()
    return [_public(row) for row in rows]


def _get_owned(conn, user_id, domain_id):
    return conn.execute(
        "SELECT " + _COLUMNS + " FROM domains"
        " WHERE id = %s AND user_id = %s AND deleted_at IS NULL",
        (domain_id, user_id),
    ).fetchone()


def verify_domain(user_id, domain_id):
    """Check the _leakguard TXT record for this domain. Returns the
    (possibly newly verified) public row. Foreign/unknown ids are a
    404; a DNS provider failure is a 503 (unreachable is not the
    same as 'record absent')."""
    with pool.connection() as conn:
        row = _get_owned(conn, user_id, domain_id)
    if row is None:
        raise errors.not_found("Domain not found")
    public = _public(row)
    if row["verified"]:
        return public
    providers = providers_registry.get_registry().get_providers("domain_dns")
    provider = providers[0] if providers else None
    if provider is None:
        raise errors.unavailable(
            "dns_unavailable", "Domain checks are not available right now")
    result = provider.txt_records(TXT_NAME_PREFIX + row["domain"])
    if result.status != "ok":
        raise errors.unavailable(
            "dns_unavailable",
            "Could not read DNS records just now — try again in a moment")
    expected = row["verify_token"]
    for record in result.data or []:
        if hmac_mod.compare_digest(str(record).strip(), expected):
            with pool.connection() as conn:
                updated = conn.execute(
                    "UPDATE domains SET verified = true,"
                    " verified_at = now()"
                    " WHERE id = %s AND user_id = %s"
                    " AND deleted_at IS NULL RETURNING " + _COLUMNS,
                    (domain_id, user_id),
                ).fetchone()
            return _public(updated)
    return public


def delete_domain(user_id, domain_id):
    """Soft-delete the caller's domain row. The vault identifier is
    deliberately left alone ('saved details' and 'monitored
    domains' are separate lists); scanning just stops treating the
    domain as verified."""
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE domains SET deleted_at = now()"
            " WHERE id = %s AND user_id = %s AND deleted_at IS NULL"
            " RETURNING id",
            (domain_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("Domain not found")
    return {"deleted": True, "id": str(domain_id)}


def verified_domain_names(user_id):
    """The set of normalized domains this user has VERIFIED and not
    removed — the orchestrator's gate for domain scanning."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT domain FROM domains WHERE user_id = %s"
            " AND verified = true AND deleted_at IS NULL",
            (user_id,),
        ).fetchall()
    return {row["domain"] for row in rows}
