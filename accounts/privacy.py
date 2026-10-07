"""Privacy Center: the data export (spec Phase 49).

POST /api/privacy/export is — together with the login-internal email
decrypt — the ONLY place plaintext identifier values leave the
server, and only to the authenticated owner of the data, as a file
download. Because the file contains the owner's details in full,
the export re-authenticates first (Batch B hardening): the caller
must present the account password again, verified against the
stored Argon2id hash, and every attempt — successful or not — is
counted by the same credential rate limiter that guards login, so
the export can never become a password-guessing oracle bolted onto
a stolen session. There is deliberately no GET variant any more:
a download this sensitive is never one stray link away.

The document contains:

* the account (email REVEALED — it is the owner's own data — plus the
  masked form and creation date),
* every live identifier (kind, value REVEALED, masked, created_at),
* every live domain row (domain, verification state — domains are
  public, never secret),
* the FULL consent history (every version ever recorded),
* generated_at.

Two formats carry the SAME data: JSON (the document as-is) and CSV
(flattened section,record,field,value rows). Every successful
export writes an audit row ('privacy_export', with the format).

Never log the export body. The handler sends it as an attachment so
browsers do not render it inline.
"""

import csv
import io
import json
from datetime import datetime, timezone

from accounts import audit, auth, consents, passwords, ratelimit
from core import errors
from db import pool
from vault import crypto

FORMATS = ("json", "csv")


def build_export(user_id):
    """Assemble the export document for one authenticated user."""
    row = auth._get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    master_key = crypto.load_key_from_env("VAULT_MASTER_KEY")
    with pool.connection() as conn:
        id_rows = conn.execute(
            "SELECT kind, ciphertext, masked, created_at FROM identifiers"
            " WHERE user_id = %s AND deleted_at IS NULL"
            " ORDER BY created_at, id",
            (user_id,),
        ).fetchall()
    exported_identifiers = []
    for id_row in id_rows:
        exported_identifiers.append({
            "kind": id_row["kind"],
            "value": crypto.decrypt_value(
                master_key, bytes(id_row["ciphertext"])),
            "masked": id_row["masked"],
            "created_at": auth._iso(id_row["created_at"]),
        })
    with pool.connection() as conn:
        domain_rows = conn.execute(
            "SELECT domain, verified, verified_at, created_at"
            " FROM domains WHERE user_id = %s AND deleted_at IS NULL"
            " ORDER BY created_at, id",
            (user_id,),
        ).fetchall()
    exported_domains = [{
        "domain": d_row["domain"],
        "verified": bool(d_row["verified"]),
        "verified_at": auth._iso(d_row["verified_at"]),
        "created_at": auth._iso(d_row["created_at"]),
    } for d_row in domain_rows]
    return {
        "account": {
            "email": auth.reveal_email(row),
            "email_masked": row["email_masked"],
            "created_at": auth._iso(row["created_at"]),
        },
        "identifiers": exported_identifiers,
        "domains": exported_domains,
        "consents": consents.history(user_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# The gated export (Batch B): password re-auth + formats
# ---------------------------------------------------------------------------

def _csv_cell(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_csv(document):
    """Flatten an export document to CSV text: one row per field,
    (section, record, field, value). `record` is the 1-based row
    number within the section ('account' for the single account
    row), so a spreadsheet reader can regroup the document exactly
    — the CSV carries precisely the JSON's data, no more, no less.
    """
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "record", "field", "value"])
    account = document["account"]
    for field in ("email", "email_masked", "created_at"):
        writer.writerow(["account", "account", field,
                         _csv_cell(account.get(field))])
    for index, ident in enumerate(document["identifiers"], 1):
        for field in ("kind", "value", "masked", "created_at"):
            writer.writerow(["identifiers", index, field,
                             _csv_cell(ident.get(field))])
    for index, domain in enumerate(document["domains"], 1):
        for field in ("domain", "verified", "verified_at",
                      "created_at"):
            writer.writerow(["domains", index, field,
                             _csv_cell(domain.get(field))])
    for index, consent in enumerate(document["consents"], 1):
        for field in ("purpose", "granted", "version", "updated_at"):
            writer.writerow(["consents", index, field,
                             _csv_cell(consent.get(field))])
    writer.writerow(["meta", "export", "generated_at",
                     _csv_cell(document["generated_at"])])
    return out.getvalue()


def export_document(user_id, password, export_format, client_ip):
    """Verify the account password, then build the export in the
    requested format. Returns (body_text, content_type, filename).

    The attempt is counted by the credential rate limiter (per
    client IP AND per account — the same two buckets login uses)
    BEFORE the password is checked, so failures and successes alike
    consume the budget and an exhausted bucket answers 429. A wrong
    password answers the identical 401 login gives, so the route
    reveals nothing about which part failed.
    """
    fmt = export_format if isinstance(export_format, str) else "json"
    fmt = fmt.strip().lower() or "json"
    if fmt not in FORMATS:
        raise errors.bad_request(
            "invalid_format", "Pick the JSON or CSV format")
    row = auth._get_user_by_id(user_id)
    if row is None:
        raise errors.unauthorized()
    buckets = ("ip:" + str(client_ip),
               "email:" + bytes(row["email_hmac"]).hex())
    if not ratelimit.allow(buckets):
        raise errors.too_many_requests()
    if not passwords.verify_password(row["password_hash"], password):
        raise errors.unauthorized(
            "invalid_credentials", "Invalid email or password")
    document = build_export(user_id)
    audit.record(user_id, "user", "privacy_export", "account",
                 user_id, {"format": fmt})
    if fmt == "csv":
        return (render_csv(document), "text/csv; charset=utf-8",
                "leakguard-export.csv")
    return (json.dumps(document, indent=2), "application/json",
            "leakguard-export.json")
