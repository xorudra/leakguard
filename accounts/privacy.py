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
  masked form, the display name, and creation date),
* every live identifier (kind, value REVEALED, masked, created_at),
* every live domain row (domain, verification state — domains are
  public, never secret),
* the FULL consent history (every version ever recorded, including
  the registration policy acceptance — purpose 'policy_acceptance',
  with the accepted policy_version),
* every scan job and every finding those jobs produced,
* every remediation case (the removal history),
* every notification,
* the monitoring settings row, if one exists,
* household members of the user's own household,
* passkey and API-token METADATA (names, timestamps, state — never
  key material, never token values or hashes),
* generated_at.

Metadata-only is a hard rule for credentials: a data export must
never become a credential leak with a download button on it, so
passkeys contribute nickname/created/last-used/revoked only and
API tokens name/prefix/scopes/timestamps only.

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


def _csv_value(value):
    """One export field as a CSV-cell string, in build_export so
    render_csv can share it: scalars pass through; a list/dict
    (jsonb columns, text[] columns) becomes compact JSON text.
    None stays None (render_csv renders it as an empty cell) —
    a missing value must never be confused with the text 'null'
    or '[]'."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, sort_keys=True, default=str)


# Section name -> ordered field names, for the row-list sections of
# the document. render_csv flattens with EXACTLY this table, so the
# CSV can never drift from the JSON's field sets again (the bug
# this fixes: the account section once dropped 'name' in CSV only).
_ACCOUNT_FIELDS = ("email", "email_masked", "name", "created_at")
_SECTION_FIELDS = {
    "identifiers": ("kind", "value", "masked", "created_at"),
    "domains": ("domain", "verified", "verified_at", "created_at"),
    "consents": ("purpose", "granted", "version", "policy_version",
                "updated_at"),
    "scan_jobs": ("id", "status", "attempts", "error_kind", "score",
                  "score_explanation", "summary", "created_at",
                  "started_at", "finished_at"),
    "findings": ("id", "job_id", "identifier_kind", "provider",
                 "source_name", "source_url", "source_date",
                 "discovered_at", "exposed_fields", "confidence",
                 "reliability", "status", "remediation_eligible",
                 "details"),
    "remediation_cases": ("id", "broker_slug", "finding_id", "status",
                          "reason", "created_at", "updated_at",
                          "submitted_at"),
    "notifications": ("id", "kind", "payload", "status", "created_at",
                      "sent_at"),
    "household_members": ("label", "created_at"),
    "passkeys": ("nickname", "created_at", "last_used_at", "revoked_at"),
    "api_tokens": ("name", "prefix", "scopes", "created_at",
                   "last_used_at", "revoked_at"),
}
_SETTINGS_FIELDS = ("monitor_cadence_days", "created_at", "updated_at")


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

    def fetch(sql, params=(user_id,)):
        with pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    scan_rows = fetch(
        "SELECT id, status, attempts, error_kind, score,"
        " score_explanation, summary, created_at, started_at,"
        " finished_at FROM scan_jobs WHERE user_id = %s"
        " ORDER BY created_at, id")
    exported_scans = [{
        "id": str(s_row["id"]),
        "status": s_row["status"],
        "attempts": s_row["attempts"],
        "error_kind": s_row["error_kind"],
        "score": s_row["score"],
        "score_explanation": _csv_value(s_row["score_explanation"]),
        "summary": _csv_value(s_row["summary"]),
        "created_at": auth._iso(s_row["created_at"]),
        "started_at": auth._iso(s_row["started_at"]),
        "finished_at": auth._iso(s_row["finished_at"]),
    } for s_row in scan_rows]
    finding_rows = fetch(
        "SELECT id, job_id, identifier_kind, provider, source_name,"
        " source_url, source_date, discovered_at, exposed_fields,"
        " confidence, reliability, status, remediation_eligible,"
        " details FROM findings WHERE user_id = %s"
        " ORDER BY discovered_at, id")
    exported_findings = [{
        "id": str(f_row["id"]),
        "job_id": str(f_row["job_id"]),
        "identifier_kind": f_row["identifier_kind"],
        "provider": f_row["provider"],
        "source_name": f_row["source_name"],
        "source_url": f_row["source_url"],
        "source_date": auth._iso(f_row["source_date"]),
        "discovered_at": auth._iso(f_row["discovered_at"]),
        "exposed_fields": _csv_value(list(f_row["exposed_fields"] or [])),
        "confidence": f_row["confidence"],
        "reliability": f_row["reliability"],
        "status": f_row["status"],
        "remediation_eligible": bool(f_row["remediation_eligible"]),
        "details": _csv_value(f_row["details"]),
    } for f_row in finding_rows]
    case_rows = fetch(
        "SELECT id, broker_slug, finding_id, status, reason,"
        " created_at, updated_at, submitted_at FROM remediation_cases"
        " WHERE user_id = %s ORDER BY created_at, id")
    exported_cases = [{
        "id": str(c_row["id"]),
        "broker_slug": c_row["broker_slug"],
        "finding_id": (str(c_row["finding_id"])
                       if c_row["finding_id"] else None),
        "status": c_row["status"],
        "reason": c_row["reason"],
        "created_at": auth._iso(c_row["created_at"]),
        "updated_at": auth._iso(c_row["updated_at"]),
        "submitted_at": auth._iso(c_row["submitted_at"]),
    } for c_row in case_rows]
    notification_rows = fetch(
        "SELECT id, kind, payload, status, created_at, sent_at"
        " FROM notifications WHERE user_id = %s"
        " ORDER BY created_at, id")
    exported_notifications = [{
        "id": str(n_row["id"]),
        "kind": n_row["kind"],
        "payload": _csv_value(n_row["payload"]),
        "status": n_row["status"],
        "created_at": auth._iso(n_row["created_at"]),
        "sent_at": auth._iso(n_row["sent_at"]),
    } for n_row in notification_rows]
    settings_rows = fetch(
        "SELECT monitor_cadence_days, created_at, updated_at"
        " FROM user_settings WHERE user_id = %s")
    exported_settings = None
    if settings_rows:
        s_row = settings_rows[0]
        exported_settings = {
            "monitor_cadence_days": s_row["monitor_cadence_days"],
            "created_at": auth._iso(s_row["created_at"]),
            "updated_at": auth._iso(s_row["updated_at"]),
        }
    member_rows = fetch(
        "SELECT m.label, m.created_at FROM household_members m"
        " JOIN households h ON h.id = m.household_id"
        " WHERE h.owner_user_id = %s ORDER BY m.created_at, m.id")
    exported_members = [{
        "label": m_row["label"],
        "created_at": auth._iso(m_row["created_at"]),
    } for m_row in member_rows]
    # Credential METADATA only — never key material, never token
    # values or their hashes (see module docstring).
    passkey_rows = fetch(
        "SELECT nickname, created_at, last_used_at, revoked_at"
        " FROM passkey_credentials WHERE user_id = %s"
        " ORDER BY created_at, id")
    exported_passkeys = [{
        "nickname": p_row["nickname"],
        "created_at": auth._iso(p_row["created_at"]),
        "last_used_at": auth._iso(p_row["last_used_at"]),
        "revoked_at": auth._iso(p_row["revoked_at"]),
    } for p_row in passkey_rows]
    token_rows = fetch(
        "SELECT name, prefix, scopes, created_at, last_used_at,"
        " revoked_at FROM api_tokens WHERE user_id = %s"
        " ORDER BY created_at, id")
    exported_tokens = [{
        "name": t_row["name"],
        "prefix": t_row["prefix"],
        "scopes": _csv_value(list(t_row["scopes"] or [])),
        "created_at": auth._iso(t_row["created_at"]),
        "last_used_at": auth._iso(t_row["last_used_at"]),
        "revoked_at": auth._iso(t_row["revoked_at"]),
    } for t_row in token_rows]
    return {
        "account": {
            "email": auth.reveal_email(row),
            "email_masked": row["email_masked"],
            "name": auth.reveal_name(row),
            "created_at": auth._iso(row["created_at"]),
        },
        "identifiers": exported_identifiers,
        "domains": exported_domains,
        "consents": consents.history(user_id),
        "scan_jobs": exported_scans,
        "findings": exported_findings,
        "remediation_cases": exported_cases,
        "notifications": exported_notifications,
        "settings": exported_settings,
        "household_members": exported_members,
        "passkeys": exported_passkeys,
        "api_tokens": exported_tokens,
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
    number within the section ('account' / 'settings' for the
    single-object sections), so a spreadsheet reader can regroup
    the document exactly — the CSV carries precisely the JSON's
    data, no more, no less. The field lists come from the same
    _ACCOUNT_FIELDS / _SECTION_FIELDS / _SETTINGS_FIELDS tables
    build_export's document follows, so a new JSON field reaches
    the CSV by extending one table, never by remembering a second
    hand-written list (the account section once silently dropped
    'name' in CSV only — that class of bug is designed out here).
    Structured values (jsonb, text[]) are already JSON text in the
    document (see _csv_value), so every cell stays a scalar.
    """
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["section", "record", "field", "value"])
    account = document["account"]
    for field in _ACCOUNT_FIELDS:
        writer.writerow(["account", "account", field,
                         _csv_cell(account.get(field))])
    for section, fields in _SECTION_FIELDS.items():
        for index, record in enumerate(document[section], 1):
            for field in fields:
                writer.writerow([section, index, field,
                                 _csv_cell(record.get(field))])
    settings = document.get("settings")
    if settings is not None:
        for field in _SETTINGS_FIELDS:
            writer.writerow(["settings", "settings", field,
                             _csv_cell(settings.get(field))])
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
