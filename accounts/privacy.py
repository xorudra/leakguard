"""Privacy Center: the data export (spec Phase 49).

GET /api/privacy/export is — together with the login-internal email
decrypt — the ONLY place plaintext identifier values leave the
server, and only to the authenticated owner of the data, as a file
download. It contains:

* the account (email REVEALED — it is the owner's own data — plus the
  masked form and creation date),
* every live identifier (kind, value REVEALED, masked, created_at),
* the FULL consent history (every version ever recorded),
* generated_at.

Never log the export body. The handler sends it as an attachment so
browsers do not render it inline.
"""

from datetime import datetime, timezone

from accounts import auth, consents
from core import errors
from db import pool
from vault import crypto


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
    return {
        "account": {
            "email": auth.reveal_email(row),
            "email_masked": row["email_masked"],
            "created_at": auth._iso(row["created_at"]),
        },
        "identifiers": exported_identifiers,
        "consents": consents.history(user_id),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
