"""Audit log writer (Stage S11, spec Phases 106–114).

One append-only trail of the events that matter — registrations,
logins, consent changes, identifier add/remove, scan and removal
runs, password resets, account deletion, admin reads — so "what
happened on this account / this platform" is always answerable from
data, never from memory.

Two hard rules:

* BEST-EFFORT, ALWAYS. record() swallows every failure (no database,
  a dropped table, anything) and only logs the exception class. An
  audit write must never fail the user action it describes.
* PII-FREE BY CONSTRUCTION. detail carries counts, enums and ids
  only — never identifier values, emails, tokens or secrets. As a
  second line of defence, detail is filtered here to plain scalar
  values under innocuous keys: anything nested, oversized, or under
  a key that smells like a secret is dropped before it can reach
  the database.
"""

import json

from core import logging_setup
from db import pool

_SECRETY_KEYS = ("email", "password", "token", "secret", "value",
                 "ciphertext", "hmac", "code")


def _clean_detail(detail):
    clean = {}
    for key, value in (detail or {}).items():
        key = str(key)[:40]
        lowered = key.lower()
        if any(word in lowered for word in _SECRETY_KEYS):
            continue
        if value is None or isinstance(value, (bool, int, float)):
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:80]
        # Anything else (dicts, lists, objects) is dropped: the audit
        # trail deals in flat facts, not payloads.
    return clean


def record(actor_user_id, actor_kind, action, target_kind=None,
           target_id=None, detail=None):
    """Append one audit row. Never raises."""
    try:
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO audit_log"
                " (actor_user_id, actor_kind, action, target_kind,"
                " target_id, detail)"
                " VALUES (%s, %s, %s, %s, %s, %s)",
                (
                    actor_user_id,
                    actor_kind,
                    str(action)[:80],
                    target_kind,
                    str(target_id) if target_id is not None else None,
                    json.dumps(_clean_detail(detail)),
                ),
            )
    except Exception as exc:  # the audit trail must never break a flow
        logging_setup.log_error(
            None, "audit record failed: " + type(exc).__name__)
