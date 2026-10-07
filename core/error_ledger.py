"""Server-side error ledger (spec Phase 76).

Until now a server-side failure lived only in the process's stdout
log lines (core/logging_setup.log_error) — invisible to the admin
panel, uncountable, gone when the host rotated logs. This module
persists one row per DISTINCT error per hour bucket in
error_events (migration 0013), so the owner can see "what is
failing, how often" from data (the admin metrics block reads it).

An error is identified by (context, error_class, message_hash):

* context      — a short label of the call site ("retention
                 sessions failed"), never user data;
* error_class  — the exception class name;
* message_hash — sha256 hex of the message. NEVER the raw message:
                 messages can sit next to user data, and the hash
                 is all dedupe/counting needs.

Dedupe is by construction: the writer issues ONE upsert against
the (context, error_class, message_hash, bucket_start) unique
constraint — a repeat inside the same hour bucket increments
occurrence_count and refreshes last_seen_at instead of adding a
row. The hour granularity is deliberate: it is what lets the
Phase 77 error-spike rule count "occurrences in the last hour"
from rollup rows (approximately — a bucket is a clock hour; see
monitoring/alerts.py).

BEST-EFFORT, ALWAYS — the same contract as the audit writer.
record() swallows every failure (no database, a dropped table,
anything) and never raises: an error tracker that can itself fail
the request it describes is worse than no tracker. It also never
logs (logging_setup.log_error calls INTO this module; a failure
here must not recurse).
"""

import hashlib

_MAX_CONTEXT = 80
_MAX_CLASS = 120


def _error_class_of(exc_or_class):
    if isinstance(exc_or_class, BaseException):
        return type(exc_or_class).__name__
    if isinstance(exc_or_class, type):
        return exc_or_class.__name__
    text = str(exc_or_class or "").strip()
    return text or "Error"


def message_hash(message):
    """sha256 hex of the message text — the only form of the
    message that is ever stored."""
    return hashlib.sha256(
        str(message or "").encode("utf-8")).hexdigest()


def record(context, exc_or_class, message, request_id=None):
    """Record one error occurrence. Returns True when the row was
    written, False when it was swallowed. Never raises.

    `exc_or_class` may be an exception instance, an exception
    class, or a class-name string. `message` is hashed, never
    stored. One SQL statement on one short-lived connection.
    """
    try:
        ctx = str(context or "unknown")[:_MAX_CONTEXT]
        cls = _error_class_of(exc_or_class)[:_MAX_CLASS]
        digest = message_hash(message)
        rid = str(request_id) if request_id else None
        from db import pool

        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO error_events"
                " (context, error_class, message_hash, request_id)"
                " VALUES (%s, %s, %s, %s)"
                " ON CONFLICT (context, error_class, message_hash,"
                " bucket_start)"
                " DO UPDATE SET"
                " occurrence_count = error_events.occurrence_count + 1,"
                " last_seen_at = now(),"
                " request_id = COALESCE(EXCLUDED.request_id,"
                " error_events.request_id)",
                (ctx, cls, digest, rid),
            )
        return True
    except Exception:
        return False
