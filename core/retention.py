"""Retention worker (Stage S12, spec Phases 76–80): an in-process
daily thread that deletes data whose retention period has run out,
so the database holds only what the product still needs.

WHY core/: retention is cross-cutting platform hygiene — it spans
accounts, scanning, remediation and monitoring tables and belongs
with the other platform primitives (errors, logging, rate limits),
not inside any one feature package. Its single upward dependency,
the audit writer, is imported lazily inside run_once() (the same
lazy-import pattern db/pool.py uses for its driver), so importing
this module never drags the accounts package into core.

Rules (mirrored in README's Operations section):

* Sessions: expired more than 7 days ago, or revoked more than
  7 days ago. A live session is never touched.
* Password-reset tokens: used (used_at) or expired (expires_at)
  more than 7 days ago. A pending, unexpired token survives.
* Notifications: every kind, created more than 90 days ago.
* Soft-deleted accounts (users.deleted_at more than 30 days ago):
  HARD purge of the user and everything they own, in FK-safe order.
  audit_log is deliberately NOT touched: its actor_user_id carries
  no foreign key (0007) precisely so the PII-free trail of counts
  and actions survives the account it describes.
* Broker source sweep (Phases 32/125): the daily LOOP also hosts
  remediation/source_checks.maybe_run(), as a separate step after
  the purge — run_once() itself stays a pure purge, so its many
  library/test callers never touch the network. The sweep is armed
  only when this worker was actually started (start_retention),
  self-gates to one run per 24h via the checks table, and is
  failure-isolated so it can never sink the purge it rides with.

Failure isolation: every category runs in its own transaction and
its own try/except, and every account purge is its own transaction
— one bad category (or one bad account) cannot stop the rest. The
run ends with one PII-free log line of counts and one audit row
(actor_kind 'system', action 'retention.purge', counts in detail).
"""

import threading
from datetime import datetime, timedelta, timezone

from core import logging_setup
from db import pool

TICK_SECONDS = 24 * 3600.0
SESSION_GRACE_DAYS = 7
RESET_TOKEN_GRACE_DAYS = 7
NOTIFICATION_TTL_DAYS = 90
DELETED_USER_GRACE_DAYS = 30

_thread = None
_thread_lock = threading.Lock()
_stop = threading.Event()


def _log(message):
    logging_setup.get_logger().info(message)


def _delete(conn, sql, params=()):
    return conn.execute(sql, params).rowcount


# ---------------------------------------------------------------------------
# Category passes. Each takes a connection + a `now` and returns a count.
# ---------------------------------------------------------------------------

def _purge_sessions(conn, now):
    expired = _delete(
        conn,
        "DELETE FROM sessions WHERE expires_at < %s",
        (now - timedelta(days=SESSION_GRACE_DAYS),))
    revoked = _delete(
        conn,
        "DELETE FROM sessions"
        " WHERE revoked_at IS NOT NULL AND revoked_at < %s",
        (now - timedelta(days=SESSION_GRACE_DAYS),))
    return expired + revoked


def _purge_reset_tokens(conn, now):
    cutoff = now - timedelta(days=RESET_TOKEN_GRACE_DAYS)
    return _delete(
        conn,
        "DELETE FROM password_reset_tokens"
        " WHERE (used_at IS NOT NULL AND used_at < %s)"
        " OR expires_at < %s",
        (cutoff, cutoff))


def _purge_notifications(conn, now):
    return _delete(
        conn,
        "DELETE FROM notifications WHERE created_at < %s",
        (now - timedelta(days=NOTIFICATION_TTL_DAYS),))


# FK-safe order for one account: children before parents, the cases'
# children (attempts, verification checks) before the cases, cases
# before the findings they may reference, findings before the jobs
# and identifiers they reference, household members before the
# household. audit_log is absent on purpose (see module docstring).
_USER_CHILDREN = (
    "DELETE FROM notifications WHERE user_id = %s",
    "DELETE FROM user_settings WHERE user_id = %s",
    "DELETE FROM domains WHERE user_id = %s",
    "DELETE FROM verification_checks WHERE case_id IN"
    " (SELECT id FROM remediation_cases WHERE user_id = %s)",
    "DELETE FROM remediation_attempts WHERE case_id IN"
    " (SELECT id FROM remediation_cases WHERE user_id = %s)",
    "DELETE FROM remediation_cases WHERE user_id = %s",
    "DELETE FROM finding_feedback WHERE user_id = %s",
    "DELETE FROM findings WHERE user_id = %s",
    "DELETE FROM scan_jobs WHERE user_id = %s",
    "DELETE FROM consents WHERE user_id = %s",
    "DELETE FROM sessions WHERE user_id = %s",
    "DELETE FROM password_reset_tokens WHERE user_id = %s",
    "DELETE FROM identifiers WHERE user_id = %s",
    "DELETE FROM household_members WHERE household_id IN"
    " (SELECT id FROM households WHERE owner_user_id = %s)",
    "DELETE FROM households WHERE owner_user_id = %s",
)


def _purge_one_user(user_id):
    """Hard-delete one soft-deleted account and everything it owns,
    in a single transaction. Returns True on success."""
    with pool.connection() as conn:
        for sql in _USER_CHILDREN:
            conn.execute(sql, (user_id,))
        row = conn.execute(
            "DELETE FROM users WHERE id = %s AND deleted_at IS NOT NULL",
            (user_id,)).rowcount
    return row == 1


def _purge_deleted_users(now):
    cutoff = now - timedelta(days=DELETED_USER_GRACE_DAYS)
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id FROM users WHERE deleted_at IS NOT NULL"
            " AND deleted_at < %s", (cutoff,)).fetchall()
    purged = 0
    for row in rows:
        try:
            if _purge_one_user(str(row["id"])):
                purged += 1
        except Exception as exc:  # one bad account must not stop the rest
            logging_setup.log_error(
                None, "retention user purge failed: "
                + type(exc).__name__)
    return purged


_CATEGORIES = (
    ("sessions", _purge_sessions),
    ("reset_tokens", _purge_reset_tokens),
    ("notifications", _purge_notifications),
)


def run_once(now=None):
    """One retention pass. Returns the counts dict (also logged and
    audited). Never raises for a single category's failure — the
    failed category reports -1 and the rest still run. Raises only
    when no database is configured at all (callers guard that)."""
    now = now or datetime.now(timezone.utc)
    counts = {}
    for name, fn in _CATEGORIES:
        try:
            with pool.connection() as conn:
                counts[name] = fn(conn, now)
        except Exception as exc:
            counts[name] = -1
            logging_setup.log_error(
                None, "retention %s failed: %s"
                % (name, type(exc).__name__))
    try:
        counts["users_purged"] = _purge_deleted_users(now)
    except Exception as exc:
        counts["users_purged"] = -1
        logging_setup.log_error(
            None, "retention users failed: " + type(exc).__name__)
    _log("retention_purge " + " ".join(
        "%s=%s" % (k, counts[k]) for k in (
            "sessions", "reset_tokens", "notifications", "users_purged")))
    try:
        from accounts import audit

        audit.record(None, "system", "retention.purge", None, None,
                     dict(counts))
    except Exception as exc:  # audit is best-effort by contract anyway
        logging_setup.log_error(
            None, "retention audit failed: " + type(exc).__name__)
    return counts


def _run_source_sweep():
    """One broker source sweep as part of the daily tick (Phases
    32/125). Returns {"source_checks": n} — brokers checked, 0 when
    the sweep skipped (not armed / ran within 24h), -1 on failure.
    Deliberately NOT part of run_once(): the purge's contract (and
    its many direct callers) stays network-free; the sweep lives
    only on the started worker's loop."""
    try:
        from remediation import source_checks

        sweep = source_checks.maybe_run()
        checked = (0 if sweep.get("skipped")
                   else int(sweep.get("checked", 0)))
    except Exception as exc:
        checked = -1
        logging_setup.log_error(
            None, "retention source sweep failed: "
            + type(exc).__name__)
    _log("retention_source_sweep checked=%s" % checked)
    return {"source_checks": checked}


def _loop():
    while not _stop.is_set():
        try:
            run_once()
        except Exception as exc:
            logging_setup.log_error(
                None, "retention run failed: " + type(exc).__name__)
        _run_source_sweep()
        _stop.wait(TICK_SECONDS)


def start_retention():
    """Start the daily thread (idempotent)."""
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        # The broker source sweep (remediation/source_checks.py)
        # arms here — and only here: the sweep exists because this
        # worker runs in production, so it must not fire from
        # library/test calls of run_once().
        try:
            from remediation import source_checks

            source_checks.arm()
        except Exception:
            pass  # a missing sweep must never stop retention
        _stop.clear()
        _thread = threading.Thread(
            target=_loop, name="leakguard-retention", daemon=True)
        _thread.start()
        return True


def start_retention_if_configured():
    """app.main() entry point: retention exists only when a database
    is configured — with no database there is nothing to retain."""
    if not pool.configured():
        return False
    return start_retention()


def stop_retention():
    """Signal the loop to end (tests / shutdown)."""
    _stop.set()
