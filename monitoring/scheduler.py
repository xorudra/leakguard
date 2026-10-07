"""Monitoring scheduler (spec Phases 41, 42): an in-process thread
(the modular monolith has no separate worker service — migration
plan adaptation 1) that ticks hourly and enqueues a normal scan job
for every user who is due.

A user is DUE when ALL of these hold:
* their 'monitoring' consent is currently granted (the latest
  consent row decides — consent precedes capability);
* they have at least one live saved identifier;
* their latest COMPLETED scan job is older than their cadence
  (user_settings.monitor_cadence_days, default 7) — or they have
  never completed one.

Enqueueing inserts a scan_jobs row directly with the idempotency
key 'monitor-<user_id>-<period_start>', where period_start is the
start of the current cadence-length bucket (days since the epoch,
bucketed). The key is deterministic within a period, so restarts,
deploys and overlapping ticks can never double-enqueue: the
(user_id, idempotency_key) unique constraint absorbs the retry.
The monitoring consent IS the authorization for these scheduled
runs — the scan worker then executes the job exactly like a
hand-started one, and the completion hook diffs and notifies.

Logs carry user counts only — never user ids, never data.
"""

import threading
from datetime import datetime, timedelta, timezone

from accounts import audit
from core import logging_setup
from db import pool

TICK_SECONDS = 3600.0
_EPOCH_DATE = datetime(1970, 1, 1, tzinfo=timezone.utc).date()

_thread = None
_thread_lock = threading.Lock()
_stop = threading.Event()


def _log(message):
    logging_setup.get_logger().info(message)


def period_start_for(now, cadence_days):
    """The date this cadence period started (bucketed days since
    the epoch, so the boundary is the same for every process)."""
    days = (now.date() - _EPOCH_DATE).days
    bucket = (int(days) // int(cadence_days)) * int(cadence_days)
    return _EPOCH_DATE + timedelta(days=bucket)


def monitor_key(user_id, now, cadence_days):
    return "monitor-%s-%s" % (
        user_id, period_start_for(now, cadence_days).isoformat())


def _candidates():
    """Users who pass the consent + identifier gates, with their
    cadence and latest completed-scan timestamp."""
    with pool.connection() as conn:
        return conn.execute(
            "SELECT u.id AS user_id,"
            " COALESCE(s.monitor_cadence_days, 7) AS cadence,"
            " (SELECT MAX(j.finished_at) FROM scan_jobs j"
            "   WHERE j.user_id = u.id AND j.status = 'done')"
            "   AS last_done"
            " FROM users u"
            " LEFT JOIN user_settings s ON s.user_id = u.id"
            " WHERE u.deleted_at IS NULL"
            " AND EXISTS (SELECT 1 FROM consents c"
            "   WHERE c.user_id = u.id AND c.purpose = 'monitoring'"
            "   AND c.granted = true"
            "   AND c.version = (SELECT MAX(c2.version) FROM consents c2"
            "     WHERE c2.user_id = u.id"
            "     AND c2.purpose = 'monitoring'))"
            " AND EXISTS (SELECT 1 FROM identifiers i"
            "   WHERE i.user_id = u.id AND i.deleted_at IS NULL)",
        ).fetchall()


def _is_due(candidate, now):
    last_done = candidate["last_done"]
    if last_done is None:
        return True
    cadence = int(candidate["cadence"])
    return last_done <= now - timedelta(days=cadence)


def tick(now=None):
    """One scheduler pass. Returns the ids of the jobs created
    (empty when nobody was due, or when a same-period job already
    existed for every due user)."""
    now = now or datetime.now(timezone.utc)
    created = []
    for candidate in _candidates():
        if not _is_due(candidate, now):
            continue
        user_id = str(candidate["user_id"])
        key = monitor_key(user_id, now, int(candidate["cadence"]))
        with pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO scan_jobs (user_id, idempotency_key)"
                " VALUES (%s, %s)"
                " ON CONFLICT (user_id, idempotency_key) DO NOTHING"
                " RETURNING id",
                (user_id, key),
            ).fetchone()
        if row is not None:
            created.append(str(row["id"]))
            audit.record(user_id, "system", "scan.job_created",
                         "scan_job", row["id"], {"source": "monitor"})
    if created:
        _log("monitoring_scheduler enqueued=%d" % len(created))
    return created


def _loop():
    while not _stop.is_set():
        try:
            tick()
        except Exception as exc:
            logging_setup.log_error(
                None, "monitoring scheduler tick failed: "
                + type(exc).__name__)
        _stop.wait(TICK_SECONDS)


def start_scheduler():
    """Start the hourly thread (idempotent)."""
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(
            target=_loop, name="leakguard-monitoring-scheduler",
            daemon=True)
        _thread.start()
        return True


def start_scheduler_if_configured():
    """app.main() entry point: the scheduler exists only when a
    database is configured — with no database there are no users,
    no consents and nothing to schedule."""
    if not pool.configured():
        return False
    return start_scheduler()


def stop_scheduler():
    """Signal the loop to end (tests / shutdown)."""
    _stop.set()
