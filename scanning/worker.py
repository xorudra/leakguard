"""In-process scan worker (spec Phase 12).

One daemon thread inside the web process (the modular monolith has
no separate worker service — MIGRATION_PLAN adaptation 1). It polls
scan_jobs every 2 seconds and claims one job at a time with
SELECT ... FOR UPDATE SKIP LOCKED inside an UPDATE, so concurrent
claimants (a second process during a deploy overlap, a test driver)
can never take the same job twice.

Retry policy: a failed run increments attempts and parks the job as
'failed' with next_attempt_at = now + backoff (30s after the first
failure, 120s after the second). After 3 failed attempts the job is
'dead' — the dead-letter state — with error_kind recorded. On worker
start, stale 'running' jobs (started more than 10 minutes ago,
i.e. orphaned by a restart) are requeued.

Logs carry job ids and outcome words only — never identifier values,
never user data.
"""

import threading
from datetime import datetime, timedelta, timezone

from core import logging_setup
from db import pool
from scanning import orchestrator

POLL_SECONDS = 2.0
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (30, 120)
STALE_RUNNING_MINUTES = 10

_thread = None
_thread_lock = threading.Lock()
_stop = threading.Event()


def _log(message):
    logging_setup.get_logger().info(message)


def requeue_stale():
    """Return orphaned 'running' jobs to the queue. Returns the
    number requeued."""
    with pool.connection() as conn:
        rows = conn.execute(
            "UPDATE scan_jobs SET status = 'queued', started_at = NULL"
            " WHERE status = 'running'"
            " AND started_at < now() - (%s || ' minutes')::interval"
            " RETURNING id",
            (str(STALE_RUNNING_MINUTES),),
        ).fetchall()
    return len(rows)


def claim_job():
    """Atomically claim the oldest runnable job. Returns
    (job_id, attempts) or None when the queue is empty."""
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE scan_jobs AS j SET status = 'running',"
            " started_at = now(), error_kind = NULL"
            " WHERE j.id = ("
            "   SELECT id FROM scan_jobs"
            "   WHERE status = 'queued'"
            "      OR (status = 'failed' AND next_attempt_at IS NOT NULL"
            "          AND next_attempt_at <= now())"
            "   ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)"
            " RETURNING j.id, j.attempts",
        ).fetchone()
    if row is None:
        return None
    return str(row["id"]), int(row["attempts"])


def _record_failure(job_id, attempts_before, exc):
    attempts = attempts_before + 1
    error_kind = getattr(exc, "error_kind", None) or type(exc).__name__
    with pool.connection() as conn:
        if attempts >= MAX_ATTEMPTS:
            conn.execute(
                "UPDATE scan_jobs SET status = 'dead', attempts = %s,"
                " error_kind = %s, next_attempt_at = NULL,"
                " finished_at = now() WHERE id = %s",
                (attempts, error_kind, job_id),
            )
            outcome = "dead"
        else:
            delay = BACKOFF_SECONDS[min(attempts - 1,
                                         len(BACKOFF_SECONDS) - 1)]
            next_at = datetime.now(timezone.utc) + timedelta(seconds=delay)
            conn.execute(
                "UPDATE scan_jobs SET status = 'failed', attempts = %s,"
                " error_kind = %s, next_attempt_at = %s WHERE id = %s",
                (attempts, error_kind, next_at, job_id),
            )
            outcome = "failed"
    _log("scan_worker job=%s outcome=%s attempts=%d kind=%s"
         % (job_id, outcome, attempts, error_kind))


def run_once():
    """Claim and process one job. Returns True when a job was
    claimed (whatever its outcome), False when the queue is empty.
    Used by the polling loop and directly by tests."""
    claimed = claim_job()
    if claimed is None:
        return False
    job_id, attempts = claimed
    try:
        orchestrator.run_scan_job(job_id)
    except orchestrator.JobNotFoundError:
        _log("scan_worker job=%s outcome=gone" % job_id)
        return True
    except Exception as exc:  # retry policy owns every failure
        _record_failure(job_id, attempts, exc)
        return True
    # Stage S8: monitoring diff + notifications hook. Guarded hard —
    # the job is already 'done'; a notification failure must never
    # fail, retry or resurrect it.
    try:
        from monitoring import events as monitoring_events

        monitoring_events.handle_scan_completed(job_id)
    except Exception as exc:
        logging_setup.log_error(None, "monitoring completion hook "
                                "failed: " + type(exc).__name__)
    _log("scan_worker job=%s outcome=done" % job_id)
    return True


def _loop():
    try:
        requeued = requeue_stale()
        if requeued:
            _log("scan_worker requeued=%d stale jobs" % requeued)
    except Exception as exc:
        logging_setup.log_error(None, "scan worker requeue failed: "
                                + type(exc).__name__)
    while not _stop.is_set():
        try:
            worked = run_once()
        except Exception as exc:
            logging_setup.log_error(None, "scan worker cycle failed: "
                                    + type(exc).__name__)
            worked = False
        if not worked:
            _stop.wait(POLL_SECONDS)


def start_worker():
    """Start the polling thread (idempotent). Returns True when the
    thread is running after the call."""
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(
            target=_loop, name="leakguard-scan-worker", daemon=True)
        _thread.start()
        return True


def start_worker_if_configured():
    """app.main() entry point: the worker exists only when a
    database is configured — with no database there are no jobs,
    and the anonymous product must not grow threads it cannot use."""
    if not pool.configured():
        return False
    return start_worker()


def stop_worker():
    """Signal the polling loop to end (tests / shutdown)."""
    _stop.set()
