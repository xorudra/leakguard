"""In-process remediation worker (spec Phases 12, 35).

Mirrors scanning/worker.py's shape: daemon thread(s) inside the web
process poll remediation_cases every 2 seconds and claim queued
cases with SELECT ... FOR UPDATE SKIP LOCKED inside an UPDATE, so a
case can never be processed twice concurrently — and combined with
the one-live-case index and the submitted-case guards, never
submitted twice at all.

Stage 7.1 (speed): the polling loop now keeps up to MAX_CONCURRENT
drainer threads busy instead of processing one case at a time —
cases are independent (one broker each, consent re-checked per case
inside the engine), so a 40-case run no longer pays the slowest
broker's probe latency forty times in a row. Claims, stale-running
recovery, and failure parking are unchanged.

Stage 7.2: MAX_CONCURRENT raised 3 -> 5 — probes are I/O-bound (the
drain spends its time waiting on broker pages, not on CPU), and the
SKIP LOCKED claim still guarantees no case executes twice.

There is no retry backoff for cases (unlike scan jobs): a broker
outcome is a state, not a failure — walls park the case at blocked,
human steps at needs_human, and only the user (or a new run)
re-queues them. An unexpected engine exception parks the case as
failed/internal_error with the exception CLASS in the attempt log;
stale 'running' cases (orphaned by a restart) are requeued on start.

Priority (spec Phase 159): unlike scan jobs, this queue has exactly
ONE class of work. Every queued case originates from a user action —
the "Remove all" run (service.run_removal) or a case retry
(service.retry_case) — and verification never queues at all
(verify.verify_case runs synchronously inside the user's request).
There is no scheduled/background class to deprioritize, so the
FIFO claim below already IS the priority order; if a scheduler
ever starts queueing cases, it must mark them and the claim gets
the same two-class ordering as scanning/worker.py.

Logs carry case ids and outcome words only — never identifier
values, never user data.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from core import logging_setup
from db import pool
from remediation import engine

POLL_SECONDS = 2.0
STALE_RUNNING_MINUTES = 10
MAX_CONCURRENT = 5
# Idle polling (owner order 2026-11-18): with an empty queue the
# top-up below used to launch a fresh round of drainers every
# POLL_SECONDS, each making a claim query, which kept the Neon
# compute awake around the clock and burned the free monthly
# compute allowance by mid-month (110 of 100 CU-hrs, project
# paused 2026-11-17). A round that finds no work now waits
# IDLE_POLL_SECONDS before the next round; every in-process
# enqueue path calls wake(), so real work still starts at once
# and the long wait is only a safety net. A round whose claims
# failed retries on ERROR_RETRY_SECONDS instead, so a short
# database blip still recovers within a minute.
IDLE_POLL_SECONDS = 1800.0
ERROR_RETRY_SECONDS = 60.0

_thread = None
_thread_lock = threading.Lock()
_stop = threading.Event()
_wake = threading.Event()


def wake():
    """Ask the worker to poll now (new work was just enqueued)."""
    _wake.set()


def _idle_wait():
    """Wait up to IDLE_POLL_SECONDS, returning at once on wake()
    or stop. The wait is sliced so shutdown stays responsive."""
    deadline = time.monotonic() + IDLE_POLL_SECONDS
    while not _stop.is_set() and not _wake.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        _stop.wait(min(POLL_SECONDS, remaining))
    _wake.clear()


def _log(message):
    logging_setup.get_logger().info(message)


def requeue_stale():
    """Return orphaned 'running' cases to the queue. Returns the
    number requeued."""
    with pool.connection() as conn:
        rows = conn.execute(
            "UPDATE remediation_cases SET status = 'queued',"
            " updated_at = now()"
            " WHERE status = 'running'"
            " AND updated_at < now() - (%s || ' minutes')::interval"
            " RETURNING id",
            (str(STALE_RUNNING_MINUTES),),
        ).fetchall()
    from core import records

    for row in rows:
        records.removal_snapshot(row["id"])
    return len(rows)


def claim_case():
    """Atomically claim the oldest queued case. Returns the case id
    or None when the queue is empty."""
    with pool.connection() as conn:
        row = conn.execute(
            "UPDATE remediation_cases AS c SET status = 'running',"
            " updated_at = now()"
            " WHERE c.id = ("
            "   SELECT id FROM remediation_cases AS c2"
            "   WHERE status = 'queued'"
            # A soft-deleted owner's cases are never claimed
            # (audit 2026-10-16, remediation.deleted-account-
            # cases-still-processed): deletion cancels them, and
            # this EXISTS guard keeps even a pre-fix queued row
            # from being picked up.
            "   AND EXISTS (SELECT 1 FROM users"
            "   WHERE users.id = c2.user_id"
            "   AND users.deleted_at IS NULL)"
            "   ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)"
            " RETURNING c.id",
        ).fetchone()
    return str(row["id"]) if row is not None else None


def _record_failure(case_id, exc):
    try:
        engine._transition(case_id, "failed", "internal_error",
                           "error", type(exc).__name__, {})
    except Exception:
        pass  # the log line below still records the failure
    _log("remediation_worker case=%s outcome=failed kind=%s"
         % (case_id, type(exc).__name__))


def run_once(executor=None):
    """Claim and process one case. Returns True when a case was
    claimed (whatever its outcome), False when the queue is empty.
    Used by the polling loop and directly by tests."""
    case_id = claim_case()
    if case_id is None:
        return False
    try:
        case = engine.process_case(case_id, executor)
    except Exception as exc:  # infrastructure failure — park the case
        _record_failure(case_id, exc)
        return True
    _log("remediation_worker case=%s outcome=%s"
         % (case_id, (case or {}).get("status")))
    return True


def _drain(executor):
    """Claim and process cases until the queue is empty (or a stop
    is signalled). Runs on a pool thread; the SKIP LOCKED claim means
    concurrent drainers can never take the same case. Returns True
    when at least one case was claimed, so the loop can tell a
    worked round from an empty one."""
    worked = False
    while not _stop.is_set():
        if not run_once(executor):
            return worked
        worked = True
    return worked


def _loop(executor=None):
    try:
        requeued = requeue_stale()
        if requeued:
            _log("remediation_worker requeued=%d stale cases" % requeued)
    except Exception as exc:
        logging_setup.log_error(None, "remediation worker requeue failed: "
                                + type(exc).__name__)
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT,
                            thread_name_prefix="leakguard-remediation") as pool:
        futures = set()
        # The first pass tops up immediately (round_worked starts
        # True); after that, a completed round with no work and no
        # error means the queue is empty and the next round waits
        # out the idle poll instead of re-claiming every 2 seconds.
        round_worked = True
        round_error = False
        while not _stop.is_set():
            # Reap finished drainers. A drainer raises only when the
            # claim itself failed (e.g. database down) — run_once
            # parks engine failures itself. Log the class and let
            # the top-up below replace the drainer.
            for fut in list(futures):
                if fut.done():
                    futures.discard(fut)
                    exc = fut.exception()
                    if exc is not None:
                        round_error = True
                        logging_setup.log_error(
                            None, "remediation worker cycle failed: "
                            + type(exc).__name__)
                    elif fut.result():
                        round_worked = True
            if futures:
                _stop.wait(POLL_SECONDS)
                continue
            if round_error:
                _stop.wait(ERROR_RETRY_SECONDS)
            elif not round_worked:
                _idle_wait()
            round_worked = False
            round_error = False
            while len(futures) < MAX_CONCURRENT:
                futures.add(pool.submit(_drain, executor))
    # Leaving the with-block waits for the pool: drainers check _stop
    # between cases, so each finishes its in-flight case and exits.


def start_worker(executor=None):
    """Start the polling thread (idempotent). The executor is
    injectable for tests; production passes None and the engine
    builds its AgentExecutor per case."""
    global _thread
    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return True
        _stop.clear()
        _thread = threading.Thread(
            target=_loop, args=(executor,),
            name="leakguard-remediation-worker", daemon=True)
        _thread.start()
        return True


def start_worker_if_configured():
    """app.main() entry point: the worker exists only when a database
    is configured — with no database there are no cases, and the
    anonymous product must not grow threads it cannot use."""
    if not pool.configured():
        return False
    return start_worker()


def stop_worker():
    """Signal the polling loop to end (tests / shutdown)."""
    _stop.set()
