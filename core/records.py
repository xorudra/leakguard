"""Records queue (owner order 2026-11-18): every project records
EVERY record to the records Google Drive, split by category, and
the records stay visible in the project itself.

This module is the app-side half. Product events append one flat
JSON line per record to a per-category queue file
(consent/audit/scans/removals) in LG_RECORDS_DIR (default:
<repo>/records-queue). A separate sync (never this process) moves
batches to the project's Drive folders, verifies each upload, and
only then clears the server copy — the same discipline as the
Nexus consent sync.

Rules:
  * Records only — never keys, vault material, passwords, full
    email addresses (masked form only), findings or letters.
  * Appending NEVER raises and never blocks a product flow: the
    database stays the source of truth (the admin views read it);
    a lost line loses a copy, never the record itself.
  * The queue directory is read from the environment on every
    call, so tests and deployments can steer it without a restart
    of anything but the process's own environment.
"""

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from core import logging_setup

CATEGORIES = ("consent", "audit", "scans", "removals")

_lock = threading.Lock()


def queue_dir():
    override = os.environ.get("LG_RECORDS_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "records-queue"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _iso(value):
    # Local copy of the accounts._iso one-liner: core must not
    # reach up into accounts (architecture guard), even deferred.
    return value.isoformat() if hasattr(value, "isoformat") else value


def append(category, record):
    """Append one record line to a category queue. Never raises."""
    if category not in CATEGORIES:
        return
    try:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with _lock:
            directory = queue_dir()
            directory.mkdir(parents=True, exist_ok=True)
            with open(directory / (category + ".jsonl"), "a",
                      encoding="utf-8") as fh:
                fh.write(line + "\n")
    except Exception as exc:  # a records copy must never break a flow
        logging_setup.log_error(
            None, "records append failed: " + type(exc).__name__)


def _masked_email(user_id):
    from db import pool

    with pool.connection() as conn:
        row = conn.execute(
            "SELECT email_masked FROM users WHERE id = %s",
            (user_id,),
        ).fetchone()
    return row["email_masked"] if row else None


def consent_event(user_id, purpose, granted, policy_version=None,
                  event="changed"):
    """One consent record: a registration agreement or a switch
    change. The masked email is looked up here so callers only ever
    pass the user id."""
    try:
        record = {
            "ts": _now_iso(),
            "email_masked": _masked_email(user_id),
            "event": event,
            "purpose": purpose,
            "granted": bool(granted),
        }
        if policy_version is not None:
            record["policy_version"] = policy_version
        append("consent", record)
    except Exception as exc:
        logging_setup.log_error(
            None, "records consent event failed: "
            + type(exc).__name__)


def audit_event(actor_user_id, actor_kind, action, target_kind,
                target_id, detail):
    """One audit record, mirroring the audit_log row (whose detail
    is PII-free by construction in accounts/audit.py)."""
    append("audit", {
        "ts": _now_iso(),
        "actor_user_id": (str(actor_user_id)
                          if actor_user_id is not None else None),
        "actor_kind": actor_kind,
        "action": action,
        "target_kind": target_kind,
        "target_id": target_id,
        "detail": detail or {},
    })


def scan_snapshot(job_id):
    """One scan record: the job's state read back from the DB right
    after a write, so the line is always the committed truth."""
    try:
        from db import pool

        with pool.connection() as conn:
            row = conn.execute(
                "SELECT j.idempotency_key, j.status, j.score,"
                " j.attempts, j.error_kind, j.finished_at,"
                " u.email_masked"
                " FROM scan_jobs j JOIN users u ON u.id = j.user_id"
                " WHERE j.id = %s",
                (job_id,),
            ).fetchone()
        if row is None:
            return

        append("scans", {
            "ts": _now_iso(),
            "email_masked": row["email_masked"],
            "job_id": str(job_id),
            "kind": ("monitor" if (row["idempotency_key"] or "")
                     .startswith("monitor-") else "scan"),
            "status": row["status"],
            "score": row["score"],
            "attempts": row["attempts"],
            "error_kind": row["error_kind"],
            "finished_at": _iso(row["finished_at"]),
        })
    except Exception as exc:
        logging_setup.log_error(
            None, "records scan snapshot failed: "
            + type(exc).__name__)


def removal_snapshot(case_id):
    """One removal record: the case's state read back from the DB
    right after a write (broker, status, reason — never the letter
    or the user's details)."""
    try:
        from db import pool

        with pool.connection() as conn:
            row = conn.execute(
                "SELECT b.name AS broker_name, c.status, c.reason,"
                " c.submitted_at, c.updated_at, u.email_masked"
                " FROM remediation_cases c"
                " JOIN users u ON u.id = c.user_id"
                " JOIN brokers b ON b.slug = c.broker_slug"
                " WHERE c.id = %s",
                (case_id,),
            ).fetchone()
        if row is None:
            return

        append("removals", {
            "ts": _now_iso(),
            "email_masked": row["email_masked"],
            "case_id": str(case_id),
            "broker": row["broker_name"],
            "status": row["status"],
            "reason": row["reason"],
            "submitted_at": _iso(row["submitted_at"]),
            "updated_at": _iso(row["updated_at"]),
        })
    except Exception as exc:
        logging_setup.log_error(
            None, "records removal snapshot failed: "
            + type(exc).__name__)
