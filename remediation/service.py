"""Remediation API service (spec Phases 33–37, 154) — the layer
behind /api/remediation/*.

Authorization by construction (the Stage S3 pattern): every function
takes the session's user id and scopes every query by it; a foreign
case id answers the same 404 as a nonexistent one.

Case creation is consent-gated (by the run endpoint) and idempotent
by the schema: the partial unique index allows at most one LIVE case
per (user, broker) — live meaning status NOT IN ('verified_removed',
'failed'); see db/migrations/0005_remediation.sql. Re-running the
user's one command returns the existing live cases, never duplicates
them, and never re-submits a case that is already submitted.
"""

from accounts.auth import _iso
from core import errors
from db import pool
from remediation import engine, letters

_CASE_SELECT = (
    "SELECT c.id, c.broker_slug, b.name AS broker_name, c.status,"
    " c.reason, c.created_at, c.updated_at, c.submitted_at"
    " FROM remediation_cases c"
    " JOIN brokers b ON b.slug = c.broker_slug")


def public_case(row):
    return {
        "id": str(row["id"]),
        "broker_slug": row["broker_slug"],
        "broker_name": row["broker_name"],
        "status": row["status"],
        "reason": row["reason"],
        "created_at": _iso(row["created_at"]),
        "updated_at": _iso(row["updated_at"]),
        "submitted_at": _iso(row["submitted_at"]),
    }


def _case_row(user_id, case_id):
    """One of the caller's cases (with broker name). Foreign or
    unknown ids raise the same 404."""
    with pool.connection() as conn:
        row = conn.execute(
            _CASE_SELECT + " WHERE c.id = %s AND c.user_id = %s",
            (case_id, user_id),
        ).fetchone()
    if row is None:
        raise errors.not_found("Removal case not found")
    return row


# ---------------------------------------------------------------------------
# The one command
# ---------------------------------------------------------------------------

def run_removal(user_id):
    """POST /api/remediation/run: the consent gate, then case creation."""
    if not engine.remediation_consented(user_id):
        raise errors.forbidden(
            "consent_required",
            "Turn on the Automatic removal permission to let LeakGuard "
            "remove your data for you")
    return create_cases_for_user(user_id)


def create_cases_for_user(user_id):
    """One live case per active broker, idempotently. Returns
    {cases_created, cases_total, by_status} over ALL the user's
    cases (closed history included in the counts)."""
    created = 0
    with pool.connection() as conn:
        brokers = conn.execute(
            "SELECT slug FROM brokers WHERE active = true"
            " ORDER BY position, slug",
        ).fetchall()
        for broker in brokers:
            row = conn.execute(
                "INSERT INTO remediation_cases (user_id, broker_slug)"
                " VALUES (%s, %s)"
                " ON CONFLICT (user_id, broker_slug)"
                " WHERE status NOT IN ('verified_removed', 'failed')"
                " DO NOTHING RETURNING id",
                (user_id, broker["slug"]),
            ).fetchone()
            if row is not None:
                created += 1
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM remediation_cases"
            " WHERE user_id = %s GROUP BY status",
            (user_id,),
        ).fetchall()
    by_status = {row["status"]: int(row["n"]) for row in rows}
    return {
        "cases_created": created,
        "cases_total": sum(by_status.values()),
        "by_status": by_status,
    }


# ---------------------------------------------------------------------------
# Cases + the human queue
# ---------------------------------------------------------------------------

def list_cases(user_id):
    """The caller's cases, in registry order."""
    with pool.connection() as conn:
        rows = conn.execute(
            _CASE_SELECT + " WHERE c.user_id = %s"
            " ORDER BY b.position, b.slug",
            (user_id,),
        ).fetchall()
    return [public_case(row) for row in rows]


_FIELD_LABELS = {
    "full_name": "full name",
    "email": "email address",
    "phone": "phone number",
    "city": "city",
    "listing_url": "listing URL — find your record on the broker's "
                   "site and copy its web address",
}

_NOTES = {
    "captcha": "This broker's form is protected by a CAPTCHA — only a "
               "human can pass it. Open the opt-out page, complete the "
               "check, and submit the form with your details.",
    "login_required": "This broker asks you to sign in before it will "
                      "remove data. Open the opt-out page, sign in, "
                      "and complete the removal there.",
    "browser_required": "This broker's form only works in a real "
                        "browser. Open the opt-out page and complete "
                        "the removal there.",
    "manual_only": "This broker has no automatic removal channel. "
                   "Open the opt-out page and follow its removal steps.",
    "consent_withdrawn": "Your Automatic removal permission was off "
                         "when this case ran, so LeakGuard stopped. "
                         "Turn it back on under My permissions, then "
                         "press Try again.",
}


def _next_step(case_row, broker_row):
    """The exact next step for one needs_human case (spec Phase 154):
    email_send_required carries the ready-to-send letter from the
    case's attempt detail; everything else points at the broker's
    opt-out page with a reason-specific note."""
    reason = case_row["reason"] or ""
    if reason == "email_send_required":
        letter = None
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT detail FROM remediation_attempts"
                " WHERE case_id = %s AND action = 'letter'"
                " AND result = 'generated'"
                " ORDER BY attempt_no DESC LIMIT 1",
                (case_row["id"],),
            ).fetchone()
        if row is not None:
            letter = row["detail"]
        if letter is None:  # defensive — the worker always stores it
            letter = letters.letter_for_broker(
                broker_row, engine.assemble_profile(case_row["user_id"]))
        return {"action": "send_email", "to": letter.get("to") or "",
                "subject": letter.get("subject") or letters.SUBJECT,
                "body": letter.get("body") or ""}
    if reason.startswith("missing_field:"):
        field = reason.split(":", 1)[1]
        note = ("This broker's form needs your %s, which is not in "
                "your saved details. Add it under My saved details, "
                "then press Try again."
                % _FIELD_LABELS.get(field, field))
    else:
        note = _NOTES.get(
            reason,
            "Open the broker's opt-out page and complete the removal "
            "there.")
    return {"action": "open_optout", "url": broker_row["optout_url"],
            "note": note}


def human_queue(user_id):
    """The caller's needs_human cases, each with its exact next step."""
    with pool.connection() as conn:
        rows = conn.execute(
            _CASE_SELECT + " WHERE c.user_id = %s"
            " AND c.status = 'needs_human'"
            " ORDER BY b.position, b.slug",
            (user_id,),
        ).fetchall()
        brokers = {}
        if rows:
            slugs = [row["broker_slug"] for row in rows]
            for brow in conn.execute(
                    "SELECT slug, name, optout_url, contact_email"
                    " FROM brokers WHERE slug = ANY(%s)",
                    (slugs,)).fetchall():
                brokers[brow["slug"]] = brow
    queue = []
    for row in rows:
        item = public_case(row)
        # The letter lookup needs the owner id; keep it off the wire.
        scoped = dict(row)
        scoped["user_id"] = user_id
        item.update(_next_step(scoped, brokers[row["broker_slug"]]))
        queue.append(item)
    return queue


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

_RETRYABLE = ("needs_human", "blocked", "failed")


def retry_case(user_id, case_id):
    """Send a case the user has acted on back to the queue. Only
    needs_human / blocked / failed cases may retry — a submitted or
    verified case is never re-run (that would double-submit)."""
    row = _case_row(user_id, case_id)
    if row["status"] not in _RETRYABLE:
        raise errors.conflict(
            "not_retryable",
            "This case is already in progress or finished")
    with pool.connection() as conn:
        if row["status"] == "failed":
            # A failed case is closed history; if a newer live case
            # already covers this broker, retrying would violate the
            # one-live-case rule.
            live = conn.execute(
                "SELECT 1 AS x FROM remediation_cases"
                " WHERE user_id = %s AND broker_slug = %s AND id <> %s"
                " AND status NOT IN ('verified_removed', 'failed')"
                " LIMIT 1",
                (user_id, row["broker_slug"], case_id),
            ).fetchone()
            if live is not None:
                raise errors.conflict(
                    "not_retryable",
                    "A newer case already covers this broker")
        conn.execute(
            "UPDATE remediation_cases SET status = 'queued',"
            " reason = NULL, updated_at = now() WHERE id = %s",
            (case_id,),
        )
    return public_case(_case_row(user_id, case_id))
