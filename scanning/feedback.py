"""False-positive feedback on findings (spec Phase 156).

A user can mark a finding "not_me" ("this exposure is not about
me") or "confirmed" ("yes, this is me"), and can clear the verdict
again. The finding row is never edited or deleted — it is evidence
of what a source said; the verdict lives in finding_feedback
(migration 0010) alongside it.

THIS MODULE IS THE ONE PLACE verdicts are read for behaviour. The
scan view, the Action Center counts and the monitoring alerts all
consult it, so the surfaces cannot drift: a finding the user has
disowned is not counted at them and does not alert them, anywhere.

Matching is by finding IDENTITY (monitoring/diff.py: identifier,
provider, source) for behaviour across scans — the same exposure in
a later scan is a new row, and the user's verdict on the exposure
must still hold. The verdict row itself points at one concrete
finding row, which is what the scan view renders.
"""

from accounts import audit
from core import errors
from db import pool
from monitoring import diff

VERDICTS = ("not_me", "confirmed")
CLEAR = "none"


def set_verdict(user_id, finding_id, verdict):
    """Store, change or clear the caller's verdict on one of their
    own findings. Returns the stored verdict, or None when cleared.
    verdict 'none' clears. A foreign or unknown finding id answers
    the same 404 as every other owner-scoped object."""
    if verdict != CLEAR and verdict not in VERDICTS:
        raise errors.bad_request(
            "invalid_verdict",
            "Verdict must be 'not_me', 'confirmed' or 'none'")
    try:
        import uuid

        finding_uuid = str(uuid.UUID(str(finding_id)))
    except (ValueError, AttributeError, TypeError):
        raise errors.not_found("Finding not found")
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id FROM findings WHERE id = %s AND user_id = %s",
            (finding_uuid, user_id),
        ).fetchone()
        if row is None:
            raise errors.not_found("Finding not found")
        if verdict == CLEAR:
            conn.execute(
                "DELETE FROM finding_feedback"
                " WHERE user_id = %s AND finding_id = %s",
                (user_id, finding_uuid))
            stored = None
        else:
            conn.execute(
                "INSERT INTO finding_feedback"
                " (user_id, finding_id, verdict) VALUES (%s, %s, %s)"
                " ON CONFLICT (user_id, finding_id) DO UPDATE"
                " SET verdict = EXCLUDED.verdict, updated_at = now()",
                (user_id, finding_uuid, verdict))
            stored = verdict
    audit.record(user_id, "user", "finding.feedback", "finding",
                 finding_uuid, {"verdict": verdict})
    return stored


def feedback_map(user_id, finding_ids):
    """{finding_id (str): verdict} for the caller's verdicts on the
    given finding rows — what the scan view renders per row."""
    ids = [str(fid) for fid in (finding_ids or ())]
    if not ids:
        return {}
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT finding_id, verdict FROM finding_feedback"
            " WHERE user_id = %s AND finding_id = ANY(%s)",
            (user_id, ids),
        ).fetchall()
    return {str(row["finding_id"]): row["verdict"] for row in rows}


def not_me_identities(user_id):
    """The identity tuples (monitoring/diff.identity_of) of every
    finding the caller has marked 'not_me'. Behavioural surfaces
    match findings — from ANY scan — against this set, so a verdict
    on an exposure survives the exposure being re-found."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT f.identifier_id, f.provider, f.source_name"
            " FROM finding_feedback fb"
            " JOIN findings f ON f.id = fb.finding_id"
            " WHERE fb.user_id = %s AND fb.verdict = 'not_me'",
            (user_id,),
        ).fetchall()
    return {diff.identity_of(row) for row in rows}


def is_disowned(user_id, finding, disowned=None):
    """True when `finding` (row/dict from any scan) matches one of
    the caller's 'not_me' identities. Pass a pre-fetched
    not_me_identities() set as `disowned` in loops."""
    if disowned is None:
        disowned = not_me_identities(user_id)
    return diff.identity_of(finding) in disowned
