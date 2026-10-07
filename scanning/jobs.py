"""Scan job API service (spec Phases 11, 12) — the layer behind
GET/POST /api/scans.

Authorization by construction (the Stage S3 pattern): every function
takes the session's user id and scopes every query by it; a foreign
job id answers the same 404 as a nonexistent one.

Creation is consent-gated and idempotent:
* the 'scanning' consent must currently be granted (the latest
  consent row decides) — otherwise 403 consent_required;
* the user must have at least one saved identifier — otherwise
  400 no_identifiers (a full scan of nothing is a user error, and
  saying so beats queueing a meaningless job);
* (user_id, idempotency_key) is unique: a retried create returns
  the existing job instead of queueing a duplicate.

Responses never contain identifier values — findings join the
vault's pre-computed masked rendering, and that is all.
"""

from accounts import audit
from accounts import consents as consents_service
from accounts import identifiers as identifiers_service
from core import errors
from db import pool
from scanning import risk

_JOB_LIST_COLUMNS = "id, status, score, created_at, finished_at"
_JOB_FULL_COLUMNS = (
    "id, status, attempts, error_kind, score, score_explanation,"
    " summary, created_at, started_at, finished_at")


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _public_list(row):
    return {
        "id": str(row["id"]),
        "status": row["status"],
        "score": row["score"],
        "created_at": _iso(row["created_at"]),
        "finished_at": _iso(row["finished_at"]),
    }


def _public_full(row):
    out = _public_list(row)
    out.update({
        "attempts": int(row["attempts"]),
        "error_kind": row["error_kind"],
        "score_explanation": row["score_explanation"],
        "summary": row["summary"],
        "started_at": _iso(row["started_at"]),
    })
    return out


def _public_finding(row):
    return {
        "id": str(row["id"]),
        "job_id": str(row["job_id"]),
        "identifier_id": (str(row["identifier_id"])
                          if row.get("identifier_id") else None),
        "identifier_kind": row["identifier_kind"],
        "identifier_masked": row.get("identifier_masked"),
        "provider": row["provider"],
        "source_name": row["source_name"],
        "source_url": row["source_url"],
        "source_date": _iso(row["source_date"]),
        "discovered_at": _iso(row["discovered_at"]),
        "exposed_fields": list(row["exposed_fields"] or []),
        "confidence": row["confidence"],
        "reliability": row["reliability"],
        "risk": risk.finding_risk(row["exposed_fields"],
                                  row["reliability"]),
        "status": row["status"],
        "evidence_ref": row["evidence_ref"],
        "remediation_eligible": bool(row["remediation_eligible"]),
        "details": row["details"] or {},
    }


def _scanning_consented(user_id):
    for entry in consents_service.current_consents(user_id):
        if entry["purpose"] == "scanning":
            return bool(entry["granted"])
    return False


def create_job(user_id, idempotency_key):
    """Create (or fetch, on retry) the user's scan job.
    Returns (public_job, created: bool) where public_job is the
    {id, status} creation shape."""
    if not isinstance(idempotency_key, str) \
            or not idempotency_key.strip() \
            or len(idempotency_key) > 128:
        raise errors.bad_request(
            "invalid_idempotency_key",
            "A non-empty idempotency key is required")
    if not _scanning_consented(user_id):
        raise errors.forbidden(
            "consent_required",
            "Turn on the Scanning permission to run a full scan")
    if not identifiers_service.list_identifiers(user_id):
        raise errors.bad_request(
            "no_identifiers",
            "Save at least one detail before running a full scan")
    with pool.connection() as conn:
        row = conn.execute(
            "INSERT INTO scan_jobs (user_id, idempotency_key)"
            " VALUES (%s, %s)"
            " ON CONFLICT (user_id, idempotency_key) DO NOTHING"
            " RETURNING id, status",
            (user_id, idempotency_key),
        ).fetchone()
        if row is not None:
            job = {"id": str(row["id"]), "status": row["status"]}
            audit.record(user_id, "user", "scan.job_created",
                         "scan_job", job["id"], {"source": "manual"})
            return job, True
        row = conn.execute(
            "SELECT id, status FROM scan_jobs"
            " WHERE user_id = %s AND idempotency_key = %s",
            (user_id, idempotency_key),
        ).fetchone()
    if row is None:  # pragma: no cover - the conflict guarantees a row
        raise errors.internal_error()
    return {"id": str(row["id"]), "status": row["status"]}, False


def list_jobs(user_id):
    """The caller's jobs, newest first (list shape)."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT " + _JOB_LIST_COLUMNS + " FROM scan_jobs"
            " WHERE user_id = %s ORDER BY created_at DESC, id DESC",
            (user_id,),
        ).fetchall()
    return [_public_list(row) for row in rows]


def get_job(user_id, job_id):
    """One of the caller's jobs in full, with its findings.
    Foreign or unknown ids raise the same 404."""
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT " + _JOB_FULL_COLUMNS + " FROM scan_jobs"
            " WHERE id = %s AND user_id = %s",
            (job_id, user_id),
        ).fetchone()
        if row is None:
            raise errors.not_found("Scan not found")
        findings = conn.execute(
            "SELECT f.*, i.masked AS identifier_masked FROM findings f"
            " LEFT JOIN identifiers i ON i.id = f.identifier_id"
            " WHERE f.job_id = %s AND f.user_id = %s"
            " ORDER BY f.discovered_at, f.id",
            (job_id, user_id),
        ).fetchall()
    return {"job": _public_full(row),
            "findings": [_public_finding(f) for f in findings]}
