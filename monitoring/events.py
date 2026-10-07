"""Scan-completion hook (spec Phases 43–46, 158–160): after a scan
job completes, diff it against the user's previous completed job
and write the notification ledger (monitoring/notify.py).

Wired from scanning/worker.py's success path, guarded there so a
notification failure can never fail or retry the scan itself.

Rules:
* The FIRST completed job is a baseline: it produces one
  scan_summary (baseline: true) and no per-finding notifications —
  everything in it is "new" only relative to nothing.
* Later jobs: up to NEW_FINDING_CAP new_finding notifications (one
  per genuinely new finding, dedupe 'new:<identity hash>'), one
  finding_resolved per disappeared finding, and exactly one
  scan_summary carrying the totals — including how many new
  findings the cap folded into it — plus the score and its delta.
* Reappearance (spec Phase 39): a NEW finding whose source matches
  a 'verified_removed' remediation case's broker flips that case
  back through remediation.verify.mark_reappeared (which records
  the evidence as a verification check) and earns a 'reappeared'
  notification. Matching is conservative and documented in
  _broker_matches_finding.
* The hook is idempotent per job: the summary's dedupe key is
  'summary:<job id>', and a job that already has one is skipped.
* Delivery honours the 'notifications' consent inside
  notify.create_notification (mode "auto"): no consent, no email —
  the rows land as in_app_only.
"""

import re
import urllib.parse

from db import pool
from monitoring import diff, notify

NEW_FINDING_CAP = 5

_FINDING_COLUMNS = (
    "f.id, f.identifier_id, f.identifier_kind, f.provider,"
    " f.source_name, f.source_url, f.discovered_at, f.exposed_fields,"
    " f.confidence, f.evidence_ref, i.masked AS identifier_masked")


def _load_job(job_id):
    with pool.connection() as conn:
        return conn.execute(
            "SELECT id, user_id, status, score, finished_at"
            " FROM scan_jobs WHERE id = %s",
            (job_id,),
        ).fetchone()


def _load_findings(job_id, user_id):
    with pool.connection() as conn:
        return conn.execute(
            "SELECT " + _FINDING_COLUMNS + " FROM findings f"
            " LEFT JOIN identifiers i ON i.id = f.identifier_id"
            " WHERE f.job_id = %s AND f.user_id = %s"
            " ORDER BY f.discovered_at, f.id",
            (job_id, user_id),
        ).fetchall()


def _previous_job(job):
    """The most recent OTHER completed job of the same user that
    finished no later than this one, or None (baseline)."""
    with pool.connection() as conn:
        return conn.execute(
            "SELECT id, user_id, status, score, finished_at"
            " FROM scan_jobs WHERE user_id = %s AND status = 'done'"
            " AND id <> %s AND finished_at IS NOT NULL"
            " AND finished_at <= %s"
            " ORDER BY finished_at DESC, created_at DESC LIMIT 1",
            (job["user_id"], job["id"], job["finished_at"]),
        ).fetchone()


def _summary_exists(user_id, job_id):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id FROM notifications WHERE user_id = %s"
            " AND dedupe_key = %s LIMIT 1",
            (user_id, "summary:%s" % job_id),
        ).fetchone()
    return row is not None


def _finding_payload(finding):
    return {
        "source_name": finding["source_name"],
        "provider": finding["provider"],
        "identifier_kind": finding["identifier_kind"],
        "identifier_masked": finding.get("identifier_masked"),
        "confidence": finding["confidence"],
        "exposed_fields": list(finding["exposed_fields"] or []),
    }


# ---------------------------------------------------------------------------
# Reappearance matching
# ---------------------------------------------------------------------------

def _norm_text(value):
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _host_of(url):
    if not url:
        return ""
    host = urllib.parse.urlparse(str(url)).netloc.casefold()
    return host.split("@")[-1].split(":")[0]


def _broker_matches_finding(broker, finding):
    """Conservative broker↔finding source match. True when ANY of:
    * the finding's source name IS the broker's name (normalized);
    * the finding's source name IS the broker's slug (normalized);
    * the finding's source URL lives on the broker's own host (the
      host of its opt-out or search URL, or a subdomain of it).
    Anything fuzzier would risk flipping a case on a stranger's
    listing — a missed match costs a delay, a wrong match costs
    the truth of the case ledger."""
    source = _norm_text(finding.get("source_name"))
    if source and source in (_norm_text(broker.get("name")),
                             _norm_text(broker.get("slug"))):
        return True
    finding_host = _host_of(finding.get("source_url"))
    if finding_host:
        for url in (broker.get("optout_url"), broker.get("search_url")):
            broker_host = _host_of(url)
            if broker_host and (finding_host == broker_host
                                or finding_host.endswith("." + broker_host)):
                return True
    return False


def _verified_cases(user_id):
    with pool.connection() as conn:
        return conn.execute(
            "SELECT c.id, c.broker_slug, b.name AS broker_name,"
            " b.optout_url, b.search_url FROM remediation_cases c"
            " JOIN brokers b ON b.slug = c.broker_slug"
            " WHERE c.user_id = %s AND c.status = 'verified_removed'",
            (user_id,),
        ).fetchall()


def _handle_reappearance(user_id, new_findings, job_id, created):
    """Flip verified_removed cases whose broker a NEW finding
    matches. Returns the number of cases flipped."""
    if not new_findings:
        return 0
    cases = _verified_cases(user_id)
    if not cases:
        return 0
    from remediation import verify as remediation_verify

    flipped = 0
    for case in cases:
        match = None
        for finding in new_findings:
            broker = {"name": case["broker_name"], "slug": case["broker_slug"],
                      "optout_url": case["optout_url"],
                      "search_url": case["search_url"]}
            if _broker_matches_finding(broker, finding):
                match = finding
                break
        if match is None:
            continue
        try:
            did_flip = remediation_verify.mark_reappeared(
                str(case["id"]), match["evidence_ref"])
        except Exception:
            did_flip = False
        if not did_flip:
            continue
        flipped += 1
        payload = _finding_payload(match)
        payload.update({
            "broker_slug": case["broker_slug"],
            "broker_name": case["broker_name"],
            "case_id": str(case["id"]),
            "job_id": str(job_id),
        })
        try:
            created.append(notify.create_notification(
                user_id, "reappeared", payload,
                dedupe_key="reappeared:%s:%s" % (
                    case["id"], diff.identity_hash(match))))
        except Exception:
            pass  # the flip is the fact; the notice is best-effort
    return flipped


# ---------------------------------------------------------------------------
# The hook
# ---------------------------------------------------------------------------

def handle_scan_completed(job_id):
    """Process one completed scan job. Returns a small dict of what
    happened ({"skipped": True} when there was nothing to do).
    Raises only for infrastructure failures — the worker guards."""
    job = _load_job(job_id)
    if job is None or job["status"] != "done":
        return {"skipped": True, "reason": "job_not_done"}
    user_id = str(job["user_id"])

    from accounts import auth

    if auth._get_user_by_id(user_id) is None:
        return {"skipped": True, "reason": "user_gone"}
    if _summary_exists(user_id, job_id):
        return {"skipped": True, "reason": "already_processed"}

    current = _load_findings(job_id, user_id)
    previous = _previous_job(job)
    baseline = previous is None
    previous_findings = [] if baseline else _load_findings(
        previous["id"], user_id)
    delta = diff.diff_findings(previous_findings, current)
    new_findings = delta["new"]
    resolved_findings = delta["resolved"]

    created = []
    emitted_new = 0
    if not baseline:
        for finding in new_findings[:NEW_FINDING_CAP]:
            try:
                created.append(notify.create_notification(
                    user_id, "new_finding", _finding_payload(finding),
                    dedupe_key="new:" + diff.identity_hash(finding)))
                emitted_new += 1
            except Exception:
                pass  # one bad notice must not sink the rest
        for finding in resolved_findings:
            try:
                created.append(notify.create_notification(
                    user_id, "finding_resolved",
                    _finding_payload(finding),
                    dedupe_key="resolved:" + diff.identity_hash(finding)))
            except Exception:
                pass

    reappeared = 0
    if not baseline:
        reappeared = _handle_reappearance(
            user_id, new_findings, job_id, created)

    extra_new = 0 if baseline else max(
        0, len(new_findings) - emitted_new)
    summary_payload = {
        "job_id": str(job_id),
        "baseline": baseline,
        "new_count": len(new_findings),
        "resolved_count": len(resolved_findings),
        "continuing_count": delta["continuing"],
        "extra_new_count": extra_new,
        "score": job["score"],
        "score_delta": diff.score_delta(
            None if baseline else previous["score"], job["score"]),
    }
    created.append(notify.create_notification(
        user_id, "scan_summary", summary_payload,
        dedupe_key="summary:%s" % job_id))
    return {
        "skipped": False,
        "baseline": baseline,
        "new": len(new_findings),
        "resolved": len(resolved_findings),
        "continuing": delta["continuing"],
        "reappeared": reappeared,
        "notifications": [n["id"] for n in created],
    }
