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
  diff.broker_matches_finding. The same flip is fed by the stored
  lifecycle (Phase 25): a finding the lifecycle writer moved to
  'reappeared' in this completion (e.g. one remediation had
  resolved that this cycle found again) is a candidate too.
* Stored lifecycle (spec Phase 25): the same completion pass
  persists each identity's canonical lifecycle state through
  diff.apply_lifecycle — the diff above now only drives the
  notification ledger, never a per-read state derivation.
* False-positive feedback (Phase 156): a finding whose identity
  the user has marked 'not_me' (scanning/feedback.py — the one
  shared helper) is excluded from the new-exposure side of this
  hook entirely: no per-finding notification, no summary count,
  and it cannot flip a verified_removed case back to reappeared.
  The diff itself is untouched — 'resolved' notices for findings
  the user still owns behave exactly as before.
* The hook is idempotent per job: the summary's dedupe key is
  'summary:<job id>', and a job that already has one is skipped.
* Delivery split (the inbox rule): per-finding notices are
  IN-APP ONLY — written through
  notify.create_notifications_batch in a single transaction,
  never emailed, whatever the consent. Email for a cycle is
  the once-per-cycle scan_summary, still created via
  notify.create_notification (mode "auto"), so the
  'notifications' consent governs the digest: no consent, no
  email — the summary row lands as in_app_only. One finding
  must never mean one email: a single large cycle would
  otherwise burn the free lane's daily quota (~215 emails for
  a 214-finding cycle against Brevo's 300/day) and bury the
  inbox. If the batch write fails, the hook falls back to the
  per-item loop (mode "auto") so the ledger is still written.
"""

from db import pool
from monitoring import diff, notify
from scanning import feedback as feedback_service

NEW_FINDING_CAP = 5

_FINDING_COLUMNS = (
    "f.id, f.identifier_id, f.identifier_kind, f.provider,"
    " f.source_name, f.source_url, f.discovered_at, f.exposed_fields,"
    " f.confidence, f.evidence_ref, f.lifecycle_state,"
    " f.lifecycle_changed_at, i.masked AS identifier_masked")


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
# Reappearance matching (the matcher itself lives in
# monitoring/diff.py: broker_matches_finding — one implementation
# shared with the lifecycle writer)
# ---------------------------------------------------------------------------

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
            if diff.broker_matches_finding(broker, finding):
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

    current = _load_findings(job_id, user_id)
    previous = _previous_job(job)
    baseline = previous is None
    previous_findings = [] if baseline else _load_findings(
        previous["id"], user_id)
    delta = diff.diff_findings(previous_findings, current)
    # Stored lifecycle (Phase 25): persist this cycle's transitions
    # BEFORE the already-processed check — the writer is idempotent
    # and refuses stale jobs itself, so re-running the hook can
    # neither double-apply nor rewind state, and a completion whose
    # notification pass was already recorded still leaves the
    # lifecycle correct.
    lifecycle = diff.apply_lifecycle(
        user_id, job, current, previous_findings)
    if _summary_exists(user_id, job_id):
        return {"skipped": True, "reason": "already_processed"}
    new_findings = delta["new"]
    resolved_findings = delta["resolved"]
    # 'not_me' identities are excluded from everything this hook
    # would say about NEW exposures (see the module docstring).
    disowned = feedback_service.not_me_identities(user_id)
    notifiable_new = [
        f for f in new_findings
        if diff.identity_of(f) not in disowned]

    created = []
    emitted_new = 0
    if not baseline:
        # Per-finding notices are in-app only (see the module
        # docstring): one batch write for the whole cycle. The
        # per-item fallback below preserves the old path —
        # including its mode "auto" delivery — for the day the
        # batch itself fails.
        new_items = [
            {"kind": "new_finding",
             "payload": _finding_payload(finding),
             "dedupe_key": "new:" + diff.identity_hash(finding)}
            for finding in notifiable_new[:NEW_FINDING_CAP]]
        resolved_items = [
            {"kind": "finding_resolved",
             "payload": _finding_payload(finding),
             "dedupe_key": "resolved:" + diff.identity_hash(finding)}
            for finding in resolved_findings]
        batch = None
        try:
            batch = notify.create_notifications_batch(
                user_id, new_items + resolved_items)
        except Exception as exc:
            from core import logging_setup

            logging_setup.log_error(
                None, "notification batch failed, falling back to"
                " per-item writes: " + type(exc).__name__)
        if batch is not None:
            created.extend(batch)
            emitted_new = len(new_items)
        else:
            for finding in notifiable_new[:NEW_FINDING_CAP]:
                try:
                    created.append(notify.create_notification(
                        user_id, "new_finding",
                        _finding_payload(finding),
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
        # Case-flip candidates: the diff's NEW findings, plus any
        # finding the lifecycle writer moved to 'reappeared' in
        # this completion (a remediation-resolved exposure the set
        # diff can only call "continuing"). Disowned identities
        # stay excluded from both, exactly as for new findings.
        candidates = list(notifiable_new)
        candidate_ids = {str(f["id"]) for f in candidates}
        for finding in lifecycle["reappeared"]:
            if str(finding["id"]) in candidate_ids:
                continue
            if diff.identity_of(finding) in disowned:
                continue
            candidates.append(finding)
        reappeared = _handle_reappearance(
            user_id, candidates, job_id, created)

    extra_new = 0 if baseline else max(
        0, len(notifiable_new) - emitted_new)
    summary_payload = {
        "job_id": str(job_id),
        "baseline": baseline,
        "new_count": len(notifiable_new),
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
