"""Action Center API service — the layer behind
GET /api/action-center.

A READ MODEL over rows that already exist (identifiers, scan_jobs,
findings, remediation_cases, brokers, consents) plus the Stage S8
monitoring timeline. No new tables, no second truth.

Authorization by construction (the Stage S3 pattern): the function
takes the session's user id and scopes every query by it.

The centrepiece is next_action: ONE recommendation, computed here
so the signed-in home is one glance + one button — the owner's UX
law (details entered once → LeakGuard fetches the leaks → the user
gives ONE command → LeakGuard completes it). Priority, first match
wins:

  a. add_details       — nothing saved yet.
  b. scan_now          — saved details, no completed scan yet, and
                         no scan currently queued/running.
  c. remove_all        — the latest scan found exposures, the
                         Automatic removal permission is on, and at
                         least one active broker has no live case.
     enable_removal    — the same state with the permission OFF:
                         the honest alternative. LeakGuard never
                         submits anything without that consent, so
                         the recommendation is to grant it, never
                         a removal we would not really run.
  d. review_queue      — removals parked on one step only the user
                         can take (CAPTCHA, sign-in, an email from
                         their own mailbox).
  e. scanning          — a scan is queued or running right now.
  f. enable_monitoring — nothing else pending and monitoring off.
  g. all_clear         — covered; monitoring keeps watch.

Honesty rules: a broker counts as removed only from a
verified_removed case (Stage S7 verification), never inferred; the
score and band come from the user's own latest completed scan job,
never from the anonymous quick scan.
"""

from accounts import consents as consents_service
from accounts.auth import _iso
from db import pool
from monitoring import diff as diff_mod
from monitoring import service as monitoring_service
from scanning import feedback as feedback_service

_CASE_STATUSES = ("queued", "running", "submitted", "needs_human",
                  "blocked", "verified_removed", "reappeared")
_CLOSED_CASE_STATUSES = ("verified_removed", "failed")


def score_band(score):
    """Plain-language band for an exposure score, on the same
    thresholds the anonymous Quick Scan has always used."""
    if score is None:
        return None
    if score <= 0:
        return "No exposure found"
    if score < 35:
        return "Some exposure"
    if score < 70:
        return "Serious exposure"
    return "Critical exposure"


def _consent_granted(user_id, purpose):
    for entry in consents_service.current_consents(user_id):
        if entry["purpose"] == purpose:
            return bool(entry["granted"])
    return False


def _next_action(state):
    """The one recommendation, from the aggregate state dict.
    Pure decision logic over already-fetched facts."""
    if state["identifiers"] == 0:
        return {
            "kind": "add_details",
            "label": "Add your details to start",
            "detail": "Save the details you want protected — an email "
                      "address is enough to begin. LeakGuard checks "
                      "them against the breach databases, and you "
                      "never type them again.",
        }
    if state["latest_job"] is None and not state["scan_in_progress"]:
        return {
            "kind": "scan_now",
            "label": "Scan my saved details",
            "detail": "You have saved details but no completed scan "
                      "yet. One tap checks them all against the "
                      "breach databases.",
        }
    if state["findings_total"] > 0 and state["removal_pending"]:
        if state["remediation_on"]:
            return {
                "kind": "remove_all",
                "label": "Remove my data everywhere",
                "detail": "Your latest scan found %d exposure(s). One "
                          "tap opens a removal case with every broker "
                          "that does not have one yet, and LeakGuard "
                          "works through them for you."
                          % state["findings_total"],
            }
        return {
            "kind": "enable_removal",
            "label": "Turn on automatic removal",
            "detail": "Your latest scan found %d exposure(s), but "
                      "the Automatic removal permission is off — "
                      "LeakGuard never submits anything for you "
                      "without it. Turn it on and removal becomes "
                      "one tap." % state["findings_total"],
        }
    needs_human = state["cases"]["needs_human"]
    if needs_human > 0:
        return {
            "kind": "review_queue",
            "label": "%d removal%s need%s one step from you" % (
                needs_human, "" if needs_human == 1 else "s",
                "s" if needs_human == 1 else ""),
            "detail": "These brokers would not accept an automatic "
                      "request — a CAPTCHA, a sign-in, or an email "
                      "only you can send. Each case in your queue "
                      "below has the exact step to finish it.",
        }
    if state["scan_in_progress"]:
        return {
            "kind": "scanning",
            "label": "Scan running…",
            "detail": "LeakGuard is checking your saved details "
                      "right now. The result lands here and in your "
                      "timeline when it finishes.",
        }
    if not state["monitoring_on"]:
        return {
            "kind": "enable_monitoring",
            "label": "Turn on monitoring",
            "detail": "Nothing needs you right now. Turn on the "
                      "Monitoring permission and LeakGuard re-checks "
                      "your saved details on a schedule, telling you "
                      "when something new appears.",
        }
    return {
        "kind": "all_clear",
        "label": "You're covered — monitoring keeps watch",
        "detail": "Nothing needs you right now. Monitoring re-checks "
                  "your saved details on schedule, and anything new "
                  "will show up here.",
    }


def action_center(user_id):
    """The full aggregate for the caller's signed-in home."""
    with pool.connection() as conn:
        identifiers = conn.execute(
            "SELECT COUNT(*) AS n FROM identifiers"
            " WHERE user_id = %s AND deleted_at IS NULL",
            (user_id,),
        ).fetchone()["n"]
        jobs = conn.execute(
            "SELECT id, score, finished_at FROM scan_jobs"
            " WHERE user_id = %s AND status = 'done'"
            " AND finished_at IS NOT NULL"
            " ORDER BY finished_at DESC, id DESC LIMIT 2",
            (user_id,),
        ).fetchall()
        in_flight = conn.execute(
            "SELECT COUNT(*) AS n FROM scan_jobs"
            " WHERE user_id = %s AND status IN ('queued', 'running')",
            (user_id,),
        ).fetchone()["n"]
        case_rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM remediation_cases"
            " WHERE user_id = %s GROUP BY status",
            (user_id,),
        ).fetchall()
        active_brokers = conn.execute(
            "SELECT COUNT(*) AS n FROM brokers WHERE active = true",
            (),
        ).fetchone()["n"]

    latest = jobs[0] if jobs else None
    previous = jobs[1] if len(jobs) > 1 else None
    findings_total = 0
    if latest is not None:
        with pool.connection() as conn:
            latest_findings = conn.execute(
                "SELECT identifier_id, provider, source_name"
                " FROM findings WHERE user_id = %s AND job_id = %s",
                (user_id, latest["id"]),
            ).fetchall()
        # Findings the user has disowned ('not_me', Phase 156) do
        # not count here — the same shared helper the alerts and
        # the scan view consult, so the surfaces cannot drift.
        disowned = feedback_service.not_me_identities(user_id)
        findings_total = sum(
            1 for f in latest_findings
            if diff_mod.identity_of(f) not in disowned)

    cases = {status: 0 for status in _CASE_STATUSES}
    closed = 0
    for row in case_rows:
        if row["status"] in cases:
            cases[row["status"]] = int(row["n"])
        if row["status"] in _CLOSED_CASE_STATUSES:
            closed += int(row["n"])
    total_cases = sum(int(row["n"]) for row in case_rows)
    live_cases = total_cases - closed

    score = latest["score"] if latest is not None else None
    delta = None
    if latest is not None and previous is not None \
            and latest["score"] is not None \
            and previous["score"] is not None:
        delta = int(latest["score"]) - int(previous["score"])

    state = {
        "identifiers": int(identifiers),
        "latest_job": latest,
        "scan_in_progress": int(in_flight) > 0,
        "findings_total": int(findings_total),
        # Removal is still actionable while some active broker has
        # no live case for this user (see remediation.service:
        # create_cases_for_user opens exactly one per broker).
        "removal_pending": live_cases < int(active_brokers),
        "remediation_on": _consent_granted(
            user_id, "automated_remediation"),
        "monitoring_on": _consent_granted(user_id, "monitoring"),
        "cases": cases,
    }
    return {
        "exposure": {
            "score": score,
            "band": score_band(score),
            "delta": delta,
            "scored_at": _iso(latest["finished_at"])
            if latest is not None else None,
            "findings_total": int(findings_total),
        },
        "counts": {
            "identifiers": int(identifiers),
            "cases": cases,
        },
        "scan_in_progress": state["scan_in_progress"],
        "monitoring_on": state["monitoring_on"],
        "next_action": _next_action(state),
        "recent": monitoring_service.timeline(user_id, limit=5),
    }
