"""Monitoring API service — the layer behind
GET/PUT /api/monitoring/settings, GET /api/monitoring/timeline and
GET /api/notifications.

Authorization by construction (the Stage S3 pattern): every
function takes the session's user id and scopes every query by it.

* Settings are just the cadence: whether monitoring runs at all is
  the 'monitoring' consent's answer, reported alongside so the UI
  can show one honest state. last/next scan come from real job rows.
* The timeline is a READ MODEL (spec Phases 46, 47): events derived
  from rows that already exist — completed scan jobs, findings'
  first appearances, and remediation case history (case rows plus
  their verification checks; the derivation rules are spelled out
  in timeline()'s docstring). No events table, no second truth.
* The notifications projection NEVER returns a password_reset
  payload's reset_url: the URL is delivery content for the email,
  not something an in-app list should hand out (the row reports
  has_reset_link instead).
"""

from datetime import timedelta

from accounts.auth import _iso
from core import errors
from db import pool

CADENCES = (7, 14, 30)
_TIMELINE_LIMIT = 100
_NOTIFICATIONS_LIMIT = 50


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def _monitoring_consented(user_id):
    from accounts import consents as consents_service

    for entry in consents_service.current_consents(user_id):
        if entry["purpose"] == "monitoring":
            return bool(entry["granted"])
    return False


def _last_completed_scan(user_id):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT MAX(finished_at) AS last_done FROM scan_jobs"
            " WHERE user_id = %s AND status = 'done'",
            (user_id,),
        ).fetchone()
    return row["last_done"] if row else None


def get_settings(user_id):
    """{cadence_days, monitoring_consent, last_scan_at,
    next_scan_at, due_now}. next_scan_at is last + cadence; with no
    completed scan yet it is null and due_now is true (the first
    scheduled run happens on the next scheduler tick)."""
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT monitor_cadence_days FROM user_settings"
            " WHERE user_id = %s",
            (user_id,),
        ).fetchone()
    cadence = int(row["monitor_cadence_days"]) if row else 7
    last = _last_completed_scan(user_id)
    next_due = last + timedelta(days=cadence) if last else None
    from datetime import datetime, timezone

    due_now = last is None or next_due <= datetime.now(timezone.utc)
    return {
        "cadence_days": cadence,
        "monitoring_consent": _monitoring_consented(user_id),
        "last_scan_at": _iso(last),
        "next_scan_at": _iso(next_due),
        "due_now": bool(due_now),
    }


def update_settings(user_id, cadence_days):
    """Set the cadence (7 | 14 | 30 — anything else is a 400) and
    return the fresh settings."""
    if isinstance(cadence_days, bool) \
            or not isinstance(cadence_days, int) \
            or cadence_days not in CADENCES:
        raise errors.bad_request(
            "invalid_cadence",
            "Pick a schedule of 7, 14 or 30 days")
    with pool.connection() as conn:
        conn.execute(
            "INSERT INTO user_settings (user_id, monitor_cadence_days)"
            " VALUES (%s, %s)"
            " ON CONFLICT (user_id) DO UPDATE"
            " SET monitor_cadence_days = EXCLUDED.monitor_cadence_days,"
            " updated_at = now()",
            (user_id, cadence_days),
        )
    return get_settings(user_id)


# ---------------------------------------------------------------------------
# Notifications (the ledger, as the owner may see it)
# ---------------------------------------------------------------------------

def _public_notification(row):
    payload = dict(row["payload"] or {})
    if row["kind"] == "password_reset":
        # The reset URL is the email's content, not list content.
        payload.pop("reset_url", None)
        payload["has_reset_link"] = True
    return {
        "id": str(row["id"]),
        "kind": row["kind"],
        "status": row["status"],
        "payload": payload,
        "created_at": _iso(row["created_at"]),
        "sent_at": _iso(row["sent_at"]),
    }


def list_notifications(user_id, limit=_NOTIFICATIONS_LIMIT):
    """The caller's notification ledger, newest first."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, kind, payload, status, created_at, sent_at"
            " FROM notifications WHERE user_id = %s"
            " ORDER BY created_at DESC, id DESC LIMIT %s",
            (user_id, int(limit)),
        ).fetchall()
    return [_public_notification(row) for row in rows]


# ---------------------------------------------------------------------------
# Timeline (read model)
# ---------------------------------------------------------------------------

_CASE_STATUS_WORDS = {
    "needs_human": "needs your help",
    "blocked": "is blocked",
    "failed": "failed",
}


def _scan_events(user_id, events):
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, score, finished_at FROM scan_jobs"
            " WHERE user_id = %s AND status = 'done'"
            " AND finished_at IS NOT NULL"
            " ORDER BY finished_at DESC LIMIT 50",
            (user_id,),
        ).fetchall()
    for row in rows:
        summary = "Full scan finished"
        if row["score"] is not None:
            summary += " — exposure score %s / 100" % row["score"]
        events.append({
            "type": "scan_completed",
            "at": row["finished_at"],
            "summary": summary,
            "refs": {"job_id": str(row["id"])},
        })


def _finding_events(user_id, events):
    """One event per finding identity, at its FIRST appearance
    across all of the user's jobs — a finding seen in five scans is
    one event, dated when it first showed up."""
    from monitoring import diff

    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT f.id, f.identifier_id, f.provider, f.source_name,"
            " f.discovered_at, i.masked AS identifier_masked"
            " FROM findings f"
            " LEFT JOIN identifiers i ON i.id = f.identifier_id"
            " WHERE f.user_id = %s ORDER BY f.discovered_at, f.id",
            (user_id,),
        ).fetchall()
    seen = set()
    for row in rows:
        key = diff.identity_key(row)
        if key in seen:
            continue
        seen.add(key)
        summary = "Exposure found in %s" % row["source_name"]
        if row.get("identifier_masked"):
            summary += " (%s)" % row["identifier_masked"]
        events.append({
            "type": "finding_found",
            "at": row["discovered_at"],
            "summary": summary,
            "refs": {
                "finding_id": str(row["id"]),
                "identifier_id": (str(row["identifier_id"])
                                  if row["identifier_id"] else None),
            },
        })


def _case_events(user_id, events):
    """Remediation history, derived from the case row plus its
    verification checks:
    * case_opened     — the case's created_at;
    * case_submitted  — submitted_at, when set;
    * case_verified   — the FIRST 'gone' check (the one that proved
      removal — later 'gone' checks only reconfirm it);
    * case_reappeared — every 'still_present' check AFTER that first
      'gone' (evidence the listing came back);
    * case_still_listed — 'still_present' checks with no 'gone'
      before them (a submitted case that is simply still there);
    * case_attention  — at updated_at, when the case currently sits
      at needs_human / blocked / failed.
    'unknown' checks teach nothing and produce no event."""
    with pool.connection() as conn:
        cases = conn.execute(
            "SELECT c.id, c.broker_slug, b.name AS broker_name,"
            " c.status, c.created_at, c.updated_at, c.submitted_at"
            " FROM remediation_cases c"
            " JOIN brokers b ON b.slug = c.broker_slug"
            " WHERE c.user_id = %s",
            (user_id,),
        ).fetchall()
        checks = {}
        if cases:
            ids = [str(c["id"]) for c in cases]
            for check in conn.execute(
                    "SELECT case_id, outcome, checked_at"
                    " FROM verification_checks"
                    " WHERE case_id = ANY(%s)"
                    " ORDER BY checked_at, id",
                    (ids,)).fetchall():
                checks.setdefault(str(check["case_id"]), []).append(check)
    for case in cases:
        name = case["broker_name"]
        refs = {"case_id": str(case["id"]),
                "broker_slug": case["broker_slug"]}
        events.append({
            "type": "case_opened", "at": case["created_at"],
            "summary": "Removal case opened for %s" % name,
            "refs": dict(refs),
        })
        if case["submitted_at"] is not None:
            events.append({
                "type": "case_submitted", "at": case["submitted_at"],
                "summary": "Removal request sent to %s" % name,
                "refs": dict(refs),
            })
        case_checks = checks.get(str(case["id"]), [])
        gone_at = None
        for check in case_checks:
            if check["outcome"] == "gone" and gone_at is None:
                gone_at = check["checked_at"]
                events.append({
                    "type": "case_verified", "at": check["checked_at"],
                    "summary": "Removal verified at %s — LeakGuard "
                               "checked and the listing was gone" % name,
                    "refs": dict(refs),
                })
            elif check["outcome"] == "still_present":
                if gone_at is not None:
                    events.append({
                        "type": "case_reappeared",
                        "at": check["checked_at"],
                        "summary": "A listing at %s appears to be back"
                                   % name,
                        "refs": dict(refs),
                    })
                else:
                    events.append({
                        "type": "case_still_listed",
                        "at": check["checked_at"],
                        "summary": "Checked %s — your listing is still "
                                   "there" % name,
                        "refs": dict(refs),
                    })
        if case["status"] in _CASE_STATUS_WORDS:
            events.append({
                "type": "case_attention", "at": case["updated_at"],
                "summary": "Removal case for %s %s"
                           % (name, _CASE_STATUS_WORDS[case["status"]]),
                "refs": dict(refs),
            })


def timeline(user_id, limit=_TIMELINE_LIMIT):
    """The unified, newest-first event list for one user."""
    events = []
    _scan_events(user_id, events)
    _finding_events(user_id, events)
    _case_events(user_id, events)
    events.sort(key=lambda e: e["at"], reverse=True)
    return [{
        "type": e["type"],
        "at": _iso(e["at"]),
        "summary": e["summary"],
        "refs": e["refs"],
    } for e in events[:int(limit)]]
