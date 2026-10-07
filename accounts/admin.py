"""Admin — the product owner's operational view (Stage S11, spec
Phases 106–114).

There is exactly ONE admin concept in this product: the owner.
Access is gated by the ADMIN_EMAILS environment variable
(comma-separated addresses, matched against the account email via
the same vault decryption the owner-only export uses — emails are
never stored in plaintext, so the check decrypts in memory and
compares; nothing is logged or returned).

PRIVACY CONTRACT: the admin sees AGGREGATES ONLY — platform counts,
status breakdowns, provider health and the PII-free audit trail.
Never another user's identifiers, emails, findings or letters: this
module's queries count rows and group them; no per-user row ever
leaves it. Non-admins cannot even tell the routes exist — the
handlers answer 404, not 403.
"""

import os
import uuid

from accounts import audit
from accounts import auth as auth_service
from accounts import consents as consents_service
from accounts.auth import _iso
from core import errors, flags
from db import pool as db_pool
from providers import registry as providers_registry
from providers import usage as provider_usage


def _admin_emails():
    """The configured admin addresses, normalized with the vault's
    email recipe so the comparison matches how accounts are stored."""
    configured = set()
    for part in os.environ.get("ADMIN_EMAILS", "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            configured.add(auth_service.normalize_email(part))
        except Exception:
            configured.add(part.lower())
    return configured


def is_admin(user_id):
    """True when the account's email is in ADMIN_EMAILS. With no
    addresses configured, nobody is an admin — the panel stays dark
    until the owner opts in on the server."""
    configured = _admin_emails()
    if not configured or user_id is None:
        return False
    row = auth_service._get_user_by_id(user_id)
    if row is None:
        return False
    try:
        email = auth_service.reveal_email(row)
    except Exception:
        return False
    return auth_service.normalize_email(email) in configured


def admin_user_ids():
    """The user ids of every live account whose email is in
    ADMIN_EMAILS — the recipients of owner-only operational mail
    (Phase 77 engineering alerts). Empty when ADMIN_EMAILS is
    unset: with no owner configured there is nobody to alert."""
    if not _admin_emails():
        return []
    with db_pool.connection() as conn:
        rows = conn.execute(
            "SELECT id FROM users WHERE deleted_at IS NULL",
        ).fetchall()
    return [str(row["id"]) for row in rows
            if is_admin(str(row["id"]))]


# The security-events view (spec Phase 62): audit actions that are
# about authentication and account security, matched by prefix so
# the family stays complete as actions are added ('auth.login'
# covers 'auth.login' and 'auth.login_failed'). Only meta is ever
# exposed — action, actor kind, time; the audit detail (PII-free as
# it is) stays in the full audit view.
_SECURITY_ACTION_PATTERNS = (
    "auth.login%",
    "auth.passkey%",
    "auth.password_reset%",
    "auth.totp%",
    "account.deleted%",
    "api_token.%",
    "privacy_export",
    # Phase 77 engineering alerts land in the same trail (written by
    # monitoring/alerts.py via the audit writer) so the owner sees a
    # fired rule next to the sign-in events it sits alongside.
    "engineering_alert",
)
_SECURITY_EVENTS_LIMIT = 20


def _security_events(conn):
    rows = conn.execute(
        "SELECT action, actor_kind, created_at FROM audit_log"
        " WHERE action LIKE ANY(%s)"
        " ORDER BY created_at DESC, id DESC LIMIT %s",
        (list(_SECURITY_ACTION_PATTERNS), _SECURITY_EVENTS_LIMIT),
    ).fetchall()
    return [{
        "action": row["action"],
        "actor_kind": row["actor_kind"],
        "created_at": _iso(row["created_at"]),
    } for row in rows]


def _counts_by(conn, table, column, where=""):
    rows = conn.execute(
        "SELECT " + column + " AS k, COUNT(*) AS n FROM " + table
        + where + " GROUP BY " + column,
    ).fetchall()
    return {row["k"]: int(row["n"]) for row in rows}


_DAY = "interval '24 hours'"

# Start of the current UTC day as a timestamptz expression (the
# usage ledger buckets by UTC date — providers/usage.py).
_UTC_DAY_START = ("(date_trunc('day', now() AT TIME ZONE 'UTC')"
                  " AT TIME ZONE 'UTC')")


def _provider_usage_block(conn):
    """Today's provider usage vs daily budgets (Phases 66, 124).

    One entry per provider that has a budget or any usage today:
    calls / successes / failures from provider_usage_daily
    (migration 0014), the budget from providers/usage.py BUDGETS
    (an operator-set safety budget, None when the provider has
    none), the percentage of the budget used, and whether the
    budget is spent. Sorted by provider name. Callers flush the
    in-memory tracker first (metrics()/overview() do), so the
    table is current for this process."""
    rows = conn.execute(
        "SELECT provider, calls, successes, failures"
        " FROM provider_usage_daily"
        " WHERE day = (now() AT TIME ZONE 'UTC')::date",
    ).fetchall()
    by_provider = {row["provider"]: row for row in rows}
    names = sorted(set(by_provider) | set(provider_usage.BUDGETS))
    block = []
    for name in names:
        row = by_provider.get(name)
        calls = int(row["calls"]) if row else 0
        budget = provider_usage.budget_for(name)
        block.append({
            "provider": name,
            "calls": calls,
            "successes": int(row["successes"]) if row else 0,
            "failures": int(row["failures"]) if row else 0,
            "budget": budget,
            "pct_used": (round(100.0 * calls / budget, 1)
                         if budget else None),
            "exhausted": bool(budget) and calls >= budget,
        })
    return block


def _metrics_block(conn):
    """Operational metrics (spec Phase 76): live queue state plus
    trailing-24h throughput/failure numbers, all computed from the
    product's own tables — no external monitoring service. Every
    windowed figure is labeled in its key; counts only, per the
    module's privacy contract.

    Window notes: a completed (done) or dead job is counted in the
    24h window by finished_at (both terminal paths stamp it); a
    'failed' job is mid-retry and has no finished_at yet, so it is
    counted by created_at. Error-event figures aggregate the
    ledger's hour-bucket rollups (error_events.bucket_start inside
    the window), so occurrence totals carry at most one partial
    bucket of edge at the window boundary. The providers section
    and the scan_jobs 'today' figures use the current UTC day —
    the usage ledger's bucket (providers/usage.py)."""
    scan_by_status = _counts_by(conn, "scan_jobs", "status")
    jobs_today = conn.execute(
        "SELECT COUNT(*) AS jobs, COUNT(DISTINCT user_id) AS users,"
        " COALESCE((SELECT MAX(c) FROM"
        "   (SELECT COUNT(*) AS c FROM scan_jobs"
        "    WHERE created_at >= "
        + _UTC_DAY_START +
        "    GROUP BY user_id) AS per_user), 0) AS max_per_user"
        " FROM scan_jobs WHERE created_at >= " + _UTC_DAY_START,
    ).fetchone()
    terminal = conn.execute(
        "SELECT"
        " COUNT(*) FILTER (WHERE status = 'done') AS completed,"
        " COUNT(*) FILTER (WHERE status = 'dead') AS dead"
        " FROM scan_jobs"
        " WHERE finished_at >= now() - " + _DAY,
    ).fetchone()
    failed_24h = conn.execute(
        "SELECT COUNT(*) AS n FROM scan_jobs WHERE status = 'failed'"
        " AND created_at >= now() - " + _DAY,
    ).fetchone()["n"]
    median = conn.execute(
        "SELECT percentile_cont(0.5) WITHIN GROUP"
        " (ORDER BY EXTRACT(EPOCH FROM (finished_at - started_at)))"
        " AS med FROM scan_jobs"
        " WHERE status = 'done' AND started_at IS NOT NULL"
        " AND finished_at >= now() - " + _DAY,
    ).fetchone()["med"]
    queue = conn.execute(
        "SELECT"
        " COUNT(*) FILTER (WHERE status = 'queued') AS queued,"
        " COUNT(*) FILTER (WHERE status = 'running') AS running,"
        " EXTRACT(EPOCH FROM (now() - MIN(created_at)"
        "   FILTER (WHERE status = 'queued'))) AS oldest_age"
        " FROM scan_jobs WHERE status IN ('queued', 'running')",
    ).fetchone()
    cases_by_status = _counts_by(conn, "remediation_cases", "status")
    # Phase 31: attempts grouped by the broker workflow version
    # they ran under — all-time, because version history is the
    # point (a re-map's before/after failure modes must both stay
    # visible). workflow_version is NULL for attempts written
    # before attempts recorded versions; the row says so honestly
    # instead of folding them into a guessed version.
    attempt_version_rows = conn.execute(
        "SELECT c.broker_slug AS broker,"
        " a.workflow_version AS workflow_version,"
        " a.result AS result, COUNT(*) AS n"
        " FROM remediation_attempts a"
        " JOIN remediation_cases c ON c.id = a.case_id"
        " GROUP BY c.broker_slug, a.workflow_version, a.result"
        " ORDER BY c.broker_slug, a.workflow_version, a.result",
    ).fetchall()
    attempts_by_version = [{
        "broker": row["broker"],
        "workflow_version": row["workflow_version"],
        "result": row["result"],
        "attempts": int(row["n"]),
    } for row in attempt_version_rows]
    notifications_24h = _counts_by(
        conn, "notifications", "status",
        " WHERE created_at >= now() - " + _DAY)
    sources = conn.execute(
        "SELECT COUNT(*) AS total,"
        " COUNT(*) FILTER (WHERE checked_at >= now() - " + _DAY
        + ") AS checked_24h,"
        " COUNT(*) FILTER (WHERE state = 'unreachable')"
        " AS unreachable"
        " FROM broker_source_checks",
    ).fetchone()
    security_rows = conn.execute(
        "SELECT action AS k, COUNT(*) AS n FROM audit_log"
        " WHERE action LIKE ANY(%s)"
        " AND created_at >= now() - " + _DAY
        + " GROUP BY action",
        (list(_SECURITY_ACTION_PATTERNS),),
    ).fetchall()
    security_by_kind = {row["k"]: int(row["n"]) for row in security_rows}
    error_pairs = conn.execute(
        "SELECT COUNT(*) AS pairs FROM"
        " (SELECT 1 FROM error_events"
        " WHERE bucket_start >= now() - " + _DAY
        + " GROUP BY context, error_class) AS d",
    ).fetchone()["pairs"]
    error_total = conn.execute(
        "SELECT COALESCE(SUM(occurrence_count), 0) AS total"
        " FROM error_events WHERE bucket_start >= now() - " + _DAY,
    ).fetchone()["total"]
    top_rows = conn.execute(
        "SELECT context, error_class,"
        " SUM(occurrence_count) AS n FROM error_events"
        " WHERE bucket_start >= now() - " + _DAY
        + " GROUP BY context, error_class"
        " ORDER BY n DESC, context, error_class LIMIT 5",
    ).fetchall()
    providers_block = _provider_usage_block(conn)
    # Phases 158/160: the scan-budget registry and the findings
    # data-quality summary. Deferred imports — accounts reaches
    # scanning only through function-level imports (the recorded
    # import graph), never at module top.
    from scanning import budgets as scan_budgets
    from scanning import data_quality

    budgets_block = scan_budgets.budgets_snapshot()
    dq_block = data_quality.latest_summary(conn)
    return {
        "scan_jobs": {
            "by_status": scan_by_status,
            # Per-user volume for the current UTC day, aggregate
            # only (Phase 66): signed-in work is attributed via
            # scan_jobs.user_id; anonymous traffic has no user
            # identity by design and is governed by the per-IP
            # rate limits instead (providers/usage.py docstring).
            "today": {
                "jobs": int(jobs_today["jobs"]),
                "distinct_users": int(jobs_today["users"]),
                "max_jobs_per_user": int(jobs_today["max_per_user"]),
            },
            "last_24h": {
                "completed": int(terminal["completed"]),
                "failed": int(failed_24h),
                "dead": int(terminal["dead"]),
            },
            "median_completed_duration_seconds_last_24h": (
                float(median) if median is not None else None),
        },
        "queue": {
            "queued": int(queue["queued"]),
            "running": int(queue["running"]),
            "active": int(queue["queued"]) + int(queue["running"]),
            "oldest_queued_age_seconds": (
                float(queue["oldest_age"])
                if queue["oldest_age"] is not None else None),
        },
        "remediation_cases_by_status": cases_by_status,
        "remediation_attempts_by_workflow_version": attempts_by_version,
        "notifications_by_status_last_24h": notifications_24h,
        "broker_sources": {
            "total": int(sources["total"]),
            "checked_last_24h": int(sources["checked_24h"]),
            "unreachable": int(sources["unreachable"]),
        },
        "security_events_by_kind_last_24h": security_by_kind,
        "errors_last_24h": {
            "distinct_context_class_pairs": int(error_pairs),
            "total_occurrences": int(error_total),
            "top": [{
                "context": row["context"],
                "error_class": row["error_class"],
                "occurrences": int(row["n"]),
            } for row in top_rows],
        },
        # Provider cost monitoring (Phase 124): today's calls
        # against each provider's daily budget (Phase 66).
        "providers": providers_block,
        # Scan budget engine (Phase 158): the whole budget
        # policy, read live from the constants that enforce it.
        "budgets": budgets_block,
        # Data-quality stage (Phase 160): latest run + the
        # per-provider duplicate/malformed rollup.
        "data_quality": dq_block,
    }


def _broker_health_block(conn):
    """Per-broker verification + workflow health (spec Phase 125).

    source_health answers "is the broker's opt-out page alive";
    this block answers the question the dashboard was missing:
    "does this broker actually REMOVE people, and is its removal
    workflow healthy?" Per broker that has any removal activity:

      * verification — how many post-removal checks ran against
        its cases and how they came out (gone / still_present /
        unknown, the verification_checks outcome vocabulary), plus
        removed_rate: gone over the decisive checks (gone +
        still_present) — None when no check has been decisive yet,
        never a fabricated 0.
      * cases — removal cases by stored status.
      * attempts — engine attempts by result.

    Counts only, per the module's privacy contract: no user, no
    case id, no detail ever appears here. Brokers with no cases,
    checks or attempts are omitted — an idle broker has no health
    signal to report. Sorted by slug for a stable rendering."""
    names = {
        row["slug"]: row["name"]
        for row in conn.execute(
            "SELECT slug, name FROM brokers").fetchall()
    }
    verification = {}
    for row in conn.execute(
            "SELECT c.broker_slug AS slug, v.outcome AS outcome,"
            " COUNT(*) AS n FROM verification_checks v"
            " JOIN remediation_cases c ON c.id = v.case_id"
            " GROUP BY c.broker_slug, v.outcome").fetchall():
        entry = verification.setdefault(
            row["slug"], {"checks": 0, "gone": 0, "still_present": 0,
                          "unknown": 0})
        entry["checks"] += int(row["n"])
        if row["outcome"] in entry:
            entry[row["outcome"]] += int(row["n"])
    cases = {}
    for row in conn.execute(
            "SELECT broker_slug AS slug, status, COUNT(*) AS n"
            " FROM remediation_cases"
            " GROUP BY broker_slug, status").fetchall():
        cases.setdefault(row["slug"], {})[row["status"]] = int(row["n"])
    attempts = {}
    for row in conn.execute(
            "SELECT c.broker_slug AS slug, a.result AS result,"
            " COUNT(*) AS n FROM remediation_attempts a"
            " JOIN remediation_cases c ON c.id = a.case_id"
            " GROUP BY c.broker_slug, a.result").fetchall():
        attempts.setdefault(row["slug"], {})[row["result"]] = \
            int(row["n"])
    block = []
    for slug in sorted(set(verification) | set(cases) | set(attempts)):
        ver = verification.get(slug) or {
            "checks": 0, "gone": 0, "still_present": 0, "unknown": 0}
        decisive = ver["gone"] + ver["still_present"]
        block.append({
            "slug": slug,
            "name": names.get(slug) or slug,
            "verification": {
                "checks": ver["checks"],
                "gone": ver["gone"],
                "still_present": ver["still_present"],
                "unknown": ver["unknown"],
                "removed_rate": (round(ver["gone"] / decisive, 3)
                                 if decisive else None),
            },
            "cases": cases.get(slug, {}),
            "attempts": attempts.get(slug, {}),
        })
    return block


def metrics(admin_user_id):
    """The metrics block on its own (GET /api/admin/metrics) —
    the same object overview() embeds under "metrics"."""
    provider_usage.flush()
    with db_pool.connection() as conn:
        block = _metrics_block(conn)
    audit.record(admin_user_id, "admin", "admin.metrics_viewed")
    return block


def overview(admin_user_id):
    """Platform aggregates for the owner. Counts only — see the
    module docstring's privacy contract."""
    provider_usage.flush()
    with db_pool.connection() as conn:
        users_total = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL",
        ).fetchone()["n"]
        users_last_30d = conn.execute(
            "SELECT COUNT(*) AS n FROM users"
            " WHERE deleted_at IS NULL"
            " AND created_at >= now() - interval '30 days'",
        ).fetchone()["n"]
        identifiers_by_kind = _counts_by(
            conn, "identifiers", "kind", " WHERE deleted_at IS NULL")
        scan_jobs_by_status = _counts_by(conn, "scan_jobs", "status")
        cases_by_status = _counts_by(
            conn, "remediation_cases", "status")
        notifications_by_status = _counts_by(
            conn, "notifications", "status")
        brokers = conn.execute(
            "SELECT COUNT(*) AS n FROM brokers WHERE active = true",
        ).fetchone()["n"]
        security_events = _security_events(conn)
        metrics_block = _metrics_block(conn)
        broker_health = _broker_health_block(conn)
    from remediation import source_checks

    result = {
        "users": {
            "total": int(users_total),
            "registered_last_30d": int(users_last_30d),
        },
        "identifiers_by_kind": identifiers_by_kind,
        "scan_jobs_by_status": scan_jobs_by_status,
        "remediation_cases_by_status": cases_by_status,
        "notifications_by_status": notifications_by_status,
        "brokers": int(brokers),
        "providers": providers_registry.get_registry().summary(),
        "db": db_pool.db_status(),
        # The emergency controls' current state (core/flags.py,
        # spec Phases 120/122): booleans only, so the owner can see
        # at a glance which capabilities a flag has switched off.
        "flags": flags.snapshot(),
        # Per-broker source health (Phases 32/125-lite): the daily
        # sweep's latest state per broker opt-out page — counts +
        # flagged slugs only, from remediation/source_checks.py.
        "source_health": source_checks.source_health(),
        # The security-events view (Phase 62): the latest auth /
        # account-security audit rows, meta only.
        "security_events": security_events,
        # Operational metrics (Phase 76): live queue state +
        # trailing-24h throughput and failure numbers. The same
        # block is served standalone at GET /api/admin/metrics.
        "metrics": metrics_block,
        # Per-broker verification + workflow health (Phase 125):
        # which brokers actually remove people (verification
        # outcomes) and which removal workflows are failing
        # (cases by status, attempts by result).
        "broker_health": broker_health,
    }
    audit.record(admin_user_id, "admin", "admin.overview_viewed")
    return result


def _public_audit_row(row):
    return {
        "id": int(row["id"]),
        "actor_user_id": (str(row["actor_user_id"])
                          if row["actor_user_id"] else None),
        "actor_kind": row["actor_kind"],
        "action": row["action"],
        "target_kind": row["target_kind"],
        "target_id": row["target_id"],
        "detail": row["detail"] if isinstance(row["detail"], dict)
        else {},
        "created_at": _iso(row["created_at"]),
    }


def list_audit(admin_user_id, limit=100):
    """The most recent audit rows, newest first. Detail is PII-free
    by construction (accounts/audit.py) — safe to show as-is."""
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))
    with db_pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, actor_user_id, actor_kind, action, target_kind,"
            " target_id, detail, created_at FROM audit_log"
            " ORDER BY created_at DESC, id DESC LIMIT %s",
            (limit,),
        ).fetchall()
    entries = [_public_audit_row(row) for row in rows]
    # Recorded AFTER the read, so a view never lists itself.
    audit.record(admin_user_id, "admin", "admin.audit_viewed",
                 detail={"limit": limit})
    return entries


# ---------------------------------------------------------------------------
# Dead-letter replay (Phase 119)
# ---------------------------------------------------------------------------
#
# This is the module's ONE write operation, and it is deliberately
# narrow enough to keep the privacy contract above: the admin
# supplies a kind + id they already hold (from the metrics blocks
# or the audit trail), and the response carries only that id and
# its new status — never anything about the row's owner. The
# operation itself is recorded in the audit trail like every other
# admin action.
#
# A dead letter is a row in its persisted terminal-failure state:
# a scan job in 'dead' (its three-attempt budget spent) or a
# removal case in 'failed' (the closed state of migration 0005's
# vocabulary — the user-facing retry exists for the owner; this
# replay is the operator's lane for cases and jobs whose owner
# cannot or should not have to resurrect them by hand).
#
# Semantics, shared by both kinds:
#   * one row per call, addressed by id, returned to 'queued';
#   * history is never erased — job attempts / case attempts and
#     the reason the row died are preserved (see each lane below),
#     and the replay itself writes an audit row carrying the prior
#     state;
#   * the owner's CURRENT consent for the lane is re-checked at
#     replay time: a row whose consent was revoked after it died
#     is refused and stays dead — replay never resurrects work
#     the owner has withdrawn permission for;
#   * a second replay of the same row is a typed refusal
#     ('already_active'), never a second queue entry: the row IS
#     the queue entry, and it is already queued.

_MONITOR_JOB_PREFIX = "monitor-"


def _purpose_granted(user_id, purpose):
    """The owner's current word on one consent purpose — the same
    latest-version read the engine and the job creator make."""
    for entry in consents_service.current_consents(user_id):
        if entry["purpose"] == purpose:
            return bool(entry["granted"])
    return False


def replay_dead_letter(admin_user_id, kind, target_id):
    """Return ONE dead scan job or removal case to the queue.

    Typed refusals (core/errors.py): invalid_kind (400) for a kind
    outside the two lanes; not_found (404) for an unknown or
    malformed id; consent_required (403) when the owner's current
    consent for the lane is not granted; already_active (409) when
    the row is queued/running (including a replay repeated);
    not_dead_letter (409) when the row is in any other state;
    not_retryable (409) when a removal case's broker is already
    covered by a newer live case."""
    if kind not in ("scan_job", "remediation_case"):
        raise errors.bad_request(
            "invalid_kind",
            "kind must be 'scan_job' or 'remediation_case'")
    try:
        target = str(uuid.UUID(str(target_id)))
    except (ValueError, AttributeError, TypeError):
        raise errors.not_found("That dead letter does not exist")
    if kind == "scan_job":
        return _replay_scan_job(admin_user_id, target)
    return _replay_case(admin_user_id, target)


def _replay_scan_job(admin_user_id, job_id):
    with db_pool.connection() as conn:
        row = conn.execute(
            "SELECT id, user_id, idempotency_key, status, attempts,"
            " error_kind FROM scan_jobs WHERE id = %s",
            (job_id,),
        ).fetchone()
    if row is None:
        raise errors.not_found("That scan job does not exist")
    status = row["status"]
    if status in ("queued", "running"):
        raise errors.conflict(
            "already_active",
            "That scan job is already queued or running — it does "
            "not need a replay")
    if status != "dead":
        raise errors.conflict(
            "not_dead_letter",
            "Only a dead scan job can be replayed — this one is %s"
            % status)
    # The lane decides which consent authorizes a resurrection: a
    # monitoring-scheduled job answers to the 'monitoring'
    # consent that created it, a hand-started job to 'scanning'.
    purpose = ("monitoring"
               if str(row["idempotency_key"]).startswith(
                   _MONITOR_JOB_PREFIX)
               else "scanning")
    owner_id = str(row["user_id"])
    if not _purpose_granted(owner_id, purpose):
        raise errors.forbidden(
            "consent_required",
            "The owner's %s permission is off — a dead job is "
            "never resurrected without it" % purpose)
    # Attempt-counter semantics: the counter resets to 0, giving
    # the job a fresh three-attempt budget — leaving it at the
    # budget would re-dead the job on its first new failure,
    # making the replay pointless. Nothing is lost by the reset:
    # the prior count and the error that killed the job are
    # carried in the audit row below, and finished_at is cleared
    # because the job is, truthfully, no longer finished.
    with db_pool.connection() as conn:
        updated = conn.execute(
            "UPDATE scan_jobs SET status = 'queued', attempts = 0,"
            " error_kind = NULL, next_attempt_at = NULL,"
            " started_at = NULL, finished_at = NULL"
            " WHERE id = %s AND status = 'dead' RETURNING id",
            (job_id,),
        ).fetchone()
    if updated is None:  # raced with another replay or drain
        raise errors.conflict(
            "already_active",
            "That scan job is already queued or running — it does "
            "not need a replay")
    audit.record(admin_user_id, "admin", "admin.dead_letter_replayed",
                 "scan_job", job_id,
                 {"prior_status": "dead",
                  "prior_attempts": int(row["attempts"]),
                  "prior_error_kind": row["error_kind"],
                  "lane": purpose})
    return {"kind": "scan_job", "id": job_id, "status": "queued"}


def _replay_case(admin_user_id, case_id):
    with db_pool.connection() as conn:
        row = conn.execute(
            "SELECT id, user_id, broker_slug, status, reason"
            " FROM remediation_cases WHERE id = %s",
            (case_id,),
        ).fetchone()
    if row is None:
        raise errors.not_found("That removal case does not exist")
    status = row["status"]
    if status in ("queued", "running"):
        raise errors.conflict(
            "already_active",
            "That removal case is already queued or running — it "
            "does not need a replay")
    if status != "failed":
        raise errors.conflict(
            "not_dead_letter",
            "Only a failed removal case can be replayed — this "
            "one is %s" % status)
    owner_id = str(row["user_id"])
    if not _purpose_granted(owner_id, "automated_remediation"):
        raise errors.forbidden(
            "consent_required",
            "The owner's Automatic removal permission is off — a "
            "dead case is never resurrected without it")
    # The one-live-case rule (the partial unique index over
    # (user_id, broker_slug)): a newer live case already covers
    # this broker, so resurrecting the dead one would collide —
    # refused with the same code the owner's own retry uses.
    with db_pool.connection() as conn:
        sibling = conn.execute(
            "SELECT 1 AS x FROM remediation_cases"
            " WHERE user_id = %s AND broker_slug = %s"
            " AND status NOT IN ('verified_removed', 'failed')"
            " LIMIT 1",
            (owner_id, row["broker_slug"]),
        ).fetchone()
    if sibling is not None:
        raise errors.conflict(
            "not_retryable", "A newer case already covers this broker")
    # Attempt-history semantics: a case has no counter to reset —
    # its attempts are append-only rows in remediation_attempts,
    # and they are left exactly as they stand; the worker's next
    # run appends after them (attempt_no = MAX + 1), so the record
    # of why the case died remains part of its trail. The reason
    # the case died is also carried in the audit row below before
    # the live row's reason is cleared for the fresh run.
    with db_pool.connection() as conn:
        updated = conn.execute(
            "UPDATE remediation_cases SET status = 'queued',"
            " reason = NULL, updated_at = now()"
            " WHERE id = %s AND status = 'failed' RETURNING id",
            (case_id,),
        ).fetchone()
    if updated is None:  # raced with another replay
        raise errors.conflict(
            "already_active",
            "That removal case is already queued or running — it "
            "does not need a replay")
    audit.record(admin_user_id, "admin", "admin.dead_letter_replayed",
                 "remediation_case", case_id,
                 {"prior_status": "failed",
                  "prior_reason": row["reason"],
                  "broker": row["broker_slug"]})
    return {"kind": "remediation_case", "id": case_id,
            "status": "queued"}
