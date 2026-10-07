"""Remediation engine (spec Phases 33, 35, 36, 167).

Executor-injected design: the case processor talks only to an
Executor (probe / submit / verify_search). Production uses
AgentExecutor, which wraps the anonymous agent's machinery
(agent.py: the HTTP → relay → browser probe chain and the guarded
form submit). Tests inject stubs, so the full transition matrix is
exercised offline with zero network.

Transition rules (each one writes a remediation_attempts row):
* consent re-checked at execution time — withdrawn mid-queue means
  needs_human/consent_withdrawn and NO probe, NO submit, nothing.
* email channel: the erasure letter is generated and the case parks
  at needs_human/email_send_required (the user sends it from their
  own mailbox). If the case comes back queued with a letter already
  on file, the user has told us they sent it (the queue's retry is
  the "I sent it" action) → submitted/letter_sent_by_user.
* manual channel: needs_human (browser_required / manual_only).
* form channel: probe decides —
    CAPTCHA blocker        -> needs_human/captcha        (never bypassed)
    login blocker          -> needs_human/login_required (never bypassed)
    unreachable / HTTP wall-> blocked (http_<status> / unreachable)
    fillable               -> submit: 2xx -> submitted (+ submitted_at)
                                   403 -> blocked/submit_http_403
                                   else -> failed/submit_failed
    no HTML form           -> needs_human/browser_required
    form needs a profile field the user has not saved
                           -> needs_human/missing_field:<field>
    form present but nothing maps -> blocked/form_not_fillable

Profiles are assembled from the vault per run and live only in
memory; nothing here logs identifier values.
"""

import re
import urllib.error
import urllib.parse
import urllib.request

import agent as agent_engine
from accounts import consents as consents_service
from db import pool
from remediation import letters, registry_seed
from vault import store as vault_store


# ---------------------------------------------------------------------------
# Executor protocol + production executor
# ---------------------------------------------------------------------------

class Executor:
    """The engine's view of the outside world. Implementations must
    return plain dicts and must never raise for ordinary broker
    behaviour (walls, downtime) — encode it in the result instead."""

    def probe(self, profile, broker):  # pragma: no cover - protocol
        raise NotImplementedError

    def submit(self, profile, broker, probe):  # pragma: no cover
        raise NotImplementedError

    def verify_search(self, profile, broker):  # pragma: no cover
        raise NotImplementedError


class AgentExecutor(Executor):
    """Production executor over agent.py (the anonymous engine)."""

    def probe(self, profile, broker):
        return agent_engine.probe_with_browser_fallback(
            broker["name"], profile)

    def submit(self, profile, broker, probe):
        # Same SSRF guard as POST /api/agent/submit: the form action
        # must live on a known broker host.
        allowed = {
            urllib.parse.urlparse(b["optout_url"]).netloc.lower()
            for b in agent_engine.load_brokers()
        }
        for form in (probe or {}).get("forms") or []:
            payload, _unmapped = agent_engine.match_fields(
                form.get("fields") or [], profile)
            if not payload:
                continue
            action = form.get("action") or broker["optout_url"]
            host = urllib.parse.urlparse(action).netloc.lower()
            if host not in allowed:
                return {"ok": False, "status": None, "error": "host_guard"}
            return agent_engine.submit_form(
                action, form.get("method") or "POST", payload)
        return {"ok": False, "status": None, "error": "no_fillable_form"}

    def verify_search(self, profile, broker):
        """Search-presence check (spec Phase 38): when the broker's
        playbook/registry row defines a search_url, fetch it with the
        agent's machinery and look for the user's name on the page —
        found: still_present; page loads without it (or 404): gone;
        anything else: unknown. With no search_url defined the honest
        answer is 'unknown' — presence is never guessed."""
        search_url = broker.get("search_url")
        if not search_url:
            playbook = agent_engine.get_playbook(
                registry_seed._public_file_shape(broker))
            search_url = playbook.get("search_url")
        if not search_url:
            return {"outcome": "unknown", "evidence_ref": None}
        name = (profile.get("full_name") or "").strip()
        if not name:
            return {"outcome": "unknown", "evidence_ref": search_url}
        req = urllib.request.Request(search_url, headers=agent_engine.UA)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read(512 * 1024).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {"outcome": "gone", "evidence_ref": search_url}
            return {"outcome": "unknown", "evidence_ref": search_url}
        except Exception:
            return {"outcome": "unknown", "evidence_ref": search_url}
        found = name.casefold() in html.casefold()
        return {"outcome": "still_present" if found else "gone",
                "evidence_ref": search_url}


# ---------------------------------------------------------------------------
# Profile assembly (vault -> agent profile), in memory only
# ---------------------------------------------------------------------------

def assemble_profile(user_id):
    """The agent profile {full_name, email, phone, city} for a user,
    resolved from their vault identifiers. city is the first segment
    of the address identifier (before the first comma) — the field
    broker forms actually ask for; '' when no address is saved."""
    profile = {"full_name": "", "email": "", "phone": "", "city": ""}
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT id, kind FROM identifiers"
            " WHERE user_id = %s AND deleted_at IS NULL"
            " ORDER BY created_at, id",
            (user_id,),
        ).fetchall()
    for row in rows:
        value = vault_store.reveal_by_id(str(row["id"]), user_id=user_id)
        if not value:
            continue
        kind = row["kind"]
        if kind == "name" and not profile["full_name"]:
            profile["full_name"] = value
        elif kind == "email" and not profile["email"]:
            profile["email"] = value
        elif kind == "phone" and not profile["phone"]:
            profile["phone"] = value
        elif kind == "address" and not profile["city"]:
            profile["city"] = value.split(",")[0].strip()
    return profile


# ---------------------------------------------------------------------------
# Probe interpretation (pure — unit-tested directly)
# ---------------------------------------------------------------------------

def _missing_field(probe, profile):
    """First profile field (in agent.PROFILE_FIELDS order) that some
    form field maps to but the profile has no value for — or None."""
    for semantic, patterns in agent_engine.PROFILE_FIELDS.items():
        if profile.get(semantic):
            continue
        for form in probe.get("forms") or []:
            for field in form.get("fields") or []:
                hay = " ".join([
                    field.get("name", ""), field.get("id", ""),
                    field.get("placeholder", "")]).lower()
                if any(re.search(p, hay) for p in patterns):
                    return semantic
    return None


def interpret_probe(probe, profile):
    """Map a probe result onto (action, reason). Actions:
    'submit', 'needs_human', 'blocked'. See the module docstring for
    the full table. CAPTCHA and login are checked first, on every
    layer's blockers — they are never routed around."""
    if not isinstance(probe, dict) or probe.get("error"):
        return ("blocked", "probe_error")
    blockers = probe.get("blockers") or []
    if any("CAPTCHA" in b for b in blockers):
        return ("needs_human", "captcha")
    if any("account login" in b for b in blockers):
        return ("needs_human", "login_required")
    if not probe.get("reachable"):
        status = probe.get("status")
        return ("blocked", "http_%s" % status if status else "unreachable")
    if probe.get("fillable"):
        return ("submit", None)
    if not probe.get("forms"):
        return ("needs_human", "browser_required")
    missing = _missing_field(probe, profile)
    if missing:
        return ("needs_human", "missing_field:" + missing)
    return ("blocked", "form_not_fillable")


# ---------------------------------------------------------------------------
# Case storage helpers
# ---------------------------------------------------------------------------

_CASE_COLUMNS = ("id, user_id, broker_slug, finding_id, status, reason,"
                 " created_at, updated_at, submitted_at")


def load_case(case_id):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT " + _CASE_COLUMNS + " FROM remediation_cases"
            " WHERE id = %s",
            (case_id,),
        ).fetchone()
    if row is None:
        return None
    out = dict(row)
    out["id"] = str(out["id"])
    out["user_id"] = str(out["user_id"])
    out["finding_id"] = str(out["finding_id"]) if out.get("finding_id") else None
    return out


def _insert_attempt(conn, case_id, action, result, detail):
    row = conn.execute(
        "SELECT COALESCE(MAX(attempt_no), 0) AS n"
        " FROM remediation_attempts WHERE case_id = %s",
        (case_id,),
    ).fetchone()
    import json as _json

    conn.execute(
        "INSERT INTO remediation_attempts"
        " (case_id, attempt_no, action, result, detail)"
        " VALUES (%s, %s, %s, %s, %s)",
        (case_id, int(row["n"]) + 1, action, result,
         _json.dumps(detail or {})),
    )


def _transition(case_id, status, reason, action=None, result=None,
                detail=None, submitted=False):
    """Move a case, atomically logging the attempt that caused the
    move when (action, result, detail) are given."""
    with pool.connection() as conn:
        if submitted:
            conn.execute(
                "UPDATE remediation_cases SET status = %s, reason = %s,"
                " submitted_at = now(), updated_at = now() WHERE id = %s",
                (status, reason, case_id),
            )
        else:
            conn.execute(
                "UPDATE remediation_cases SET status = %s, reason = %s,"
                " updated_at = now() WHERE id = %s",
                (status, reason, case_id),
            )
        if action is not None:
            _insert_attempt(conn, case_id, action, result, detail)


def _record_attempt(case_id, action, result, detail):
    """Append one attempt row without moving the case (an action
    whose outcome is recorded before the transition it feeds)."""
    with pool.connection() as conn:
        _insert_attempt(conn, case_id, action, result, detail)


def _has_attempt(case_id, action, result=None):
    with pool.connection() as conn:
        if result is None:
            row = conn.execute(
                "SELECT 1 AS x FROM remediation_attempts"
                " WHERE case_id = %s AND action = %s LIMIT 1",
                (case_id, action),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT 1 AS x FROM remediation_attempts"
                " WHERE case_id = %s AND action = %s AND result = %s"
                " LIMIT 1",
                (case_id, action, result),
            ).fetchone()
    return row is not None


def remediation_consented(user_id):
    for entry in consents_service.current_consents(user_id):
        if entry["purpose"] == "automated_remediation":
            return bool(entry["granted"])
    return False


# ---------------------------------------------------------------------------
# The case processor (worker entry point)
# ---------------------------------------------------------------------------

def process_case(case_id, executor=None):
    """Drive one queued/running case to its next state. Returns the
    refreshed case dict (or None when the case vanished). Raises only
    for infrastructure failures — the worker owns those."""
    executor = executor if executor is not None else AgentExecutor()
    case = load_case(case_id)
    if case is None or case["status"] not in ("queued", "running"):
        return case
    broker = registry_seed.get_broker(case["broker_slug"])
    if broker is None:
        _transition(case_id, "failed", "unknown_broker",
                    "route", "failed", {})
        return load_case(case_id)

    # Consent is re-checked at execution time, before ANY external
    # action: a withdrawal mid-queue stops the case cold.
    if not remediation_consented(case["user_id"]):
        _transition(case_id, "needs_human", "consent_withdrawn",
                    "consent_check", "withdrawn", {})
        return load_case(case_id)

    profile = assemble_profile(case["user_id"])
    channel = broker["channel"]

    if channel == "email":
        if _has_attempt(case_id, "letter", "generated"):
            # The case only returns to the queue via the user's
            # "I sent it" retry — their attestation is the submission.
            _transition(case_id, "submitted", "letter_sent_by_user",
                        "letter_confirmed", "submitted", {}, submitted=True)
        else:
            letter = letters.letter_for_broker(broker, profile)
            _transition(case_id, "needs_human", "email_send_required",
                        "letter", "generated", letter)
        return load_case(case_id)

    if channel == "manual":
        playbook = agent_engine.get_playbook(
            registry_seed._public_file_shape(broker))
        reason = ("browser_required"
                  if playbook.get("automation") == "browser_required"
                  else "manual_only")
        _transition(case_id, "needs_human", reason, "route", "manual", {})
        return load_case(case_id)

    # form channel: probe first — the probe is an auditable action
    # in its own right, whatever it leads to.
    probe = executor.probe(profile, broker)
    action, reason = interpret_probe(probe, profile)
    probe_detail = {"status": probe.get("status") if isinstance(probe, dict)
                    else None,
                    "via": probe.get("via") if isinstance(probe, dict)
                    else None}
    if action == "submit":
        probe_word = "fillable"
    elif action == "needs_human":
        probe_word = reason.split(":")[0]
    else:
        probe_word = "blocked"
    _record_attempt(case_id, "probe", probe_word, probe_detail)
    if action == "submit":
        result = executor.submit(profile, broker, probe)
        if result.get("ok"):
            _transition(case_id, "submitted", None,
                        "submit", "submitted",
                        {"http_status": result.get("status")},
                        submitted=True)
        elif result.get("status") == 403:
            _transition(case_id, "blocked", "submit_http_403",
                        "submit", "blocked", {"http_status": 403})
        else:
            _transition(case_id, "failed", "submit_failed",
                        "submit", "failed",
                        {"http_status": result.get("status")})
    elif action == "needs_human":
        _transition(case_id, "needs_human", reason)
    else:  # blocked
        _transition(case_id, "blocked", reason)
    return load_case(case_id)
