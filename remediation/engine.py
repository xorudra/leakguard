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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import agent as agent_engine
from accounts import consents as consents_service
from core import ssrf
from db import pool
from providers.ddg_discovery import parse_results as _ddg_parse_results
from remediation import letters, registry_seed, verify_sources
from vault import store as vault_store


# ---------------------------------------------------------------------------
# Verification fetching (verify_search's one network path)
# ---------------------------------------------------------------------------

_VERIFY_TIMEOUT = 15  # seconds, per verification fetch
_VERIFY_MAX_BYTES = 512 * 1024
_DDG_HTML_ENDPOINT = "https://html.duckduckgo.com/html/?q="

# DuckDuckGo's bot-challenge page (observed live: "Unfortunately,
# bots use DuckDuckGo too... Please complete the following
# challenge") must never be mistaken for a results page — a
# challenge says nothing about the listing either way.
_DDG_CHALLENGE_MARKERS = (
    "bots use duckduckgo",
    "complete the following challenge",
    "assets/anomaly",
)

# Markup that proves a DuckDuckGo page really is a results page:
# result anchors/snippets (the S6 parser's classes), the results
# container, or DDG's own zero-hit wording. A genuine zero-hit page
# carries the last of these and no anchors at all.
_DDG_RESULTS_CHROME = (
    "result__a",
    "result__snippet",
    'class="links"',
)


def _default_fetcher(url):
    """GET `url` -> (status, text); status is None on transport
    failure. Never raises: verification treats every surprise as
    'unknown', so the fetch layer encodes surprises in the result
    instead of throwing them."""
    req = urllib.request.Request(url, headers=agent_engine.UA)
    try:
        with urllib.request.urlopen(req, timeout=_VERIFY_TIMEOUT) as resp:
            body = resp.read(_VERIFY_MAX_BYTES)
            return resp.status, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(_VERIFY_MAX_BYTES)
            return exc.code, body.decode("utf-8", "replace")
        except Exception:
            return exc.code, ""
    except Exception:
        return None, ""


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


def _probe_inconclusive(result):
    """True when a fast (HTTP) probe result cannot settle the case
    AND the relay reader might still see something the fast probe
    could not. That is exactly the no-usable-page cases: a transport
    failure (nothing arrived) or an HTTP error page (403/404/5xx —
    the relay can sometimes un-wall those or fetch through a moved
    page).

    A fast probe that GOT a page (HTTP 200, reachable) is conclusive
    even with no form on it: the page is JS-driven / manual-only, the
    relay reader fetches the same markup, and escalating only burns
    ~a minute of relay retries for no new signal (Stage 7.2 gate —
    the dominant live case: most brokers answer 200 with a JS page).
    Such pages classify immediately through the unchanged
    interpret_probe transitions. CAPTCHA and login blockers are
    definitive too — human steps at every layer, never routed
    around — as are a found form (interpret_probe can judge it) and
    a fillable form."""
    blockers = result.get("blockers") or []
    if any("CAPTCHA" in b for b in blockers):
        return False
    if any("account login" in b for b in blockers):
        return False
    if result.get("fillable"):
        return False
    if result.get("forms"):
        return False
    if result.get("reachable"):
        return False
    return True


def _relay_skip_reason(result):
    """Why a conclusive fast probe skipped the relay escalation, for
    the probe trail — or None when no skip needs recording. Only the
    Stage 7.2 gate case is recorded: a page WAS received (HTTP 200)
    but carried no form and no definitive blocker, so the relay would
    have fetched the same JS-driven page. The other conclusive cases
    (fillable, form found, CAPTCHA, login) settle the case on their
    own evidence and keep the trail as it was."""
    if not result.get("reachable"):
        return None
    if result.get("fillable") or result.get("forms"):
        return None
    blockers = result.get("blockers") or []
    if any("CAPTCHA" in b for b in blockers):
        return None
    if any("account login" in b for b in blockers):
        return None
    return "page_received"


class AgentExecutor(Executor):
    """Production executor over agent.py (the anonymous engine).

    Probe strategy (Stage 7.1 — speed; Stage 7.2 — gate): the
    anonymous engine's full chain (agent.probe_with_browser_fallback)
    always paid for the relay layer plus a browser step that cannot
    run on the server at all, so a walled broker burned ~2 minutes of
    relay retries per case. Remediation probes are staged instead:

    1. fast probe (agent.probe_broker) — one HTTP fetch;
    2. ONE relay-reader escalation, only when the fast probe got NO
       usable page (transport failure or HTTP error page — see
       _probe_inconclusive), merged with exactly the rules of the
       fallback chain's layer 2 — but WITHOUT the browser step
       (Playwright cannot run on Render; attempting it per case
       wastes time and the skip is recorded in the trail). A fast
       probe that received a page is conclusive even without a form
       (Stage 7.2): the gate decision is recorded in the trail as
       relay skipped / page_received;
    3. a per-case SOFT budget (default ~40s of probing): if the
       relay outruns the remaining budget it is abandoned and the
       best evidence so far is classified by the unchanged
       interpret_probe — a 403 seen at any point still lands
       blocked/http_403, persistent unreachability still lands
       blocked/unreachable.

    Every step appends to probe["probe_trail"], which process_case
    copies into the probe attempt's detail: the audit trail shows
    exactly what was tried. Statuses and reasons are unchanged —
    only the route to the probe result got faster."""

    def __init__(self, probe_budget_seconds=40.0, fetcher=None):
        self.probe_budget_seconds = float(probe_budget_seconds)
        # Verification's network path — injectable so tests stub it
        # exactly like they stub agent functions. Signature:
        # fetcher(url) -> (status, text); see _default_fetcher.
        self._fetcher = fetcher if fetcher is not None else _default_fetcher

    def probe(self, profile, broker):
        started = time.monotonic()
        result = agent_engine.probe_broker(broker["name"], profile)
        if not isinstance(result, dict) or result.get("error"):
            return result
        result.setdefault("via", "http")
        trail = [{
            "step": "http",
            "status": result.get("status"),
            "reachable": bool(result.get("reachable")),
            "ms": int((time.monotonic() - started) * 1000),
        }]
        result["probe_trail"] = trail
        if not _probe_inconclusive(result):
            skip = _relay_skip_reason(result)
            if skip:
                # The audit trail must explain why no relay was
                # tried for a formless page (Stage 7.2 gate).
                trail.append({"step": "relay", "skipped": skip})
            return result
        remaining = self.probe_budget_seconds - (time.monotonic() - started)
        if remaining <= 0:
            trail.append({"step": "relay", "skipped": "probe_budget"})
        else:
            relay, timed_out = self._relay_attempt(
                result["url"], profile, remaining)
            if timed_out:
                trail.append({
                    "step": "relay", "outcome": "budget_exceeded",
                    "ms": int((time.monotonic() - started) * 1000)})
            elif relay is None:
                trail.append({"step": "relay", "outcome": "error"})
            else:
                trail.append({
                    "step": "relay",
                    "status": relay.get("status"),
                    "reachable": bool(relay.get("reachable")),
                    "challenge": bool(relay.get("challenge")),
                    "forms": len(relay.get("forms") or []),
                    "ms": int((time.monotonic() - started) * 1000),
                })
                self._merge_relay(result, relay)
        trail.append({"step": "browser", "skipped": "on_server"})
        return result

    @staticmethod
    def _relay_attempt(url, profile, timeout):
        """Run agent.relay_probe in a daemon thread, waiting at most
        `timeout` seconds. The relay's own retry loop (3 x 45s plus
        backoff) far exceeds the per-case budget, so a hung relay is
        abandoned — its thread is a daemon and its late result is
        discarded. Returns (relay_dict_or_None, timed_out)."""
        box = {}

        def _run():
            try:
                box["relay"] = agent_engine.relay_probe(url, profile)
            except Exception:
                box["relay"] = None

        thread = threading.Thread(target=_run, name="leakguard-relay-probe",
                                  daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            return None, True
        return box.get("relay"), False

    @staticmethod
    def _merge_relay(result, relay):
        """Merge a relay result into the fast-probe result with the
        same rules as layer 2 of agent.probe_with_browser_fallback."""
        result["relay"] = {"reachable": relay["reachable"],
                           "challenge": relay["challenge"],
                           "status": relay["status"],
                           "title": relay.get("title", "")}
        if relay["reachable"] and relay["forms"]:
            result["via"] = "http+relay"
            result["reachable"] = True
            result["status"] = result.get("status") or relay["status"]
            result["forms"] = relay["forms"]
            if relay["payload_preview"]:
                result["payload_preview"] = relay["payload_preview"]
            result["blockers"] = relay["blockers"]
            result["fillable"] = (bool(result["payload_preview"])
                                  and not relay["challenge"])
        else:
            result["blockers"] = list(dict.fromkeys(
                result.get("blockers", []) + relay["blockers"]))

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

    def _fetch(self, url):
        """The injectable verification fetch, armoured: a stub or a
        network surprise can never make verification raise."""
        try:
            status, text = self._fetcher(url)
        except Exception:
            return None, ""
        if status is not None and not isinstance(status, int):
            status = None
        return status, text if isinstance(text, str) else ""

    def verify_search(self, profile, broker):
        """Search-presence check (spec Phase 38), driven by the
        verification source map (verify_sources.json):

        * method 'search_index' — the broker's site is walled, but
          its listings are indexed: query DuckDuckGo for
          site:<domain> "<name>" and read the result hosts. A
          broker-domain result is still_present; a demonstrably
          loaded results page with none is gone.
        * method 'direct' — the broker's own search is
          server-rendered and name-addressable: fetch the templated
          URL and read the page (404 or an empty-search phrase is
          gone; the name on the page is still_present).
        * method 'none' / unmapped — B2B and credit brokers publish
          no public listing: unverifiable by design, answered
          'unknown'. Presence is never guessed, and every
          ambiguous page (wall, challenge, error, empty shell) is
          'unknown' too.

        The result carries 'method' ('search_index' |
        'broker_search' | 'none' | 'unconfigured') so the check
        row records HOW the verdict was reached."""
        cfg = verify_sources.config_for(broker)
        if cfg is None:
            return {"outcome": "unknown", "evidence_ref": None,
                    "method": "unconfigured"}
        method = cfg.get("method")
        if method == "search_index":
            result_method = "search_index"
        elif method == "direct":
            result_method = "broker_search"
        else:
            return {"outcome": "unknown", "evidence_ref": None,
                    "method": "none"}
        name = (profile.get("full_name") or "").strip()
        if not name:
            return {"outcome": "unknown", "evidence_ref": None,
                    "method": result_method}
        if method == "search_index":
            return self._verify_via_index(profile, cfg, name)
        return self._verify_direct(profile, cfg, name)

    def _verify_via_index(self, profile, cfg, name):
        """Evidence = the index of the broker's public pages. The
        query URL is the evidence_ref: it is exactly what was
        asked, reproducible by anyone."""
        domain = (cfg.get("domain") or "").strip().lower()
        query = 'site:%s "%s"' % (domain, name)
        city = (profile.get("city") or "").strip()
        if city:
            query += " " + city
        url = _DDG_HTML_ENDPOINT + urllib.parse.quote_plus(query)
        unknown = {"outcome": "unknown", "evidence_ref": url,
                   "method": "search_index"}
        status, html = self._fetch(url)
        if status != 200 or not html:
            return unknown
        folded = html.casefold()
        if any(marker in folded for marker in _DDG_CHALLENGE_MARKERS):
            return unknown  # a bot wall, not a results page
        for result in _ddg_parse_results(html):
            host = (result.get("domain") or "").lower()
            if host == domain or host.endswith("." + domain):
                return {"outcome": "still_present",
                        "evidence_ref": url, "method": "search_index"}
        has_chrome = (
            any(marker in html for marker in _DDG_RESULTS_CHROME)
            or "no results found" in folded
        )
        if has_chrome:
            # A real results page, and the broker's domain is not
            # in it: as far as the public index shows, the listing
            # is gone (indexes lag — the check records when and
            # how this was determined).
            return {"outcome": "gone", "evidence_ref": url,
                    "method": "search_index"}
        return unknown

    def _verify_direct(self, profile, cfg, name):
        """Evidence = the broker's own search page for this name."""
        tokens = name.split()
        first = tokens[0]
        last = tokens[-1] if len(tokens) > 1 else ""
        city = (profile.get("city") or "").strip()
        url = cfg.get("url") or ""
        for placeholder, value in (("{name}", name), ("{first}", first),
                                   ("{last}", last), ("{city}", city)):
            url = url.replace(
                placeholder, urllib.parse.quote(value, safe=""))
        result = {"evidence_ref": url, "method": "broker_search"}
        # The template comes from verify_sources.json (data): the
        # built URL must pass the SSRF DNS guard before this server
        # fetches it (Phase 70). A refusal is ambiguity, not
        # evidence — the verdict is 'unknown', never a guess.
        try:
            ssrf.assert_public_url(url)
        except ssrf.SsrfError:
            return dict(result, outcome="unknown")
        status, html = self._fetch(url)
        if status == 404:
            return dict(result, outcome="gone")
        if status != 200 or not html:
            return dict(result, outcome="unknown")
        folded = html.casefold()
        for marker in cfg.get("no_results") or []:
            if marker and str(marker).casefold() in folded:
                return dict(result, outcome="gone")
        if name.casefold() in folded:
            return dict(result, outcome="still_present")
        return dict(result, outcome="unknown")


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
    if isinstance(probe, dict) and probe.get("probe_trail"):
        # The executor's step-by-step trail (Stage 7.1): which probe
        # layers ran, which were skipped, and what each concluded —
        # part of the audit record for the probe action.
        probe_detail["trail"] = probe["probe_trail"]
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
