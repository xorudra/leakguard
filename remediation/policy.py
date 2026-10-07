"""Removal policy engine (spec Phase 153) + the Phase 141 state
mapping.

Before this module, the removal POLICY — the deterministic table
that decides what a case does next — existed only as control flow
inside remediation/engine.py: probe interpretation, the consent
re-check, channel routing and submit outcomes were interleaved
with the IO that executes them. This module extracts that table,
unchanged, into pure functions over plain data:

    decide_*(facts) -> decision dict

A decision dict is::

    {"status": <next case status>, "reason": <reason or None>,
     "attempt": (attempt_action, attempt_result) or None,
     "mark_submitted": <stamp submitted_at on the transition>}

The engine keeps every side effect (database writes, probe and
submit calls, letter rendering) and applies the decision it is
handed; the attempt row's DETAIL payload (probe diagnostics, the
letter body, the submit's HTTP status) is evidence produced by
that IO and is attached by the engine, never by the policy.

POLICY_VERSION versions this table. Any change to a decision
below — a new branch, a changed reason, a different next state —
must move it, so a case's behaviour can always be attributed to
exactly one published version of the policy.

Purity contract: this module imports nothing outside the standard
library, reads no environment, and touches no database. The one
input that looks like configuration — the ordered profile-field
patterns used to name a missing form field — is passed in by the
caller (the engine passes agent.PROFILE_FIELDS), so the policy
stays testable as plain data in / plain data out.

The Phase 141 state mapping lives here too, next to the decisions
that produce the states: SPEC_STATE_NAMES is the formal mapping
from the product's internal case states to the spec-facing names
published in docs/REMOVAL_STATES.md. POLICY_VERSION covers the
mapping as well — renaming a spec-facing name is a policy change.
"""

import re

POLICY_VERSION = 1

# The internal case states, in the order the CHECK in migration
# 0005_remediation.sql declares them (that CHECK is the
# storage-level source of truth; this tuple exists so tests can
# assert the mapping below covers the stored vocabulary exactly).
CASE_STATES = ("queued", "running", "submitted", "needs_human",
               "verified_removed", "reappeared", "failed", "blocked")

# Phase 141 — the formal mapping, internal -> spec-facing.
#
# Two of the spec's names differ from the internal ones and are
# mapped explicitly: needs_human is AWAITING_USER (the case is
# parked on a step only the user can take) and blocked is REJECTED
# (the broker's side refused or could not be reached, so the
# request could not be carried through). The remaining states keep
# their internal word in the spec's UPPER_SNAKE style — the mapping
# still names them, so the translation is total and tested rather
# than implied.
SPEC_STATE_NAMES = {
    "queued": "QUEUED",
    "running": "IN_PROGRESS",
    "submitted": "SUBMITTED",
    "needs_human": "AWAITING_USER",
    "blocked": "REJECTED",
    "verified_removed": "VERIFIED_REMOVED",
    "reappeared": "REAPPEARED",
    "failed": "FAILED",
}

# Spec-facing names with NO internal state. The spec's lifecycle
# opens with AUTHORIZED and NOT_STARTED; this product expresses
# both as consent-gated case creation instead of states: a case
# exists only after the owner has granted the
# 'automated_remediation' consent (run_removal refuses without it),
# so "not started" and "not yet authorized" are the absence of a
# case, never a stored row. Declaring them here — instead of
# inventing states no transition produces — keeps the mapping
# honest in both directions.
SPEC_STATES_WITHOUT_INTERNAL_STATE = {
    "AUTHORIZED": (
        "Expressed by the 'automated_remediation' consent that "
        "gates case creation: no case is created for an owner who "
        "has not authorized removal, and the worker re-checks the "
        "consent before acting (see decide_consent)."),
    "NOT_STARTED": (
        "The same consent gate from the other side: a broker with "
        "no case yet has simply not been started — cases spring "
        "into existence already queued once consent is granted, "
        "so there is no stored pre-start state."),
}


def spec_state_name(internal_status):
    """The spec-facing name for an internal case status, or None
    for a value outside the stored vocabulary."""
    return SPEC_STATE_NAMES.get(internal_status)


# ---------------------------------------------------------------------------
# Channel derivation (moved from remediation/registry_seed.py, which
# now delegates here; the seed calls this once per broker at seed time)
# ---------------------------------------------------------------------------

def derive_channel(broker, playbook):
    """How a broker is worked: a direct contact address always wins
    (email); otherwise a fillable HTTP opt-out form (form); whatever
    is left needs the user's own browser (manual)."""
    if broker.get("contact_email"):
        return "email"
    if playbook and playbook.get("automation") == "http_form":
        return "form"
    return "manual"


# ---------------------------------------------------------------------------
# Entry decisions — evaluated in this exact order by the engine:
# unknown broker first, then the consent re-check, then the channel.
# ---------------------------------------------------------------------------

def decide_unknown_broker():
    """The case names a broker the registry no longer knows: the
    case fails closed and says why."""
    return {"status": "failed", "reason": "unknown_broker",
            "attempt": ("route", "failed"), "mark_submitted": False}


def decide_consent(consented):
    """The consent re-check, run before any external action: a
    withdrawn 'automated_remediation' consent parks the case for
    the human — it is never silently dropped, and the withdrawal
    itself is the recorded attempt. Returns None when consent
    stands and the case may proceed."""
    if consented:
        return None
    return {"status": "needs_human", "reason": "consent_withdrawn",
            "attempt": ("consent_check", "withdrawn"),
            "mark_submitted": False}


def decide_email(letter_on_file):
    """Email channel: brokers only accept requests from the data
    subject's own mailbox, so the engine renders a ready-to-send
    letter and parks the case. When the case comes back to the
    queue with a generated letter already on file, that return IS
    the user's 'I sent it' — the case is recorded submitted, by
    the user's own hand.

    Ambiguity preserved from the engine's original control flow:
    the decision keys only on a letter attempt existing, so ANY
    re-queue of an email case with a letter on file is treated as
    the user's attestation, whoever re-queued it."""
    if letter_on_file:
        return {"status": "submitted",
                "reason": "letter_sent_by_user",
                "attempt": ("letter_confirmed", "submitted"),
                "mark_submitted": True}
    return {"status": "needs_human", "reason": "email_send_required",
            "attempt": ("letter", "generated"),
            "mark_submitted": False}


def decide_manual(playbook_automation):
    """Manual channel: the case always parks for the user; the
    reason distinguishes a broker whose playbook is known to need
    a real browser from one that is manual for any other reason.
    A missing/unknown automation value is manual_only."""
    reason = ("browser_required"
              if playbook_automation == "browser_required"
              else "manual_only")
    return {"status": "needs_human", "reason": reason,
            "attempt": ("route", "manual"), "mark_submitted": False}


# ---------------------------------------------------------------------------
# Form channel — probe interpretation and the submit outcome.
# ---------------------------------------------------------------------------

def missing_field(probe, profile, field_patterns):
    """The first profile field (in field_patterns order) that some
    form field maps to but the profile has no value for — or None.

    field_patterns is the ordered mapping of profile key ->
    [regex, …] the caller owns (the engine passes
    agent.PROFILE_FIELDS, so the field vocabulary stays with the
    probe implementation); an iterable of (key, patterns) pairs
    is accepted too.

    Preserved quirk: only the mapped `fields` entries are scanned
    (name / id / placeholder) — a form's `unmapped_fields` list
    plays no part, exactly as in the engine's original helper."""
    pairs = (field_patterns.items() if hasattr(field_patterns, "items")
             else field_patterns)
    for semantic, patterns in pairs:
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


def decide_probe(probe, profile, field_patterns):
    """Interpret a probe result into (action, reason) — action is
    'submit', 'needs_human' or 'blocked'. Pure port of the engine's
    original interpret_probe; the branch ORDER is part of the
    policy: a probe-level error beats every page signal, and
    CAPTCHA / login walls beat reachability and fillability — a
    wall is a human step, never routed around (their evidence→
    verdict classification was pinned separately by Phase 137)."""
    if not isinstance(probe, dict) or probe.get("error"):
        return "blocked", "probe_error"
    blockers = probe.get("blockers") or []
    if any("CAPTCHA" in b for b in blockers):
        return "needs_human", "captcha"
    if any("account login" in b for b in blockers):
        return "needs_human", "login_required"
    if not probe.get("reachable"):
        status = probe.get("status")
        return "blocked", ("http_%s" % status) if status else "unreachable"
    if probe.get("fillable"):
        return "submit", None
    if not probe.get("forms"):
        return "needs_human", "browser_required"
    missing = missing_field(probe, profile, field_patterns)
    if missing:
        return "needs_human", "missing_field:%s" % missing
    return "blocked", "form_not_fillable"


def probe_attempt_word(action, reason):
    """The result word recorded on the probe attempt row: what the
    probe found, in the vocabulary the attempt trail has always
    used (fillable / the human step's kind / blocked)."""
    if action == "submit":
        return "fillable"
    if action == "needs_human":
        return reason.split(":")[0]
    return "blocked"


def decide_probe_transition(action, reason):
    """A probe outcome that ends the run without a submission:
    the case takes the action as its status (needs_human parks
    for the user; blocked records the broker-side refusal). No
    attempt accompanies the transition — the probe attempt
    already recorded above is the trail."""
    return {"status": action, "reason": reason, "attempt": None,
            "mark_submitted": False}


def decide_submit(submit_result):
    """The submit outcome. `ok` is judged FIRST (ambiguity
    preserved: a result that is both ok and HTTP 403 counts as
    submitted, exactly as the engine's original branch order had
    it); a bare 403 is a broker-side block; every other failure —
    including a host-guard refusal, whose result carries no HTTP
    status — fails the case with submit_failed."""
    if submit_result.get("ok"):
        return {"status": "submitted", "reason": None,
                "attempt": ("submit", "submitted"),
                "mark_submitted": True}
    if submit_result.get("status") == 403:
        return {"status": "blocked", "reason": "submit_http_403",
                "attempt": ("submit", "blocked"),
                "mark_submitted": False}
    return {"status": "failed", "reason": "submit_failed",
            "attempt": ("submit", "failed"), "mark_submitted": False}
