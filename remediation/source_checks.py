"""Broker source change detection (spec Phases 32, 125-lite).

Once a day, LeakGuard re-fetches every broker's opt-out page from
brokers.json and compares a SHA-256 of the body (capped at 64KB)
with the last sweep's hash, in broker_source_checks (migration
0010). A broker whose page changed gets flagged 'changed' in the
admin overview — the signal that its playbook may need a human
re-check. A broker that cannot be fetched at all is 'unreachable'
(its previous hash is kept, so recovery still compares against the
last page actually seen). Only the hash is stored, never the page.

Rules:
* At most one sweep per 24h — the checks table is its own stamp:
  a sweep is due unless EVERY registry broker carries a row
  younger than 24h. The gate reads the OLDEST row (audit
  2026-10-16, remediation.source-sweep-partial-run-poisons-24h-
  gate): the old max(checked_at) reading let one fast broker's
  fresh stamp certify a sweep that had died before reaching the
  other 39, leaving their change detection dark for a day.
* Every fetch has a per-broker total deadline and the sweep an
  aggregate budget (audit 2026-10-16,
  remediation.source-sweep-no-total-deadline): slow or hanging
  pages cannot stretch the daily pass without bound; brokers
  past the budget are recorded as skipped in the summary and
  keep their old stamps, so the next tick retries them.
* Fetches go through the SSRF guard (core/ssrf.py): an opt-out URL
  from data may not point this server at a non-public address. A
  guard refusal reads as 'unreachable', never as an error.
* The sweep NEVER raises into its caller (the daily retention
  tick): per-broker failures are data ('unreachable'), and a
  whole-sweep failure is logged and reported as skipped.
* It runs only when armed: app startup arms it via
  core/retention.start_retention() (the worker that owns the daily
  tick). Library/test callers of retention.run_once() never touch
  the network implicitly — tests call check_broker_sources() with a
  stub fetcher, or arm() explicitly.
"""

import hashlib
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import agent as agent_engine
from core import logging_setup, ssrf
from db import pool
from remediation import registry_seed

FETCH_TIMEOUT_SECONDS = 10
MAX_BODY_BYTES = 64 * 1024
SWEEP_INTERVAL = timedelta(hours=24)
# The whole sweep's budget: 40 brokers at a 10s worst case would
# be ~7 minutes of a hanging pass; four minutes still covers a
# healthy registry many times over (a normal fetch is ~1s).
SWEEP_BUDGET_SECONDS = 240

_armed = False


def arm():
    """Enable the daily sweep (called by the retention worker's
    startup — see the module docstring)."""
    global _armed
    _armed = True


def _read_deadline(resp, deadline):
    """Read up to MAX_BODY_BYTES in chunks under a TOTAL deadline:
    the per-operation socket timeout alone lets a slow-drip page
    hold the sweep open indefinitely (audit 2026-10-16)."""
    chunks = []
    total = 0
    while total < MAX_BODY_BYTES:
        if time.monotonic() > deadline:
            raise TimeoutError("source fetch exceeded its deadline")
        chunk = resp.read(min(16 * 1024, MAX_BODY_BYTES - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _default_fetcher(url):
    """GET `url` -> (status, body bytes capped at MAX_BODY_BYTES).

    HTTP error statuses are answers too (the page exists; its body
    is hashed like any other). Transport failures and SSRF-guard
    refusals RAISE — the caller records them as 'unreachable'.
    The fetch has a total deadline (FETCH_TIMEOUT_SECONDS across
    connect + read), not just a per-operation timeout."""
    ssrf.assert_public_url(url)
    deadline = time.monotonic() + FETCH_TIMEOUT_SECONDS
    req = urllib.request.Request(url, headers=agent_engine.UA)

    def _fetch():
        # The whole fetch runs inside this callable so the total
        # deadline bounds the connect/header phase too, not only
        # body reads (run-2 revalidation).
        try:
            # Connection-pinned fetch (Phase 70): the pinned
            # connection re-resolves and validates inside
            # connect(), so the guard above cannot be raced by a
            # DNS rebinding; a pinning refusal raises here exactly
            # like a transport failure.
            with ssrf.pinned_urlopen(
                    req, timeout=FETCH_TIMEOUT_SECONDS) as resp:
                return resp.status, _read_deadline(resp, deadline)
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, _read_deadline(exc, deadline)
            except Exception:
                return exc.code, b""

    return ssrf.run_with_deadline(_fetch, FETCH_TIMEOUT_SECONDS)


def brokers_to_check():
    """[{slug, name, url}] for every brokers.json entry that has an
    opt-out URL. Slugs come from registry_seed.slugify — the same
    derivation the brokers table uses."""
    out = []
    for broker in agent_engine.load_brokers():
        url = str(broker.get("optout_url") or "").strip()
        if not url:
            continue
        out.append({
            "slug": registry_seed.slugify(broker.get("name")),
            "name": broker.get("name"),
            "url": url,
        })
    return out


def _last_sweep_at(conn):
    row = conn.execute(
        "SELECT max(checked_at) AS last FROM broker_source_checks",
    ).fetchone()
    return row["last"] if row else None


def _all_fresh(conn, now):
    """True only when EVERY registry broker has a check row from
    the last SWEEP_INTERVAL (audit 2026-10-16): freshness is a
    property of the whole registry, never of its freshest row —
    a never-checked broker is due, and so is a stale one."""
    rows = conn.execute(
        "SELECT slug, checked_at FROM broker_source_checks",
    ).fetchall()
    stamps = {row["slug"]: row["checked_at"] for row in rows}
    for broker in brokers_to_check():
        stamp = stamps.get(broker["slug"])
        if stamp is None or (now - stamp) >= SWEEP_INTERVAL:
            return False
    return True


def sweep_due(now=None):
    """True unless every registry broker was checked within the
    last 24h (the checks table is the stamp)."""
    now = now or datetime.now(timezone.utc)
    with pool.connection() as conn:
        return not _all_fresh(conn, now)


def check_broker_sources(fetcher=None, now=None, force=False):
    """One sweep over the registry. Returns a summary dict:
    {skipped, checked, ok, changed, unreachable, changed_slugs,
    unreachable_slugs} — or {skipped: True, reason} when the 24h
    gate holds. `fetcher(url) -> (status, body)`; body may be bytes
    or str. Never raises for broker behaviour."""
    now = now or datetime.now(timezone.utc)
    if fetcher is None:
        fetcher = _default_fetcher
    with pool.connection() as conn:
        if not force and _all_fresh(conn, now):
            last = _last_sweep_at(conn)
            return {"skipped": True, "reason": "recent",
                    "last_checked_at": last.isoformat() if last else None}
        previous = {
            row["slug"]: row for row in conn.execute(
                "SELECT slug, content_hash FROM broker_source_checks",
            ).fetchall()
        }
    summary = {"skipped": False, "checked": 0, "ok": 0, "changed": 0,
               "unreachable": 0, "changed_slugs": [],
               "unreachable_slugs": [], "skipped_budget": 0,
               "skipped_slugs": []}
    sweep_started = time.monotonic()
    for broker in brokers_to_check():
        slug = broker["slug"]
        if time.monotonic() - sweep_started > SWEEP_BUDGET_SECONDS:
            # Aggregate budget spent (audit 2026-10-16): the
            # remaining brokers keep their old stamps — the gate
            # reads the oldest, so the next tick retries them
            # instead of certifying a partial sweep.
            summary["skipped_budget"] += 1
            summary["skipped_slugs"].append(slug)
            continue
        prev_hash = (previous.get(slug) or {}).get("content_hash")
        try:
            status, body = fetcher(broker["url"])
            if isinstance(body, str):
                body = body.encode("utf-8", "replace")
            body = (body or b"")[:MAX_BODY_BYTES]
            digest = hashlib.sha256(body).hexdigest()
            state = ("changed" if prev_hash and prev_hash != digest
                     else "ok")
            stored_hash = digest
        except Exception:
            status, stored_hash, state = None, prev_hash, "unreachable"
        # Each row is stamped with ITS OWN check time, never the
        # sweep's start time — freshness claims stay per-broker.
        checked_at = datetime.now(timezone.utc)
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO broker_source_checks"
                " (slug, url, status, content_hash, state, checked_at)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (slug) DO UPDATE SET"
                " url = EXCLUDED.url, status = EXCLUDED.status,"
                " content_hash = EXCLUDED.content_hash,"
                " state = EXCLUDED.state, checked_at = EXCLUDED.checked_at",
                (slug, broker["url"], status, stored_hash, state,
                 checked_at))
        summary["checked"] += 1
        summary[state] += 1
        if state == "changed":
            summary["changed_slugs"].append(slug)
        elif state == "unreachable":
            summary["unreachable_slugs"].append(slug)
    return summary


def maybe_run():
    """The retention tick's entry point: sweep when armed AND due.
    Never raises — a failed sweep is logged and reported skipped,
    so it can never sink the retention pass that hosts it."""
    if not _armed:
        return {"skipped": True, "reason": "not_armed"}
    try:
        return check_broker_sources()
    except Exception as exc:
        logging_setup.log_error(
            None, "broker source sweep failed: " + type(exc).__name__)
        return {"skipped": True, "reason": "failed"}


def source_health():
    """The admin overview's per-broker source health: counts of
    brokers by their LATEST sweep state, the flagged slug lists,
    and when the last sweep ran. Empty table -> zeros + None.

    'stale' names the brokers whose change detection is dark
    (audit 2026-10-16): no row at all, or a row older than the
    sweep interval — the overview must never present a partial
    or long-dead sweep as full knowledge."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT slug, state, checked_at FROM broker_source_checks"
            " ORDER BY slug",
        ).fetchall()
    health = {"ok": 0, "changed": 0, "unreachable": 0,
              "changed_slugs": [], "unreachable_slugs": [],
              "stale": 0, "stale_slugs": [],
              "last_checked_at": None}
    last = None
    now = datetime.now(timezone.utc)
    stamps = {}
    for row in rows:
        state = row["state"]
        if state in ("ok", "changed", "unreachable"):
            health[state] += 1
        if state == "changed":
            health["changed_slugs"].append(row["slug"])
        elif state == "unreachable":
            health["unreachable_slugs"].append(row["slug"])
        checked = row["checked_at"]
        stamps[row["slug"]] = checked
        if checked is not None and (last is None or checked > last):
            last = checked
    for broker in brokers_to_check():
        stamp = stamps.get(broker["slug"])
        if stamp is None or (now - stamp) >= SWEEP_INTERVAL:
            health["stale"] += 1
            health["stale_slugs"].append(broker["slug"])
    if last is not None:
        health["last_checked_at"] = (
            last.isoformat() if hasattr(last, "isoformat") else last)
    return health
