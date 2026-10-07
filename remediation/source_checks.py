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
  a sweep is skipped while max(checked_at) is younger than that.
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

_armed = False


def arm():
    """Enable the daily sweep (called by the retention worker's
    startup — see the module docstring)."""
    global _armed
    _armed = True


def _default_fetcher(url):
    """GET `url` -> (status, body bytes capped at MAX_BODY_BYTES).

    HTTP error statuses are answers too (the page exists; its body
    is hashed like any other). Transport failures and SSRF-guard
    refusals RAISE — the caller records them as 'unreachable'."""
    ssrf.assert_public_url(url)
    req = urllib.request.Request(url, headers=agent_engine.UA)
    try:
        with urllib.request.urlopen(
                req, timeout=FETCH_TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read(MAX_BODY_BYTES)
        except Exception:
            return exc.code, b""


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


def sweep_due(now=None):
    """True when no sweep has run in the last 24h (the checks table
    is the stamp)."""
    now = now or datetime.now(timezone.utc)
    with pool.connection() as conn:
        last = _last_sweep_at(conn)
    return last is None or (now - last) >= SWEEP_INTERVAL


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
        if not force:
            last = _last_sweep_at(conn)
            if last is not None and (now - last) < SWEEP_INTERVAL:
                return {"skipped": True, "reason": "recent",
                        "last_checked_at": last.isoformat()}
        previous = {
            row["slug"]: row for row in conn.execute(
                "SELECT slug, content_hash FROM broker_source_checks",
            ).fetchall()
        }
    summary = {"skipped": False, "checked": 0, "ok": 0, "changed": 0,
               "unreachable": 0, "changed_slugs": [],
               "unreachable_slugs": []}
    for broker in brokers_to_check():
        slug = broker["slug"]
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
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO broker_source_checks"
                " (slug, url, status, content_hash, state, checked_at)"
                " VALUES (%s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (slug) DO UPDATE SET"
                " url = EXCLUDED.url, status = EXCLUDED.status,"
                " content_hash = EXCLUDED.content_hash,"
                " state = EXCLUDED.state, checked_at = EXCLUDED.checked_at",
                (slug, broker["url"], status, stored_hash, state, now))
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
    and when the last sweep ran. Empty table -> zeros + None."""
    with pool.connection() as conn:
        rows = conn.execute(
            "SELECT slug, state, checked_at FROM broker_source_checks"
            " ORDER BY slug",
        ).fetchall()
    health = {"ok": 0, "changed": 0, "unreachable": 0,
              "changed_slugs": [], "unreachable_slugs": [],
              "last_checked_at": None}
    last = None
    for row in rows:
        state = row["state"]
        if state in ("ok", "changed", "unreachable"):
            health[state] += 1
        if state == "changed":
            health["changed_slugs"].append(row["slug"])
        elif state == "unreachable":
            health["unreachable_slugs"].append(row["slug"])
        checked = row["checked_at"]
        if checked is not None and (last is None or checked > last):
            last = checked
    if last is not None:
        health["last_checked_at"] = (
            last.isoformat() if hasattr(last, "isoformat") else last)
    return health
