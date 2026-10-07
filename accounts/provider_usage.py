"""Persistence glue for the provider usage ledger (Phases 66, 124).

providers/usage.py is a leaf module (it imports no project code —
the architecture guard keeps providers/ ignorant of the database),
so the two database operations it needs are injected from here:

* persister — upsert one batch of (provider, day, calls,
  successes, failures) deltas into provider_usage_daily
  (migration 0014), incrementing the stored counters;
* loader — read back one provider-day's stored counters, so a
  process restart re-seeds budget enforcement instead of handing
  every provider a fresh day's budget.

install() is called once at process start (app.py) and by the
test suites. Both operations are total: they report failure by
return value (False / None), never by raising — the tracker's
fail-open contract depends on it.
"""

from db import pool as db_pool
from providers import usage

_INSTALLED = False


def _persist(rows):
    """Upsert delta rows; True when written. One connection, one
    statement per row (batches are per-provider-per-day, so a
    batch is a handful of rows)."""
    try:
        with db_pool.connection() as conn:
            for provider, day, calls, successes, failures in rows:
                conn.execute(
                    "INSERT INTO provider_usage_daily"
                    " (provider, day, calls, successes, failures,"
                    " updated_at)"
                    " VALUES (%s, %s, %s, %s, %s, now())"
                    " ON CONFLICT (provider, day) DO UPDATE SET"
                    " calls = provider_usage_daily.calls"
                    "   + EXCLUDED.calls,"
                    " successes = provider_usage_daily.successes"
                    "   + EXCLUDED.successes,"
                    " failures = provider_usage_daily.failures"
                    "   + EXCLUDED.failures,"
                    " updated_at = now()",
                    (provider, day, calls, successes, failures),
                )
        return True
    except Exception:
        return False


def _load(provider, day):
    """(calls, successes, failures) stored for one provider-day,
    or None when there is no row (or no readable database)."""
    try:
        with db_pool.connection() as conn:
            row = conn.execute(
                "SELECT calls, successes, failures"
                " FROM provider_usage_daily"
                " WHERE provider = %s AND day = %s",
                (provider, day),
            ).fetchone()
        if row is None:
            return None
        return (int(row["calls"]), int(row["successes"]),
                int(row["failures"]))
    except Exception:
        return None


def install():
    """Inject the database persister/loader into the usage
    tracker. Idempotent — safe to call from every entry point."""
    global _INSTALLED
    usage.tracker.set_persister(_persist)
    usage.tracker.set_loader(_load)
    _INSTALLED = True
