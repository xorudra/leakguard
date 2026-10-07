"""Lazy, short-lived PostgreSQL connections (spec Phase 73).

Design notes
------------
* Configuration comes from the DATABASE_URL environment variable only.
  Nothing about the connection string is ever logged or returned to
  callers — the health probe reports only "ok" / "disabled" / "error".
* Connections are opened on first use and closed per operation. The
  production endpoint is Neon's pooler (PgBouncer), which is built for
  exactly this pattern; a client-side pool would add state without
  buying anything at this scale.
* psycopg is imported lazily inside functions. Importing this module
  never fails, even where the driver is not installed.
* db_status() never raises, and caches its probe result briefly so the
  health endpoint does not open a database connection on every poll
  (UptimeRobot hits /api/health every 5 minutes; external callers may
  poll more often).
"""

import os
import time
from contextlib import contextmanager

# Generous on purpose: Neon free-tier compute autosuspends, and a cold
# wake (plus TLS + auth) can take several seconds. A 5s timeout turned
# every cold start into a spurious "db error".
_CONNECT_TIMEOUT_SECONDS = 15
_PROBE_CACHE_SECONDS = 15.0

_probe_cache = {"value": None, "at": 0.0}


def configured():
    """True when a DATABASE_URL is present in the environment."""
    return bool(os.environ.get("DATABASE_URL"))


def _dsn():
    return os.environ.get("DATABASE_URL") or ""


@contextmanager
def connection():
    """Yield a psycopg connection with dict rows; commit/rollback + close.

    Raises RuntimeError if no DATABASE_URL is configured, and whatever
    psycopg raises if the database is unreachable. Callers that must not
    fail (health probes) should use db_status() instead.
    """
    dsn = _dsn()
    if not dsn:
        raise RuntimeError("DATABASE_URL is not configured")
    import psycopg
    from psycopg.rows import dict_row

    conn = psycopg.connect(
        dsn, row_factory=dict_row, connect_timeout=_CONNECT_TIMEOUT_SECONDS
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _probe():
    """True if a trivial query succeeds against the configured database."""
    try:
        with connection() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False


def db_status():
    """Health probe for /api/health. Never raises, never leaks details.

    Returns "disabled" when no DATABASE_URL is configured, "ok" when the
    database answers, "error" when it is configured but unreachable (or
    the driver is missing).
    """
    if not configured():
        return "disabled"
    now = time.monotonic()
    if (
        _probe_cache["value"] is not None
        and now - _probe_cache["at"] < _PROBE_CACHE_SECONDS
    ):
        return _probe_cache["value"]
    value = "ok" if _probe() else "error"
    _probe_cache["value"] = value
    _probe_cache["at"] = now
    return value


def db_available():
    """Boolean convenience wrapper over db_status()."""
    return db_status() == "ok"


def reset_probe_cache():
    """Drop the cached probe result (used by tests)."""
    _probe_cache["value"] = None
    _probe_cache["at"] = 0.0
