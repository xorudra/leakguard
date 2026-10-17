"""PostgreSQL connections for serving + migrations (spec Phase 73,
warm-pool amendment 2026-10-13).

Design notes
------------
* Configuration comes from environment variables only: DATABASE_URL
  for serving, MIGRATION_DATABASE_URL (optional, owner-level) for the
  boot-time migration step — see migration_dsn(). Nothing about any
  connection string is ever logged or returned to callers — the health
  probe reports only "ok" / "disabled" / "error".
* Serving connections are drawn from a small warm pool (up to 4 idle
  connections, reused LIFO). The original Phase 73 design opened a
  fresh connection per operation; that was measured on the production
  host on 2026-10-13 at 516–1076 ms per connect+SELECT 1 against the
  Neon pooler (a 3-operation request paid ~2 s of connection setup
  alone), which is a real user-facing cost on every DB-touching
  request. The production endpoint remains Neon's pooler (PgBouncer,
  transaction pooling): pooled client connections therefore disable
  psycopg's automatic prepared statements (prepare_threshold=None),
  which are not safe across pooled transactions, and a connection is
  only ever used by one operation at a time. Connections are keyed to
  the DSN they were opened with, validated with SELECT 1 after 30 s
  idle, and discarded (never re-pooled) after any error. Explicit-DSN
  calls (the migration step) keep the original open-per-call behaviour,
  and LEAKGUARD_DB_POOL=0 disables pooling entirely (rollback switch).
* psycopg is imported lazily inside functions. Importing this module
  never fails, even where the driver is not installed.
* db_status() never raises, and caches its probe result for 10 minutes
  so the health endpoint does not open a database connection on every
  poll. The cache window is sized against Neon free-tier autosuspend
  (~5 idle minutes): with every external poller slower than the cache,
  the database can actually sleep between real user traffic instead of
  being kept awake — and billed — by health checks alone (owner order
  2026-10-17, after Neon reported 80% of the monthly free compute
  used). Trade-off: /api/health may report a cached db status up to
  10 minutes old; real user requests never use the cache.
"""

import os
import queue
import time
from contextlib import contextmanager

# Generous on purpose: Neon free-tier compute autosuspends, and a cold
# wake (plus TLS + auth) can take several seconds. A 5s timeout turned
# every cold start into a spurious "db error".
_CONNECT_TIMEOUT_SECONDS = 15
_PROBE_CACHE_SECONDS = 600.0

_probe_cache = {"value": None, "at": 0.0}


def configured():
    """True when a DATABASE_URL is present in the environment."""
    return bool(os.environ.get("DATABASE_URL"))


def _dsn():
    return os.environ.get("DATABASE_URL") or ""


def migration_dsn():
    """DSN for the boot-time migration step ONLY (spec Phase 73).

    Migrations run DDL, so in production they use MIGRATION_DATABASE_URL
    — an owner-level connection — while the serving pool runs as a
    least-privilege role (DATABASE_URL: DML only, cannot CREATE/ALTER).
    When MIGRATION_DATABASE_URL is unset (local dev, tests), this falls
    back to DATABASE_URL and the single connection does both jobs,
    exactly as before the split. The serving pool never uses this.
    """
    return os.environ.get("MIGRATION_DATABASE_URL") or _dsn()


# --- warm serving pool -------------------------------------------------
# Idle items are (dsn, conn, returned_at_monotonic). queue.LifoQueue is
# thread-safe; a checked-out connection is owned by exactly one caller.
_POOL_MAX_IDLE = 4
_POOL_VALIDATE_IDLE_SECONDS = 30.0
_idle = queue.LifoQueue(maxsize=_POOL_MAX_IDLE)


def _pool_enabled():
    return os.environ.get("LEAKGUARD_DB_POOL", "1").strip().lower() not in (
        "0",
        "false",
        "off",
    )


def _new_conn(dsn, pooled):
    import psycopg
    from psycopg.rows import dict_row

    kwargs = {}
    if pooled:
        # Neon's pooler is PgBouncer in transaction-pooling mode: a
        # server-side prepared statement belongs to whichever backend
        # the pooler assigns per transaction, so automatic preparing is
        # unsafe on a connection reused across transactions.
        kwargs["prepare_threshold"] = None
    return psycopg.connect(
        dsn,
        row_factory=dict_row,
        connect_timeout=_CONNECT_TIMEOUT_SECONDS,
        **kwargs,
    )


def _checkout(dsn):
    """A warm pooled connection for dsn, or a fresh one."""
    while True:
        try:
            item_dsn, conn, idle_since = _idle.get_nowait()
        except queue.Empty:
            return _new_conn(dsn, pooled=True)
        if item_dsn != dsn:
            # DSN changed since this connection was pooled (tests and
            # config reloads do this; production never does).
            try:
                conn.close()
            except Exception:
                pass
            continue
        try:
            if conn.closed:
                continue
            if time.monotonic() - idle_since > _POOL_VALIDATE_IDLE_SECONDS:
                conn.execute("SELECT 1")
                conn.rollback()
            return conn
        except Exception:
            try:
                conn.close()
            except Exception:
                pass
            continue


def _checkin(dsn, conn):
    """Return a healthy connection to the pool, or close it."""
    try:
        if conn.closed:
            return
        conn.rollback()  # no transaction state may leak to the next user
        _idle.put_nowait((dsn, conn, time.monotonic()))
    except Exception:
        try:
            conn.close()
        except Exception:
            pass


def reset_pool():
    """Close every idle pooled connection (tests / operator use)."""
    while True:
        try:
            _dsn_item, conn, _ts = _idle.get_nowait()
        except queue.Empty:
            return
        try:
            conn.close()
        except Exception:
            pass


@contextmanager
def connection(dsn=None):
    """Yield a psycopg connection with dict rows; commit on success.

    With no argument the connection uses DATABASE_URL (the serving
    DSN) and comes from the warm pool: it is returned to the pool on
    success and closed on any error. An explicit ``dsn`` (the migration
    step) keeps the original open-per-call, close-after behaviour.

    Raises RuntimeError if no DATABASE_URL is configured, and whatever
    psycopg raises if the database is unreachable. Callers that must not
    fail (health probes) should use db_status() instead.
    """
    serving = dsn is None
    if serving:
        dsn = _dsn()
    if not dsn:
        raise RuntimeError("DATABASE_URL is not configured")
    if not serving or not _pool_enabled():
        conn = _new_conn(dsn, pooled=False)
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
        return
    conn = _checkout(dsn)
    try:
        yield conn
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass
        raise
    _checkin(dsn, conn)


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
