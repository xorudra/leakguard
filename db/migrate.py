"""SQL migration runner (spec Phase 2).

Applies db/migrations/*.sql in filename order, each exactly once,
tracked in a schema_migrations table. Idempotent: running it twice (or
at every boot) is a no-op after the first success.

Runnable standalone:   python3 -m db.migrate
Also invoked from app.main() at startup when DATABASE_URL is set —
guarded there so a migration failure is logged and the site still
boots (a broken database must not take the anonymous scan down).

Connection details come from the DATABASE_URL environment variable
only. Nothing about the connection string is printed or logged.
"""

import sys
from pathlib import Path

from db import pool

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

_CREATE_TRACKING = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    name        text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
)
"""


def migration_files():
    """All migration files, in the order they must be applied."""
    if not MIGRATIONS_DIR.is_dir():
        return []
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def applied_migrations(conn):
    conn.execute(_CREATE_TRACKING)
    rows = conn.execute("SELECT name FROM schema_migrations").fetchall()
    return {row["name"] for row in rows}


def run_migrations():
    """Apply every unapplied migration. Returns the list of names that
    were applied by this call (empty when already up to date).

    Raises if no DATABASE_URL is configured or the database is
    unreachable — callers at app startup must guard (see
    run_migrations_if_configured).
    """
    if not pool.configured():
        raise RuntimeError("DATABASE_URL is not configured")
    done = []
    with pool.connection() as conn:
        already = applied_migrations(conn)
        for path in migration_files():
            if path.name in already:
                continue
            sql = path.read_text(encoding="utf-8")
            conn.execute(sql)
            conn.execute(
                "INSERT INTO schema_migrations (name) VALUES (%s)", (path.name,)
            )
            done.append(path.name)
    return done


def run_migrations_if_configured():
    """Startup helper: migrate when configured, stay silent otherwise.

    Returns the list of applied migration names, or [] when no database
    is configured. Exceptions from a configured-but-broken database
    propagate so the caller can log them (app.main catches them so the
    site still boots).
    """
    if not pool.configured():
        return []
    return run_migrations()


def main(argv=None):
    try:
        applied = run_migrations()
    except RuntimeError:
        print("db.migrate: DATABASE_URL is not configured", file=sys.stderr)
        return 2
    except Exception as exc:  # never print connection details
        print("db.migrate: failed (%s)" % type(exc).__name__, file=sys.stderr)
        return 1
    if applied:
        for name in applied:
            print("db.migrate: applied %s" % name)
    else:
        print("db.migrate: already up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
