"""SQL migration runner (spec Phase 2).

Applies db/migrations/*.sql in filename order, each exactly once,
tracked in a schema_migrations table. Idempotent: running it twice (or
at every boot) is a no-op after the first success.

Runnable standalone:   python3 -m db.migrate
Also invoked from app.main() at startup when a database is configured
— guarded there so a migration failure is logged and the site still
boots (a broken database must not take the anonymous scan down).

Connection details come from the environment only, resolved by
db.pool.migration_dsn(): MIGRATION_DATABASE_URL when set (production:
an owner-level connection, because migrations run DDL), otherwise
DATABASE_URL (local/dev/tests — the serving role there can DDL).
Nothing about the connection string is printed or logged.
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


def run_migrations(url=None):
    """Apply every unapplied migration. Returns the list of names that
    were applied by this call (empty when already up to date).

    ``url`` is the migration connection string. Callers pass it
    explicitly (app boot resolves db.pool.migration_dsn()); the
    default None resolves the same way, so tests and importers that
    set only DATABASE_URL keep working unchanged.

    Raises if no database URL is configured or the database is
    unreachable — callers at app startup must guard (see
    run_migrations_if_configured).
    """
    if url is None:
        url = pool.migration_dsn()
    if not url:
        raise RuntimeError("DATABASE_URL is not configured")
    done = []
    with pool.connection(url) as conn:
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


def run_migrations_if_configured(url=None):
    """Startup helper: migrate when configured, stay silent otherwise.

    Returns the list of applied migration names, or [] when no database
    is configured. "Configured" means a migration URL resolves
    (MIGRATION_DATABASE_URL, falling back to DATABASE_URL). Exceptions
    from a configured-but-broken database propagate so the caller can
    log them (app.main catches them so the site still boots).
    """
    if url is None:
        url = pool.migration_dsn()
    if not url:
        return []
    return run_migrations(url)


def main(argv=None):
    try:
        applied = run_migrations()
    except RuntimeError:
        print("db.migrate: no database URL configured "
              "(MIGRATION_DATABASE_URL / DATABASE_URL)", file=sys.stderr)
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
