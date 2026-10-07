"""Migration connection split tests (Batch A.1 — spec Phase 73).

Production serves as a least-privilege role (leakguard_app: DML only)
that cannot run DDL, so the boot-time migration step gets its own
connection: MIGRATION_DATABASE_URL when set, DATABASE_URL otherwise.

* TestMigrationUrlSelection — no database: env resolution + which URL
  the migrate entry points actually hand to the connection layer.
* TestMigrationSplitPg — pgserver integration: a restricted role
  (DML-only grants, like production) as DATABASE_URL and the owner
  connection as MIGRATION_DATABASE_URL. The app boot path must apply
  every migration; the restricted role must then serve DML but be
  refused CREATE TABLE — and running migrations over the restricted
  connection must fail with InsufficientPrivilege (the exact failure
  this split exists to prevent).

Run:  python3 -m unittest discover -s tests
"""

import os
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from db import migrate, pool  # noqa: E402

ENV_KEYS = ("DATABASE_URL", "MIGRATION_DATABASE_URL")

OWNER_URL = "postgresql://owner@/ownerdb"
APP_URL = "postgresql://app@/appdb"


class EnvGuard:
    """Save/restore the DB-URL environment variables."""

    def __init__(self, keys=ENV_KEYS):
        self.keys = keys

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.keys}
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


class _Sentinel(Exception):
    """Raised by the fake connection so run_migrations stops at once."""


class TestMigrationUrlSelection(unittest.TestCase):
    """Which DSN the migration step resolves, with no database at all."""

    def setUp(self):
        self._env = EnvGuard().__enter__()
        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("MIGRATION_DATABASE_URL", None)
        self.seen = []
        self._real_connection = pool.connection

        @contextmanager
        def fake_connection(dsn=None):
            self.seen.append(dsn)
            raise _Sentinel()
            yield  # pragma: no cover - never reached

        pool.connection = fake_connection

    def tearDown(self):
        pool.connection = self._real_connection
        self._env.__exit__()

    def test_dsn_falls_back_to_database_url(self):
        os.environ["DATABASE_URL"] = APP_URL
        self.assertEqual(pool.migration_dsn(), APP_URL)

    def test_dsn_prefers_migration_url(self):
        os.environ["DATABASE_URL"] = APP_URL
        os.environ["MIGRATION_DATABASE_URL"] = OWNER_URL
        self.assertEqual(pool.migration_dsn(), OWNER_URL)

    def test_run_migrations_uses_database_url_when_no_migration_url(self):
        os.environ["DATABASE_URL"] = APP_URL
        with self.assertRaises(_Sentinel):
            migrate.run_migrations()
        self.assertEqual(self.seen, [APP_URL])

    def test_run_migrations_uses_migration_url_when_set(self):
        os.environ["DATABASE_URL"] = APP_URL
        os.environ["MIGRATION_DATABASE_URL"] = OWNER_URL
        with self.assertRaises(_Sentinel):
            migrate.run_migrations()
        self.assertEqual(self.seen, [OWNER_URL])

    def test_run_migrations_explicit_url_wins_over_env(self):
        os.environ["DATABASE_URL"] = APP_URL
        os.environ["MIGRATION_DATABASE_URL"] = OWNER_URL
        with self.assertRaises(_Sentinel):
            migrate.run_migrations("postgresql://explicit@/db")
        self.assertEqual(self.seen, ["postgresql://explicit@/db"])

    def test_run_migrations_if_configured_passes_boot_url_through(self):
        # app._startup_migrations passes pool.migration_dsn() explicitly.
        os.environ["DATABASE_URL"] = APP_URL
        os.environ["MIGRATION_DATABASE_URL"] = OWNER_URL
        with self.assertRaises(_Sentinel):
            migrate.run_migrations_if_configured(pool.migration_dsn())
        self.assertEqual(self.seen, [OWNER_URL])

    def test_if_configured_is_noop_without_any_url(self):
        self.assertEqual(migrate.run_migrations_if_configured(), [])
        self.assertEqual(self.seen, [])  # connection never attempted

    def test_run_migrations_raises_without_any_url(self):
        with self.assertRaises(RuntimeError):
            migrate.run_migrations()
        self.assertEqual(self.seen, [])


# ---------------------------------------------------------------------------
# pgserver integration: restricted serving role + owner migration role
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None

APP_ROLE = "leakguard_app_itest"
APP_PASSWORD = "itestpw123"


def _restricted_url(owner_url):
    """Owner URI with the userinfo swapped for the restricted role."""
    parts = urlsplit(owner_url)
    netloc = "%s:%s@%s" % (APP_ROLE, APP_PASSWORD, parts.hostname or "")
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, ""))


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestMigrationSplitPg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard().__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-mig-split-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        cls.owner_url = cls._pg.get_uri()
        cls.app_url = _restricted_url(cls.owner_url)

        # Restricted role with production-shaped grants: DML on tables
        # (via default privileges, so tables the owner creates during
        # migrations are covered) and sequence usage — but no DDL.
        import psycopg

        with psycopg.connect(cls.owner_url) as conn:
            conn.execute(
                "CREATE ROLE %s LOGIN PASSWORD '%s'"
                % (APP_ROLE, APP_PASSWORD))
            conn.execute(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public"
                " GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES"
                " TO %s" % APP_ROLE)
            conn.execute(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public"
                " GRANT USAGE, SELECT ON SEQUENCES TO %s" % APP_ROLE)

        # Serving runs as the restricted role; migrations as the owner.
        os.environ["DATABASE_URL"] = cls.app_url
        os.environ["MIGRATION_DATABASE_URL"] = cls.owner_url
        pool.reset_probe_cache()
        if pool.db_status() != "ok":
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")

        # The exact app boot path.
        app._startup_migrations()

    @classmethod
    def _teardown_pg(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        pool.reset_probe_cache()
        cls._env.__exit__()

    @classmethod
    def tearDownClass(cls):
        cls._teardown_pg()

    def test_boot_applied_every_migration(self):
        expected = {p.name for p in migrate.migration_files()}
        self.assertTrue(expected)
        with pool.connection(self.owner_url) as conn:
            rows = conn.execute("SELECT name FROM schema_migrations").fetchall()
        applied = {r["name"] for r in rows}
        self.assertEqual(applied, expected)
        self.assertIn(migrate.migration_files()[-1].name, applied)

    def test_app_role_reads_schema_state(self):
        # Serving connection (DATABASE_URL = restricted role).
        with pool.connection() as conn:
            rows = conn.execute("SELECT name FROM schema_migrations").fetchall()
        self.assertIn(migrate.migration_files()[-1].name,
                      {r["name"] for r in rows})

    def test_app_role_can_dml(self):
        with pool.connection() as conn:
            conn.execute(
                "INSERT INTO schema_migrations (name) VALUES ('itest-probe')")
            row = conn.execute(
                "SELECT name FROM schema_migrations"
                " WHERE name = 'itest-probe'").fetchone()
            self.assertIsNotNone(row)
            conn.execute(
                "DELETE FROM schema_migrations WHERE name = 'itest-probe'")

    def test_app_role_cannot_create_table(self):
        import psycopg

        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with pool.connection() as conn:
                conn.execute("CREATE TABLE itest_probe (id integer)")

    def test_migrations_over_restricted_connection_fail(self):
        # The pre-split production failure, reproduced: DDL as the
        # DML-only role is refused even when nothing is pending,
        # because the tracking table's CREATE IF NOT EXISTS needs it.
        import psycopg

        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            migrate.run_migrations(self.app_url)

    def test_migrations_idempotent_over_owner_connection(self):
        self.assertEqual(migrate.run_migrations(self.owner_url), [])


if __name__ == "__main__":
    unittest.main()
