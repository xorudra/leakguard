"""Database + vault integration tests against a real PostgreSQL
(Stage S2 — spec Phases 2, 73, 3), plus a no-env boot test.

The DB tests SKIP cleanly when no database is available: the URL comes
from DATABASE_URL or, for local development, from the owner-only
.neon-database-url file in the repo root (read here, never printed).
Vault keys in these tests are EPHEMERAL, generated per run — the
production key files are never touched.

The boot test always runs: it starts app.py as a subprocess with NO
database env at all and asserts the site serves normally with
"db": "disabled" (graceful degradation).

Run:  python3 -m unittest discover -s tests
"""

import base64
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

REPO_ROOT = Path(__file__).resolve().parent.parent
NEON_FILE = REPO_ROOT / ".neon-database-url"

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")


def _database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url.strip()
    try:
        text = NEON_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EnvGuard:
    """Save/restore the DB-related environment variables."""

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in ENV_KEYS}
        return self

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return False


@unittest.skipUnless(_database_url(), "no DATABASE_URL / Neon file available")
class TestVaultAgainstRealDb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard().__enter__()
        os.environ["DATABASE_URL"] = _database_url()
        # Ephemeral vault keys for this test run only.
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(os.urandom(32)).decode()
        from db import migrate, pool

        pool.reset_probe_cache()
        cls.migrate = migrate
        cls.pool = pool
        if not pool.db_available():
            # Configured but unreachable from this network (e.g. a
            # proxy-only sandbox): skip honestly instead of erroring.
            # On any direct-egress host these tests really run.
            cls._env.__exit__()
            raise unittest.SkipTest(
                "PostgreSQL configured but not reachable from this host")
        cls.first_run = migrate.run_migrations()
        cls.digests = []  # test rows to hard-delete in tearDown

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.pool.connection() as conn:
                for digest in cls.digests:
                    conn.execute(
                        "DELETE FROM identifiers WHERE hmac_lookup = %s",
                        (digest,),
                    )
        except Exception:
            pass
        cls.pool.reset_probe_cache()
        cls._env.__exit__()

    def _unique_email(self):
        return "vault-test-%s@example.com" % uuid.uuid4().hex[:16]

    def _track(self, kind, value):
        from vault import store

        digest = store.lookup_hmac(kind, value)
        if digest not in self.digests:
            self.digests.append(digest)
        return digest

    def test_migrations_idempotent(self):
        again = self.migrate.run_migrations()
        self.assertEqual(again, [])  # second run applies nothing
        with self.pool.connection() as conn:
            rows = conn.execute("SELECT name FROM schema_migrations").fetchall()
        names = {r["name"] for r in rows}
        self.assertIn("0001_vault.sql", names)

    def test_db_status_ok(self):
        self.assertEqual(self.pool.db_status(), "ok")
        self.assertTrue(self.pool.db_available())

    def test_put_get_reveal_roundtrip(self):
        from vault import store

        value = self._unique_email()
        pretty = value.replace("vault-test-", "Vault-Test-")
        self._track("email", value)
        rec = store.put("email", pretty)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["kind"], "email")
        self.assertEqual(rec["masked"], "v•••@example.com")
        self.assertNotIn("ciphertext", rec)
        self.assertNotIn(pretty, json.dumps(rec, default=str))

        found = store.get_by_lookup("email", value.upper())
        self.assertIsNotNone(found)
        self.assertEqual(found["id"], rec["id"])
        # Plaintext comes back ONLY through reveal(), original preserved.
        self.assertEqual(store.reveal("email", value), pretty)

    def test_duplicate_put_keeps_one_live_row(self):
        from vault import store

        value = self._unique_email()
        digest = self._track("email", value)
        first = store.put("email", value)
        second = store.put("email", value)
        self.assertEqual(first["id"], second["id"])
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT COUNT(*) AS n FROM identifiers"
                " WHERE kind = 'email' AND hmac_lookup = %s"
                " AND deleted_at IS NULL",
                (digest,),
            ).fetchone()
        self.assertEqual(rows["n"], 1)

    def test_soft_delete_hides_and_allows_readd(self):
        from vault import store

        value = self._unique_email()
        self._track("email", value)
        rec = store.put("email", value)
        self.assertTrue(store.soft_delete("email", value))
        self.assertIsNone(store.get_by_lookup("email", value))
        self.assertIsNone(store.reveal("email", value))
        self.assertFalse(store.soft_delete("email", value))  # already gone
        readded = store.put("email", value)
        self.assertNotEqual(readded["id"], rec["id"])  # fresh live row
        self.assertEqual(store.reveal("email", value), value)


class TestBootWithoutEnv(unittest.TestCase):
    def test_app_boots_and_serves_with_no_database_env(self):
        env = {k: v for k, v in os.environ.items() if k not in ENV_KEYS}
        port = _free_port()
        env["HOST"] = "127.0.0.1"
        env["PORT"] = str(port)
        proc = subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "app.py")],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        base = "http://127.0.0.1:%d" % port
        try:
            health = None
            deadline = time.time() + 30
            while time.time() < deadline:
                if proc.poll() is not None:
                    self.fail("app.py exited early with code %s" % proc.returncode)
                try:
                    with OPENER.open(base + "/api/health", timeout=3) as resp:
                        health = json.loads(resp.read().decode("utf-8"))
                    break
                except Exception:
                    time.sleep(0.25)
            self.assertIsNotNone(health, "health endpoint never answered")
            self.assertEqual(health.get("ok"), True)
            self.assertEqual(health.get("service"), "leakguard")
            self.assertEqual(health.get("db"), "disabled")
            with OPENER.open(base + "/api/brokers", timeout=5) as resp:
                brokers = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(len(brokers.get("brokers", [])), 40)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    unittest.main()
