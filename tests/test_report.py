"""Exposure & removal report tests (P3 closeout — spec Phase 85).

GET /api/report renders the caller's own LeakGuard state as one
self-contained, printable HTML document. The properties under
test are the phase's privacy contract:

* session-only: anonymous callers get the house 401
  (unauthenticated), exactly like other account reads;
* the response is text/html and carries Cache-Control: no-store
  (the Phase 67 choke-point policy, asserted on the wire);
* MASKED ONLY: the report shows the seeded identifier's stored
  masked form and NEVER its plaintext value — the report builder
  holds no decryption path, and this test would catch a
  regression that introduced one;
* owner-scoped: a second user's report contains none of the
  first user's masked values, finding sources, or broker names;
* an account with no data still gets a valid report (honest
  empty states, no error).

The harness mirrors tests/test_observability_alerts.py: pgserver
PostgreSQL, env vault keys, the real app booted on an ephemeral
port. Fixture accounts use unique example.com addresses; fixture
strings are deliberately non-credential-shaped.

Run:  python3 -m unittest discover -s tests
"""

import base64
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS",
            "BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")
# The shared allowlisted fixture password (tests/test_secrets_hygiene.py).
PASSWORD = "test-password-123"


class EnvGuard:
    def __init__(self, keys):
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


class ServerMixin:
    @classmethod
    def start_server(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, cookie=None,
                headers=None):
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if cookie:
            hdrs["Cookie"] = cookie
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=hdrs, method=method)
        try:
            with OPENER.open(req, timeout=15) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def request_json(self, *args, **kwargs):
        status, headers, payload = self.request(*args, **kwargs)
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception:
            parsed = None
        return status, headers, parsed

    def request_text(self, *args, **kwargs):
        status, headers, payload = self.request(*args, **kwargs)
        return status, headers, payload.decode("utf-8")

    @staticmethod
    def session_cookie(headers):
        raw = headers.get("Set-Cookie") or ""
        first = raw.split(";")[0].strip()
        return first if first.startswith("lg_session=") else None


try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class ReportDbBase(ServerMixin):
    """Shared pgserver provisioning — a FRESH database per class,
    like the other suites."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-report-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest(
                "pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri("postgres")
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        os.environ.pop("ADMIN_EMAILS", None)
        registry_mod.reset_registry()
        from db import migrate, pool
        from remediation import registry_seed

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        cls.seeded = registry_seed.seed_brokers()
        cls.start_server()

    @classmethod
    def _teardown_pg(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        registry_mod.reset_registry()
        cls._env.__exit__()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()

    # ---------- helpers ----------

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self, email=None):
        email = email or "report-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).rowcount

    def db_one(self, sql, params=()):
        with self.pool.connection() as conn:
            rows = conn.execute(sql, params).fetchall()
        return rows[0] if rows else None

    def seed_done_job(self, user_id, score):
        row = self.db_one(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " score, created_at, started_at, finished_at)"
            " VALUES (%s, %s, 'done', %s, now() - interval '1 hour',"
            " now() - interval '59 minutes', now() - interval '58 minutes')"
            " RETURNING id",
            (user_id, "report-job-" + self.uniq(), score))
        return str(row["id"])

    def seed_finding(self, job_id, user_id, identifier_id, source_name):
        self.db_exec(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, exposed_fields,"
            " confidence, reliability, evidence_ref)"
            " VALUES (%s, %s, %s, 'email', 'xposedornot', %s, %s,"
            " 'exact', 'high', %s)",
            (job_id, user_id, identifier_id, source_name,
             ["email", "password"], "e" * 64))

    def seed_case(self, user_id, broker_slug, status="submitted"):
        self.db_exec(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status) VALUES (%s, %s, %s)",
            (user_id, broker_slug, status))


class TestReportDb(ReportDbBase, unittest.TestCase):

    def test_unauthenticated_gets_house_401(self):
        status, _h, body = self.request_json("GET", "/api/report")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthenticated")

    def test_owner_report_masked_sections_and_headers(self):
        cookie, user_id, _email = self.register()
        plaintext = "report-owner-%s@example.com" % self.uniq()
        ident = self.add_identifier(cookie, "email", plaintext)
        masked = ident["masked"]
        self.assertNotEqual(masked, plaintext)

        job_id = self.seed_done_job(user_id, 65)
        self.seed_finding(job_id, user_id, ident["id"],
                          "Seed Breach Alpha")
        broker = self.db_one(
            "SELECT slug, name FROM brokers ORDER BY slug LIMIT 1")
        self.seed_case(user_id, broker["slug"])

        status, headers, text = self.request_text(
            "GET", "/api/report", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertTrue(
            (headers.get("Content-Type") or "").startswith("text/html"),
            headers.get("Content-Type"))
        # The Phase 67 policy, asserted on the wire for THIS route.
        self.assertEqual(headers.get("Cache-Control"), "no-store")

        # Masked in, plaintext nowhere.
        self.assertIn(masked, text)
        self.assertNotIn(plaintext, text)
        # Sections + seeded content.
        self.assertIn("Exposure &amp; removal report", text)
        self.assertIn("Serious exposure", text)  # score_band(65)
        self.assertIn("Your saved details", text)
        self.assertIn("Findings from your latest scan", text)
        self.assertIn("Seed Breach Alpha", text)
        self.assertIn("Removal cases", text)
        self.assertIn(broker["name"], text)
        self.assertIn("Recent activity", text)
        self.assertIn("The honest limits", text)
        self.assertIn("Telegram", text)

    def test_second_user_sees_none_of_the_first_users_data(self):
        cookie_a, user_a, _ea = self.register()
        # A distinctive first letter: masking keeps only it plus the
        # domain, so A's identifier mask ("z•••@…") can never
        # coincide with B's own account mask ("r•••@…") — otherwise
        # the isolation assertion below would test a collision in
        # the fixture, not a leak in the product.
        plaintext_a = "zeta-owner-%s@example.com" % self.uniq()
        ident_a = self.add_identifier(cookie_a, "email", plaintext_a)
        job_a = self.seed_done_job(user_a, 90)
        self.seed_finding(job_a, user_a, ident_a["id"],
                          "First User Breach")
        brokers = self.db_one(
            "SELECT (SELECT slug FROM brokers ORDER BY slug LIMIT 1)"
            " AS slug_a, (SELECT slug FROM brokers ORDER BY slug"
            " LIMIT 1 OFFSET 1) AS slug_b")
        name_a = self.db_one(
            "SELECT name FROM brokers WHERE slug = %s",
            (brokers["slug_a"],))["name"]
        name_b = self.db_one(
            "SELECT name FROM brokers WHERE slug = %s",
            (brokers["slug_b"],))["name"]
        self.seed_case(user_a, brokers["slug_a"])

        cookie_b, user_b, _eb = self.register()
        self.seed_case(user_b, brokers["slug_b"], status="queued")

        status, _h, text_b = self.request_text(
            "GET", "/api/report", cookie=cookie_b)
        self.assertEqual(status, 200)
        # B's own case is there; nothing of A's is.
        self.assertIn(name_b, text_b)
        self.assertNotIn(name_a, text_b)
        self.assertNotIn(ident_a["masked"], text_b)
        self.assertNotIn("First User Breach", text_b)
        self.assertNotIn(plaintext_a, text_b)

    def test_empty_account_still_renders_a_valid_report(self):
        cookie, _user_id, _email = self.register()
        status, headers, text = self.request_text(
            "GET", "/api/report", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertIn("No completed scan yet", text)
        self.assertIn("No saved details yet", text)
        self.assertIn("No removal cases yet", text)
        self.assertIn("The honest limits", text)


if __name__ == "__main__":
    unittest.main()
