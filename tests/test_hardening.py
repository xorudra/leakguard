"""Hardening tests (Stage S12 — spec Phases 63–68, 71, 76–80).

Layers:

* TestRateLimiterUnit — offline: the shared sliding-window limiter
  (window slide, per-key isolation, Retry-After math, rejected
  attempts do not extend the lockout, thread smoke).
* TestAnonymousHardening — no database: the anonymous quick scan's
  per-IP cap answers the standard structured 429 (+ Retry-After)
  once exhausted, and an oversized JSON body answers 413. Limits
  are shrunk via core.ratelimit.configure() — the documented test
  hook — and restored afterwards.
* TestHardeningDb — against a local pgserver PostgreSQL: register
  per-IP cap, forgot-password 429 shape (enumeration safety kept:
  the sub-limit answers stay byte-identical 200s), per-user scan
  cap isolation (user A limited, user B unaffected), remediation
  run cap, and the retention worker (seeded expired rows per
  category; soft-deleted 31 days -> fully purged, 29 days -> kept,
  live data untouched, purge audited).

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
from accounts import ratelimit as accounts_ratelimit  # noqa: E402
from core import ratelimit as core_ratelimit  # noqa: E402
from core import retention  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
CSRF = {"X-Requested-With": "fetch"}

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


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

    def request(self, method, path, body=None, cookie=None, headers=None,
                raw=None):
        hdrs = dict(headers or {})
        data = raw
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

    @staticmethod
    def session_cookie(headers):
        raw = headers.get("Set-Cookie") or ""
        return raw.split(";")[0].strip()


class LimitGuard:
    """Shrink core limiter route classes for one test class and
    restore production limits + empty buckets afterwards."""

    def __init__(self, overrides):
        self.overrides = overrides

    def __enter__(self):
        merged = dict(core_ratelimit.DEFAULT_LIMITS)
        merged.update(self.overrides)
        core_ratelimit.configure(merged)
        core_ratelimit.reset()
        accounts_ratelimit.reset()
        return self

    def __exit__(self, *exc):
        core_ratelimit.configure()
        core_ratelimit.reset()
        accounts_ratelimit.reset()
        return False


# ---------------------------------------------------------------------------
# Limiter unit tests
# ---------------------------------------------------------------------------

class TestRateLimiterUnit(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self._real_clock = core_ratelimit._clock
        core_ratelimit._clock = lambda: self.now[0]
        core_ratelimit.reset()

    def tearDown(self):
        core_ratelimit._clock = self._real_clock
        core_ratelimit.reset()

    def test_allows_up_to_limit_then_blocks(self):
        key = ("anon_scan", "ip:203.0.113.1")
        self.assertTrue(core_ratelimit.allow(key, 3, 60))
        self.assertTrue(core_ratelimit.allow(key, 3, 60))
        self.assertTrue(core_ratelimit.allow(key, 3, 60))
        self.assertFalse(core_ratelimit.allow(key, 3, 60))

    def test_window_slides(self):
        key = ("anon_scan", "ip:203.0.113.2")
        for _ in range(3):
            self.assertTrue(core_ratelimit.allow(key, 3, 60))
        self.assertFalse(core_ratelimit.allow(key, 3, 60))
        self.now[0] += 30  # halfway: oldest hit still in window
        self.assertFalse(core_ratelimit.allow(key, 3, 60))
        self.now[0] += 31  # oldest hit has aged out
        self.assertTrue(core_ratelimit.allow(key, 3, 60))

    def test_per_key_isolation(self):
        a = ("anon_scan", "ip:203.0.113.3")
        b = ("anon_scan", "ip:203.0.113.4")
        c = ("user_scans", "user:some-uuid")
        for _ in range(2):
            core_ratelimit.allow(a, 2, 60)
        self.assertFalse(core_ratelimit.allow(a, 2, 60))
        self.assertTrue(core_ratelimit.allow(b, 2, 60))
        self.assertTrue(core_ratelimit.allow(c, 2, 60))

    def test_retry_after_math(self):
        key = ("forgot_password", "ip:203.0.113.5")
        self.assertEqual(core_ratelimit.retry_after(key, 2, 60), 0)
        core_ratelimit.allow(key, 2, 60)
        self.assertEqual(core_ratelimit.retry_after(key, 2, 60), 0)
        core_ratelimit.allow(key, 2, 60)
        after = core_ratelimit.retry_after(key, 2, 60)
        self.assertGreaterEqual(after, 59)
        self.assertLessEqual(after, 61)
        self.now[0] += 61
        self.assertEqual(core_ratelimit.retry_after(key, 2, 60), 0)

    def test_rejected_attempts_do_not_extend_lockout(self):
        key = ("anon_scan", "ip:203.0.113.6")
        core_ratelimit.allow(key, 1, 60)
        self.now[0] += 50
        self.assertFalse(core_ratelimit.allow(key, 1, 60))  # not recorded
        self.now[0] += 11  # 61s after the ONLY recorded hit
        self.assertTrue(core_ratelimit.allow(key, 1, 60))

    def test_thread_smoke_exact_budget(self):
        key = ("user_scans", "user:threads")
        allowed = []
        guard = threading.Lock()

        def hammer():
            for _ in range(20):
                if core_ratelimit.allow(key, 50, 60):
                    with guard:
                        allowed.append(1)

        threads = [threading.Thread(target=hammer) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(allowed), 50)

    def test_production_defaults_present(self):
        for route_class in ("anon_scan", "agent_probe", "agent_submit",
                            "forgot_password", "register", "user_scans",
                            "user_remediation_run"):
            limit, window = core_ratelimit.limit_for(route_class)
            self.assertGreater(limit, 0, route_class)
            self.assertEqual(window, 3600, route_class)


# ---------------------------------------------------------------------------
# Anonymous surface (no database)
# ---------------------------------------------------------------------------

class TestAnonymousHardening(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(ENV_KEYS).__enter__()
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        cls._limits = LimitGuard({"anon_scan": (3, 3600)}).__enter__()
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._limits.__exit__()
        cls._env.__exit__()

    def setUp(self):
        core_ratelimit.reset()
        accounts_ratelimit.reset()

    def test_scan_429_after_limit_with_retry_after(self):
        # Invalid emails keep this offline (no provider calls) while
        # still passing through the limiter, which runs first.
        for _ in range(3):
            status, _h, body = self.request_json(
                "POST", "/api/scan", body={"email": "not-an-email"},
                headers=CSRF)
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_email")
        status, headers, body = self.request_json(
            "POST", "/api/scan", body={"email": "not-an-email"},
            headers=CSRF)
        self.assertEqual(status, 429)
        self.assertEqual(body["error"]["code"], "rate_limited")
        self.assertIn("request_id", body["error"])
        retry = headers.get("Retry-After")
        self.assertIsNotNone(retry)
        self.assertGreater(int(retry), 0)

    def test_oversized_body_413(self):
        big = b'{"email": "' + b"a" * (300 * 1024) + b'"}'
        status, _h, body = self.request_json(
            "POST", "/api/scan", raw=big,
            headers={"Content-Type": "application/json",
                     "X-Requested-With": "fetch"})
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "body_too_large")

    def test_retention_dormant_without_database(self):
        self.assertFalse(retention.start_retention_if_configured())


# ---------------------------------------------------------------------------
# Database-backed route limits + retention (pgserver)
# ---------------------------------------------------------------------------

class PgMixin:
    @classmethod
    def _start_pg(cls, prefix):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix=prefix)
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()

    @classmethod
    def _teardown_pg(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        cls._env.__exit__()

    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def db_rows(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).rowcount


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestRouteLimitsDb(PgMixin, ServerMixin, unittest.TestCase):
    PASSWORD = "Hardening!Test1"

    @classmethod
    def setUpClass(cls):
        cls._start_pg("lg-hardening-pg-")
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        accounts_ratelimit.reset()
        core_ratelimit.reset()

    def tearDown(self):
        core_ratelimit.configure()
        core_ratelimit.reset()
        accounts_ratelimit.reset()

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "hard-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD, "policy_accepted": True}, headers=CSRF)
        return status, headers, body

    def test_register_ip_cap(self):
        with LimitGuard({"register": (3, 3600)}):
            for _ in range(3):
                status, _h, _b = self.register()
                self.assertEqual(status, 201)
            status, headers, body = self.register()
            self.assertEqual(status, 429)
            self.assertEqual(body["error"]["code"], "rate_limited")
            self.assertIsNotNone(headers.get("Retry-After"))

    def test_forgot_password_429_shape_and_identical_200s(self):
        with LimitGuard({"forgot_password": (2, 3600)}):
            bodies = []
            for _ in range(2):
                status, _h, payload = self.request(
                    "POST", "/api/auth/forgot-password",
                    body={"email": "ghost-%s@example.com" % self.uniq()},
                    headers=CSRF)
                self.assertEqual(status, 200)
                bodies.append(payload)
            # Enumeration safety below the cap: answers never vary.
            self.assertEqual(bodies[0], bodies[1])
            self.assertEqual(json.loads(bodies[0]), {"ok": True})
            status, headers, body = self.request_json(
                "POST", "/api/auth/forgot-password",
                body={"email": "ghost-%s@example.com" % self.uniq()},
                headers=CSRF)
            self.assertEqual(status, 429)
            self.assertEqual(body["error"]["code"], "rate_limited")
            self.assertIsNotNone(headers.get("Retry-After"))

    def test_client_ip_keys_on_last_forwarded_hop(self):
        # Regression (proven live 2026-10-07): the limiter keyed on the
        # FIRST X-Forwarded-For entry, which a client can spoof. The
        # bucket must follow the LAST hop — the address the platform
        # edge observed. A different fake first entry must NOT dodge
        # an exhausted last-hop bucket; a different last hop must NOT
        # be limited by it.
        with LimitGuard({"forgot_password": (2, 3600)}):
            h1 = dict(CSRF, **{"X-Forwarded-For": "9.9.9.9, 203.0.113.5"})
            for _ in range(2):
                status, _h, _p = self.request(
                    "POST", "/api/auth/forgot-password",
                    body={"email": "ghost-%s@example.com" % self.uniq()},
                    headers=h1)
                self.assertEqual(status, 200)
            h2 = dict(CSRF, **{"X-Forwarded-For": "8.8.8.8, 203.0.113.5"})
            status, _h, body = self.request_json(
                "POST", "/api/auth/forgot-password",
                body={"email": "ghost-%s@example.com" % self.uniq()},
                headers=h2)
            self.assertEqual(status, 429)
            self.assertEqual(body["error"]["code"], "rate_limited")
            h3 = dict(CSRF, **{"X-Forwarded-For": "8.8.8.8, 203.0.113.6"})
            status, _h, _p = self.request(
                "POST", "/api/auth/forgot-password",
                body={"email": "ghost-%s@example.com" % self.uniq()},
                headers=h3)
            self.assertEqual(status, 200)

    def _register_user(self):
        status, headers, body = self.register()
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def _prepare_scannable(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "email",
                  "value": "scan-%s@example.com" % self.uniq()},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)

    def test_user_scan_cap_isolates_users(self):
        with LimitGuard({"user_scans": (2, 3600)}):
            cookie_a, _uid_a = self._register_user()
            self._prepare_scannable(cookie_a)
            for i in range(2):
                status, _h, body = self.request_json(
                    "POST", "/api/scans",
                    body={"idempotency_key": "a-%d-%s" % (i, self.uniq())},
                    headers=CSRF, cookie=cookie_a)
                self.assertEqual(status, 201, body)
            status, _h, body = self.request_json(
                "POST", "/api/scans",
                body={"idempotency_key": "a-3-%s" % self.uniq()},
                headers=CSRF, cookie=cookie_a)
            self.assertEqual(status, 429)
            self.assertEqual(body["error"]["code"], "rate_limited")
            # A different user is on a different bucket entirely.
            cookie_b, _uid_b = self._register_user()
            self._prepare_scannable(cookie_b)
            status, _h, body = self.request_json(
                "POST", "/api/scans",
                body={"idempotency_key": "b-1-%s" % self.uniq()},
                headers=CSRF, cookie=cookie_b)
            self.assertEqual(status, 201, body)

    def test_remediation_run_cap(self):
        with LimitGuard({"user_remediation_run": (1, 3600)}):
            cookie, _uid = self._register_user()
            status, _h, body = self.request_json(
                "POST", "/api/consents",
                body={"purpose": "automated_remediation", "granted": True},
                headers=CSRF, cookie=cookie)
            self.assertEqual(status, 200, body)
            status, _h, _b = self.request_json(
                "POST", "/api/remediation/run", body={},
                headers=CSRF, cookie=cookie)
            self.assertNotEqual(status, 429)
            status, _h, body = self.request_json(
                "POST", "/api/remediation/run", body={},
                headers=CSRF, cookie=cookie)
            self.assertEqual(status, 429)
            self.assertEqual(body["error"]["code"], "rate_limited")


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestRetentionDb(PgMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._start_pg("lg-retention-pg-")

    @classmethod
    def tearDownClass(cls):
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    # ----- seeding helpers (raw SQL, aged timestamps) -----
    def make_user(self, deleted_days_ago=None):
        uid = str(uuid.uuid4())
        if deleted_days_ago is None:
            self.db_exec(
                "INSERT INTO users (id, email_hmac, email_ciphertext,"
                " email_masked, password_hash)"
                " VALUES (%s, %s, %s, %s, 'x')",
                (uid, os.urandom(32), os.urandom(32), "u•••@example.com"))
        else:
            self.db_exec(
                "INSERT INTO users (id, email_hmac, email_ciphertext,"
                " email_masked, password_hash, deleted_at)"
                " VALUES (%s, %s, %s, %s, 'x',"
                " now() - (%s || ' days')::interval)",
                (uid, os.urandom(32), os.urandom(32),
                 "u•••@example.com", str(deleted_days_ago)))
        return uid

    def add_session(self, uid, expires_days_ago=None, revoked_days_ago=None):
        if revoked_days_ago is not None:
            sql = ("INSERT INTO sessions (token_hash, user_id, expires_at,"
                   " revoked_at) VALUES (%s, %s,"
                   " now() + interval '1 day',"
                   " now() - (%s || ' days')::interval)")
            params = [os.urandom(32), uid, str(revoked_days_ago)]
        elif expires_days_ago is not None:
            sql = ("INSERT INTO sessions (token_hash, user_id, expires_at)"
                   " VALUES (%s, %s,"
                   " now() - (%s || ' days')::interval)")
            params = [os.urandom(32), uid, str(expires_days_ago)]
        else:
            sql = ("INSERT INTO sessions (token_hash, user_id, expires_at)"
                   " VALUES (%s, %s, now() + interval '1 day')")
            params = [os.urandom(32), uid]
        self.db_exec(sql, tuple(params))

    def add_token(self, uid, used_days_ago=None, expires_days_ago=None):
        if used_days_ago is not None:
            self.db_exec(
                "INSERT INTO password_reset_tokens"
                " (token_hash, user_id, expires_at, used_at)"
                " VALUES (%s, %s, now() - (%s || ' days')::interval,"
                " now() - (%s || ' days')::interval)",
                (os.urandom(32), uid, str(used_days_ago),
                 str(used_days_ago)))
        elif expires_days_ago is not None:
            self.db_exec(
                "INSERT INTO password_reset_tokens"
                " (token_hash, user_id, expires_at)"
                " VALUES (%s, %s, now() - (%s || ' days')::interval)",
                (os.urandom(32), uid, str(expires_days_ago)))
        else:
            self.db_exec(
                "INSERT INTO password_reset_tokens"
                " (token_hash, user_id, expires_at)"
                " VALUES (%s, %s, now() + interval '1 hour')",
                (os.urandom(32), uid))

    def add_notification(self, uid, age_days):
        self.db_exec(
            "INSERT INTO notifications (user_id, kind, created_at)"
            " VALUES (%s, 'scan_summary',"
            " now() - (%s || ' days')::interval)",
            (uid, str(age_days)))

    def count(self, table, uid=None, col="user_id"):
        if uid is None:
            row = self.db_row("SELECT COUNT(*) AS n FROM %s" % table)
        else:
            row = self.db_row(
                "SELECT COUNT(*) AS n FROM %s WHERE %s = %%s" % (table, col),
                (uid,))
        return row["n"]

    def seed_full_account(self, uid):
        """Everything a purge must remove, for one soft-deleted user."""
        self.db_exec(
            "INSERT INTO households (owner_user_id) VALUES (%s)", (uid,))
        hid = self.db_row(
            "SELECT id FROM households WHERE owner_user_id = %s",
            (uid,))["id"]
        self.db_exec(
            "INSERT INTO household_members (id, household_id, label)"
            " VALUES (%s, %s, 'Mum')", (str(uuid.uuid4()), hid))
        mid = self.db_row(
            "SELECT id FROM household_members WHERE household_id = %s",
            (hid,))["id"]
        self.db_exec(
            "INSERT INTO identifiers (user_id, kind, hmac_lookup,"
            " ciphertext, masked, member_id)"
            " VALUES (%s, 'email', %s, %s, 'u•••@example.com', %s)",
            (uid, os.urandom(32), os.urandom(32), mid))
        self.db_exec(
            "INSERT INTO consents (user_id, purpose, version, granted)"
            " VALUES (%s, 'scanning', 1, true)", (uid,))
        self.db_exec(
            "INSERT INTO user_settings (user_id) VALUES (%s)", (uid,))
        self.db_exec(
            "INSERT INTO domains (user_id, domain, verify_token)"
            " VALUES (%s, 'example.org', 'tok')", (uid,))
        job = self.db_row(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status)"
            " VALUES (%s, 'k1', 'done') RETURNING id", (uid,))
        self.db_exec(
            "INSERT INTO findings (job_id, user_id, identifier_kind,"
            " provider, source_name, confidence, reliability,"
            " evidence_ref) VALUES (%s, %s, 'email', 'mock', 'Src',"
            " 'exact', 'high', 'ref')", (job["id"], uid))
        self.db_exec(
            "INSERT INTO brokers (slug, name, category, region,"
            " optout_url) VALUES ('retention-test-broker', 'RT Broker',"
            " 'people_search', 'US', 'https://example.org/optout')"
            " ON CONFLICT (slug) DO NOTHING")
        case = self.db_row(
            "INSERT INTO remediation_cases (user_id, broker_slug, status)"
            " VALUES (%s, 'retention-test-broker', 'submitted')"
            " RETURNING id", (uid,))
        self.db_exec(
            "INSERT INTO remediation_attempts (case_id, attempt_no,"
            " action, result) VALUES (%s, 1, 'submit', 'ok')",
            (case["id"],))
        self.db_exec(
            "INSERT INTO verification_checks (case_id, method, outcome)"
            " VALUES (%s, 'search', 'unknown')", (case["id"],))

    def test_retention_pass(self):
        # --- live user: aged rows die, fresh rows survive ---
        live = self.make_user()
        self.add_session(live)                          # fresh -> kept
        self.add_session(live, expires_days_ago=8)      # -> deleted
        self.add_session(live, revoked_days_ago=8)      # -> deleted
        self.add_session(live, revoked_days_ago=1)      # -> kept
        self.add_token(live)                            # pending -> kept
        self.add_token(live, used_days_ago=8)           # -> deleted
        self.add_token(live, expires_days_ago=8)        # -> deleted
        self.add_notification(live, 91)                 # -> deleted
        self.add_notification(live, 10)                 # -> kept

        # --- soft-deleted 31 days ago: fully purged ---
        gone = self.make_user(deleted_days_ago=31)
        self.seed_full_account(gone)
        self.add_notification(gone, 1)
        self.add_session(gone)

        # --- soft-deleted 29 days ago: inside the grace period ---
        recent = self.make_user(deleted_days_ago=29)
        self.db_exec(
            "INSERT INTO identifiers (user_id, kind, hmac_lookup,"
            " ciphertext, masked) VALUES (%s, 'email', %s, %s,"
            " 'u•••@example.com')",
            (recent, os.urandom(32), os.urandom(32)))

        audit_before = self.count("audit_log")
        counts = retention.run_once()

        self.assertEqual(counts["sessions"], 2, counts)
        self.assertEqual(counts["reset_tokens"], 2, counts)
        self.assertGreaterEqual(counts["notifications"], 1, counts)
        self.assertEqual(counts["users_purged"], 1, counts)

        # Live user's survivors are exactly the fresh rows.
        self.assertEqual(self.count("sessions", live), 2)
        self.assertEqual(self.count("password_reset_tokens", live), 1)
        self.assertEqual(self.count("notifications", live), 1)
        self.assertIsNotNone(self.db_row(
            "SELECT id FROM users WHERE id = %s", (live,)))

        # The 31-day account is gone from every table it touched.
        self.assertIsNone(self.db_row(
            "SELECT id FROM users WHERE id = %s", (gone,)))
        for table, col in (
                ("identifiers", "user_id"), ("consents", "user_id"),
                ("sessions", "user_id"), ("notifications", "user_id"),
                ("scan_jobs", "user_id"), ("findings", "user_id"),
                ("remediation_cases", "user_id"),
                ("domains", "user_id"), ("user_settings", "user_id"),
                ("households", "owner_user_id")):
            self.assertEqual(self.count(table, gone, col), 0,
                             "%s still holds the purged user" % table)
        self.assertEqual(self.db_row(
            "SELECT COUNT(*) AS n FROM household_members")["n"], 0)
        self.assertEqual(self.db_row(
            "SELECT COUNT(*) AS n FROM remediation_attempts")["n"], 0)
        self.assertEqual(self.db_row(
            "SELECT COUNT(*) AS n FROM verification_checks")["n"], 0)

        # The 29-day account is untouched.
        self.assertIsNotNone(self.db_row(
            "SELECT id FROM users WHERE id = %s", (recent,)))
        self.assertEqual(self.count("identifiers", recent), 1)

        # The run itself is audited, PII-free, system actor.
        self.assertGreater(self.count("audit_log"), audit_before)
        row = self.db_row(
            "SELECT * FROM audit_log WHERE action = 'retention.purge'"
            " ORDER BY id DESC LIMIT 1")
        self.assertIsNotNone(row)
        self.assertEqual(row["actor_kind"], "system")
        self.assertIsNone(row["actor_user_id"])
        self.assertEqual(row["detail"]["users_purged"], 1)

    def test_start_when_configured(self):
        self.assertTrue(retention.start_retention_if_configured())
        retention.stop_retention()


if __name__ == "__main__":
    unittest.main()
