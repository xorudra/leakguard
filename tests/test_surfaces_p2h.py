"""Surface tests for P2-H (spec Phases 125, 40, 67).

Layers:

* TestBrokerHealthDb — pgserver + HTTP: the admin overview's
  broker_health block aggregates verification_checks outcomes,
  remediation_cases by status and remediation_attempts by result
  per broker, computed from seeded rows; brokers with no removal
  activity are absent; removed_rate is decisive-checks-only (None
  when nothing decisive yet); a non-admin still gets the house
  404 for the whole overview.
* TestSearchExposureDb — pgserver + HTTP: GET /api/search-exposure
  is owner-gated (anonymous 401, another user's findings never
  appear), returns ONLY public_web_mention discovery findings
  (breach findings and platform-presence findings excluded),
  grouped by identifier with the masked rendering, newest first,
  and answers the honest empty state for a user with none.
* TestCachePolicyDb — pgserver + HTTP: representative account
  API responses (search-exposure, notifications, scans, admin
  overview) all carry Cache-Control: no-store (Phase 67).

Against local PostgreSQL provisioned with pip `pgserver` (skips
honestly when unavailable). Test accounts use unique example.com
addresses.

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
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS")
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
class SurfacesDbBase(ServerMixin):
    """Shared pgserver provisioning — a FRESH database per class."""

    ADMIN_EMAIL = None

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-p2h-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest(
                "pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        if cls.ADMIN_EMAIL:
            os.environ["ADMIN_EMAILS"] = cls.ADMIN_EMAIL
        else:
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
        registry_seed.seed_brokers()
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
        email = email or "p2h-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).rowcount

    def db_all(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def db_one(self, sql, params=()):
        rows = self.db_all(sql, params)
        return rows[0] if rows else None

    def broker_slug(self, name):
        row = self.db_one(
            "SELECT slug FROM brokers WHERE name = %s", (name,))
        self.assertIsNotNone(row, "broker %s not seeded" % name)
        return row["slug"]

    def add_case(self, user_id, slug, status):
        row = self.db_one(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status) VALUES (%s, %s, %s) RETURNING id",
            (user_id, slug, status))
        return str(row["id"])

    def add_check(self, case_id, outcome):
        self.db_exec(
            "INSERT INTO verification_checks (case_id, method,"
            " outcome) VALUES (%s, 'search', %s)", (case_id, outcome))

    def add_attempt(self, case_id, attempt_no, result):
        self.db_exec(
            "INSERT INTO remediation_attempts (case_id, attempt_no,"
            " action, result) VALUES (%s, %s, 'submit', %s)",
            (case_id, attempt_no, result))


# ---------------------------------------------------------------------------
# Phase 125 — per-broker verification + workflow health
# ---------------------------------------------------------------------------

class TestBrokerHealthDb(SurfacesDbBase, unittest.TestCase):

    # One shared class database: each test registers its OWN admin
    # address (re-registering one address would 409) and points
    # ADMIN_EMAILS at it — is_admin reads the env live.
    ADMIN_EMAIL = "p2h-admin@example.com"

    def register_admin(self):
        email = "p2h-admin-%s@example.com" % self.uniq()
        os.environ["ADMIN_EMAILS"] = email
        cookie, user_id, _ = self.register(email)
        return cookie, user_id

    def test_broker_health_aggregates_seeded_activity(self):
        admin_cookie, _admin_id = self.register_admin()
        _cookie, user_id, _ = self.register()
        spokeo = self.broker_slug("Spokeo")
        checkpeople = self.broker_slug("CheckPeople")

        # Spokeo: one verified_removed case (2 gone, 1 still, 1
        # unknown across its checks) + one submitted case.
        removed = self.add_case(user_id, spokeo, "verified_removed")
        self.add_check(removed, "gone")
        self.add_check(removed, "gone")
        self.add_check(removed, "still_present")
        self.add_check(removed, "unknown")
        self.add_attempt(removed, 1, "submitted")
        self.add_attempt(removed, 2, "submitted")
        pending = self.add_case(user_id, spokeo, "submitted")
        self.add_attempt(pending, 1, "blocked")
        # CheckPeople: one needs_human case, one decisive gone.
        human = self.add_case(user_id, checkpeople, "needs_human")
        self.add_check(human, "gone")
        self.add_attempt(human, 1, "needs_human")

        status, _h, body = self.request_json(
            "GET", "/api/admin/overview", cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        health = {row["slug"]: row for row in body["broker_health"]}

        sp = health[spokeo]
        self.assertEqual(sp["name"], "Spokeo")
        self.assertEqual(sp["verification"], {
            "checks": 4, "gone": 2, "still_present": 1, "unknown": 1,
            "removed_rate": 0.667})
        self.assertEqual(sp["cases"],
                         {"verified_removed": 1, "submitted": 1})
        self.assertEqual(sp["attempts"],
                         {"submitted": 2, "blocked": 1})

        cp = health[checkpeople]
        self.assertEqual(cp["verification"]["checks"], 1)
        self.assertEqual(cp["verification"]["removed_rate"], 1.0)
        self.assertEqual(cp["cases"], {"needs_human": 1})
        self.assertEqual(cp["attempts"], {"needs_human": 1})

        # A broker with no removal activity has no health row.
        idle = self.broker_slug("Whitepages")
        self.assertNotIn(idle, health)

    def test_broker_health_removed_rate_none_without_decisive(self):
        admin_cookie, _admin_id = self.register_admin()
        _cookie, user_id, _ = self.register()
        slug = self.broker_slug("TruePeopleSearch")
        case = self.add_case(user_id, slug, "submitted")
        self.add_check(case, "unknown")
        self.add_check(case, "unknown")
        status, _h, body = self.request_json(
            "GET", "/api/admin/overview", cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        health = {row["slug"]: row for row in body["broker_health"]}
        ver = health[slug]["verification"]
        self.assertEqual(ver["checks"], 2)
        self.assertIsNone(ver["removed_rate"])

    def test_broker_health_hidden_from_non_admin(self):
        cookie, _uid, _email = self.register()
        status, _h, _b = self.request_json(
            "GET", "/api/admin/overview", cookie=cookie)
        self.assertEqual(status, 404)
        status, _h, _b = self.request_json("GET", "/api/admin/overview")
        self.assertEqual(status, 404)


# ---------------------------------------------------------------------------
# Phase 40 — search exposure API
# ---------------------------------------------------------------------------

class TestSearchExposureDb(SurfacesDbBase, unittest.TestCase):

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]["id"], body["identifier"]["masked"]

    def add_job(self, user_id):
        row = self.db_one(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status)"
            " VALUES (%s, %s, 'done') RETURNING id",
            (user_id, uuid.uuid4().hex))
        return str(row["id"])

    def add_finding(self, job_id, user_id, identifier_id, kind,
                    provider, match_kind, source_name, days_ago=0):
        details = json.dumps({"match_kind": match_kind})
        row = self.db_one(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, source_url,"
            " discovered_at, exposed_fields, confidence, reliability,"
            " evidence_ref, details)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s,"
            " now() - (%s || ' days')::interval, %s, 'weak', 'low',"
            " %s, %s::jsonb) RETURNING id",
            (job_id, user_id, identifier_id, kind, provider,
             source_name, "https://%s.example.com/listing" % source_name,
             str(days_ago), [kind], "e" * 64, details))
        return str(row["id"])

    def seed_user(self):
        # Identifier VALUES are globally unique by lookup hash, so
        # each seeding uses fresh ones (the class database is
        # shared across this class's tests).
        cookie, user_id, _email = self.register()
        suffix = str(uuid.uuid4().int % 10000).zfill(4)
        phone_id, phone_masked = self.add_identifier(
            cookie, "phone", "+1 555 010 " + suffix)
        user_iden, _m = self.add_identifier(
            cookie, "username", "rudra" + self.uniq())
        job = self.add_job(user_id)
        # Two discovery mentions for the phone (newest seeded last
        # via days_ago), one for the username.
        self.add_finding(job, user_id, phone_id, "phone",
                         "DuckDuckGo Discovery", "public_web_mention",
                         "peoplefinders.example.com", days_ago=5)
        self.add_finding(job, user_id, phone_id, "phone",
                         "DuckDuckGo Discovery", "public_web_mention",
                         "searchpeople.example.com", days_ago=1)
        self.add_finding(job, user_id, user_iden, "username",
                         "DuckDuckGo Discovery", "public_web_mention",
                         "socialsearch.example.com", days_ago=2)
        # NOT discovery: a breach finding and a platform-presence
        # finding must never appear in this view.
        self.add_finding(job, user_id, phone_id, "phone",
                         "XposedOrNot", "breach_record",
                         "breach.example.com", days_ago=0)
        self.add_finding(job, user_id, user_iden, "username",
                         "Username Platforms", "handle_registered",
                         "github", days_ago=0)
        return cookie, user_id, phone_masked

    def test_owner_sees_grouped_discovery_findings_only(self):
        cookie, _uid, phone_masked = self.seed_user()
        status, _h, body = self.request_json(
            "GET", "/api/search-exposure", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["total_findings"], 3)
        groups = {g["identifier_kind"]: g
                  for g in body["identifiers"]}
        self.assertEqual(set(groups), {"phone", "username"})
        phone = groups["phone"]
        self.assertEqual(phone["identifier_masked"], phone_masked)
        self.assertEqual(len(phone["findings"]), 2)
        # Newest first.
        self.assertEqual(phone["findings"][0]["source_name"],
                         "searchpeople.example.com")
        for finding in phone["findings"]:
            self.assertEqual(finding["provider"],
                             "DuckDuckGo Discovery")
            self.assertEqual(finding["confidence"], "weak")
            self.assertTrue(finding["source_url"].startswith("https://"))
        self.assertEqual(len(groups["username"]["findings"]), 1)

    def test_other_users_findings_never_leak(self):
        cookie_a, _a, _m = self.seed_user()
        cookie_b, user_b, _e = self.register()
        name_id, _m2 = self.add_identifier(cookie_b, "name", "Rudra Singh")
        job_b = self.add_job(user_b)
        self.add_finding(job_b, user_b, name_id, "name",
                         "DuckDuckGo Discovery", "public_web_mention",
                         "b-only.example.com", days_ago=0)
        status, _h, body_b = self.request_json(
            "GET", "/api/search-exposure", cookie=cookie_b)
        self.assertEqual(status, 200, body_b)
        self.assertEqual(body_b["total_findings"], 1)
        self.assertEqual(body_b["identifiers"][0]["findings"][0]
                         ["source_name"], "b-only.example.com")
        status, _h, body_a = self.request_json(
            "GET", "/api/search-exposure", cookie=cookie_a)
        self.assertEqual(status, 200, body_a)
        names = [f["source_name"] for g in body_a["identifiers"]
                 for f in g["findings"]]
        self.assertNotIn("b-only.example.com", names)

    def test_empty_state_and_anonymous_gate(self):
        status, _h, _b = self.request_json("GET", "/api/search-exposure")
        self.assertEqual(status, 401)
        cookie, _uid, _e = self.register()
        status, _h, body = self.request_json(
            "GET", "/api/search-exposure", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["identifiers"], [])
        self.assertEqual(body["total_findings"], 0)


# ---------------------------------------------------------------------------
# Phase 67 — cache headers on account APIs (DB-backed representatives)
# ---------------------------------------------------------------------------

class TestCachePolicyDb(SurfacesDbBase, unittest.TestCase):

    ADMIN_EMAIL = "p2h-cache-admin@example.com"

    def test_account_apis_carry_no_store(self):
        admin_email = "p2h-cache-admin-%s@example.com" % self.uniq()
        os.environ["ADMIN_EMAILS"] = admin_email
        admin_cookie, _aid, _e = self.register(admin_email)
        cookie, _uid, _e2 = self.register()
        for path, ck in (("/api/search-exposure", cookie),
                         ("/api/notifications", cookie),
                         ("/api/scans", cookie),
                         ("/api/identifiers", cookie),
                         ("/api/admin/overview", admin_cookie),
                         ("/api/admin/metrics", admin_cookie)):
            status, headers, _b = self.request_json(
                "GET", path, cookie=ck)
            self.assertEqual(status, 200, path)
            self.assertEqual(headers.get("Cache-Control"), "no-store",
                             path)


if __name__ == "__main__":
    unittest.main()
