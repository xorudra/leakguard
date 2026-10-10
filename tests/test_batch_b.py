"""Final-spec Batch B tests — platform depth (spec Phases 49, 88,
120, 122, 142, 159).

Layers:

* TestFlagsUnit — offline: core/flags.py parsing (default ON, the
  off values, anything else ON, unknown flags rejected, snapshot).
* TestVersioningNoDb — no database: /api/v1/* reaches the same
  handlers as /api/* (health, providers, anonymous scan validation,
  an accounts read, POST dispatch), unknown v1 paths 404, and the
  old GET export route is gone.
* TestBatchBDb — against a local PostgreSQL (pgserver, mock
  providers): the password-gated export in JSON + CSV, its
  rate-limit accounting, the four flag gates end to end (including
  the anonymous scan staying open and the admin overview's flags),
  the scan queue's manual-before-monitor priority, and the
  monitoring pause (scheduler skips, consent untouched, resume
  restores).

Run:  python3 -m unittest discover -s tests
"""

import csv
import io
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
from core import flags  # noqa: E402
from monitoring import scheduler  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from scanning import worker as scan_worker  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
FLAG_KEYS = tuple("LEAKGUARD_FLAG_" + name.upper()
                  for name in flags.FLAGS)
OTHER_KEYS = ("LEAKGUARD_PROVIDERS", "ADMIN_EMAILS")


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

    def request(self, method, path, body=None, cookie=None, headers=None):
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


# ---------------------------------------------------------------------------
# Feature flags, offline
# ---------------------------------------------------------------------------

class TestFlagsUnit(unittest.TestCase):
    def setUp(self):
        self._env = EnvGuard(FLAG_KEYS).__enter__()
        for key in FLAG_KEYS:
            os.environ.pop(key, None)

    def tearDown(self):
        self._env.__exit__()

    def test_default_on(self):
        for name in flags.FLAGS:
            self.assertTrue(flags.is_enabled(name), name)
        self.assertEqual(flags.snapshot(),
                         {name: True for name in flags.FLAGS})

    def test_off_values(self):
        for value in ("0", "false", "off", "no", "OFF", " No ", "False"):
            os.environ["LEAKGUARD_FLAG_REGISTRATION"] = value
            self.assertFalse(flags.is_enabled("registration"), value)

    def test_other_values_mean_on(self):
        for value in ("1", "true", "on", "yes", "anything"):
            os.environ["LEAKGUARD_FLAG_REMOVAL_RUNS"] = value
            self.assertTrue(flags.is_enabled("removal_runs"), value)

    def test_unknown_flag_rejected(self):
        with self.assertRaises(ValueError):
            flags.is_enabled("nonsense")
        with self.assertRaises(ValueError):
            flags.env_key("nonsense")


# ---------------------------------------------------------------------------
# API versioning, no database
# ---------------------------------------------------------------------------

class TestVersioningNoDb(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(ENV_KEYS + FLAG_KEYS).__enter__()
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def test_health_same_shape(self):
        s1, _h, b1 = self.request_json("GET", "/api/health")
        s2, _h, b2 = self.request_json("GET", "/api/v1/health")
        self.assertEqual((s1, s2), (200, 200))
        self.assertEqual(b1, b2)

    def test_providers_health_same(self):
        s1, _h, b1 = self.request_json("GET", "/api/providers/health")
        s2, _h, b2 = self.request_json("GET", "/api/v1/providers/health")
        self.assertEqual((s1, s2), (200, 200))
        self.assertEqual(b1["mode"], b2["mode"])

    def test_anonymous_scan_validation_same(self):
        for path in ("/api/scan", "/api/v1/scan"):
            status, _h, body = self.request_json(
                "POST", path, body={"email": "not-an-email"},
                headers=CSRF)
            self.assertEqual(status, 400, path)
            self.assertEqual(body["error"]["code"], "invalid_email", path)

    def test_accounts_read_same_503(self):
        for path in ("/api/auth/me", "/api/v1/auth/me"):
            status, _h, body = self.request_json("GET", path)
            self.assertEqual(status, 503, path)
            self.assertEqual(body["error"]["code"], "db_unavailable", path)

    def test_post_dispatch_normalized(self):
        # Reaching the accounts dispatcher at all is proven by the
        # CSRF guard answering (an unnormalized path would 404).
        status, _h, body = self.request_json(
            "POST", "/api/v1/auth/register",
            body={"email": "a@example.com", "password": "long-enough-1", "policy_accepted": True})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_unknown_v1_paths_404(self):
        for path in ("/api/v1/nope", "/api/v1", "/api/v2/health"):
            status, _h, body = self.request_json("GET", path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body["error"]["code"], "not_found", path)


# ---------------------------------------------------------------------------
# Full flow against a local PostgreSQL (pgserver) + mock providers
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


class PgClassMixin:
    """pgserver provisioning, mirroring tests/test_monitoring.py."""

    @classmethod
    def _start_pg(cls, prefix):
        import tempfile

        keys = ENV_KEYS + OTHER_KEYS + FLAG_KEYS
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix=prefix)
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        import base64

        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        registry_mod.reset_registry()
        for key in FLAG_KEYS + ("ADMIN_EMAILS",):
            os.environ.pop(key, None)
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
        registry_mod.reset_registry()
        cls._env.__exit__()

    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def db_rows(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()


class AccountMixin:
    PASSWORD = "batch-b-password-1"

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "batchb-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD,
                  "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers", body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def set_consent(self, cookie, purpose, granted):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": purpose, "granted": granted},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestBatchBDb(PgClassMixin, ServerMixin, AccountMixin,
                   unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._start_pg("lg-batchb-pg-")
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()
        self._flag_env = EnvGuard(FLAG_KEYS + ("ADMIN_EMAILS",)).__enter__()
        for key in FLAG_KEYS + ("ADMIN_EMAILS",):
            os.environ.pop(key, None)

    def tearDown(self):
        self._flag_env.__exit__()

    # ----- Phase 88 with a database: versioned == unversioned -----

    def test_versioned_routes_match_unversioned(self):
        cookie, user_id, _email = self.register()
        s1, _h, b1 = self.request_json("GET", "/api/auth/me",
                                       cookie=cookie)
        s2, _h, b2 = self.request_json("GET", "/api/v1/auth/me",
                                       cookie=cookie)
        self.assertEqual((s1, s2), (200, 200))
        self.assertEqual(b1["id"], b2["id"])
        self.add_identifier(cookie, "email", "v1-%s@example.com"
                            % self.uniq())
        self.set_consent(cookie, "scanning", True)
        status, _h, body = self.request_json(
            "POST", "/api/v1/scans", body={"idempotency_key": "v1-scan"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        job_id = body["job"]["id"]
        s1, _h, b1 = self.request_json("GET", "/api/scans", cookie=cookie)
        s2, _h, b2 = self.request_json("GET", "/api/v1/scans",
                                       cookie=cookie)
        self.assertEqual([j["id"] for j in b1["jobs"]],
                         [j["id"] for j in b2["jobs"]])
        status, _h, body = self.request_json(
            "GET", "/api/v1/scans/" + job_id, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body["job"]["id"], job_id)

    # ----- Phase 49: the gated export -----

    def _export(self, cookie, password, fmt="json"):
        return self.request(
            "POST", "/api/privacy/export",
            body={"password": password, "format": fmt},
            headers=CSRF, cookie=cookie)

    def test_export_password_gate_and_formats(self):
        cookie, user_id, _email = self.register()
        phone = "+1 555 010 2233"
        self.add_identifier(cookie, "phone", phone)
        self.set_consent(cookie, "monitoring", True)

        # Unauthenticated: 401, no data.
        status, _h, payload = self._export(None, self.PASSWORD)
        self.assertEqual(status, 401)
        self.assertNotIn(phone.encode(), payload)

        # GET is gone entirely.
        status, _h, _b = self.request_json(
            "GET", "/api/privacy/export", cookie=cookie)
        self.assertEqual(status, 404)

        # Wrong password: the login-identical 401, and nothing leaks.
        status, _h, payload = self._export(cookie, "wrong-password-9")
        self.assertEqual(status, 401)
        body = json.loads(payload.decode("utf-8"))
        self.assertEqual(body["error"]["code"], "invalid_credentials")
        self.assertNotIn(phone.encode(), payload)

        # Bad format: 400 before any password work matters.
        status, _h, payload = self._export(cookie, self.PASSWORD, "xml")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload.decode("utf-8"))
                         ["error"]["code"], "invalid_format")

        # JSON: the full document, as an attachment.
        status, headers, payload = self._export(cookie, self.PASSWORD)
        self.assertEqual(status, 200)
        self.assertIn("leakguard-export.json",
                      headers.get("Content-Disposition") or "")
        document = json.loads(payload.decode("utf-8"))
        self.assertEqual(len(document["identifiers"]), 1)
        self.assertEqual(document["identifiers"][0]["value"], phone)

        # CSV: parses, same identifier rows as the JSON document.
        status, headers, payload = self._export(
            cookie, self.PASSWORD, "csv")
        self.assertEqual(status, 200)
        self.assertIn("leakguard-export.csv",
                      headers.get("Content-Disposition") or "")
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"))))
        self.assertEqual(rows[0], ["section", "record", "field", "value"])
        ident_rows = [r for r in rows[1:] if r[0] == "identifiers"]
        csv_values = {r[2]: r[3] for r in ident_rows}
        json_ident = document["identifiers"][0]
        self.assertEqual(csv_values["kind"], json_ident["kind"])
        self.assertEqual(csv_values["value"], json_ident["value"])
        self.assertEqual(csv_values["masked"], json_ident["masked"])
        account_rows = [r for r in rows[1:] if r[0] == "account"]
        # The CSV carries precisely the JSON's account fields —
        # 'name' included (wave-1 F29 fix: it was silently dropped).
        self.assertEqual({r[2] for r in account_rows},
                         {"email", "email_masked", "name", "created_at"})

        # Both successful exports were audited, with their formats.
        audit_rows = self.db_rows(
            "SELECT detail FROM audit_log WHERE actor_user_id = %s"
            " AND action = 'privacy_export'", (user_id,))
        formats = sorted(r["detail"]["format"] for r in audit_rows)
        self.assertEqual(formats, ["csv", "json"])

    def test_export_attempts_count_toward_credential_limit(self):
        cookie, _user_id, _email = self.register()  # attempt #1
        for attempt in range(9):  # attempts #2..#10: still 401s
            status, _h, _p = self._export(cookie, "wrong-password-9")
            self.assertEqual(status, 401, attempt)
        # Attempt #11: the shared credential bucket is exhausted —
        # even the CORRECT password now gets the limiter's 429.
        status, _h, payload = self._export(cookie, self.PASSWORD)
        self.assertEqual(status, 429)
        self.assertEqual(json.loads(payload.decode("utf-8"))
                         ["error"]["code"], "rate_limited")

    # ----- Phases 120/122: the flag gates -----

    def test_flag_registration_gate(self):
        os.environ["LEAKGUARD_FLAG_REGISTRATION"] = "off"
        status, _h, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": "gated-%s@example.com" % self.uniq(),
                  "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "feature_disabled")
        del os.environ["LEAKGUARD_FLAG_REGISTRATION"]
        self.register()  # works again once the flag lifts

    def test_flag_account_scans_gate_anonymous_stays_open(self):
        cookie, _user_id, _email = self.register()
        self.add_identifier(cookie, "email",
                            "gate-%s@example.com" % self.uniq())
        self.set_consent(cookie, "scanning", True)
        os.environ["LEAKGUARD_FLAG_ACCOUNT_SCANS"] = "off"
        status, _h, body = self.request_json(
            "POST", "/api/scans", body={"idempotency_key": "gated"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "feature_disabled")
        # The anonymous Quick Scan is never flag-gated.
        status, _h, body = self.request_json(
            "POST", "/api/scan", body={"email": "test@example.com"},
            headers=CSRF)
        self.assertEqual(status, 200)
        self.assertIn("breach_count", body)
        del os.environ["LEAKGUARD_FLAG_ACCOUNT_SCANS"]
        status, _h, body = self.request_json(
            "POST", "/api/scans", body={"idempotency_key": "ungated"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)

    def test_flag_removal_runs_gate(self):
        cookie, _user_id, _email = self.register()
        os.environ["LEAKGUARD_FLAG_REMOVAL_RUNS"] = "0"
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "feature_disabled")
        del os.environ["LEAKGUARD_FLAG_REMOVAL_RUNS"]
        # Gate lifted: the next wall is the consent gate (403),
        # proving the flag — not the route — was what answered 503.
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "consent_required")

    def test_flag_scheduler_gate(self):
        cookie, user_id, _email = self.register()
        self.add_identifier(cookie, "email",
                            "sched-%s@example.com" % self.uniq())
        self.set_consent(cookie, "monitoring", True)
        os.environ["LEAKGUARD_FLAG_MONITORING_SCHEDULER"] = "off"
        self.assertEqual(scheduler.tick(), [])
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM scan_jobs WHERE user_id = %s",
            (user_id,))
        self.assertEqual(row["n"], 0)
        del os.environ["LEAKGUARD_FLAG_MONITORING_SCHEDULER"]
        created = scheduler.tick()
        self.assertTrue(created)
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM scan_jobs WHERE user_id = %s",
            (user_id,))
        self.assertEqual(row["n"], 1)

    def test_admin_overview_reports_flags(self):
        cookie, _user_id, email = self.register()
        os.environ["ADMIN_EMAILS"] = email
        status, _h, body = self.request_json(
            "GET", "/api/admin/overview", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["flags"],
                         {name: True for name in flags.FLAGS})
        os.environ["LEAKGUARD_FLAG_REGISTRATION"] = "off"
        status, _h, body = self.request_json(
            "GET", "/api/admin/overview", cookie=cookie)
        self.assertFalse(body["flags"]["registration"])
        self.assertTrue(body["flags"]["removal_runs"])

    # ----- Phase 159: manual work outranks scheduled work -----

    def test_priority_manual_before_monitor_fifo_within_class(self):
        _cookie, user_id, _email = self.register()
        with self.pool.connection() as conn:
            # Clear any queued leftovers from other tests in this
            # class DB: the claim is global, by design.
            conn.execute(
                "UPDATE scan_jobs SET status = 'dead'"
                " WHERE status IN ('queued', 'failed')")
            ids = {}
            for label, key, minutes in (
                    ("monitor_old", "monitor-x-2026-01-01", 3),
                    ("manual", "hand-started-1", 2),
                    ("monitor_new", "monitor-x-2026-01-08", 1)):
                row = conn.execute(
                    "INSERT INTO scan_jobs"
                    " (user_id, idempotency_key, created_at)"
                    " VALUES (%s, %s,"
                    " now() - (%s || ' minutes')::interval)"
                    " RETURNING id",
                    (user_id, key, str(minutes)),
                ).fetchone()
                ids[label] = str(row["id"])
        claimed = [scan_worker.claim_job()[0] for _ in range(3)]
        self.assertEqual(claimed, [ids["manual"], ids["monitor_old"],
                                   ids["monitor_new"]])

    # ----- Phase 142: pause is not consent withdrawal -----

    def test_monitoring_pause_and_resume(self):
        cookie, user_id, _email = self.register()
        self.add_identifier(cookie, "email",
                            "pause-%s@example.com" % self.uniq())
        self.set_consent(cookie, "monitoring", True)

        status, _h, body = self.request_json(
            "GET", "/api/monitoring/settings", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertFalse(body["monitoring_paused"])
        self.assertTrue(body["monitoring_consent"])

        consent_rows_before = self.db_row(
            "SELECT COUNT(*) AS n FROM consents WHERE user_id = %s",
            (user_id,))["n"]

        # Pause: settings show it, the scheduler skips the user,
        # and the consent record is byte-for-byte untouched.
        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"monitoring_paused": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["monitoring_paused"])
        self.assertTrue(body["monitoring_consent"])
        scheduler.tick()
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM scan_jobs WHERE user_id = %s",
            (user_id,))
        self.assertEqual(row["n"], 0)
        consent = self.db_row(
            "SELECT granted FROM consents WHERE user_id = %s"
            " AND purpose = 'monitoring' ORDER BY version DESC"
            " LIMIT 1", (user_id,))
        self.assertTrue(consent["granted"])
        self.assertEqual(
            self.db_row("SELECT COUNT(*) AS n FROM consents"
                        " WHERE user_id = %s", (user_id,))["n"],
            consent_rows_before)

        # A cadence change while paused keeps the pause.
        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"cadence_days": 14}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cadence_days"], 14)
        self.assertTrue(body["monitoring_paused"])

        # Resume: the next tick enqueues the scheduled scan again.
        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"monitoring_paused": False},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertFalse(body["monitoring_paused"])
        scheduler.tick()
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM scan_jobs WHERE user_id = %s",
            (user_id,))
        self.assertEqual(row["n"], 1)


if __name__ == "__main__":
    unittest.main()
