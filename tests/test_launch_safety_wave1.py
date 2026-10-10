"""Launch Safety Standard wave-1 fixes (2026-10-10).

Pins, one class per finding:

* TestPolicyAcceptance — F26: registration refuses without the
  Privacy Policy / Terms agreement (HTTP and service layer), and a
  registration WITH it records a versioned 'policy_acceptance'
  entry in the consent ledger that shows up in the data export.
* TestExportCompleteness — F29: the export carries scan jobs,
  findings, remediation cases, notifications, settings, household
  members and passkey/API-token METADATA (never key material or
  token values); the CSV carries precisely the JSON's data — the
  account 'name' included (the regression this wave fixes).
* TestAnonCsrf — A2: the anonymous POST routes (/api/scan,
  /api/agent/plan|probe|submit) enforce the same CSRF guard as the
  account routes; the product's own callers (X-Requested-With, or
  a same-host Origin) pass.
* TestResetPasswordRateLimit — A10: POST /api/auth/reset-password
  has a per-IP rate limit like every other route class.

DB classes skip honestly when no database is reachable (same
pattern as test_accounts.py: DATABASE_URL env, else the
owner-only .neon-database-url file). No pytest — unittest only,
CI runs `python -m unittest discover -s tests`.

Run:  python3 -m unittest discover -s tests
"""

import base64
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
from accounts import consents, ratelimit  # noqa: E402
from core import ratelimit as core_ratelimit  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

REPO_ROOT = Path(__file__).resolve().parent.parent
NEON_FILE = REPO_ROOT / ".neon-database-url"
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
CSRF = {"X-Requested-With": "fetch"}
PASSWORD = "correct-horse-battery-9"


def _database_url():
    # Env var first, else the owner-only file (repo test convention).
    url = os.environ.get("DATABASE_URL")
    if url:
        return url.strip()
    try:
        text = NEON_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return text or None


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


class DbServerMixin(ServerMixin):
    """Server + real PostgreSQL, skipping honestly without one."""

    @classmethod
    def setUpClass(cls):
        url = _database_url()
        if not url:
            raise unittest.SkipTest(
                "no DATABASE_URL and no .neon-database-url file")
        cls._env = EnvGuard().__enter__()
        os.environ["DATABASE_URL"] = url
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._env.__exit__()
            raise unittest.SkipTest(
                "PostgreSQL configured but not reachable from this host")
        migrate.run_migrations()
        cls.user_ids = []
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        try:
            with cls.pool.connection() as conn:
                for uid in cls.user_ids:
                    conn.execute(
                        "DELETE FROM households WHERE owner_user_id = %s",
                        (uid,))
                    for table in (
                            "sessions", "consents", "identifiers",
                            "password_reset_tokens", "notifications",
                            "user_settings", "passkey_credentials",
                            "api_tokens", "remediation_cases",
                            "findings", "scan_jobs"):
                        conn.execute(
                            "DELETE FROM %s WHERE user_id = %%s" % table,
                            (uid,))
                    conn.execute("DELETE FROM users WHERE id = %s", (uid,))
        except Exception:
            pass
        cls.pool.reset_probe_cache()
        cls._env.__exit__()

    def setUp(self):
        ratelimit.reset()
        core_ratelimit.reset()

    def register(self, policy=True, name="Wave One"):
        email = "wave1-%s@example.com" % uuid.uuid4().hex[:16]
        payload = {"email": email, "password": PASSWORD, "name": name}
        if policy:
            payload["policy_accepted"] = True
        status, headers, body = self.request_json(
            "POST", "/api/auth/register", body=payload, headers=CSRF)
        if status == 201:
            self.user_ids.append(body["user"]["id"])
        return status, headers, body, email

    def export(self, cookie, fmt="json"):
        return self.request(
            "POST", "/api/privacy/export",
            body={"password": PASSWORD, "format": fmt},
            headers=CSRF, cookie=cookie)


# ---------------------------------------------------------------------------
# Offline pins (no database): tables, statics, CSV parity, a11y list
# ---------------------------------------------------------------------------

class TestWave1StaticPins(unittest.TestCase):
    def test_reset_password_route_class_exists(self):
        limit, window = core_ratelimit.DEFAULT_LIMITS["reset_password"]
        self.assertGreater(limit, 0)
        self.assertEqual(window, 3600)

    def test_register_form_has_policy_checkbox(self):
        html = (REPO_ROOT / "static" / "index.html").read_text(
            encoding="utf-8")
        self.assertIn('id="acPolicy"', html)
        self.assertIn('type="checkbox" id="acPolicy"', html)
        js = (REPO_ROOT / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("policy_accepted: true", js)
        self.assertIn('$("acPolicy").checked', js)

    def test_signin_in_a11y_pages(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "a11y_check", REPO_ROOT / "tools" / "a11y_check.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIn("/signin", module.PAGES)

    def test_csv_carries_precisely_the_json(self):
        from accounts import privacy
        document = {
            "account": {"email": "owner@example.com",
                        "email_masked": "o•••@example.com",
                        "name": "Owner Name",
                        "created_at": "2026-10-01T00:00:00+00:00"},
            "identifiers": [{"kind": "email", "value": "owner@example.com",
                             "masked": "o•••@example.com",
                             "created_at": "2026-10-01T00:00:00+00:00"}],
            "domains": [],
            "consents": [{
                "purpose": "policy_acceptance", "granted": True,
                "version": 1,
                "policy_version": consents.CURRENT_POLICY_VERSION,
                "updated_at": "2026-10-01T00:00:00+00:00"}],
            "scan_jobs": [{
                "id": "job-1", "status": "done", "attempts": 1,
                "error_kind": None, "score": 42,
                "score_explanation": '{"overall": "fixture"}',
                "summary": '{"findings": 1}',
                "created_at": "2026-10-01T00:00:00+00:00",
                "started_at": None, "finished_at": None}],
            "findings": [],
            "remediation_cases": [],
            "notifications": [],
            "settings": {"monitor_cadence_days": 7,
                         "created_at": "2026-10-01T00:00:00+00:00",
                         "updated_at": "2026-10-01T00:00:00+00:00"},
            "household_members": [{"label": "Member One",
                                   "created_at":
                                   "2026-10-01T00:00:00+00:00"}],
            "passkeys": [{"nickname": "Laptop",
                          "created_at": "2026-10-01T00:00:00+00:00",
                          "last_used_at": None, "revoked_at": None}],
            "api_tokens": [{"name": "cli", "prefix": "lg_fixture",
                            "scopes": '["read"]',
                            "created_at": "2026-10-01T00:00:00+00:00",
                            "last_used_at": None, "revoked_at": None}],
            "generated_at": "2026-10-10T00:00:00+00:00",
        }
        text = privacy.render_csv(document)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(rows[0], ["section", "record", "field", "value"])
        cells = {(r[0], r[2]): r[3] for r in rows[1:]}

        def expected(value):
            if value is None:
                return ""
            if isinstance(value, bool):
                return "true" if value else "false"
            return str(value)

        for field in privacy._ACCOUNT_FIELDS:
            self.assertEqual(cells[("account", field)],
                             expected(document["account"][field]),
                             "account." + field)
        # The regression this wave fixes: the name MUST be there.
        self.assertEqual(cells[("account", "name")], "Owner Name")
        for section, fields in privacy._SECTION_FIELDS.items():
            for record in document[section]:
                for field in fields:
                    self.assertEqual(
                        cells[(section, field)],
                        expected(record[field]),
                        "%s.%s" % (section, field))
        for field in privacy._SETTINGS_FIELDS:
            self.assertEqual(cells[("settings", field)],
                             expected(document["settings"][field]),
                             "settings." + field)
        self.assertEqual(cells[("meta", "generated_at")],
                         document["generated_at"])
        # And nothing extra: one header row + exactly one row per
        # field of every section + the meta row.
        total = 1 + len(privacy._ACCOUNT_FIELDS) \
            + len(privacy._SETTINGS_FIELDS) + 1
        for section, fields in privacy._SECTION_FIELDS.items():
            total += len(fields) * len(document[section])
        self.assertEqual(len(rows), total)


# ---------------------------------------------------------------------------
# A2 — CSRF guard on the anonymous POST routes (no database needed:
# the guard fires before any account/DB work on these routes)
# ---------------------------------------------------------------------------

class TestAnonCsrf(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard().__enter__()
        os.environ.pop("DATABASE_URL", None)
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def setUp(self):
        core_ratelimit.reset()

    def test_plan_rejected_without_any_proof(self):
        status, _h, body = self.request_json(
            "POST", "/api/agent/plan",
            body={"full_name": "Test Person",
                  "email": "test@example.com"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_plan_rejected_with_foreign_origin(self):
        status, _h, body = self.request_json(
            "POST", "/api/agent/plan",
            body={"full_name": "Test Person",
                  "email": "test@example.com"},
            headers={"Origin": "https://evil.example.com"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_plan_accepts_x_requested_with(self):
        status, _h, body = self.request_json(
            "POST", "/api/agent/plan",
            body={"full_name": "Test Person",
                  "email": "test@example.com"},
            headers=CSRF)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["plan"]), 40)

    def test_plan_accepts_same_host_origin(self):
        status, _h, body = self.request_json(
            "POST", "/api/agent/plan",
            body={"full_name": "Test Person",
                  "email": "test@example.com"},
            headers={"Origin": self.base})
        self.assertEqual(status, 200)

    def test_scan_rejected_without_any_proof(self):
        status, _h, body = self.request_json(
            "POST", "/api/scan", body={"email": "test@example.com"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_scan_with_proof_reaches_validation(self):
        status, _h, body = self.request_json(
            "POST", "/api/scan", body={"email": "not-an-email"},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_email")

    def test_probe_and_submit_rejected_without_any_proof(self):
        for route in ("/api/agent/probe", "/api/agent/submit"):
            status, _h, body = self.request_json(
                "POST", route, body={"confirm": True})
            self.assertEqual(status, 403, route)
            self.assertEqual(body["error"]["code"], "csrf_failed", route)


# ---------------------------------------------------------------------------
# F26 — policy acceptance at registration (database)
# ---------------------------------------------------------------------------

class TestPolicyAcceptance(DbServerMixin, unittest.TestCase):
    def test_register_without_agreement_refused(self):
        email = "wave1-%s@example.com" % uuid.uuid4().hex[:16]
        status, _h, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD,
                  "name": "Wave One"},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"],
                         "policy_acceptance_required")
        # No account was created: the same address registers fine
        # once the agreement is given.
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD,
                  "name": "Wave One", "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        self.user_ids.append(body["user"]["id"])

    def test_service_layer_refuses_without_agreement(self):
        from accounts import auth
        from core import errors
        with self.assertRaises(errors.ApiError) as ctx:
            auth.register("wave1-svc-%s@example.com"
                          % uuid.uuid4().hex[:12], PASSWORD)
        self.assertEqual(ctx.exception.code, "policy_acceptance_required")

    def test_acceptance_recorded_and_exported(self):
        status, headers, body, _email = self.register(policy=True)
        self.assertEqual(status, 201, body)
        user_id = body["user"]["id"]
        cookie = self.session_cookie(headers)
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT granted, policy_version FROM consents"
                " WHERE user_id = %s AND purpose = 'policy_acceptance'",
                (user_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertTrue(row["granted"])
        self.assertEqual(row["policy_version"],
                         consents.CURRENT_POLICY_VERSION)
        # The capability toggles are untouched by the acceptance.
        status, _h, body = self.request_json(
            "GET", "/api/consents", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual({c["purpose"] for c in body["consents"]},
                         set(consents.PURPOSES))
        # And the acceptance appears in the export's consent history.
        status, _h, raw = self.export(cookie, "json")
        self.assertEqual(status, 200)
        document = json.loads(raw.decode("utf-8"))
        acceptance = [c for c in document["consents"]
                      if c["purpose"] == "policy_acceptance"]
        self.assertEqual(len(acceptance), 1)
        self.assertTrue(acceptance[0]["granted"])
        self.assertEqual(acceptance[0]["policy_version"],
                         consents.CURRENT_POLICY_VERSION)


# ---------------------------------------------------------------------------
# F29 — export completeness (database)
# ---------------------------------------------------------------------------

class TestExportCompleteness(DbServerMixin, unittest.TestCase):
    def _drop_fixture_broker(self):
        with self.pool.connection() as conn:
            conn.execute(
                "DELETE FROM remediation_cases"
                " WHERE broker_slug = 'zz-wave1'")
            conn.execute(
                "DELETE FROM brokers WHERE slug = 'zz-wave1'")

    def test_export_includes_activity_and_credential_metadata(self):
        status, headers, body, _email = self.register(
            policy=True, name="Export Owner")
        self.assertEqual(status, 201, body)
        user_id = body["user"]["id"]
        cookie = self.session_cookie(headers)
        token_hash = os.urandom(32)
        public_key = os.urandom(64)
        with self.pool.connection() as conn:
            job = conn.execute(
                "INSERT INTO scan_jobs (user_id, idempotency_key,"
                " status, score, summary) VALUES (%s, %s, 'done',"
                " 42, '{\"findings\": 1}'::jsonb) RETURNING id",
                (user_id, uuid.uuid4().hex)).fetchone()
            finding = conn.execute(
                "INSERT INTO findings (job_id, user_id,"
                " identifier_kind, provider, source_name,"
                " source_url, exposed_fields, confidence,"
                " reliability, evidence_ref) VALUES (%s, %s,"
                " 'email', 'FixtureProvider', 'Fixture Breach',"
                " 'https://example.com/breach', '{email}', 'exact',"
                " 'high', %s) RETURNING id",
                (job["id"], user_id, "f" * 64)).fetchone()
            conn.execute(
                "INSERT INTO brokers (slug, name, category, region,"
                " optout_url) VALUES ('zz-wave1', 'ZZ Wave1 Broker',"
                " 'people_search', 'US', 'https://example.com/optout')"
                " ON CONFLICT (slug) DO NOTHING")
            conn.execute(
                "INSERT INTO remediation_cases (user_id, broker_slug,"
                " finding_id, status) VALUES (%s, 'zz-wave1', %s,"
                " 'submitted')",
                (user_id, finding["id"]))
            # The broker row is global state (the /api/brokers
            # registry reads the table when non-empty): schedule
            # its removal (case first — it holds the FK) so no
            # other test's broker count changes.
            self.addCleanup(self._drop_fixture_broker)
            conn.execute(
                "INSERT INTO notifications (user_id, kind, payload,"
                " status) VALUES (%s, 'scan_summary',"
                " '{\"score\": 42}'::jsonb, 'sent')",
                (user_id,))
            conn.execute(
                "INSERT INTO user_settings (user_id,"
                " monitor_cadence_days) VALUES (%s, 14)",
                (user_id,))
            household = conn.execute(
                "INSERT INTO households (owner_user_id, name)"
                " VALUES (%s, 'Wave1 household') RETURNING id",
                (user_id,)).fetchone()
            conn.execute(
                "INSERT INTO household_members (household_id, label)"
                " VALUES (%s, 'Household Member One')",
                (household["id"],))
            conn.execute(
                "INSERT INTO passkey_credentials (user_id,"
                " credential_id, credential_id_hash, public_key_cose,"
                " nickname) VALUES (%s, %s, %s, %s, 'Wave1 laptop')",
                (user_id, os.urandom(16), os.urandom(32), public_key))
            conn.execute(
                "INSERT INTO api_tokens (user_id, name, token_hash,"
                " prefix, scopes) VALUES (%s, 'wave1-cli', %s,"
                " 'lg_wave1', '{read}')",
                (user_id, token_hash))

        status, _h, raw = self.export(cookie, "json")
        self.assertEqual(status, 200)
        document = json.loads(raw.decode("utf-8"))
        self.assertEqual(document["account"]["name"], "Export Owner")
        self.assertEqual(len(document["scan_jobs"]), 1)
        self.assertEqual(document["scan_jobs"][0]["score"], 42)
        self.assertEqual(document["scan_jobs"][0]["summary"],
                         '{"findings": 1}')
        self.assertEqual(len(document["findings"]), 1)
        self.assertEqual(document["findings"][0]["source_name"],
                         "Fixture Breach")
        self.assertEqual(document["findings"][0]["exposed_fields"],
                         '["email"]')
        self.assertEqual(len(document["remediation_cases"]), 1)
        self.assertEqual(document["remediation_cases"][0]["broker_slug"],
                         "zz-wave1")
        self.assertEqual(len(document["notifications"]), 1)
        self.assertEqual(document["notifications"][0]["payload"],
                         '{"score": 42}')
        self.assertEqual(document["settings"]["monitor_cadence_days"], 14)
        self.assertEqual([m["label"] for m in
                          document["household_members"]],
                         ["Household Member One"])
        self.assertEqual(len(document["passkeys"]), 1)
        self.assertEqual(document["passkeys"][0]["nickname"],
                         "Wave1 laptop")
        self.assertEqual(len(document["api_tokens"]), 1)
        self.assertEqual(document["api_tokens"][0]["name"], "wave1-cli")
        self.assertEqual(document["api_tokens"][0]["scopes"], '["read"]')
        # Metadata only: no key material, no token values/hashes,
        # anywhere in the document.
        blob = json.dumps(document)
        self.assertNotIn(token_hash.hex(), blob)
        self.assertNotIn(public_key.hex(), blob)
        self.assertNotIn("token_hash", blob)
        self.assertNotIn("public_key", blob)
        self.assertNotIn("credential_id", blob)

        # CSV: same data — the account name included.
        status, _h, raw = self.export(cookie, "csv")
        self.assertEqual(status, 200)
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8"))))
        cells = {(r[0], r[2]): r[3] for r in rows[1:]}
        self.assertEqual(cells[("account", "name")], "Export Owner")
        self.assertEqual(cells[("scan_jobs", "score")], "42")
        self.assertEqual(cells[("findings", "source_name")],
                         "Fixture Breach")
        self.assertEqual(cells[("api_tokens", "name")], "wave1-cli")
        policy_versions = [r[3] for r in rows[1:]
                           if r[0] == "consents"
                           and r[2] == "policy_version"]
        self.assertIn(consents.CURRENT_POLICY_VERSION, policy_versions)


# ---------------------------------------------------------------------------
# A10 — reset-password per-IP rate limit (database)
# ---------------------------------------------------------------------------

class TestResetPasswordRateLimit(DbServerMixin, unittest.TestCase):
    def tearDown(self):
        core_ratelimit.configure(None)
        core_ratelimit.reset()

    def test_reset_password_attempts_are_capped_per_ip(self):
        core_ratelimit.configure({"reset_password": (3, 3600)})
        core_ratelimit.reset()
        for _ in range(3):
            status, _h, body = self.request_json(
                "POST", "/api/auth/reset-password",
                body={"token": "bogus-token", "new_password": PASSWORD},
                headers=CSRF)
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_token")
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": "bogus-token", "new_password": PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 429)
        self.assertEqual(body["error"]["code"], "rate_limited")


if __name__ == "__main__":
    unittest.main()
