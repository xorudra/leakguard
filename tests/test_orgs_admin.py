"""Households, audit log and admin tests (Stage S11 — spec
Phases 57–62, 106–114).

Layers:

* TestOrgsAdminUnavailable — always runs: with NO database
  configured, the household and PATCH routes answer the same clean
  503 as every other account route, the CSRF guard still fires
  first, and the admin routes answer 503 (accounts unavailable)
  rather than leaking anything.
* TestHouseholdsDb — pgserver: lazy household creation, member
  CRUD + validation, identifier member assignment (POST + PATCH),
  member deletion SETs identifiers' member_id NULL without deleting
  them, and IDOR (foreign members/identifiers are 404 everywhere).
* TestAuditDb — pgserver: the audit rows the real API flows write
  (register, login ok/failed, consent, identifiers, password reset,
  scan jobs manual + monitor, remediation run, account deletion),
  with a hard PII check: no account email and no identifier value
  ever appears in any audit detail.
* TestAuditResilienceDb — pgserver: with the audit_log table GONE,
  register and login still succeed (audit is best-effort, always).
* TestAdminDb — pgserver: the ADMIN_EMAILS gate (unset → 404;
  non-admin → 404, even unauthenticated → 404; admin → aggregates
  matching the seeded state), me.is_admin both ways, and a privacy
  check that the overview payload contains no user emails.

No plaintext passwords are printed; test accounts use unique
example.com addresses.

Run:  python3 -m unittest discover -s tests
"""

import base64
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.parse
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
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
PASSWORD = "S11 test " + "password 123"


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
# No-database layer
# ---------------------------------------------------------------------------

class TestOrgsAdminUnavailable(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(ENV_KEYS).__enter__()
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def test_household_503_without_database(self):
        status, _h, body = self.request_json("GET", "/api/household")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_household_member_post_503_with_csrf(self):
        status, _h, body = self.request_json(
            "POST", "/api/household/members", body={"label": "Mum"},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_household_member_post_csrf_fires_first(self):
        status, _h, _b = self.request(
            "POST", "/api/household/members", body={"label": "Mum"})
        self.assertEqual(status, 403)

    def test_identifier_patch_503_without_database(self):
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + str(uuid.uuid4()),
            body={"member_id": None}, headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_admin_overview_503_without_database(self):
        status, _h, body = self.request_json("GET", "/api/admin/overview")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_admin_audit_503_without_database(self):
        status, _h, _b = self.request_json("GET", "/api/admin/audit")
        self.assertEqual(status, 503)


# ---------------------------------------------------------------------------
# pgserver provisioning + API helpers
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class OrgsDbBase(ServerMixin):
    """Shared pgserver provisioning. NOT a TestCase itself; each
    subclass gets a FRESH database (the identifier vault allows one
    owner per identifier value, and audit/admin counts are asserted
    exactly, so classes must not share state)."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        keys = ENV_KEYS + ("LEAKGUARD_PROVIDERS", "ADMIN_EMAILS")
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-orgs-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest("pgserver could not start PostgreSQL")
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

    def register(self):
        email = "s11-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def login(self, email, password=None):
        status, headers, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": password or PASSWORD},
            headers=CSRF)
        return status, headers, body

    def add_member(self, cookie, label):
        return self.request_json(
            "POST", "/api/household/members", body={"label": label},
            headers=CSRF, cookie=cookie)

    def add_identifier(self, cookie, kind, value, member_id="absent"):
        body = {"kind": kind, "value": value}
        if member_id != "absent":
            body["member_id"] = member_id
        return self.request_json(
            "POST", "/api/identifiers", body=body,
            headers=CSRF, cookie=cookie)

    def set_consent(self, cookie, purpose, granted):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": purpose, "granted": granted},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        return body

    def sql(self, query, params=()):
        with self.pool.connection() as conn:
            return conn.execute(query, params).fetchall()

    def audit_rows(self, where="", params=()):
        return self.sql(
            "SELECT actor_user_id, actor_kind, action, target_kind,"
            " target_id, detail FROM audit_log " + where
            + " ORDER BY id", params)


# ---------------------------------------------------------------------------
# Households
# ---------------------------------------------------------------------------

class TestHouseholdsDb(OrgsDbBase, unittest.TestCase):

    def test_household_lazy_create_and_stable(self):
        cookie, uid, _email = self.register()
        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["name"], "My household")
        self.assertEqual(body["members"], [])
        first_id = body["id"]
        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], first_id)
        rows = self.sql(
            "SELECT COUNT(*) AS n FROM households"
            " WHERE owner_user_id = %s", (uid,))
        self.assertEqual(rows[0]["n"], 1)

    def test_household_requires_signin(self):
        status, _h, _b = self.request_json("GET", "/api/household")
        self.assertEqual(status, 401)

    def test_member_crud_and_validation(self):
        cookie, _uid, _email = self.register()
        status, _h, body = self.add_member(cookie, "  Mum  ")
        self.assertEqual(status, 201, body)
        self.assertEqual(body["member"]["label"], "Mum")
        mum = body["member"]["id"]
        # Duplicates allowed — a label is not an identity.
        status, _h, body = self.add_member(cookie, "Mum")
        self.assertEqual(status, 201, body)
        self.assertNotEqual(body["member"]["id"], mum)
        for bad in ("", "   ", "x" * 61, None, 42):
            status, _h, body = self.add_member(cookie, bad)
            self.assertEqual(status, 400, (bad, body))
            self.assertEqual(body["error"]["code"], "invalid_label")
        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie)
        self.assertEqual(len(body["members"]), 2)

    def test_identifier_member_assignment_post_and_patch(self):
        cookie, _uid, _email = self.register()
        _s, _h, body = self.add_member(cookie, "Dad")
        dad = body["member"]["id"]
        _s, _h, body = self.add_member(cookie, "Mum")
        mum = body["member"]["id"]
        value = "fam-%s@example.com" % self.uniq()
        status, _h, body = self.add_identifier(cookie, "email", value, dad)
        self.assertEqual(status, 201, body)
        ident = body["identifier"]
        self.assertEqual(ident["member_id"], dad)
        # Reassign via PATCH, then clear back to the owner with null.
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + ident["id"],
            body={"member_id": mum}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["identifier"]["member_id"], mum)
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + ident["id"],
            body={"member_id": None}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertIsNone(body["identifier"]["member_id"])
        # The list shape carries member_id too.
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("member_id", body["identifiers"][0])

    def test_foreign_member_and_identifier_are_404(self):
        cookie_a, _ua, _ea = self.register()
        cookie_b, _ub, _eb = self.register()
        _s, _h, body = self.add_member(cookie_a, "Mum")
        a_mum = body["member"]["id"]
        value = "idor-%s@example.com" % self.uniq()
        # B cannot assign A's member, by POST or by PATCH.
        status, _h, body = self.add_identifier(cookie_b, "email", value,
                                               a_mum)
        self.assertEqual(status, 404, body)
        status, _h, body = self.add_identifier(cookie_b, "email", value)
        self.assertEqual(status, 201, body)
        b_ident = body["identifier"]["id"]
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + b_ident,
            body={"member_id": a_mum}, headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 404, body)
        # A cannot touch B's identifier at all.
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + b_ident,
            body={"member_id": None}, headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 404, body)
        # Malformed member ids are the same 404, never a 500.
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + b_ident,
            body={"member_id": "not-a-uuid"}, headers=CSRF,
            cookie=cookie_b)
        self.assertEqual(status, 404, body)
        # B cannot delete A's member; A's household still has it.
        status, _h, body = self.request_json(
            "DELETE", "/api/household/members/" + a_mum,
            headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 404, body)
        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie_a)
        self.assertEqual(len(body["members"]), 1)
        # B's own household is a different, empty one.
        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie_b)
        self.assertEqual(body["members"], [])

    def test_delete_member_sets_identifier_member_null(self):
        cookie, _uid, _email = self.register()
        _s, _h, body = self.add_member(cookie, "Mum")
        mum = body["member"]["id"]
        value = "setnull-%s@example.com" % self.uniq()
        status, _h, body = self.add_identifier(cookie, "email", value, mum)
        self.assertEqual(status, 201, body)
        ident = body["identifier"]["id"]
        status, _h, body = self.request_json(
            "DELETE", "/api/household/members/" + mum,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["deleted"])
        # The identifier survived; it just belongs to the owner again.
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie)
        self.assertEqual(len(body["identifiers"]), 1)
        self.assertEqual(body["identifiers"][0]["id"], ident)
        self.assertIsNone(body["identifiers"][0]["member_id"])
        # Deleting again (or a random id) is a plain 404.
        status, _h, _b = self.request_json(
            "DELETE", "/api/household/members/" + mum,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 404)
        status, _h, _b = self.request_json(
            "DELETE", "/api/household/members/" + str(uuid.uuid4()),
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 404)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

class TestAuditDb(OrgsDbBase, unittest.TestCase):

    def test_core_events_are_audited_without_pii(self):
        cookie, uid, email = self.register()
        # Registration itself.
        rows = self.audit_rows(
            "WHERE action = 'auth.registered' AND actor_user_id = %s",
            (uid,))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor_kind"], "user")
        # Login success + failure.
        status, _h, _b = self.login(email, "definitely-wrong-1")
        self.assertEqual(status, 401)
        status, _h, _b = self.login(email)
        self.assertEqual(status, 200)
        failed = self.audit_rows("WHERE action = 'auth.login_failed'")
        self.assertEqual(len(failed), 1)
        self.assertIsNone(failed[0]["actor_user_id"])
        self.assertEqual(failed[0]["detail"],
                         {"reason": "invalid_credentials"})
        ok = self.audit_rows(
            "WHERE action = 'auth.login' AND actor_user_id = %s", (uid,))
        self.assertEqual(len(ok), 1)
        # Consent change carries purpose + granted, nothing else.
        self.set_consent(cookie, "scanning", True)
        rows = self.audit_rows("WHERE action = 'consent.changed'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["detail"],
                         {"consent": "scanning", "granted": True})
        # Identifier add + remove carry the kind only.
        secret_value = "audit-me-%s@example.com" % self.uniq()
        status, _h, body = self.add_identifier(cookie, "email",
                                               secret_value)
        self.assertEqual(status, 201, body)
        ident = body["identifier"]["id"]
        status, _h, _b = self.request_json(
            "DELETE", "/api/identifiers/" + ident,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        added = self.audit_rows("WHERE action = 'identifier.added'")
        removed = self.audit_rows("WHERE action = 'identifier.removed'")
        self.assertEqual([r["detail"] for r in added], [{"kind": "email"}])
        self.assertEqual([r["detail"] for r in removed],
                         [{"kind": "email"}])
        # THE PII CHECK: neither the account email nor the identifier
        # value appears anywhere in the whole audit table.
        everything = json.dumps(
            [dict(r) for r in self.audit_rows()], default=str)
        self.assertNotIn(email, everything)
        self.assertNotIn(secret_value, everything)

    def test_scan_and_remediation_and_monitor_events(self):
        cookie, uid, _email = self.register()
        self.set_consent(cookie, "scanning", True)
        self.set_consent(cookie, "monitoring", True)
        self.set_consent(cookie, "automated_remediation", True)
        value = "scan-%s@example.com" % self.uniq()
        status, _h, body = self.add_identifier(cookie, "email", value)
        self.assertEqual(status, 201, body)
        # Manual scan job.
        status, _h, body = self.request_json(
            "POST", "/api/scans", body={"idempotency_key": "audit-1"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        rows = self.audit_rows("WHERE action = 'scan.job_created'")
        manual = [r for r in rows if r["detail"].get("source") == "manual"]
        self.assertEqual(len(manual), 1)
        self.assertEqual(manual[0]["actor_kind"], "user")
        # Monitor-scheduled job: the scheduler enqueues for a due
        # user (consent on, identifier saved, no completed scan).
        from monitoring import scheduler

        created = scheduler.tick()
        self.assertEqual(len(created), 1)
        rows = self.audit_rows("WHERE action = 'scan.job_created'")
        monitor = [r for r in rows
                   if r["detail"].get("source") == "monitor"]
        self.assertEqual(len(monitor), 1)
        self.assertEqual(monitor[0]["actor_kind"], "system")
        self.assertEqual(str(monitor[0]["actor_user_id"]), uid)
        # The one removal command.
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cases_created"], self.seeded)
        rows = self.audit_rows("WHERE action = 'remediation.run_created'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["detail"],
                         {"cases_created": self.seeded})

    def test_password_reset_events(self):
        cookie, uid, email = self.register()
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password", body={"email": email},
            headers=CSRF)
        self.assertEqual(status, 200, body)
        rows = self.audit_rows(
            "WHERE action = 'auth.password_reset_requested'")
        self.assertEqual(len(rows), 1)
        notes = self.sql(
            "SELECT payload FROM notifications"
            " WHERE user_id = %s AND kind = 'password_reset'", (uid,))
        self.assertEqual(len(notes), 1)
        reset_url = notes[0]["payload"]["reset_url"]
        raw_token = urllib.parse.parse_qs(
            urllib.parse.urlparse(reset_url).query)["token"][0]
        new_password = "S11 reset password 456"
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": raw_token, "new_password": new_password},
            headers=CSRF)
        self.assertEqual(status, 200, body)
        rows = self.audit_rows(
            "WHERE action = 'auth.password_reset_completed'")
        self.assertEqual(len(rows), 1)
        # The raw token never reaches the audit trail.
        everything = json.dumps(
            [dict(r) for r in self.audit_rows()], default=str)
        self.assertNotIn(raw_token, everything)
        # And the new password really works.
        status, _h, _b = self.login(email, new_password)
        self.assertEqual(status, 200)

    def test_account_deleted_event(self):
        cookie, uid, _email = self.register()
        status, _h, body = self.request_json(
            "POST", "/api/auth/delete-account",
            body={"password": PASSWORD}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        rows = self.audit_rows("WHERE action = 'account.deleted'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(str(rows[0]["actor_user_id"]), uid)


class TestAuditResilienceDb(OrgsDbBase, unittest.TestCase):

    def test_flows_survive_a_missing_audit_table(self):
        # Sabotage: the audit trail is gone entirely. Register and
        # login must still work — audit is best-effort, always.
        with self.pool.connection() as conn:
            conn.execute("DROP TABLE audit_log")
        cookie, _uid, email = self.register()
        self.assertTrue(cookie)
        status, _h, _b = self.login(email)
        self.assertEqual(status, 200)


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

class TestAdminDb(OrgsDbBase, unittest.TestCase):

    def test_no_admins_configured_means_404(self):
        cookie, _uid, _email = self.register()
        status, _h, body = self.request_json(
            "GET", "/api/auth/me", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertFalse(body["is_admin"])
        for path in ("/api/admin/overview", "/api/admin/audit"):
            status, _h, _b = self.request_json("GET", path, cookie=cookie)
            self.assertEqual(status, 404, path)

    def test_admin_gate_and_overview(self):
        admin_cookie, _auid, admin_email = self.register()
        user_cookie, _uuid2, user_email = self.register()
        # Seed a little platform state as the regular user.
        status, _h, body = self.add_identifier(
            user_cookie, "email", "agg-%s@example.com" % self.uniq())
        self.assertEqual(status, 201, body)
        status, _h, body = self.add_identifier(
            user_cookie, "phone", "+91 90000 00000")
        self.assertEqual(status, 201, body)
        # Nobody is admin until the env says so — not even signed in.
        os.environ["ADMIN_EMAILS"] = "someone-else@example.com"
        status, _h, body = self.request_json(
            "GET", "/api/auth/me", cookie=admin_cookie)
        self.assertFalse(body["is_admin"])
        status, _h, _b = self.request_json(
            "GET", "/api/admin/overview", cookie=admin_cookie)
        self.assertEqual(status, 404)
        # Now the owner's address (shouted case — normalization must
        # still match) is configured.
        os.environ["ADMIN_EMAILS"] = admin_email.upper()
        status, _h, body = self.request_json(
            "GET", "/api/auth/me", cookie=admin_cookie)
        self.assertTrue(body["is_admin"])
        status, _h, body = self.request_json(
            "GET", "/api/auth/me", cookie=user_cookie)
        self.assertFalse(body["is_admin"])
        # The regular user and the anonymous both get 404, not 403.
        for ck in (user_cookie, None):
            for path in ("/api/admin/overview", "/api/admin/audit"):
                status, _h, _b = self.request_json("GET", path, cookie=ck)
                self.assertEqual(status, 404, (path, ck))
        # The owner gets the aggregates — and they match the state
        # (compared against the tables directly: sibling tests in
        # this class share the database and register their own users).
        expected_users = self.sql(
            "SELECT COUNT(*) AS n FROM users WHERE deleted_at IS NULL"
        )[0]["n"]
        status, _h, body = self.request_json(
            "GET", "/api/admin/overview", cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["users"]["total"], expected_users)
        self.assertEqual(body["users"]["registered_last_30d"],
                         expected_users)
        self.assertGreaterEqual(body["users"]["total"], 2)
        self.assertEqual(body["identifiers_by_kind"],
                         {"email": 1, "phone": 1})
        self.assertEqual(body["brokers"], self.seeded)
        self.assertEqual(body["db"], "ok")
        self.assertIn("providers", body)
        # Aggregates ONLY: no user's email (or masked form) anywhere.
        blob = json.dumps(body)
        self.assertNotIn(admin_email, blob)
        self.assertNotIn(user_email, blob)
        self.assertNotIn("@example.com", blob)

    def test_admin_audit_endpoint(self):
        admin_cookie, _auid, admin_email = self.register()
        _uc, _uu, _ue = self.register()
        os.environ["ADMIN_EMAILS"] = admin_email
        # An overview view is itself audited.
        status, _h, _b = self.request_json(
            "GET", "/api/admin/overview", cookie=admin_cookie)
        self.assertEqual(status, 200)
        status, _h, body = self.request_json(
            "GET", "/api/admin/audit", cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        actions = [row["action"] for row in body["audit"]]
        self.assertIn("auth.registered", actions)
        self.assertIn("admin.overview_viewed", actions)
        for row in body["audit"]:
            self.assertIn(row["actor_kind"], ("user", "admin", "system"))
            self.assertIn("detail", row)
            self.assertIn("created_at", row)
        # The limit is honoured.
        status, _h, body = self.request_json(
            "GET", "/api/admin/audit?limit=2", cookie=admin_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(len(body["audit"]), 2)
        # ...and the audit view itself lands in the trail afterwards.
        status, _h, body = self.request_json(
            "GET", "/api/admin/audit?limit=500", cookie=admin_cookie)
        actions = [row["action"] for row in body["audit"]]
        self.assertIn("admin.audit_viewed", actions)


if __name__ == "__main__":
    unittest.main()
