"""Accounts / consent / Privacy Center tests (Stage S3 — spec
Phases 4, 5, 6, 48, 49, 50).

Three layers:

* TestTotpAndPasswordsUnit — offline, always runs: RFC 6238 test
  vectors, replay rules, Argon2id hash format.
* TestAccountsUnavailable — always runs: with NO database configured,
  every account route answers a clean structured 503 (never a crash),
  the CSRF guard still fires first, and the anonymous product is
  untouched.
* TestAccountsDb — the full flows against a real PostgreSQL. Skips
  honestly when no database is reachable (same pattern as test_db.py:
  DATABASE_URL env, else the owner-only .neon-database-url file).

No plaintext emails/passwords/secrets are printed anywhere; test
accounts use unique example.com addresses and are hard-deleted in
tearDownClass.

Run:  python3 -m unittest discover -s tests
"""

import base64
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit, totp  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

REPO_ROOT = Path(__file__).resolve().parent.parent
NEON_FILE = REPO_ROOT / ".neon-database-url"
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
CSRF = {"X-Requested-With": "fetch"}


def _database_url():
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

    def request(self, method, path, body=None, cookie=None, headers=None,
                raw_headers=None):
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if cookie:
            hdrs["Cookie"] = cookie
        if raw_headers:
            hdrs.update(raw_headers)
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=hdrs, method=method)
        try:
            with OPENER.open(req, timeout=15) as resp:
                payload = resp.read()
                return resp.status, resp.headers, payload
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
        """Extract the lg_session cookie pair from a response."""
        raw = headers.get("Set-Cookie") or ""
        first = raw.split(";")[0].strip()
        return first if first.startswith("lg_session=") else None


# ---------------------------------------------------------------------------
# Offline unit layer
# ---------------------------------------------------------------------------

class TestTotpAndPasswordsUnit(unittest.TestCase):
    # RFC 6238 Appendix B: seed is the ASCII string "12345678901234567890".
    RFC_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii")

    def test_rfc6238_vectors(self):
        # T=59s -> step 1 -> 94287082 (8-digit) -> 287082 (6-digit)
        self.assertEqual(totp.code_for_step(self.RFC_SECRET, 1), "287082")
        # T=1111111109s -> step 37037036 -> 07081804 -> 081804
        self.assertEqual(
            totp.code_for_step(self.RFC_SECRET, 37037036), "081804")
        # T=1234567890s -> step 41152263 -> 89005924 -> 005924
        self.assertEqual(
            totp.code_for_step(self.RFC_SECRET, 41152263), "005924")

    def test_verify_window_and_replay(self):
        secret = totp.generate_secret()
        step = totp.current_step()
        code = totp.code_for_step(secret, step)
        self.assertEqual(totp.verify(secret, code), step)
        # Same code again with that step consumed = replay, rejected.
        self.assertIsNone(totp.verify(secret, code, last_accepted_step=step))
        # Neighbouring steps are inside the window.
        nxt = totp.code_for_step(secret, step + 1)
        self.assertEqual(
            totp.verify(secret, nxt, last_accepted_step=step), step + 1)
        # Garbage never verifies.
        self.assertIsNone(totp.verify(secret, "000000"))
        self.assertIsNone(totp.verify(secret, "abcdef"))
        self.assertIsNone(totp.verify(secret, ""))

    def test_argon2id_hashes(self):
        from accounts import passwords

        stored = passwords.hash_password("correct horse battery")
        self.assertTrue(stored.startswith("$argon2id$"))
        self.assertNotIn("correct horse", stored)
        self.assertTrue(passwords.verify_password(stored, "correct horse battery"))
        self.assertFalse(passwords.verify_password(stored, "wrong password"))
        self.assertFalse(passwords.verify_password("not-a-hash", "whatever"))
        # The timing dummy is a valid hash that simply never matches.
        self.assertTrue(passwords.DUMMY_HASH.startswith("$argon2id$"))
        self.assertFalse(
            passwords.verify_password(passwords.DUMMY_HASH, "whatever123"))


# ---------------------------------------------------------------------------
# No-database layer: clean 503s, CSRF first, anonymous untouched
# ---------------------------------------------------------------------------

class TestAccountsUnavailable(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard().__enter__()
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def test_register_503_structured(self):
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": "a@example.com", "password": "long-enough-1"},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")
        self.assertEqual(body["error"]["request_id"],
                         headers.get("X-Request-Id"))

    def test_csrf_fires_before_availability(self):
        status, _headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": "a@example.com", "password": "long-enough-1"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_get_routes_503(self):
        for path in ("/api/auth/me", "/api/consents", "/api/identifiers",
                     "/api/privacy/export"):
            status, _h, body = self.request_json("GET", path)
            self.assertEqual(status, 503, path)
            self.assertEqual(body["error"]["code"], "db_unavailable", path)

    def test_delete_identifier_503(self):
        status, _h, body = self.request_json(
            "DELETE", "/api/identifiers/%s" % uuid.uuid4(), headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_anonymous_product_untouched(self):
        status, _h, body = self.request_json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("db"), "disabled")
        status, _h, _p = self.request("GET", "/")
        self.assertEqual(status, 200)


# ---------------------------------------------------------------------------
# Full flows against a real PostgreSQL
# ---------------------------------------------------------------------------

@unittest.skipUnless(_database_url(), "no DATABASE_URL / Neon file available")
class TestAccountsDb(ServerMixin, unittest.TestCase):
    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard().__enter__()
        os.environ["DATABASE_URL"] = _database_url()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(os.urandom(32)).decode()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._env.__exit__()
            raise unittest.SkipTest(
                "PostgreSQL configured but not reachable from this host")
        migrate.run_migrations()
        cls.user_ids = []  # for tearDown cleanup
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        try:
            with cls.pool.connection() as conn:
                for uid in cls.user_ids:
                    conn.execute("DELETE FROM sessions WHERE user_id = %s", (uid,))
                    conn.execute("DELETE FROM consents WHERE user_id = %s", (uid,))
                    conn.execute("DELETE FROM identifiers WHERE user_id = %s", (uid,))
                    conn.execute(
                        "DELETE FROM password_reset_tokens WHERE user_id = %s",
                        (uid,))
                    conn.execute("DELETE FROM users WHERE id = %s", (uid,))
        except Exception:
            pass
        cls.pool.reset_probe_cache()
        cls._env.__exit__()

    def setUp(self):
        ratelimit.reset()

    # ---------- helpers ----------
    def unique_email(self):
        return "acct-%s@example.com" % uuid.uuid4().hex[:16]

    def register(self, email=None, password=None):
        email = email or self.unique_email()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": password or self.PASSWORD},
            headers=CSRF)
        if status == 201:
            self.user_ids.append(body["user"]["id"])
        return status, headers, body

    def login(self, email, password=None, totp_code=None, cookie=None):
        payload = {"email": email, "password": password or self.PASSWORD}
        if totp_code is not None:
            payload["totp_code"] = totp_code
        return self.request_json("POST", "/api/auth/login", body=payload,
                                 headers=CSRF, cookie=cookie)

    def me(self, cookie):
        return self.request_json("GET", "/api/auth/me", cookie=cookie)

    # ---------- flows ----------
    def test_register_login_me_logout_flow(self):
        email = self.unique_email()
        status, headers, body = self.register(email)
        self.assertEqual(status, 201)
        user = body["user"]
        self.assertEqual(user["email_masked"], "a•••@example.com")
        self.assertFalse(user["totp_enabled"])
        raw_cookie = headers.get("Set-Cookie") or ""
        for flag in ("lg_session=", "HttpOnly", "Secure", "SameSite=Lax",
                     "Path=/"):
            self.assertIn(flag, raw_cookie)
        cookie = self.session_cookie(headers)
        self.assertTrue(cookie)

        status, _h, me = self.me(cookie)
        self.assertEqual(status, 200)
        self.assertEqual(me["id"], user["id"])
        self.assertEqual(me["email_masked"], user["email_masked"])
        self.assertIn("created_at", me)

        status, _h, _b = self.request_json(
            "POST", "/api/auth/logout", body={}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        status, _h, body = self.me(cookie)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthenticated")

        status, headers, body = self.login(email)
        self.assertEqual(status, 200)
        status, _h, me = self.me(self.session_cookie(headers))
        self.assertEqual(status, 200)
        self.assertEqual(me["id"], user["id"])

    def test_duplicate_email_409(self):
        email = self.unique_email()
        status, _h, _b = self.register(email)
        self.assertEqual(status, 201)
        status, _h, body = self.register(email)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "email_taken")

    def test_wrong_password_and_unknown_email_identical(self):
        email = self.unique_email()
        self.register(email)
        s1, _h, b1 = self.login(email, password="wrong-password-1")
        s2, _h, b2 = self.login("ghost-%s@example.com" % uuid.uuid4().hex[:8],
                                password="wrong-password-1")
        self.assertEqual((s1, s2), (401, 401))
        # Identical apart from the (always unique) request_id.
        strip = lambda e: {k: v for k, v in e.items() if k != "request_id"}
        self.assertEqual(strip(b1["error"]), strip(b2["error"]))
        self.assertEqual(b1["error"]["code"], "invalid_credentials")

    def test_register_validation(self):
        status, _h, body = self.register(password="short")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "weak_password")
        status, _h, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": "not-an-email", "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_email")

    def test_me_requires_auth(self):
        status, _h, body = self.me(None)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthenticated")
        status, _h, body = self.me("lg_session=bogus-token")
        self.assertEqual(status, 401)

    def test_csrf_required_for_state_changes(self):
        email = self.unique_email()
        # No X-Requested-With, no Origin -> rejected before credentials.
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": self.PASSWORD})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")
        # A matching Origin satisfies the guard instead (bad creds -> 401).
        origin = "http://127.0.0.1:%d" % self.port
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": "wrong-password-1"},
            raw_headers={"Origin": origin})
        self.assertEqual(status, 401)
        # A foreign Origin is rejected outright.
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": self.PASSWORD},
            raw_headers={"Origin": "https://evil.example.com"})
        self.assertEqual(status, 403)

    def test_identifiers_crud_and_idor(self):
        _s, headers_a, _b = self.register()
        cookie_a = self.session_cookie(headers_a)
        secret_value = "target-%s@example.com" % uuid.uuid4().hex[:8]

        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "email", "value": secret_value},
            headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 201)
        record = body["identifier"]
        self.assertEqual(record["masked"], "t•••@example.com")
        self.assertNotIn(secret_value, json.dumps(body))
        ident_id = record["id"]

        _s, headers_b, _b = self.register()
        cookie_b = self.session_cookie(headers_b)
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie_b)
        self.assertEqual(status, 200)
        self.assertEqual(body["identifiers"], [])
        # B deleting A's identifier: same 404 as a nonexistent id.
        status, _h, body = self.request_json(
            "DELETE", "/api/identifiers/" + ident_id,
            headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")
        status, _h, body = self.request_json(
            "DELETE", "/api/identifiers/" + str(uuid.uuid4()),
            headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 404)

        # A's row is intact; A can list and delete it.
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie_a)
        self.assertEqual([r["id"] for r in body["identifiers"]], [ident_id])
        self.assertNotIn(secret_value, json.dumps(body))
        status, _h, body = self.request_json(
            "DELETE", "/api/identifiers/" + ident_id,
            headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 200)
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie_a)
        self.assertEqual(body["identifiers"], [])
        # Bad kind is a clean 400.
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "passport", "value": "X123"},
            headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_identifier")

    def test_consents_append_only_versions(self):
        _s, headers, _b = self.register()
        cookie = self.session_cookie(headers)
        status, _h, body = self.request_json(
            "GET", "/api/consents", cookie=cookie)
        self.assertEqual(status, 200)
        state = {c["purpose"]: c for c in body["consents"]}
        self.assertEqual(set(state), {"scanning", "monitoring",
                                      "automated_remediation",
                                      "notifications"})
        for c in state.values():
            self.assertEqual((c["granted"], c["version"]), (False, 1))

        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        state = {c["purpose"]: c for c in body["consents"]}
        self.assertEqual((state["scanning"]["granted"],
                          state["scanning"]["version"]), (True, 2))
        self.assertEqual(state["monitoring"]["version"], 1)

        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": False},
            headers=CSRF, cookie=cookie)
        state = {c["purpose"]: c for c in body["consents"]}
        self.assertEqual((state["scanning"]["granted"],
                          state["scanning"]["version"]), (False, 3))

        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "teleportation", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "unknown_purpose")

    def test_export_reveals_only_to_owner(self):
        email = self.unique_email()
        _s, headers, _b = self.register(email)
        cookie = self.session_cookie(headers)
        phone = "+91 98%08d" % (uuid.uuid4().int % 100000000)
        self.request_json("POST", "/api/identifiers",
                          body={"kind": "phone", "value": phone},
                          headers=CSRF, cookie=cookie)
        self.request_json("POST", "/api/consents",
                          body={"purpose": "monitoring", "granted": True},
                          headers=CSRF, cookie=cookie)
        status, headers, body = self.request_json(
            "GET", "/api/privacy/export", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers.get("Content-Disposition") or "")
        self.assertEqual(body["account"]["email"], email)
        self.assertEqual(len(body["identifiers"]), 1)
        self.assertEqual(body["identifiers"][0]["value"],
                         " ".join(phone.split()))
        self.assertIn("generated_at", body)
        purposes = {(c["purpose"], c["version"]) for c in body["consents"]}
        self.assertIn(("monitoring", 1), purposes)   # seed row
        self.assertIn(("monitoring", 2), purposes)   # the grant

    def test_change_password_revokes_other_sessions(self):
        email = self.unique_email()
        _s, headers1, _b = self.register(email)
        cookie1 = self.session_cookie(headers1)
        _s, headers2, _b = self.login(email)
        cookie2 = self.session_cookie(headers2)

        status, _h, body = self.request_json(
            "POST", "/api/auth/change-password",
            body={"current_password": self.PASSWORD,
                  "new_password": "brand-new-password-2"},
            headers=CSRF, cookie=cookie1)
        self.assertEqual(status, 200)
        status, _h, _b = self.me(cookie2)   # other session revoked
        self.assertEqual(status, 401)
        status, _h, _b = self.me(cookie1)   # current session survives
        self.assertEqual(status, 200)
        status, _h, _b = self.login(email)  # old password is dead
        self.assertEqual(status, 401)
        status, _h, _b = self.login(email, password="brand-new-password-2")
        self.assertEqual(status, 200)

    def test_delete_account_cascades(self):
        email = self.unique_email()
        _s, headers, body = self.register(email)
        user_id = body["user"]["id"]
        cookie = self.session_cookie(headers)
        self.request_json("POST", "/api/identifiers",
                          body={"kind": "name", "value": "Delete Me"},
                          headers=CSRF, cookie=cookie)
        status, headers, _b = self.request_json(
            "POST", "/api/auth/delete-account",
            body={"password": self.PASSWORD}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", headers.get("Set-Cookie") or "")
        status, _h, _b = self.me(cookie)
        self.assertEqual(status, 401)
        status, _h, _b = self.login(email)
        self.assertEqual(status, 401)
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM identifiers"
                " WHERE user_id = %s AND deleted_at IS NULL",
                (user_id,)).fetchone()
            self.assertEqual(row["n"], 0)
            row = conn.execute(
                "SELECT deleted_at FROM users WHERE id = %s",
                (user_id,)).fetchone()
            self.assertIsNotNone(row["deleted_at"])
        # The address can be registered again (partial unique index).
        status, _h, body = self.register(email)
        self.assertEqual(status, 201)

    @staticmethod
    def _wait_next_step():
        """Sleep until the TOTP step rolls over (<= ~30s). Needed so a
        test can always mint a code that is both inside the ±1 window
        and newer than the last consumed step."""
        step = totp.current_step()
        deadline = time.time() + 35
        while totp.current_step() == step and time.time() < deadline:
            time.sleep(0.25)

    @staticmethod
    def _secret_from_uri(uri):
        return urllib.parse.parse_qs(
            urllib.parse.urlparse(uri).query)["secret"][0]

    def test_totp_full_cycle(self):
        email = self.unique_email()
        _s, headers, _b = self.register(email)
        cookie = self.session_cookie(headers)

        status, _h, body = self.request_json(
            "POST", "/api/auth/totp/enroll", body={}, headers=CSRF,
            cookie=cookie)
        self.assertEqual(status, 200)
        uri = body["otpauth_uri"]
        self.assertTrue(uri.startswith("otpauth://totp/"))
        secret = self._secret_from_uri(uri)
        self.assertIn("secret_hint", body)
        self.assertNotIn(secret, body["secret_hint"])
        _s, _h, me = self.me(cookie)
        self.assertFalse(me["totp_enabled"])

        # Activate with the current step's code; that step is consumed.
        step0 = totp.current_step()
        status, _h, body = self.request_json(
            "POST", "/api/auth/totp/activate",
            body={"code": totp.code_for_step(secret, step0)},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        _s, _h, me = self.me(cookie)
        self.assertTrue(me["totp_enabled"])

        # Disable again (password + a strictly newer in-window code)
        # while still signed in, proving the disable path end to end.
        self._wait_next_step()
        status, _h, body = self.request_json(
            "POST", "/api/auth/totp/disable",
            body={"password": self.PASSWORD,
                  "code": totp.code_for_step(secret, totp.current_step())},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        _s, _h, me = self.me(cookie)
        self.assertFalse(me["totp_enabled"])
        # With TOTP off, password-only login works immediately.
        self.request_json("POST", "/api/auth/logout", body={},
                          headers=CSRF, cookie=cookie)
        status, _h, body = self.login(email)
        self.assertEqual(status, 200)
        self.assertIn("user", body)

        # Enroll + activate a second time for the login-factor flow.
        status, headers, _b = self.login(email)
        cookie = self.session_cookie(headers)
        status, _h, body = self.request_json(
            "POST", "/api/auth/totp/enroll", body={}, headers=CSRF,
            cookie=cookie)
        self.assertEqual(status, 200)
        secret = self._secret_from_uri(body["otpauth_uri"])
        step1 = totp.current_step()
        code1 = totp.code_for_step(secret, step1)
        status, _h, body = self.request_json(
            "POST", "/api/auth/totp/activate", body={"code": code1},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        self.request_json("POST", "/api/auth/logout", body={},
                          headers=CSRF, cookie=cookie)

        # Login now demands the second factor and issues NO session.
        status, headers, body = self.login(email)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"totp_required": True})
        self.assertIsNone(self.session_cookie(headers))
        # The activation code is already consumed: replay rejected.
        status, _h, body = self.login(email, totp_code=code1)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_credentials")
        # The next step's code (inside the window, strictly newer) works.
        fresh = totp.code_for_step(secret, step1 + 1)
        status, headers, body = self.login(email, totp_code=fresh)
        self.assertEqual(status, 200)
        self.assertIn("user", body)
        cookie2 = self.session_cookie(headers)
        self.assertTrue(cookie2)
        # Replaying the login code fails too.
        self.request_json("POST", "/api/auth/logout", body={},
                          headers=CSRF, cookie=cookie2)
        status, _h, body = self.login(email, totp_code=fresh)
        self.assertEqual(status, 401)

    def test_rate_limit_trips(self):
        email = self.unique_email()
        self.register(email)
        ratelimit.reset()  # count ONLY this test's login attempts
        for _i in range(10):
            status, _h, _b = self.login(email, password="wrong-password-1")
            self.assertEqual(status, 401)
        status, _h, body = self.login(email, password="wrong-password-1")
        self.assertEqual(status, 429)
        self.assertEqual(body["error"]["code"], "rate_limited")

    def test_password_and_email_storage(self):
        email = self.unique_email()
        _s, _h, body = self.register(email)
        user_id = body["user"]["id"]
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT password_hash, email_ciphertext, email_masked"
                " FROM users WHERE id = %s", (user_id,)).fetchone()
        self.assertTrue(row["password_hash"].startswith("$argon2id$"))
        self.assertNotIn(self.PASSWORD, row["password_hash"])
        self.assertNotIn(email.encode(), bytes(row["email_ciphertext"]))
        self.assertEqual(row["email_masked"], "a•••@example.com")


if __name__ == "__main__":
    unittest.main()
