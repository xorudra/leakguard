"""API tokens, trust page and security.txt (Stage S13 — spec
Phases 126–132).

Layers:

* TestApiTokensUnavailable — always runs: with NO database
  configured, the token routes answer the same clean 503 as every
  other account route (CSRF still fires first), a Bearer token
  changes nothing, and the static trust surfaces (/trust,
  /.well-known/security.txt, home, health) serve fine.
* TestApiTokensDb — pgserver: the full token lifecycle (create
  shows the raw value exactly once; the database stores only its
  SHA-256 digest; the list exposes neither), Bearer reads on all
  six read endpoints, the read-only wall (no mutation is ever
  authorized by a token), revocation, IDOR, last_used bookkeeping,
  audit rows free of token material, and tokens dying with their
  account.

No token values are printed; test accounts use unique
example.com addresses.

Run:  python3 -m unittest discover -s tests
"""

import base64
import hashlib
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
PASSWORD = "S13 test " + "password 123"


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

    def bearer(self, raw):
        return {"Authorization": "Bearer " + raw}


# ---------------------------------------------------------------------------
# No-database layer
# ---------------------------------------------------------------------------

class TestApiTokensUnavailable(ServerMixin, unittest.TestCase):
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

    def test_health_and_home_untouched(self):
        status, _h, body = self.request_json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["db"], "disabled")
        status, _h, _b = self.request("GET", "/")
        self.assertEqual(status, 200)

    def test_token_list_503_without_database(self):
        status, _h, body = self.request_json("GET", "/api/tokens")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_token_create_503_with_csrf(self):
        status, _h, _b = self.request_json(
            "POST", "/api/tokens", body={"name": "cli"}, headers=CSRF)
        self.assertEqual(status, 503)

    def test_token_create_csrf_fires_first(self):
        status, _h, _b = self.request(
            "POST", "/api/tokens", body={"name": "cli"})
        self.assertEqual(status, 403)

    def test_token_revoke_503_without_database(self):
        status, _h, _b = self.request_json(
            "DELETE", "/api/tokens/" + str(uuid.uuid4()), headers=CSRF)
        self.assertEqual(status, 503)

    def test_bearer_read_503_without_database(self):
        status, _h, body = self.request_json(
            "GET", "/api/scans",
            headers={"Authorization": "Bearer lg_whatever"})
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_trust_page_serves_with_facts(self):
        status, _h, payload = self.request("GET", "/trust")
        self.assertEqual(status, 200)
        html = payload.decode("utf-8")
        for needle in ("AES-256-GCM", "Argon2id", "k-anonymity",
                       "Have I Been Pwned", "XposedOrNot", "Neon",
                       "Brevo", "DuckDuckGo",
                       "Cannot be removed", "Telegram",
                       "Trust &amp; security",
                       'id="apiTokenList"'):
            self.assertIn(needle, html)

    def test_security_txt(self):
        status, headers, payload = self.request(
            "GET", "/.well-known/security.txt")
        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers.get("Content-Type"))
        text = payload.decode("utf-8")
        self.assertIn("Contact: mailto:forapikeyonly2008@gmail.com", text)
        self.assertIn("Canonical: https://leakguard-hh8e.onrender.com"
                      "/.well-known/security.txt", text)
        expires = None
        for line in text.splitlines():
            if line.startswith("Expires:"):
                expires = datetime.fromisoformat(
                    line.split(":", 1)[1].strip().replace("Z", "+00:00"))
        self.assertIsNotNone(expires)
        self.assertGreater(expires, datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# pgserver layer
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestApiTokensDb(ServerMixin, unittest.TestCase):
    """Fresh database per class (token + audit state is asserted
    exactly), following the S11 harness."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        keys = ENV_KEYS + ("LEAKGUARD_PROVIDERS",)
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-tokens-pg-")
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
        registry_mod.reset_registry()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        from remediation import registry_seed

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

    def register(self):
        email = "s13-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def create_token(self, cookie, name="cli"):
        status, _h, body = self.request_json(
            "POST", "/api/tokens", body={"name": name},
            cookie=cookie, headers=CSRF)
        self.assertEqual(status, 201, body)
        return body

    def list_tokens(self, cookie):
        status, _h, body = self.request_json(
            "GET", "/api/tokens", cookie=cookie)
        self.assertEqual(status, 200, body)
        return body["tokens"]

    # ---------- lifecycle ----------

    def test_create_shows_raw_once_and_stores_only_hash(self):
        cookie, user_id = self.register()
        body = self.create_token(cookie)
        raw = body["token"]
        self.assertTrue(raw.startswith("lg_"))
        record = body["record"]
        self.assertEqual(record["prefix"], raw[:8])
        self.assertEqual(record["scopes"], ["read"])
        self.assertIsNone(record["last_used_at"])
        self.assertIsNone(record["revoked_at"])

        # The list shape can never leak the raw value or the digest.
        listed = self.list_tokens(cookie)
        self.assertEqual(len(listed), 1)
        blob = json.dumps(listed)
        self.assertNotIn(raw, blob)
        digest = hashlib.sha256(raw.encode("utf-8")).digest()
        self.assertNotIn(digest.hex(), blob)

        # At rest: exactly the SHA-256 digest, never the raw bytes.
        with self.pool.connection() as conn:
            row = conn.execute(
                "SELECT token_hash, prefix FROM api_tokens"
                " WHERE user_id = %s", (user_id,)).fetchone()
        self.assertEqual(bytes(row["token_hash"]), digest)
        self.assertEqual(row["prefix"], raw[:8])

    def test_create_validation_and_session_required(self):
        cookie, _uid = self.register()
        for bad in ("", "   ", "x" * 61, None, 42):
            status, _h, body = self.request_json(
                "POST", "/api/tokens", body={"name": bad},
                cookie=cookie, headers=CSRF)
            self.assertEqual(status, 400, (bad, body))
            self.assertEqual(body["error"]["code"], "invalid_name")
        status, _h, _b = self.request_json(
            "POST", "/api/tokens", body={"name": "cli"}, headers=CSRF)
        self.assertEqual(status, 401)
        # No CSRF header: the guard fires before the session check.
        status, _h, _b = self.request(
            "POST", "/api/tokens", body={"name": "cli"}, cookie=cookie)
        self.assertEqual(status, 403)

    # ---------- bearer reads ----------

    def test_bearer_reads_all_six_endpoints(self):
        cookie, _uid = self.register()
        # Seed one scan job so /api/scans/<id> has a target.
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": True},
            cookie=cookie, headers=CSRF)
        self.assertEqual(status, 200, body)
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "email",
                  "value": "s13-scan-%s@example.com" % self.uniq()},
            cookie=cookie, headers=CSRF)
        self.assertEqual(status, 201, body)
        status, _h, body = self.request_json(
            "POST", "/api/scans", body={"idempotency_key": "s13-job"},
            cookie=cookie, headers=CSRF)
        self.assertEqual(status, 201, body)
        job_id = body["job"]["id"]

        raw = self.create_token(cookie)["token"]
        for path in ("/api/action-center", "/api/scans",
                     "/api/scans/" + job_id, "/api/remediation/cases",
                     "/api/notifications", "/api/monitoring/timeline"):
            status, _h, body = self.request_json(
                "GET", path, headers=self.bearer(raw))
            self.assertEqual(status, 200, (path, body))
        # The job fetched by token is the owner's own job.
        status, _h, body = self.request_json(
            "GET", "/api/scans/" + job_id, headers=self.bearer(raw))
        self.assertEqual(body["job"]["id"], job_id)
        # Session access to the same endpoints is unchanged.
        status, _h, _b = self.request_json(
            "GET", "/api/scans", cookie=cookie)
        self.assertEqual(status, 200)

    def test_bearer_rejects_unknown_malformed_and_foreign(self):
        cookie_a, _uid_a = self.register()
        cookie_b, _uid_b = self.register()
        raw_a = self.create_token(cookie_a)["token"]
        # Unknown token: same 401 as signed out.
        status, _h, body = self.request_json(
            "GET", "/api/scans",
            headers={"Authorization": "Bearer lg_" + "x" * 43})
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthenticated")
        # Not an lg_ token at all.
        status, _h, _b = self.request_json(
            "GET", "/api/scans",
            headers={"Authorization": "Bearer something-else"})
        self.assertEqual(status, 401)
        status, _h, _b = self.request_json(
            "GET", "/api/scans",
            headers={"Authorization": "Basic dXNlcjpwYXNz"})
        self.assertEqual(status, 401)
        # A token is not a session: token management stays shut.
        status, _h, _b = self.request_json(
            "GET", "/api/tokens", headers=self.bearer(raw_a))
        self.assertEqual(status, 401)
        # B's list never contains A's token.
        self.assertEqual(self.list_tokens(cookie_b), [])

    def test_bearer_never_authorizes_mutations(self):
        cookie, _uid = self.register()
        created = self.create_token(cookie)
        raw = created["token"]
        token_id = created["record"]["id"]
        auth = dict(self.bearer(raw))
        auth.update(CSRF)
        mutations = [
            ("POST", "/api/tokens", {"name": "via-token"}),
            ("POST", "/api/scans", {"idempotency_key": "nope"}),
            ("POST", "/api/consents",
             {"purpose": "scanning", "granted": True}),
            ("DELETE", "/api/tokens/" + token_id, None),
            ("PUT", "/api/monitoring/settings", {"cadence_days": 14}),
        ]
        for method, path, payload in mutations:
            status, _h, body = self.request_json(
                method, path, body=payload, headers=auth)
            self.assertEqual(status, 401, (method, path, body))
        # And nothing actually changed: still exactly one live token.
        tokens = self.list_tokens(cookie)
        self.assertEqual(len(tokens), 1)
        self.assertIsNone(tokens[0]["revoked_at"])

    # ---------- revocation / last_used / audit ----------

    def test_revoke_flow_and_idor(self):
        cookie_a, _uid_a = self.register()
        cookie_b, _uid_b = self.register()
        created = self.create_token(cookie_a)
        raw, token_id = created["token"], created["record"]["id"]
        # Foreign revoke: same 404 as nonexistent.
        status, _h, _b = self.request_json(
            "DELETE", "/api/tokens/" + token_id,
            cookie=cookie_b, headers=CSRF)
        self.assertEqual(status, 404)
        status, _h, body = self.request_json(
            "GET", "/api/scans", headers=self.bearer(raw))
        self.assertEqual(status, 200)  # still alive after foreign try
        # Owner revokes.
        status, _h, body = self.request_json(
            "DELETE", "/api/tokens/" + token_id,
            cookie=cookie_a, headers=CSRF)
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"deleted": True, "id": token_id})
        # The revoked token is dead and reads as signed out.
        status, _h, body = self.request_json(
            "GET", "/api/scans", headers=self.bearer(raw))
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthenticated")
        # The list shows the revocation; a second revoke is a 404.
        tokens = self.list_tokens(cookie_a)
        self.assertIsNotNone(tokens[0]["revoked_at"])
        status, _h, _b = self.request_json(
            "DELETE", "/api/tokens/" + token_id,
            cookie=cookie_a, headers=CSRF)
        self.assertEqual(status, 404)

    def test_last_used_updates_and_throttles(self):
        cookie, _uid = self.register()
        raw = self.create_token(cookie)["token"]
        status, _h, _b = self.request_json(
            "GET", "/api/notifications", headers=self.bearer(raw))
        self.assertEqual(status, 200)
        first = self.list_tokens(cookie)[0]["last_used_at"]
        self.assertIsNotNone(first)
        # An immediate second use is inside the 5-minute throttle:
        # the stored timestamp must not move.
        status, _h, _b = self.request_json(
            "GET", "/api/notifications", headers=self.bearer(raw))
        self.assertEqual(status, 200)
        self.assertEqual(self.list_tokens(cookie)[0]["last_used_at"],
                         first)

    def test_audit_rows_carry_no_token_material(self):
        cookie, user_id = self.register()
        created = self.create_token(cookie)
        raw = created["token"]
        status, _h, _b = self.request_json(
            "DELETE", "/api/tokens/" + created["record"]["id"],
            cookie=cookie, headers=CSRF)
        self.assertEqual(status, 200)
        with self.pool.connection() as conn:
            rows = conn.execute(
                "SELECT action FROM audit_log"
                " WHERE actor_user_id = %s AND action LIKE %s",
                (user_id, "api_token.%")).fetchall()
            everything = conn.execute(
                "SELECT action || ' ' || coalesce(target_kind, '')"
                " || ' ' || coalesce(target_id, '')"
                " || ' ' || detail::text AS blob FROM audit_log"
            ).fetchall()
        actions = {row["action"] for row in rows}
        self.assertEqual(actions,
                         {"api_token.created", "api_token.revoked"})
        blob = "\n".join(row["blob"] for row in everything)
        self.assertNotIn(raw, blob)
        self.assertNotIn(
            hashlib.sha256(raw.encode("utf-8")).hexdigest(), blob)

    def test_token_dies_with_deleted_account(self):
        cookie, _uid = self.register()
        raw = self.create_token(cookie)["token"]
        status, _h, _b = self.request_json(
            "GET", "/api/scans", headers=self.bearer(raw))
        self.assertEqual(status, 200)
        status, _h, body = self.request_json(
            "POST", "/api/auth/delete-account",
            body={"password": PASSWORD}, cookie=cookie, headers=CSRF)
        self.assertEqual(status, 200, body)
        status, _h, _b = self.request_json(
            "GET", "/api/scans", headers=self.bearer(raw))
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
