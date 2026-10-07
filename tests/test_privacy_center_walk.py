"""Privacy Center — one continuous signed-in walk (spec Phase 48).

Phase 48's constituent features are covered piecemeal elsewhere
(accounts in test_accounts.py, tokens in test_api_tokens.py,
monitoring in test_monitoring.py, household in the org/admin
suites). What was missing — and what this file records — is the
Privacy Center verified AS A WHOLE: a single user journey that
enters at registration and walks every section of the signed-in
Privacy Center in the order the SPA presents them, asserting real
content at each step (not just status codes):

    register -> login -> identifiers (add / list / delete)
    -> consents (read / change / re-read) -> household (create /
    member add / identifier assignment) -> monitoring settings
    (read / update / pause / resume) -> timeline -> notifications
    -> API tokens (create / list / use / revoke / dead-after-revoke)
    -> exposure graph -> privacy export (JSON, password re-auth)
    -> passkeys (empty list) -> account deletion -> 401 afterwards

Section -> backing endpoint map (read from app.py, not guessed):

    identifiers ......... GET|POST /api/identifiers,
                          PATCH|DELETE /api/identifiers/<id>
    consents ............ GET|POST /api/consents
    household ........... GET /api/household,
                          POST /api/household/members,
                          DELETE /api/household/members/<id>
    monitoring settings . GET|PUT /api/monitoring/settings
    timeline ............ GET /api/monitoring/timeline
    notifications ....... GET /api/notifications
    API tokens .......... GET|POST /api/tokens,
                          DELETE /api/tokens/<id>
    exposure graph/map .. GET /api/graph
    privacy export ...... POST /api/privacy/export (password re-auth)
    passkeys ............ GET /api/auth/passkeys
    account deletion .... POST /api/auth/delete-account

Every section has a backing endpoint — none is pure client-side.
The SPA markup that hosts the sections is asserted separately
(test_spa_serves_every_privacy_center_section).

pgserver harness (fresh database per class), following
test_api_tokens.py. The journey account deletes itself at the end,
so there is nothing to clean up.

Run:  python3 -m pytest tests/test_privacy_center_walk.py -q
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
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
PASSWORD = "walk-through-pass-1"


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


try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestPrivacyCenterWalk(ServerMixin, unittest.TestCase):
    """Fresh database per class; the ONE journey test walks the
    whole Privacy Center in order against a single account."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        keys = ENV_KEYS + ("LEAKGUARD_PROVIDERS",)
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-walk-pg-")
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
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        registry_mod.reset_registry()
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
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

    # ------------------------------------------------------------------
    # The walk
    # ------------------------------------------------------------------

    def test_privacy_center_full_walk(self):
        uniq = uuid.uuid4().hex[:12]
        email = "walk-%s@example.com" % uniq
        ident_email = "detail-%s@example.com" % uniq
        ident_phone = "+91 98%08d" % (uuid.uuid4().int % 100000000)

        # --- register -------------------------------------------------
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD}, headers=CSRF)
        self.assertEqual(status, 201, body)
        user = body["user"]
        self.assertEqual(user["email_masked"], "w•••@example.com")
        register_cookie = self.session_cookie(headers)
        self.assertTrue(register_cookie)

        # --- logout, then a real login --------------------------------
        status, _h, _b = self.request_json(
            "POST", "/api/auth/logout", body={}, headers=CSRF,
            cookie=register_cookie)
        self.assertEqual(status, 200)
        status, _h, body = self.request_json(
            "GET", "/api/auth/me", cookie=register_cookie)
        self.assertEqual(status, 401)  # the register session is gone

        status, headers, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": PASSWORD}, headers=CSRF)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["user"]["id"], user["id"])
        cookie = self.session_cookie(headers)
        self.assertTrue(cookie)

        status, _h, me = self.request_json(
            "GET", "/api/auth/me", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual(me["id"], user["id"])
        self.assertEqual(me["email_masked"], "w•••@example.com")
        self.assertFalse(me["is_admin"])
        self.assertFalse(me["totp_enabled"])

        # --- identifiers: add two, list, delete one -------------------
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "email", "value": ident_email},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        email_ident = body["identifier"]
        self.assertEqual(email_ident["kind"], "email")
        self.assertEqual(email_ident["masked"], "d•••@example.com")
        self.assertNotIn(ident_email, json.dumps(body))

        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "phone", "value": ident_phone},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        phone_ident = body["identifier"]
        self.assertEqual(phone_ident["kind"], "phone")
        self.assertNotIn(ident_phone.replace(" ", ""), 
                         phone_ident["masked"].replace(" ", ""))
        self.assertNotIn(ident_phone, json.dumps(body))

        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie)
        self.assertEqual(status, 200)
        listed = {r["id"]: r for r in body["identifiers"]}
        self.assertEqual(set(listed), {email_ident["id"],
                                       phone_ident["id"]})
        self.assertEqual(listed[email_ident["id"]]["masked"],
                         "d•••@example.com")
        self.assertNotIn(ident_email, json.dumps(body))
        self.assertNotIn(ident_phone, json.dumps(body))

        status, _h, body = self.request_json(
            "DELETE", "/api/identifiers/" + phone_ident["id"],
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie)
        self.assertEqual([r["id"] for r in body["identifiers"]],
                         [email_ident["id"]])

        # --- consents: read defaults, change, re-read -----------------
        status, _h, body = self.request_json(
            "GET", "/api/consents", cookie=cookie)
        self.assertEqual(status, 200)
        state = {c["purpose"]: c for c in body["consents"]}
        self.assertEqual(set(state), {"scanning", "monitoring",
                                      "automated_remediation",
                                      "notifications"})
        for c in state.values():
            self.assertEqual((c["granted"], c["version"]), (False, 1))

        for purpose in ("scanning", "monitoring",
                        "automated_remediation"):
            status, _h, body = self.request_json(
                "POST", "/api/consents",
                body={"purpose": purpose, "granted": True},
                headers=CSRF, cookie=cookie)
            self.assertEqual(status, 200, (purpose, body))
        status, _h, body = self.request_json(
            "GET", "/api/consents", cookie=cookie)
        state = {c["purpose"]: c for c in body["consents"]}
        for purpose in ("scanning", "monitoring",
                        "automated_remediation"):
            self.assertEqual(
                (state[purpose]["granted"], state[purpose]["version"]),
                (True, 2), purpose)
        self.assertEqual(
            (state["notifications"]["granted"],
             state["notifications"]["version"]), (False, 1))

        # --- household: lazily created, member add, assignment --------
        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["id"])
        self.assertEqual(body["members"], [])

        status, _h, body = self.request_json(
            "POST", "/api/household/members", body={"label": "Rudra"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        member = body["member"]
        self.assertEqual(member["label"], "Rudra")

        status, _h, body = self.request_json(
            "GET", "/api/household", cookie=cookie)
        self.assertEqual([m["id"] for m in body["members"]],
                         [member["id"]])
        self.assertEqual(body["members"][0]["label"], "Rudra")

        # The saved email detail now belongs to that member.
        status, _h, body = self.request_json(
            "PATCH", "/api/identifiers/" + email_ident["id"],
            body={"member_id": member["id"]}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["identifier"]["member_id"], member["id"])
        status, _h, body = self.request_json(
            "GET", "/api/identifiers", cookie=cookie)
        self.assertEqual(body["identifiers"][0]["member_id"],
                         member["id"])

        # --- monitoring settings: read, update, pause, resume ---------
        status, _h, body = self.request_json(
            "GET", "/api/monitoring/settings", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cadence_days"], 7)          # default
        self.assertFalse(body["monitoring_paused"])
        self.assertTrue(body["monitoring_consent"])        # granted above
        self.assertTrue(body["due_now"])                   # never scanned

        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"cadence_days": 30}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cadence_days"], 30)
        self.assertFalse(body["monitoring_paused"])

        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"monitoring_paused": True}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["monitoring_paused"])
        self.assertFalse(body["due_now"])  # paused users are never due

        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"monitoring_paused": False}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertFalse(body["monitoring_paused"])

        status, _h, body = self.request_json(
            "GET", "/api/monitoring/settings", cookie=cookie)
        self.assertEqual((body["cadence_days"],
                          body["monitoring_paused"]), (30, False))

        # --- timeline: a fresh account's history is an empty list -----
        # (Events are derived from completed scans, findings and
        # remediation cases — none exist yet, and the endpoint must
        # say so with a well-formed empty list, not an error.)
        status, _h, body = self.request_json(
            "GET", "/api/monitoring/timeline", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["events"], [])

        # --- notifications: empty ledger, well-formed -----------------
        status, _h, body = self.request_json(
            "GET", "/api/notifications", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["notifications"], [])

        # --- API tokens: create, list, use, revoke, dead --------------
        status, _h, body = self.request_json(
            "POST", "/api/tokens", body={"name": "walk-cli"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        raw_token = body["token"]
        record = body["record"]
        self.assertTrue(raw_token.startswith("lg_"))
        self.assertEqual(record["name"], "walk-cli")
        self.assertIsNone(record["revoked_at"])

        status, _h, body = self.request_json(
            "GET", "/api/tokens", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual([t["id"] for t in body["tokens"]],
                         [record["id"]])
        self.assertNotIn(raw_token, json.dumps(body))

        # The token works for reads while it lives.
        status, _h, body = self.request_json(
            "GET", "/api/notifications", headers=self.bearer(raw_token))
        self.assertEqual(status, 200, body)
        self.assertEqual(body["notifications"], [])

        status, _h, body = self.request_json(
            "DELETE", "/api/tokens/" + record["id"],
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

        status, _h, body = self.request_json(
            "GET", "/api/tokens", cookie=cookie)
        by_id = {t["id"]: t for t in body["tokens"]}
        self.assertIsNotNone(by_id[record["id"]]["revoked_at"])

        # …and it is dead afterwards.
        status, _h, body = self.request_json(
            "GET", "/api/notifications", headers=self.bearer(raw_token))
        self.assertEqual(status, 401, body)

        # --- exposure graph: well-formed, masked only -----------------
        status, _h, body = self.request_json(
            "GET", "/api/graph", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(set(body), {"nodes", "edges", "propagation"})
        self.assertIsInstance(body["nodes"], list)
        self.assertIsInstance(body["edges"], list)
        self.assertEqual(set(body["propagation"]),
                         {"entries", "rollups"})
        self.assertEqual(body["propagation"]["entries"], [])
        self.assertEqual(body["propagation"]["rollups"], [])
        # No findings yet, so no nodes — and never any plaintext.
        self.assertNotIn(ident_email, json.dumps(body))
        self.assertNotIn(email, json.dumps(body))

        # --- privacy export: password re-auth, then the real data -----
        status, _h, body = self.request_json(
            "POST", "/api/privacy/export",
            body={"password": "not-the-password-1", "format": "json"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 401, body)  # re-auth actually gates

        status, headers, body = self.request_json(
            "POST", "/api/privacy/export",
            body={"password": PASSWORD, "format": "json"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("attachment",
                      headers.get("Content-Disposition") or "")
        # The export is the ONLY plaintext exit, and it is the
        # owner's own data: account email in full, the surviving
        # identifier in full, the deleted one gone.
        self.assertEqual(body["account"]["email"], email)
        self.assertEqual(body["account"]["email_masked"],
                         "w•••@example.com")
        exported = {i["kind"]: i for i in body["identifiers"]}
        self.assertEqual(set(exported), {"email"})
        self.assertEqual(exported["email"]["value"], ident_email)
        self.assertEqual(exported["email"]["masked"],
                         "d•••@example.com")
        granted = {c["purpose"] for c in body["consents"]
                   if c["granted"]}
        self.assertTrue({"scanning", "monitoring",
                         "automated_remediation"} <= granted)
        self.assertIn("generated_at", body)

        # --- passkeys: none enrolled, list answers cleanly ------------
        status, _h, body = self.request_json(
            "GET", "/api/auth/passkeys", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["passkeys"], [])

        # --- delete account: session dies with it ---------------------
        status, headers, body = self.request_json(
            "POST", "/api/auth/delete-account",
            body={"password": PASSWORD}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertIn("Max-Age=0", headers.get("Set-Cookie") or "")

        status, _h, body = self.request_json(
            "GET", "/api/auth/me", cookie=cookie)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthenticated")
        # Every Privacy Center section is closed to the dead session.
        for path in ("/api/identifiers", "/api/consents",
                     "/api/household", "/api/monitoring/settings",
                     "/api/tokens", "/api/graph"):
            status, _h, _b = self.request_json("GET", path, cookie=cookie)
            self.assertEqual(status, 401, path)
        # And the credentials themselves no longer log in.
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": PASSWORD}, headers=CSRF)
        self.assertEqual(status, 401)

    # ------------------------------------------------------------------
    # Section gating + SPA markup
    # ------------------------------------------------------------------

    def test_every_section_requires_auth(self):
        for path in ("/api/auth/me", "/api/auth/passkeys",
                     "/api/consents", "/api/identifiers",
                     "/api/household", "/api/monitoring/settings",
                     "/api/monitoring/timeline", "/api/notifications",
                     "/api/tokens", "/api/graph"):
            status, _h, body = self.request_json("GET", path)
            self.assertEqual(status, 401, path)
            self.assertEqual(body["error"]["code"], "unauthenticated",
                             path)

    def test_spa_serves_every_privacy_center_section(self):
        status, _h, payload = self.request("GET", "/")
        self.assertEqual(status, 200)
        html = payload.decode("utf-8")
        # One marker per Privacy Center section, taken from
        # static/index.html: the section host plus each section's
        # primary control/list element.
        for marker in (
                'id="privacyCenter"',      # the center itself
                'id="consentList"',        # consents
                'id="memberList"',         # household members
                'id="memberLabel"',        # household member add
                'id="monCadence"',         # monitoring settings
                'id="monPauseBtn"',        # monitoring pause/resume
                'id="timelineList"',       # timeline
                'id="notifList"',          # notifications
                'id="apiTokenList"',       # API tokens
                'id="apiTokenCreateBtn"',  # API token create
                'id="graphWrap"',          # exposure graph/map
                'id="exportBtn"',          # privacy export
                'id="exportPassword"',     # export re-auth field
                'id="passkeyList"',        # passkeys
                'id="delBtn"',             # account deletion
                'id="delPassword"',        # deletion re-auth field
        ):
            self.assertIn(marker, html)


if __name__ == "__main__":
    unittest.main()
