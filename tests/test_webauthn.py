"""WebAuthn passkey tests (Batch D1 — spec Phase 4: the optional
stronger authentication method).

Layers:

* TestCborUnit — offline: the CBOR codec's round trips and its
  rejection of malformed / out-of-bounds input.
* TestWebauthnUnavailable — no database: every passkey route
  answers the same clean structured 503 as the other account
  routes (CSRF guard still first).
* TestWebauthnDb — the full ceremonies against a local PostgreSQL
  (pgserver), driven by a SOFTWARE AUTHENTICATOR built in this
  file on the cryptography package: real P-256 / RSA keypairs
  producing real attestation objects and assertions, so every
  check the relying party runs (challenge, origin, RP hash, flags,
  COSE key, signature, counter) is exercised for real — including
  each failure mode, one at a time.

The RP id / origin are pinned by environment
(LEAKGUARD_WEBAUTHN_RP_ID / LEAKGUARD_WEBAUTHN_ORIGIN), the same
override production can use.

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
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import cbor, ratelimit, totp  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_WEBAUTHN_RP_ID", "LEAKGUARD_WEBAUTHN_ORIGIN")

RP_ID = "example.com"
ORIGIN = "https://example.com"


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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
# CBOR codec, offline
# ---------------------------------------------------------------------------

class TestCborUnit(unittest.TestCase):
    def test_round_trips(self):
        values = [
            0, 1, 23, 24, 255, 256, 65535, 65536, 2 ** 40,
            -1, -24, -25, -256, -100000,
            b"", b"\x00\x01\x02", "text", "ünïcode",
            [], [1, "two", b"three", [4]], {}, True, False, None, 1.5,
            {1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32},
            {"fmt": "none", "attStmt": {}, "authData": b"\x01" * 37},
        ]
        for value in values:
            self.assertEqual(cbor.decode(cbor.encode(value)), value, value)

    def test_decode_one_reports_offset(self):
        blob = b"\xff\xff" + cbor.encode({1: 2}) + b"\xee"
        value, next_offset = cbor.decode_one(blob, 2)
        self.assertEqual(value, {1: 2})
        self.assertEqual(blob[next_offset:], b"\xee")

    def test_malformed_inputs_rejected(self):
        bad = [
            b"",                       # empty
            b"\x1c",                  # reserved additional info
            b"\x5f",                  # indefinite byte string
            b"\x7f",                  # indefinite text string
            b"\x9f\x01\xff",          # indefinite array
            b"\xbf",                  # indefinite map
            b"\x18",                  # truncated argument
            b"\x42\x01",              # truncated byte string
            b"\x81",                  # truncated array
            b"\xa1\x01",              # truncated map (value missing)
            b"\x01\x00",              # trailing bytes
            b"\xa2\x01\x02\x01\x03",  # duplicate map key
            b"\xf8\x00",              # one-byte simple value (unsupported)
        ]
        for blob in bad:
            with self.assertRaises(cbor.CborError, msg=repr(blob)):
                cbor.decode(blob)

    def test_bounds(self):
        with self.assertRaises(cbor.CborError):
            cbor.decode(b"\x82" * 40 + b"\x00")  # nesting beyond depth
        with self.assertRaises(cbor.CborError):
            cbor.decode(b"\x9a\x00\x0f\x42\x40")  # array claiming 999,999
        with self.assertRaises(cbor.CborError):
            cbor.decode(b"\x00" * (cbor.MAX_INPUT_BYTES + 1))


# ---------------------------------------------------------------------------
# No-database behaviour
# ---------------------------------------------------------------------------

class TestWebauthnUnavailable(ServerMixin, unittest.TestCase):
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

    def test_login_options_503(self):
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/login/options", body={},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_register_options_503(self):
        status, _h, _b = self.request_json(
            "POST", "/api/auth/passkey/register/options",
            body={"password": "whatever-pass"}, headers=CSRF)
        self.assertEqual(status, 503)

    def test_passkey_list_503(self):
        status, _h, _b = self.request_json("GET", "/api/auth/passkeys")
        self.assertEqual(status, 503)

    def test_csrf_still_first(self):
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/login/options", body={})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")


# ---------------------------------------------------------------------------
# Software authenticator fixture
# ---------------------------------------------------------------------------

class SoftwareAuthenticator:
    """A WebAuthn authenticator in software: a real keypair from
    the cryptography package, emitting real ceremony bytes."""

    def __init__(self, rsa_key=False):
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        if rsa_key:
            self._key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048)
        else:
            self._key = ec.generate_private_key(ec.SECP256R1())
        self.is_rsa = rsa_key
        self.credential_id = os.urandom(32)

    def cose(self):
        numbers = self._key.public_key().public_numbers()
        if self.is_rsa:
            n_bytes = numbers.n.to_bytes(
                (numbers.n.bit_length() + 7) // 8, "big")
            e_bytes = numbers.e.to_bytes(
                (numbers.e.bit_length() + 7) // 8, "big")
            return cbor.encode({1: 3, 3: -257, -1: n_bytes, -2: e_bytes})
        return cbor.encode({
            1: 2, 3: -7, -1: 1,
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })

    @staticmethod
    def _client_data(ceremony, challenge, origin):
        return json.dumps(
            {"type": ceremony, "challenge": challenge,
             "origin": origin, "crossOrigin": False},
            separators=(",", ":")).encode("utf-8")

    def create(self, challenge, fmt="none", origin=ORIGIN, rp_id=RP_ID,
               up=True, uv=True, sign_count=0):
        cd = self._client_data("webauthn.create", challenge, origin)
        flags = 0x40 | (0x01 if up else 0) | (0x04 if uv else 0)
        auth_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags]) + int(sign_count).to_bytes(4, "big")
            + b"\x00" * 16
            + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id + self.cose())
        attestation = cbor.encode(
            {"fmt": fmt, "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(cd),
                "attestationObject": _b64(attestation),
            },
        }

    def get(self, challenge, sign_count=1, origin=ORIGIN, rp_id=RP_ID,
            up=True, uv=True, key=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding

        cd = self._client_data("webauthn.get", challenge, origin)
        flags = (0x01 if up else 0) | (0x04 if uv else 0)
        auth_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags]) + int(sign_count).to_bytes(4, "big"))
        signed = auth_data + hashlib.sha256(cd).digest()
        signing_key = key or self._key
        if self.is_rsa:
            signature = signing_key.sign(
                signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            signature = signing_key.sign(
                signed, ec.ECDSA(hashes.SHA256()))
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(cd),
                "authenticatorData": _b64(auth_data),
                "signature": _b64(signature),
            },
        }


# ---------------------------------------------------------------------------
# Full ceremonies against a local PostgreSQL
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestWebauthnDb(ServerMixin, unittest.TestCase):
    PASSWORD = "<redacted>"

    @classmethod
    def setUpClass(cls):
        import base64
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="leakguard-webauthn-")
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
        os.environ["LEAKGUARD_WEBAUTHN_RP_ID"] = RP_ID
        os.environ["LEAKGUARD_WEBAUTHN_ORIGIN"] = ORIGIN
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        cls.start_server()

    @classmethod
    def _teardown(cls):
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        import shutil

        shutil.rmtree(cls._pg_dir, ignore_errors=True)
        cls._env.__exit__()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._teardown()

    def setUp(self):
        ratelimit.reset()

    # ---------- helpers ----------

    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def register_user(self):
        email = "webauthn-%s@example.com" % uuid.uuid4().hex[:12]
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def reg_options(self, cookie, password=None):
        return self.request_json(
            "POST", "/api/auth/passkey/register/options",
            body={"password": password if password is not None
                    else self.PASSWORD},
            headers=CSRF, cookie=cookie)

    def add_passkey(self, cookie, authenticator=None, nickname="My phone"):
        authenticator = authenticator or SoftwareAuthenticator()
        status, _h, options = self.reg_options(cookie)
        self.assertEqual(status, 200, options)
        payload = authenticator.create(options["challenge"])
        payload["nickname"] = nickname
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/register/verify", body=payload,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return authenticator, body["passkey"]

    def login_options(self):
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/login/options", body={},
            headers=CSRF)
        self.assertEqual(status, 200, body)
        return body

    def attempt_login(self, authenticator, **kwargs):
        options = self.login_options()
        payload = authenticator.get(options["challenge"], **kwargs)
        return self.request_json(
            "POST", "/api/auth/passkey/login/verify", body=payload,
            headers=CSRF)

    # ---------- registration ----------

    def test_register_and_login_happy_path(self):
        cookie, user_id, _email = self.register_user()
        authenticator, stored = self.add_passkey(cookie)
        self.assertEqual(stored["nickname"], "My phone")
        self.assertEqual(len(stored["id_prefix"]), 8)
        # The full credential id never appears in any API shape.
        self.assertNotIn(_b64(authenticator.credential_id), json.dumps(stored))
        row = self.db_row(
            "SELECT credential_id_hash, sign_count, last_used_at"
            " FROM passkey_credentials WHERE user_id = %s", (user_id,))
        self.assertEqual(bytes(row["credential_id_hash"]),
                         hashlib.sha256(authenticator.credential_id).digest())
        self.assertIsNone(row["last_used_at"])

        status, _h, listing = self.request_json(
            "GET", "/api/auth/passkeys", cookie=cookie)
        self.assertEqual(status, 200)
        self.assertEqual([p["id"] for p in listing["passkeys"]],
                         [stored["id"]])

        options = self.login_options()
        self.assertEqual(options["rpId"], RP_ID)
        self.assertEqual(options["allowCredentials"], [])
        payload = authenticator.get(options["challenge"])
        status, headers, body = self.request_json(
            "POST", "/api/auth/passkey/login/verify", body=payload,
            headers=CSRF)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["user"]["id"], user_id)
        new_cookie = self.session_cookie(headers)
        self.assertTrue(new_cookie)
        status, _h, me = self.request_json(
            "GET", "/api/auth/me", cookie=new_cookie)
        self.assertEqual(status, 200)
        self.assertEqual(me["id"], user_id)
        row = self.db_row(
            "SELECT sign_count, last_used_at FROM passkey_credentials"
            " WHERE user_id = %s", (user_id,))
        self.assertEqual(row["sign_count"], 1)
        self.assertIsNotNone(row["last_used_at"])
        audit = self.db_row(
            "SELECT count(*) AS n FROM audit_log"
            " WHERE action = 'auth.passkey_login' AND actor_user_id = %s",
            (user_id,))
        self.assertGreaterEqual(audit["n"], 1)

    def test_registration_options_shape_and_exclusions(self):
        cookie, _uid, _email = self.register_user()
        status, _h, options = self.reg_options(cookie)
        self.assertEqual(status, 200)
        self.assertEqual(options["rp"], {"name": "LeakGuard", "id": RP_ID})
        self.assertEqual(options["attestation"], "none")
        self.assertEqual(options["excludeCredentials"], [])
        algs = [p["alg"] for p in options["pubKeyCredParams"]]
        self.assertEqual(algs, [-7, -257])
        authenticator, _stored = self.add_passkey(cookie)
        status, _h, options = self.reg_options(cookie)
        self.assertEqual(status, 200)
        self.assertEqual(
            [c["id"] for c in options["excludeCredentials"]],
            [_b64(authenticator.credential_id)])

    def test_registration_requires_session_and_password(self):
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/register/options",
            body={"password": self.PASSWORD}, headers=CSRF)
        self.assertEqual(status, 401)
        cookie, _uid, _e = self.register_user()
        status, _h, body = self.reg_options(cookie, password="WrongPass-999")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "invalid_credentials")

    def test_attestation_format_rejected_by_name(self):
        cookie, _uid, _e = self.register_user()
        authenticator = SoftwareAuthenticator()
        status, _h, options = self.reg_options(cookie)
        self.assertEqual(status, 200)
        payload = authenticator.create(options["challenge"], fmt="packed")
        payload["nickname"] = "Packed key"
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/register/verify", body=payload,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"],
                         "attestation_format_unsupported")

    def test_registration_wrong_rp_and_origin(self):
        cookie, _uid, _e = self.register_user()
        authenticator = SoftwareAuthenticator()
        status, _h, options = self.reg_options(cookie)
        payload = authenticator.create(options["challenge"],
                                       rp_id="other.example")
        payload["nickname"] = "Wrong RP"
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/register/verify", body=payload,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"],
                         "passkey_registration_failed")
        status, _h, options = self.reg_options(cookie)
        payload = authenticator.create(
            options["challenge"], origin="https://phishing.example")
        payload["nickname"] = "Wrong origin"
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/register/verify", body=payload,
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 400)

    def test_challenge_bound_to_user_and_session(self):
        cookie_a, _uid_a, _e = self.register_user()
        cookie_b, _uid_b, _e = self.register_user()
        status, _h, options = self.reg_options(cookie_a)
        self.assertEqual(status, 200)
        payload = SoftwareAuthenticator().create(options["challenge"])
        payload["nickname"] = "Not yours"
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/register/verify", body=payload,
            headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"],
                         "passkey_registration_failed")

    def test_rsa_passkey_round_trip(self):
        cookie, user_id, _e = self.register_user()
        authenticator, _stored = self.add_passkey(
            cookie, SoftwareAuthenticator(rsa_key=True), "Security key")
        status, _h, body = self.attempt_login(authenticator)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["user"]["id"], user_id)

    # ---------- sign-in failure modes: one generic 401 each ----------

    def assert_login_fails(self, authenticator, **kwargs):
        status, _h, body = self.attempt_login(authenticator, **kwargs)
        self.assertEqual(status, 401, body)
        self.assertEqual(body["error"]["code"], "passkey_failed")

    def test_login_unknown_credential(self):
        self.register_user()
        self.assert_login_fails(SoftwareAuthenticator())

    def test_login_wrong_challenge(self):
        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        payload = authenticator.get(_b64(b"\x07" * 32))
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/login/verify", body=payload,
            headers=CSRF)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "passkey_failed")

    def test_login_wrong_origin_and_rp(self):
        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        self.assert_login_fails(authenticator,
                                origin="https://phishing.example")
        self.assert_login_fails(authenticator, rp_id="other.example")

    def test_login_missing_flags(self):
        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        self.assert_login_fails(authenticator, uv=False)
        self.assert_login_fails(authenticator, up=False)

    def test_login_bad_signature(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        stranger = ec.generate_private_key(ec.SECP256R1())
        self.assert_login_fails(authenticator, key=stranger)

    def test_login_challenge_replay(self):
        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        options = self.login_options()
        payload = authenticator.get(options["challenge"])
        status, _h, _b = self.request_json(
            "POST", "/api/auth/passkey/login/verify", body=payload,
            headers=CSRF)
        self.assertEqual(status, 200)
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/login/verify", body=payload,
            headers=CSRF)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "passkey_failed")

    def test_login_challenge_expired(self):
        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        options = self.login_options()
        digest = hashlib.sha256(_unb64(options["challenge"])).digest()
        with self.pool.connection() as conn:
            conn.execute(
                "UPDATE webauthn_challenges"
                " SET expires_at = now() - interval '1 minute'"
                " WHERE challenge_hash = %s", (digest,))
        payload = authenticator.get(options["challenge"])
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkey/login/verify", body=payload,
            headers=CSRF)
        self.assertEqual(status, 401)

    def test_sign_counter_rules(self):
        cookie, _uid, _e = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        # Authenticators that always report 0 are accepted.
        status, _h, _b = self.attempt_login(authenticator, sign_count=0)
        self.assertEqual(status, 200)
        status, _h, _b = self.attempt_login(authenticator, sign_count=0)
        self.assertEqual(status, 200)
        # A real counter must strictly increase.
        status, _h, _b = self.attempt_login(authenticator, sign_count=5)
        self.assertEqual(status, 200)
        self.assert_login_fails(authenticator, sign_count=5)
        self.assert_login_fails(authenticator, sign_count=3)
        status, _h, _b = self.attempt_login(authenticator, sign_count=6)
        self.assertEqual(status, 200)

    # ---------- management ----------

    def test_revoke_flow(self):
        cookie, user_id, _e = self.register_user()
        authenticator, stored = self.add_passkey(cookie)
        status, _h, _b = self.attempt_login(authenticator)
        self.assertEqual(status, 200)
        url = "/api/auth/passkeys/%s/revoke" % stored["id"]
        status, _h, body = self.request_json(
            "POST", url, body={"password": "WrongPass-999"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 401)
        status, _h, body = self.request_json(
            "POST", url, body={"password": self.PASSWORD},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        status, _h, listing = self.request_json(
            "GET", "/api/auth/passkeys", cookie=cookie)
        self.assertEqual(listing["passkeys"], [])
        self.assert_login_fails(authenticator)

    def test_other_users_passkeys_are_invisible(self):
        cookie_a, _uid_a, _e = self.register_user()
        _auth, stored = self.add_passkey(cookie_a)
        cookie_b, _uid_b, _e = self.register_user()
        status, _h, listing = self.request_json(
            "GET", "/api/auth/passkeys", cookie=cookie_b)
        self.assertEqual(status, 200)
        self.assertEqual(listing["passkeys"], [])
        status, _h, body = self.request_json(
            "POST", "/api/auth/passkeys/%s/revoke" % stored["id"],
            body={"password": self.PASSWORD}, headers=CSRF,
            cookie=cookie_b)
        self.assertEqual(status, 404)
        # ...and user A's passkey is untouched by the attempt.
        status, _h, listing = self.request_json(
            "GET", "/api/auth/passkeys", cookie=cookie_a)
        self.assertEqual(len(listing["passkeys"]), 1)

    # ---------- coexistence with password + TOTP ----------

    def test_password_and_totp_flows_unaffected(self):
        cookie, user_id, email = self.register_user()
        authenticator, _s = self.add_passkey(cookie)
        # Password login still works exactly as before.
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 200, body)
        # Turn TOTP on.
        status, _h, enroll = self.request_json(
            "POST", "/api/auth/totp/enroll", body={}, headers=CSRF,
            cookie=cookie)
        self.assertEqual(status, 200, enroll)
        query = urllib.parse.parse_qs(
            urllib.parse.urlparse(enroll["otpauth_uri"]).query)
        secret = query["secret"][0]
        status, _h, body = self.request_json(
            "POST", "/api/auth/totp/activate",
            body={"code": totp.generate_code(secret)},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        # Password login now asks for the TOTP code, as before.
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 200)
        self.assertTrue(body.get("totp_required"))
        # Passkey sign-in does not stack TOTP on top (documented
        # policy: the UV-required ceremony is possession + user
        # verification in one step).
        status, _h, body = self.attempt_login(authenticator)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["user"]["id"], user_id)


if __name__ == "__main__":
    unittest.main()
