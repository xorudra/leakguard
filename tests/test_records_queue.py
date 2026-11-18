"""Records queue (owner order 2026-11-18): product events append
flat JSON lines per category (consent/audit/scans/removals) for the
Drive sync, masked emails only, and appending never breaks a flow.

* TestRecordsUnit — no database: queue-dir steering, line format,
  unknown categories ignored, a broken directory never raises.
* TestRecordsDb — pgserver: registration writes the two agreement
  lines, a consent switch change writes its line, audit rows are
  mirrored, and the scan/removal snapshots read back the committed
  state. No full address appears in any line.
"""

import base64
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None

import app
from core import records

PASSWORD = "correct-horse-9"
CSRF = {"X-Requested-With": "fetch"}
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS", "LG_RECORDS_DIR")


class EnvGuard:
    def __init__(self, keys=ENV_KEYS):
        self._keys = keys
        self._saved = {}

    def __enter__(self):
        for key in self._keys:
            self._saved[key] = os.environ.get(key)
        return self

    def __exit__(self, *exc):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


class TestRecordsUnit(unittest.TestCase):
    def setUp(self):
        self._env = EnvGuard(("LG_RECORDS_DIR",)).__enter__()
        self.dir = tempfile.mkdtemp(prefix="lg-records-")
        os.environ["LG_RECORDS_DIR"] = self.dir

    def tearDown(self):
        self._env.__exit__()

    def test_append_writes_sorted_json_lines(self):
        records.append("consent", {"b": 1, "a": "x"})
        records.append("consent", {"a": "y"})
        lines = (Path(self.dir) / "consent.jsonl").read_text(
            encoding="utf-8").splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0]), {"a": "x", "b": 1})
        self.assertEqual(json.loads(lines[1]), {"a": "y"})

    def test_unknown_category_ignored(self):
        records.append("vault", {"secret": True})
        self.assertEqual(list(Path(self.dir).iterdir()), [])

    def test_broken_directory_never_raises(self):
        os.environ["LG_RECORDS_DIR"] = "/proc/lg-cannot-exist/x"
        records.append("audit", {"action": "x"})  # must not raise


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestRecordsDb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard().__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-records-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
            cls._env.__exit__()
            raise unittest.SkipTest("pgserver could not start")
        os.environ["DATABASE_URL"] = cls._pg.get_uri()
        os.environ["VAULT_MASTER_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            os.urandom(32)).decode()
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        os.environ.pop("ADMIN_EMAILS", None)
        cls.queue_dir = tempfile.mkdtemp(prefix="lg-records-q-")
        os.environ["LG_RECORDS_DIR"] = cls.queue_dir
        from db import migrate, pool
        from remediation import registry_seed

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        registry_seed.seed_brokers()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.pool.reset_probe_cache()
        try:
            cls._pg.cleanup()
        except Exception:
            pass
        cls._env.__exit__()

    # ---------- helpers ----------
    def request_json(self, method, path, body=None, cookie=None,
                     headers=None):
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if cookie:
            hdrs["Cookie"] = cookie
        req = urllib.request.Request(
            self.base + path, data=data, headers=hdrs, method=method)
        try:
            with OPENER.open(req, timeout=15) as resp:
                return (resp.status, resp.headers,
                        json.loads(resp.read().decode("utf-8")))
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except Exception:
                parsed = None
            return e.code, e.headers, parsed

    def queue_lines(self, category):
        path = Path(self.queue_dir) / (category + ".jsonl")
        if not path.exists():
            return []
        return [json.loads(line) for line in
                path.read_text(encoding="utf-8").splitlines() if line]

    def register(self):
        email = "rec-%s@example.com" % uuid.uuid4().hex[:16]
        status, _h, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD,
                  "policy_accepted": True, "age_confirmed": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        from accounts import auth as auth_service

        digest = auth_service.account_email_hmac(
            auth_service.normalize_email(email))
        with self.pool.connection() as conn:
            row = conn.execute(
                "UPDATE users SET email_verified = true"
                " WHERE email_hmac = %s AND deleted_at IS NULL"
                " RETURNING id, email_masked", (digest,)).fetchone()
        status, headers, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": PASSWORD}, headers=CSRF)
        self.assertEqual(status, 200, body)
        raw = headers.get("Set-Cookie") or ""
        cookie = raw.split(";")[0].strip()
        return cookie, str(row["id"]), email, row["email_masked"]

    # ---------- tests ----------
    def test_registration_and_consent_change_lines(self):
        cookie, user_id, email, masked = self.register()
        consent = [line for line in self.queue_lines("consent")
                   if line["email_masked"] == masked]
        registered = {line["purpose"] for line in consent
                      if line["event"] == "registered"}
        self.assertEqual(
            registered, {"policy_acceptance", "age_confirmation"})
        policy_line = next(
            line for line in consent
            if line["purpose"] == "policy_acceptance")
        self.assertEqual(policy_line["policy_version"], "2026-10-07")
        self.assertTrue(policy_line["granted"])
        audit = self.queue_lines("audit")
        self.assertIn("auth.registered",
                      {line["action"] for line in audit})
        # A switch change appends its own consent + audit lines.
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "monitoring", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        changed = [line for line in self.queue_lines("consent")
                   if line["event"] == "changed"
                   and line["email_masked"] == masked]
        self.assertEqual(len(changed), 1)
        self.assertEqual(changed[0]["purpose"], "monitoring")
        self.assertTrue(changed[0]["granted"])
        self.assertIn(
            "consent.changed",
            {line["action"] for line in self.queue_lines("audit")})
        # Records only: the full address appears in NO queue file.
        for category in records.CATEGORIES:
            path = Path(self.queue_dir) / (category + ".jsonl")
            if path.exists():
                self.assertNotIn(
                    email, path.read_text(encoding="utf-8"), category)

    def test_scan_and_removal_snapshots(self):
        _cookie, user_id, _email, masked = self.register()
        with self.pool.connection() as conn:
            job = conn.execute(
                "INSERT INTO scan_jobs (user_id, idempotency_key,"
                " status, score, attempts, finished_at)"
                " VALUES (%s, %s, 'done', 42, 1, now()) RETURNING id",
                (user_id, "rec-" + uuid.uuid4().hex[:12]),
            ).fetchone()
            broker = conn.execute(
                "SELECT slug FROM brokers ORDER BY position, slug"
                " LIMIT 1").fetchone()
            case = conn.execute(
                "INSERT INTO remediation_cases (user_id, broker_slug)"
                " VALUES (%s, %s) RETURNING id",
                (user_id, broker["slug"]),
            ).fetchone()
        records.scan_snapshot(job["id"])
        records.removal_snapshot(case["id"])
        scans = [line for line in self.queue_lines("scans")
                 if line["email_masked"] == masked]
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["status"], "done")
        self.assertEqual(scans[0]["score"], 42)
        self.assertEqual(scans[0]["kind"], "scan")
        removals = [line for line in self.queue_lines("removals")
                    if line["email_masked"] == masked]
        self.assertEqual(len(removals), 1)
        self.assertEqual(removals[0]["status"], "queued")
        self.assertTrue(removals[0]["broker"])


if __name__ == "__main__":
    unittest.main()
