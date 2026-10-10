"""Monitoring + notifications + password reset tests (Stage S8 —
spec Phases 41–47, 99, 158–160).

Layers:

* TestDiff / TestNotifyRender / TestSchedulerPeriod — offline:
  the pure finding-set diff (identity, new/resolved/continuing,
  score delta), the email rendering (honest wording), and the
  scheduler's period bucketing.
* TestMonitoringUnavailable — no database: the monitoring /
  notifications routes answer the same clean 503 as every other
  account route (CSRF first), forgot-password included, and
  GET /reset serves the SPA.
* TestMonitoringDb — the full flow against a local PostgreSQL
  provisioned with pip `pgserver` (skips honestly when pgserver or
  Postgres is unavailable) with mock providers and a fake email
  lane: the completion-hook diff (baseline -> new -> resolved),
  the 5-per-job notification cap, consent-off in_app_only, the
  no-lane unsent record, scheduler due rules, settings, timeline,
  and the password-reset flow end to end.
* TestMonitoringServiceDb — a second local PostgreSQL for the two
  service-level behaviours that need hand-built job rows: the
  7-day dedupe suppression, and reappearance wiring into the
  Stage S7 remediation cases.

No real email is ever sent: the lane transport is a recording fake.
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
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from monitoring import diff, notify, scheduler  # noqa: E402
from providers import registry as registry_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
LANE_KEYS = ("BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")


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


class FakeTransport:
    """Recording stand-in for the Brevo lane. Returns a fixed HTTP
    status; every call's parsed JSON body is kept for assertions."""

    def __init__(self, status=201):
        self.status = status
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append({
            "url": url,
            "headers": dict(headers),
            "body": json.loads(body.decode("utf-8")),
        })
        return self.status, "{}"

    def calls_to(self, email):
        return [c for c in self.calls
                if c["body"].get("to", [{}])[0].get("email") == email]


# ---------------------------------------------------------------------------
# Pure diff
# ---------------------------------------------------------------------------

def _f(identifier_id, provider, source, **extra):
    row = {"identifier_id": identifier_id, "provider": provider,
           "source_name": source}
    row.update(extra)
    return row


class TestDiff(unittest.TestCase):
    def test_new_resolved_continuing(self):
        prev = [_f("i1", "P", "A"), _f("i1", "P", "B"),
                _f("i2", "P", "A")]
        cur = [_f("i1", "P", "B"), _f("i2", "P", "A"),
               _f("i3", "P", "C")]
        out = diff.diff_findings(prev, cur)
        self.assertEqual([diff.identity_key(f) for f in out["new"]],
                         ["i3|P|C"])
        self.assertEqual([diff.identity_key(f) for f in out["resolved"]],
                         ["i1|P|A"])
        self.assertEqual(out["continuing"], 2)

    def test_identity_ignores_detail_changes(self):
        prev = [_f("i1", "P", "A", confidence="weak")]
        cur = [_f("i1", "P", "A", confidence="exact")]
        out = diff.diff_findings(prev, cur)
        self.assertEqual(out["new"], [])
        self.assertEqual(out["resolved"], [])
        self.assertEqual(out["continuing"], 1)

    def test_duplicate_identity_collapses(self):
        cur = [_f("i1", "P", "A"), _f("i1", "P", "A")]
        out = diff.diff_findings([], cur)
        self.assertEqual(len(out["new"]), 1)

    def test_none_identifier_id_is_a_valid_identity(self):
        prev = [_f(None, "P", "PasswordFinding")]
        out = diff.diff_findings(prev, [])
        self.assertEqual(len(out["resolved"]), 1)
        self.assertEqual(len(diff.identity_hash(prev[0])), 64)

    def test_score_delta(self):
        self.assertEqual(diff.score_delta(40, 72), 32)
        self.assertEqual(diff.score_delta(72, 72), 0)
        self.assertIsNone(diff.score_delta(None, 72))
        self.assertIsNone(diff.score_delta(72, None))
        self.assertIsNone(diff.score_delta(None, None))


class TestNotifyRender(unittest.TestCase):
    def test_new_finding_wording(self):
        subject, body = notify.render_email("new_finding", {
            "source_name": "SomeBreach", "identifier_masked": "b•••@x.io",
            "identifier_kind": "email", "confidence": "exact"})
        self.assertIn("SomeBreach", subject)
        self.assertIn("b•••@x.io", body)
        self.assertIn("sources we use", body)

    def test_resolved_wording_never_claims_clean(self):
        _subject, body = notify.render_email("finding_resolved", {
            "source_name": "SomeBreach"})
        self.assertIn("did not appear", body)
        self.assertIn("not a guarantee", body)

    def test_summary_carries_score_and_delta(self):
        _subject, body = notify.render_email("scan_summary", {
            "new_count": 2, "resolved_count": 1, "continuing_count": 3,
            "extra_new_count": 0, "score": 72, "score_delta": -8})
        self.assertIn("New exposures this check: 2", body)
        self.assertIn("Exposure score: 72 / 100 (-8", body)

    def test_password_reset_body_carries_the_link(self):
        _subject, body = notify.render_email("password_reset", {
            "reset_url": "https://leakguard-hh8e.onrender.com/reset?token=abc"})
        self.assertIn("/reset?token=abc", body)
        self.assertIn("1 hour", body)


class TestSchedulerPeriod(unittest.TestCase):
    def test_bucket_is_stable_within_a_period(self):
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        start = scheduler.period_start_for(epoch + timedelta(days=100), 7)
        self.assertEqual(start.isoformat(), "1970-04-09")  # epoch + 98d
        key_a = scheduler.monitor_key("u1", epoch + timedelta(days=100), 7)
        key_b = scheduler.monitor_key("u1", epoch + timedelta(days=103), 7)
        key_c = scheduler.monitor_key("u1", epoch + timedelta(days=105), 7)
        self.assertEqual(key_a, key_b)
        self.assertNotEqual(key_a, key_c)
        self.assertTrue(key_a.startswith("monitor-u1-"))


# ---------------------------------------------------------------------------
# No-database layer
# ---------------------------------------------------------------------------

class TestMonitoringUnavailable(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(ENV_KEYS + LANE_KEYS).__enter__()
        for key in ENV_KEYS + LANE_KEYS:
            os.environ.pop(key, None)
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls._env.__exit__()

    def test_reads_503(self):
        for path in ("/api/monitoring/settings", "/api/monitoring/timeline",
                     "/api/notifications"):
            status, _h, body = self.request_json("GET", path)
            self.assertEqual(status, 503, path)
            self.assertEqual(body["error"]["code"], "db_unavailable", path)

    def test_put_settings_csrf_first_then_503(self):
        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings", body={"cadence_days": 14})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")
        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings", body={"cadence_days": 14},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_forgot_password_csrf_first_then_503(self):
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password",
            body={"email": "x@example.com"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password",
            body={"email": "x@example.com"}, headers=CSRF)
        self.assertEqual(status, 503)

    def test_reset_page_serves_the_spa(self):
        status, _h, payload = self.request("GET", "/reset?token=abc")
        self.assertEqual(status, 200)
        self.assertIn(b"LeakGuard", payload)


# ---------------------------------------------------------------------------
# Full flow against a local PostgreSQL (pgserver) + mock providers
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


class PgClassMixin:
    """pgserver provisioning shared by the DB test classes."""

    @classmethod
    def _start_pg(cls, prefix, providers_mock=True):
        import tempfile

        keys = ENV_KEYS + (("LEAKGUARD_PROVIDERS",) if providers_mock
                           else ())
        cls._env = EnvGuard(keys).__enter__()
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
        if providers_mock:
            os.environ["LEAKGUARD_PROVIDERS"] = "mock"
            registry_mod.reset_registry()
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

    # ----- DB helpers -----
    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def db_rows(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def notifications_for(self, user_id, kind=None):
        if kind:
            return self.db_rows(
                "SELECT * FROM notifications WHERE user_id = %s"
                " AND kind = %s ORDER BY created_at, id",
                (user_id, kind))
        return self.db_rows(
            "SELECT * FROM notifications WHERE user_id = %s"
            " ORDER BY created_at, id", (user_id,))


class AccountMixin:
    PASSWORD = "correct-horse-9"

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "mon-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD, "policy_accepted": True},
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


class LaneMixin:
    """Per-test lane control: BREVO env vars + a recording fake."""

    def setUp(self):
        ratelimit.reset()
        self._lane_saved = {k: os.environ.get(k) for k in LANE_KEYS}
        self.transport = FakeTransport()
        notify.TRANSPORT = self.transport
        self.set_lane(True)

    def tearDown(self):
        notify.TRANSPORT = None
        for k, v in self._lane_saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def set_lane(self, on):
        if on:
            os.environ["BREVO_API_KEY"] = "test-brevo-key"
            os.environ["NOTIFY_FROM_EMAIL"] = "alerts@leakguard.example"
            os.environ.pop("NOTIFY_FROM_NAME", None)
        else:
            for k in LANE_KEYS:
                os.environ.pop(k, None)


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestMonitoringDb(PgClassMixin, LaneMixin, AccountMixin,
                       ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._start_pg("lg-monitoring-pg-")
        from scanning import worker

        cls.scan_worker = worker
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    # ---------- scan pipeline helpers ----------
    def create_job(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/scans",
            body={"idempotency_key": uuid.uuid4().hex},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["job"]["id"]

    def run_until_done(self, cookie, job_id):
        for _ in range(50):
            status, _h, body = self.request_json(
                "GET", "/api/scans/" + job_id, cookie=cookie)
            self.assertEqual(status, 200, body)
            if body["job"]["status"] in ("done", "dead"):
                return body
            self.assertTrue(self.scan_worker.run_once(),
                            "worker had nothing to claim")
        self.fail("job never finished")

    def scan_user(self, cookie, identifiers, consents=("scanning",)):
        for kind, value in identifiers:
            self.add_identifier(cookie, kind, value)
        for purpose in consents:
            self.set_consent(cookie, purpose, True)
        return cookie

    # ---------- completion hook: baseline -> new -> resolved ----------
    def test_hook_diff_notifications(self):
        cookie, uid, email = self.register()
        clean = "clean-%s@example.com" % self.uniq()
        self.scan_user(cookie, [("email", clean),
                                ("email", "shared-b@example.com")],
                       consents=("scanning", "notifications"))
        self.add_identifier(cookie, "phone", "+91 99999 99999")

        # Job 1 = baseline (2 findings: the shared breach + the
        # phone listing). Only a summary, no per-finding notices.
        job1 = self.create_job(cookie)
        result = self.run_until_done(cookie, job1)
        self.assertEqual(result["job"]["status"], "done")
        self.assertEqual(len(result["findings"]), 2)
        rows = self.notifications_for(uid)
        self.assertEqual([r["kind"] for r in rows], ["scan_summary"])
        self.assertEqual(rows[0]["status"], "sent")
        self.assertTrue(rows[0]["payload"]["baseline"])
        self.assertEqual(self.transport.calls_to(email).__len__(), 1)

        # Job 2 with one identifier REMOVED: the phone finding is
        # resolved, nothing is new.
        idents = self.request_json("GET", "/api/identifiers",
                                   cookie=cookie)[2]["identifiers"]
        phone = [i for i in idents if i["kind"] == "phone"][0]
        status, _h, _b = self.request(
            "DELETE", "/api/identifiers/" + phone["id"],
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        job2 = self.create_job(cookie)
        result = self.run_until_done(cookie, job2)
        self.assertEqual(len(result["findings"]), 1)
        resolved = self.notifications_for(uid, "finding_resolved")
        self.assertEqual(len(resolved), 1)
        # Per-finding notices are in-app only now — email is the
        # once-per-cycle summary, never one email per finding.
        self.assertEqual(resolved[0]["status"], "in_app_only")
        self.assertEqual(resolved[0]["payload"]["source_name"],
                         "people-fixture.example.com")
        self.assertTrue(resolved[0]["dedupe_key"].startswith("resolved:"))
        summaries = self.notifications_for(uid, "scan_summary")
        self.assertEqual(len(summaries), 2)
        self.assertEqual(summaries[1]["payload"]["resolved_count"], 1)
        self.assertEqual(summaries[1]["payload"]["new_count"], 0)
        self.assertEqual(self.notifications_for(uid, "new_finding"), [])
        # Job 2 emailed ONLY its summary: 2 transport calls total
        # (one summary per cycle), none for the resolved finding.
        self.assertEqual(len(self.transport.calls_to(email)), 2)

        # Job 3 identical to job 2: no changes, still one summary.
        job3 = self.create_job(cookie)
        self.run_until_done(cookie, job3)
        self.assertEqual(len(self.notifications_for(uid)), 4)
        summaries = self.notifications_for(uid, "scan_summary")
        self.assertEqual(summaries[2]["payload"]["score_delta"], 0)

    # ---------- the 5-per-job cap ----------
    def test_new_finding_cap_and_summary_totals(self):
        cookie, uid, email = self.register()
        clean = "clean-%s@example.com" % self.uniq()
        self.scan_user(cookie, [("email", clean)],
                       consents=("scanning", "notifications"))
        job1 = self.create_job(cookie)
        self.run_until_done(cookie, job1)
        self.assertEqual(self.notifications_for(uid, "new_finding"), [])

        # Six brand-new findings appear at once: 2 breach findings +
        # 1 shared breach + 2 phone listings + 1 username presence.
        self.add_identifier(cookie, "email", "breached@example.com")
        self.add_identifier(cookie, "email", "shared-a@example.com")
        self.add_identifier(cookie, "phone", "+1 99999 99999")
        self.add_identifier(cookie, "phone", "+44 99999 99999")
        self.add_identifier(cookie, "username", "fixturehandle")
        job2 = self.create_job(cookie)
        result = self.run_until_done(cookie, job2)
        self.assertEqual(len(result["findings"]), 6)

        news = self.notifications_for(uid, "new_finding")
        self.assertEqual(len(news), 5)  # the cap, exactly
        # Per-finding notices are in-app only, consent or not.
        self.assertTrue(all(r["status"] == "in_app_only" for r in news))
        summaries = self.notifications_for(uid, "scan_summary")
        self.assertEqual(len(summaries), 2)
        payload = summaries[1]["payload"]
        self.assertEqual(payload["new_count"], 6)
        self.assertEqual(payload["extra_new_count"], 1)
        # Job 2 emailed ONLY its summary (plus job 1's summary):
        # exactly one email per cycle, never one per finding.
        self.assertEqual(len(self.transport.calls_to(email)), 1 + 1)

    # ---------- consent off: in-app only, lane untouched ----------
    def test_notifications_consent_off_in_app_only(self):
        cookie, uid, email = self.register()
        clean = "clean-%s@example.com" % self.uniq()
        self.scan_user(cookie, [("email", clean)],
                       consents=("scanning",))  # notifications stays OFF
        job1 = self.create_job(cookie)
        self.run_until_done(cookie, job1)
        self.add_identifier(cookie, "phone", "+61 99999 99999")
        job2 = self.create_job(cookie)
        self.run_until_done(cookie, job2)

        rows = self.notifications_for(uid)
        self.assertTrue(rows)
        self.assertTrue(all(r["status"] == "in_app_only" for r in rows))
        self.assertEqual(
            [r["kind"] for r in rows].count("new_finding"), 1)
        self.assertEqual(self.transport.calls_to(email), [])

    # ---------- no lane: recorded unsent, never 'sent' ----------
    def test_no_lane_records_unsent_no_lane(self):
        self.set_lane(False)
        cookie, uid, email = self.register()
        clean = "clean-%s@example.com" % self.uniq()
        self.scan_user(cookie, [("email", clean)],
                       consents=("scanning", "notifications"))
        job1 = self.create_job(cookie)
        self.run_until_done(cookie, job1)
        rows = self.notifications_for(uid)
        self.assertEqual([r["kind"] for r in rows], ["scan_summary"])
        self.assertEqual(rows[0]["status"], "unsent_no_lane")
        self.assertIsNone(rows[0]["sent_at"])

        # Lane restored: the next summary delivers for real.
        self.set_lane(True)
        job2 = self.create_job(cookie)
        self.run_until_done(cookie, job2)
        rows = self.notifications_for(uid)
        self.assertEqual(rows[1]["status"], "sent")
        self.assertIsNotNone(rows[1]["sent_at"])

    # ---------- scheduler ----------
    def monitor_jobs(self, user_id):
        return self.db_rows(
            "SELECT * FROM scan_jobs WHERE user_id = %s"
            " AND idempotency_key LIKE 'monitor-%%'", (user_id,))

    def test_scheduler_due_rules(self):
        now = datetime.now(timezone.utc)

        # Due: monitoring on + an identifier + never scanned.
        cookie1, uid1, _e = self.register()
        self.add_identifier(cookie1, "email",
                            "sched-%s@example.com" % self.uniq())
        self.set_consent(cookie1, "monitoring", True)
        created = scheduler.tick(now=now)
        self.assertEqual(len(self.monitor_jobs(uid1)), 1)
        key = self.monitor_jobs(uid1)[0]["idempotency_key"]
        self.assertTrue(key.startswith("monitor-%s-" % uid1))
        # Same period re-tick: no duplicate.
        scheduler.tick(now=now)
        self.assertEqual(len(self.monitor_jobs(uid1)), 1)

        # Consent granted then withdrawn: never touched.
        cookie3, uid3, _e = self.register()
        self.add_identifier(cookie3, "email",
                            "sched-%s@example.com" % self.uniq())
        self.set_consent(cookie3, "monitoring", True)
        self.set_consent(cookie3, "monitoring", False)
        # Monitoring on but NO identifiers: never touched.
        cookie4, uid4, _e = self.register()
        self.set_consent(cookie4, "monitoring", True)
        scheduler.tick(now=now)
        self.assertEqual(self.monitor_jobs(uid3), [])
        self.assertEqual(self.monitor_jobs(uid4), [])

        # Not yet due: a scan completed moments ago, cadence 7.
        cookie2, uid2, _e = self.register()
        self.add_identifier(cookie2, "email",
                            "sched-%s@example.com" % self.uniq())
        self.set_consent(cookie2, "monitoring", True)
        self.set_consent(cookie2, "scanning", True)
        job = self.create_job(cookie2)
        self.run_until_done(cookie2, job)
        scheduler.tick(now=now + timedelta(days=1))
        self.assertEqual(self.monitor_jobs(uid2), [])
        scheduler.tick(now=now + timedelta(days=8))
        self.assertEqual(len(self.monitor_jobs(uid2)), 1)

        # Cadence honoured: 30-day user is not due at day 8.
        cookie5, uid5, _e = self.register()
        self.add_identifier(cookie5, "email",
                            "sched-%s@example.com" % self.uniq())
        self.set_consent(cookie5, "monitoring", True)
        self.set_consent(cookie5, "scanning", True)
        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"cadence_days": 30}, headers=CSRF, cookie=cookie5)
        self.assertEqual(status, 200, body)
        job = self.create_job(cookie5)
        self.run_until_done(cookie5, job)
        scheduler.tick(now=now + timedelta(days=8))
        self.assertEqual(self.monitor_jobs(uid5), [])
        self.assertEqual(len(self.monitor_jobs(uid2)), 1)  # no dupe
        scheduler.tick(now=now + timedelta(days=31))
        self.assertEqual(len(self.monitor_jobs(uid5)), 1)

    # ---------- settings ----------
    def test_settings_roundtrip_and_validation(self):
        cookie_a, uid_a, _e = self.register()
        cookie_b, _uid_b, _e = self.register()

        status, _h, body = self.request_json(
            "GET", "/api/monitoring/settings", cookie=cookie_a)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cadence_days"], 7)
        self.assertFalse(body["monitoring_consent"])
        self.assertIsNone(body["last_scan_at"])
        self.assertTrue(body["due_now"])

        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"cadence_days": 14}, headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["cadence_days"], 14)

        # Another user's settings are their own (no cross-talk).
        status, _h, body = self.request_json(
            "GET", "/api/monitoring/settings", cookie=cookie_b)
        self.assertEqual(body["cadence_days"], 7)

        for bad in (5, 0, "7", None, True):
            status, _h, body = self.request_json(
                "PUT", "/api/monitoring/settings",
                body={"cadence_days": bad}, headers=CSRF, cookie=cookie_a)
            self.assertEqual(status, 400, bad)
            self.assertEqual(body["error"]["code"], "invalid_cadence")

        status, _h, body = self.request_json(
            "PUT", "/api/monitoring/settings",
            body={"cadence_days": 30}, cookie=cookie_a)
        self.assertEqual(status, 403)  # CSRF guard before anything
        self.assertEqual(body["error"]["code"], "csrf_failed")

        status, _h, body = self.request_json(
            "GET", "/api/monitoring/settings")
        self.assertEqual(status, 401)

    # ---------- timeline + IDOR ----------
    def test_timeline_shape_and_idor(self):
        cookie_a, uid_a, _e = self.register()
        self.scan_user(cookie_a, [("phone", "+81 99999 99999")],
                       consents=("scanning", "notifications"))
        job = self.create_job(cookie_a)
        result = self.run_until_done(cookie_a, job)
        self.assertEqual(result["job"]["score"], 0)

        status, _h, body = self.request_json(
            "GET", "/api/monitoring/timeline", cookie=cookie_a)
        self.assertEqual(status, 200, body)
        types = [e["type"] for e in body["events"]]
        self.assertIn("scan_completed", types)
        self.assertIn("finding_found", types)
        scan_event = [e for e in body["events"]
                      if e["type"] == "scan_completed"][0]
        self.assertIn("exposure score 0 / 100", scan_event["summary"])
        self.assertEqual(scan_event["refs"]["job_id"], job)
        finding_event = [e for e in body["events"]
                         if e["type"] == "finding_found"][0]
        self.assertIn("people-fixture.example.com",
                      finding_event["summary"])
        # Newest first.
        ats = [e["at"] for e in body["events"]]
        self.assertEqual(ats, sorted(ats, reverse=True))

        cookie_b, _uid_b, _e = self.register()
        status, _h, body = self.request_json(
            "GET", "/api/monitoring/timeline", cookie=cookie_b)
        self.assertEqual(body["events"], [])
        status, _h, body = self.request_json(
            "GET", "/api/notifications", cookie=cookie_b)
        self.assertEqual(body["notifications"], [])

    # ---------- password reset ----------
    def _token_rows(self, user_id):
        return self.db_rows(
            "SELECT * FROM password_reset_tokens WHERE user_id = %s"
            " ORDER BY created_at", (user_id,))

    def test_password_reset_flow(self):
        cookie, uid, email = self.register()
        old_password = self.PASSWORD
        new_password = "brand-new-password-2"

        # CSRF fires before anything else.
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password", body={"email": email})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")

        # Unknown email: identical 200, no token, no notification.
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password",
            body={"email": "ghost-%s@example.com" % self.uniq()},
            headers=CSRF)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": True})
        self.assertEqual(self._token_rows(uid), [])

        # Real user: token + ledger row + an actual email, even
        # though the notifications consent was never granted (a
        # reset is user-requested transactional mail).
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password", body={"email": email},
            headers=CSRF)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": True})
        tokens = self._token_rows(uid)
        self.assertEqual(len(tokens), 1)
        self.assertIsNone(tokens[0]["used_at"])
        notes = self.notifications_for(uid, "password_reset")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["status"], "sent")
        reset_url = notes[0]["payload"]["reset_url"]
        raw_token = urllib.parse.parse_qs(
            urllib.parse.urlparse(reset_url).query)["token"][0]
        sent = self.transport.calls_to(email)
        self.assertEqual(len(sent), 1)
        self.assertIn("/reset?token=" + raw_token,
                      sent[0]["body"]["textContent"])

        # The in-app projection never hands out the reset URL.
        status, _h, body = self.request_json(
            "GET", "/api/notifications", cookie=cookie)
        item = [n for n in body["notifications"]
                if n["kind"] == "password_reset"][0]
        self.assertNotIn("reset_url", item["payload"])
        self.assertTrue(item["payload"]["has_reset_link"])

        # Garbage token: the one error shape.
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": "not-a-token", "new_password": new_password},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_token")

        # Weak password: rejected WITHOUT consuming the token.
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": raw_token, "new_password": "short"},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "weak_password")
        self.assertIsNone(self._token_rows(uid)[0]["used_at"])

        # The real reset.
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": raw_token, "new_password": new_password},
            headers=CSRF)
        self.assertEqual(status, 200, body)
        self.assertIsNotNone(self._token_rows(uid)[0]["used_at"])

        # Old sessions are revoked; old password is dead; new works.
        status, _h, _b = self.request_json("GET", "/api/auth/me",
                                          cookie=cookie)
        self.assertEqual(status, 401)
        status, _h, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": old_password},
            headers=CSRF)
        self.assertEqual(status, 401)
        status, headers, body = self.request_json(
            "POST", "/api/auth/login",
            body={"email": email, "password": new_password},
            headers=CSRF)
        self.assertEqual(status, 200, body)
        cookie = self.session_cookie(headers)

        # Token reuse: same 400 shape.
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": raw_token, "new_password": "another-pass-33"},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_token")

        # A fresh token, expired by hand: same 400 shape.
        self.request_json("POST", "/api/auth/forgot-password",
                          body={"email": email}, headers=CSRF)
        tokens = self._token_rows(uid)
        self.assertEqual(len(tokens), 2)
        fresh_url = self.notifications_for(
            uid, "password_reset")[1]["payload"]["reset_url"]
        fresh_token = urllib.parse.parse_qs(
            urllib.parse.urlparse(fresh_url).query)["token"][0]
        with self.pool.connection() as conn:
            conn.execute(
                "UPDATE password_reset_tokens"
                " SET expires_at = now() - interval '1 minute'"
                " WHERE user_id = %s AND used_at IS NULL", (uid,))
        status, _h, body = self.request_json(
            "POST", "/api/auth/reset-password",
            body={"token": fresh_token, "new_password": "another-pass-33"},
            headers=CSRF)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_token")

        # Deleted user: identical 200, and no token is minted.
        cookie_d, uid_d, email_d = self.register()
        status, _h, body = self.request_json(
            "POST", "/api/auth/delete-account",
            body={"password": self.PASSWORD}, headers=CSRF,
            cookie=cookie_d)
        self.assertEqual(status, 200, body)
        status, _h, body = self.request_json(
            "POST", "/api/auth/forgot-password",
            body={"email": email_d}, headers=CSRF)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": True})
        self.assertEqual(self._token_rows(uid_d), [])


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestMonitoringServiceDb(PgClassMixin, LaneMixin, AccountMixin,
                               ServerMixin, unittest.TestCase):
    """Service-level behaviours driven with hand-built job rows."""

    @classmethod
    def setUpClass(cls):
        cls._start_pg("lg-monitoring-svc-pg-")
        from remediation import registry_seed

        registry_seed.seed_brokers()
        cls.start_server()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    # ---------- hand-built rows ----------
    def insert_job(self, user_id, finished_at, score=10):
        row = self.db_row(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " score, finished_at) VALUES (%s, %s, 'done', %s, %s)"
            " RETURNING id",
            (user_id, uuid.uuid4().hex, score, finished_at))
        return str(row["id"])

    def insert_finding(self, job_id, user_id, identifier_id,
                       source_name, provider="FixtureProvider"):
        row = self.db_row(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, exposed_fields,"
            " confidence, reliability, evidence_ref)"
            " VALUES (%s, %s, %s, 'email', %s, %s, '{}', 'exact',"
            " 'high', %s) RETURNING id",
            (job_id, user_id, identifier_id, provider, source_name,
             "e" * 64))
        return str(row["id"])

    # ---------- dedupe: reappearance inside 7 days is suppressed ----------
    def test_dedupe_suppresses_repeat_within_window(self):
        from monitoring import events

        cookie, uid, email = self.register()
        ident = self.add_identifier(
            cookie, "email", "dedupe-%s@example.com" % self.uniq())
        self.set_consent(cookie, "notifications", True)
        now = datetime.now(timezone.utc)

        job0 = self.insert_job(uid, now - timedelta(days=3))
        events.handle_scan_completed(job0)  # baseline
        job1 = self.insert_job(uid, now - timedelta(days=2))
        self.insert_finding(job1, uid, ident["id"], "FixtureBreach")
        events.handle_scan_completed(job1)
        news = self.notifications_for(uid, "new_finding")
        self.assertEqual(len(news), 1)
        self.assertEqual(news[0]["status"], "in_app_only")
        calls_after_first = len(self.transport.calls_to(email))

        job2 = self.insert_job(uid, now - timedelta(days=1))
        events.handle_scan_completed(job2)  # finding resolves
        self.assertEqual(
            len(self.notifications_for(uid, "finding_resolved")), 1)

        job3 = self.insert_job(uid, now)
        self.insert_finding(job3, uid, ident["id"], "FixtureBreach")
        events.handle_scan_completed(job3)  # ...and reappears < 7d
        news = self.notifications_for(uid, "new_finding")
        self.assertEqual(len(news), 2)
        self.assertEqual(news[0]["dedupe_key"], news[1]["dedupe_key"])
        self.assertEqual(news[1]["status"], "suppressed")
        # The suppressed repeat produced no email: after the first
        # pass, the lane saw job2's summary and job3's summary —
        # the resolved notice is in-app only, and the suppressed
        # re-finding emailed nothing. One email per cycle.
        self.assertEqual(len(self.transport.calls_to(email)),
                         calls_after_first + 2)

        # The hook is idempotent per job: reprocessing changes nil.
        before = len(self.notifications_for(uid))
        out = events.handle_scan_completed(job3)
        self.assertTrue(out["skipped"])
        self.assertEqual(len(self.notifications_for(uid)), before)

    # ---------- reappearance wiring into remediation cases ----------
    def test_reappeared_wiring(self):
        from monitoring import events
        from remediation import engine as engine_mod
        from remediation import worker as remediation_worker

        class StubExecutor:
            def __init__(self):
                self.verify_by_broker = {}

            def probe(self, profile, broker):
                return {"reachable": True, "status": 200,
                        "fillable": True,
                        "forms": [{"action": broker["optout_url"],
                                   "method": "POST",
                                   "fields": [{
                                       "name": "email", "id": "",
                                       "placeholder": "",
                                       "type": "email"}],
                                   "unmapped_fields": []}],
                        "blockers": [],
                        "payload_preview": {"email": profile.get(
                            "email", "")},
                        "via": "stub"}

            def submit(self, profile, broker, probe):
                return {"ok": True, "status": 200}

            def verify_search(self, profile, broker):
                return {"outcome": self.verify_by_broker.get(
                    broker["name"], "unknown"),
                    "evidence_ref": "stub://search"}

        cookie, uid, _email = self.register()
        tag = self.uniq()
        self.add_identifier(cookie, "name", "Test Person %s" % tag)
        email_ident = self.add_identifier(
            cookie, "email", "person-%s@example.com" % tag)
        self.add_identifier(cookie, "address",
                            "%s Test Street, Pune, India" % tag)
        self.set_consent(cookie, "automated_remediation", True)
        self.set_consent(cookie, "notifications", True)

        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={}, headers=CSRF,
            cookie=cookie)
        self.assertEqual(status, 200, body)
        stub = StubExecutor()
        worked = 0
        while worked < 500 and remediation_worker.run_once(stub):
            worked += 1

        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases", cookie=cookie)
        cases = {c["broker_name"]: c for c in body["cases"]}
        self.assertEqual(cases["Spokeo"]["status"], "submitted")
        # TruthFinder takes the email channel since the 2026-10-08
        # email-coverage pass: its case parks with a ready letter.
        # Confirm "I sent it" (retry) and drain again so the case
        # is submitted — the state the reappeared wiring exercises.
        tf = cases["TruthFinder"]
        self.assertEqual(tf["status"], "needs_human")
        self.assertEqual(tf["reason"], "email_send_required")
        status, _h, body = self.request_json(
            "POST", "/api/remediation/cases/%s/retry" % tf["id"],
            body={}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        worked = 0
        while worked < 500 and remediation_worker.run_once(stub):
            worked += 1
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases", cookie=cookie)
        cases = {c["broker_name"]: c for c in body["cases"]}
        self.assertEqual(cases["TruthFinder"]["status"], "submitted")

        original = engine_mod.AgentExecutor
        engine_mod.AgentExecutor = lambda: stub
        try:
            stub.verify_by_broker["Spokeo"] = "gone"
            stub.verify_by_broker["TruthFinder"] = "gone"
            for name in ("Spokeo", "TruthFinder"):
                status, _h, body = self.request_json(
                    "POST", "/api/remediation/cases/%s/verify"
                    % cases[name]["id"], body={}, headers=CSRF,
                    cookie=cookie)
                self.assertEqual(status, 200, body)
                self.assertEqual(body["case"]["status"],
                                 "verified_removed")
        finally:
            engine_mod.AgentExecutor = original

        # A later scan finds the Spokeo listing again.
        now = datetime.now(timezone.utc)
        job0 = self.insert_job(uid, now - timedelta(days=1))
        events.handle_scan_completed(job0)  # baseline
        job1 = self.insert_job(uid, now)
        self.insert_finding(job1, uid, email_ident["id"], "Spokeo",
                            provider="FixtureScan")
        out = events.handle_scan_completed(job1)
        self.assertEqual(out["reappeared"], 1)

        row = self.db_row(
            "SELECT status FROM remediation_cases WHERE id = %s",
            (cases["Spokeo"]["id"],))
        self.assertEqual(row["status"], "reappeared")
        check = self.db_row(
            "SELECT method, outcome FROM verification_checks"
            " WHERE case_id = %s AND method = 'scan_finding'",
            (cases["Spokeo"]["id"],))
        self.assertIsNotNone(check)
        self.assertEqual(check["outcome"], "still_present")
        # The non-matching verified case is untouched.
        row = self.db_row(
            "SELECT status FROM remediation_cases WHERE id = %s",
            (cases["TruthFinder"]["id"],))
        self.assertEqual(row["status"], "verified_removed")
        notes = self.notifications_for(uid, "reappeared")
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["payload"]["broker_name"], "Spokeo")


if __name__ == "__main__":
    unittest.main()
