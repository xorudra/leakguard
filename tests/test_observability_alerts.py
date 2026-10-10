"""Observability + engineering alerts tests (P2-C — spec
Phases 76, 77).

Layers:

* TestErrorLedgerDb — pgserver: error_ledger.record writes one
  rollup row per distinct error per hour bucket and dedupes
  repeats into occurrence_count; the raw message is never stored
  (only its sha256); record never raises with the pool broken;
  log_error mirrors into the ledger with derived context/class;
  retention prunes error_events older than 30 days and keeps
  fresh rows.
* TestAdminMetricsDb — pgserver + HTTP: GET /api/admin/metrics
  answers the house 404 to anonymous and non-admin callers, and
  to the owner returns numbers matching the seeded jobs, queue,
  cases, notifications, source checks, security events and error
  ledger; the overview embeds the same block.
* TestAlert*Db — pgserver: each rule stays silent below its
  threshold, fires on the seeded breach (audit row +
  one notification per admin, emailed via the fake lane), and a
  second evaluate() the same day does not email again (dedupe).
  The Phase 175 scan_latency classes add: the sample-size floor
  (extreme durations on a quiet system stay silent), the healthy
  band staying silent above the floor, and flag-respect — the
  rule rides the scheduler tick behind the monitoring_scheduler
  flag, so a flagged-off tick never evaluates it.
* TestSchedulerAlertGuard — no database: a raising alerts
  evaluator cannot break scheduler.tick().

Against local PostgreSQL provisioned with pip `pgserver` (skips
honestly when unavailable). No real email: the lane transport
is a recording fake. Test accounts use unique example.com
addresses; no plaintext passwords are printed.

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
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS",
            "BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")
PASSWORD = "S76 test " + "password 123"


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


class _FakeTransport:
    """Recording stand-in for the Brevo lane."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append(json.loads(body.decode("utf-8")))
        return 201, "{}"

    def to(self, email):
        return [c for c in self.calls
                if c.get("to") and c["to"][0].get("email") == email]


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
class ObsDbBase(ServerMixin):
    """Shared pgserver provisioning — a FRESH database per class,
    like the other suites. Subclasses set ADMIN_EMAIL (the account
    that counts as owner) or leave it None."""

    ADMIN_EMAIL = None

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-obs-pg-")
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

    def register(self, email=None):
        email = email or "s76-%s@example.com" % self.uniq()
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


# ---------------------------------------------------------------------------
# Phase 76 — the error ledger + retention
# ---------------------------------------------------------------------------

class TestErrorLedgerDb(ObsDbBase, unittest.TestCase):

    def test_record_writes_and_dedupes(self):
        from core import error_ledger

        marker = "ledger-marker-%s" % self.uniq()
        message = "kaboom happened: " + marker
        self.assertTrue(error_ledger.record(
            "ledger test ctx", ValueError(message), message,
            request_id="req-ledger-1"))
        self.assertTrue(error_ledger.record(
            "ledger test ctx", "ValueError", message))
        rows = self.db_all(
            "SELECT * FROM error_events WHERE context = %s",
            ("ledger test ctx",))
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["error_class"], "ValueError")
        self.assertEqual(row["occurrence_count"], 2)
        self.assertEqual(row["message_hash"],
                         error_ledger.message_hash(message))
        self.assertEqual(row["request_id"], "req-ledger-1")
        # The raw message — and its unique marker — is nowhere.
        for value in row.values():
            self.assertNotIn(marker, str(value))

    def test_record_never_raises_with_broken_pool(self):
        from core import error_ledger, logging_setup
        from db import pool

        original = pool.connection

        def broken(dsn=None):
            raise RuntimeError("pool is down")

        pool.connection = broken
        try:
            self.assertFalse(error_ledger.record(
                "ctx", ValueError("x"), "some message"))
            # log_error keeps working (and returning None) too.
            self.assertIsNone(logging_setup.log_error(
                None, "broken pool ctx failed: ValueError"))
        finally:
            pool.connection = original

    def test_log_error_mirrors_into_ledger(self):
        from core import logging_setup

        tag = self.uniq()
        logging_setup.log_error(
            "req-%s" % tag, "wiring check %s failed: KeyError" % tag)
        row = self.db_one(
            "SELECT * FROM error_events WHERE context = %s",
            ("wiring check %s failed" % tag,))
        self.assertIsNotNone(row)
        self.assertEqual(row["error_class"], "KeyError")
        self.assertEqual(row["request_id"], "req-%s" % tag)

    def test_retention_prunes_error_events(self):
        from core import error_ledger, retention

        self.assertTrue(error_ledger.record(
            "fresh ctx", "RuntimeError", "fresh failure"))
        self.db_exec(
            "INSERT INTO error_events (context, error_class,"
            " message_hash, created_at, last_seen_at, bucket_start)"
            " VALUES ('stale ctx', 'RuntimeError', %s,"
            " now() - interval '31 days',"
            " now() - interval '31 days',"
            " date_trunc('hour', now() - interval '31 days'))",
            (error_ledger.message_hash("stale failure"),))
        counts = retention.run_once()
        self.assertGreaterEqual(counts["error_events"], 1, counts)
        self.assertIsNone(self.db_one(
            "SELECT id FROM error_events WHERE context = 'stale ctx'"))
        self.assertIsNotNone(self.db_one(
            "SELECT id FROM error_events WHERE context = 'fresh ctx'"))


# ---------------------------------------------------------------------------
# Phase 76 — the admin metrics endpoint
# ---------------------------------------------------------------------------

class TestAdminMetricsDb(ObsDbBase, unittest.TestCase):
    ADMIN_EMAIL = "owner-metrics@example.com"

    def test_metrics_gating_and_values(self):
        from core import error_ledger

        admin_cookie, admin_id, _email = self.register(self.ADMIN_EMAIL)
        user_cookie, user_id, _e2 = self.register()

        # Anonymous and non-admin both get the house 404.
        status, _h, body = self.request_json("GET", "/api/admin/metrics")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")
        status, _h, body = self.request_json(
            "GET", "/api/admin/metrics", cookie=user_cookie)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

        # Seed the platform state the metrics must report.
        t0 = datetime.now(timezone.utc)

        def ago(seconds):
            return t0 - timedelta(seconds=seconds)

        job = ("INSERT INTO scan_jobs (user_id, idempotency_key,"
               " status, created_at, started_at, finished_at)"
               " VALUES (%s, %s, %s, %s, %s, %s)")
        self.db_exec(job, (admin_id, "m-done-1", "done", ago(300),
                           ago(100), ago(90)))
        self.db_exec(job, (admin_id, "m-done-2", "done", ago(400),
                           ago(200), ago(170)))
        self.db_exec(job, (admin_id, "m-dead-1", "dead", ago(60),
                           None, ago(30)))
        self.db_exec(job, (admin_id, "m-failed-1", "failed", ago(50),
                           None, None))
        self.db_exec(job, (admin_id, "m-queued-old", "queued", ago(120),
                           None, None))
        self.db_exec(job, (admin_id, "m-queued-1", "queued", ago(10),
                           None, None))
        self.db_exec(job, (admin_id, "m-running-1", "running", ago(20),
                           ago(5), None))
        broker = self.db_one("SELECT slug FROM brokers LIMIT 1")["slug"]
        self.db_exec(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status) VALUES (%s, %s, 'submitted')",
            (admin_id, broker))
        self.db_exec(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status) VALUES (%s, %s, 'failed')",
            (user_id, broker))
        self.db_exec(
            "INSERT INTO broker_source_checks (slug, url, state,"
            " checked_at) VALUES ('met-a', 'https://a.invalid', 'ok',"
            " now()), ('met-b', 'https://b.invalid', 'unreachable',"
            " now()), ('met-c', 'https://c.invalid', 'changed',"
            " now() - interval '2 days')")
        from monitoring import notify

        notify.create_notifications_batch(admin_id, [{
            "kind": "new_finding", "payload": {"source_name": "Seed"},
            "dedupe_key": "met-seed-1"}])
        error_ledger.record("metrics ctx one", "ValueError", "m1")
        error_ledger.record("metrics ctx one", "ValueError", "m1")
        error_ledger.record("metrics ctx one", "ValueError", "m1")
        error_ledger.record("metrics ctx two", "KeyError", "m2")

        status, _h, body = self.request_json(
            "GET", "/api/admin/metrics", cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["scan_jobs"]["by_status"]["done"], 2)
        self.assertEqual(body["scan_jobs"]["by_status"]["dead"], 1)
        last24 = body["scan_jobs"]["last_24h"]
        self.assertEqual(last24["completed"], 2)
        self.assertEqual(last24["failed"], 1)
        self.assertEqual(last24["dead"], 1)
        self.assertAlmostEqual(
            body["scan_jobs"]
            ["median_completed_duration_seconds_last_24h"],
            20.0, delta=1.0)
        queue = body["queue"]
        self.assertEqual(queue["queued"], 2)
        self.assertEqual(queue["running"], 1)
        self.assertEqual(queue["active"], 3)
        self.assertGreater(queue["oldest_queued_age_seconds"], 100)
        self.assertEqual(
            body["remediation_cases_by_status"]["submitted"], 1)
        self.assertEqual(
            body["remediation_cases_by_status"]["failed"], 1)
        self.assertEqual(
            body["notifications_by_status_last_24h"]["in_app_only"], 1)
        self.assertEqual(body["broker_sources"]["total"], 3)
        self.assertEqual(body["broker_sources"]["checked_last_24h"], 2)
        self.assertEqual(body["broker_sources"]["unreachable"], 1)
        errors = body["errors_last_24h"]
        self.assertEqual(errors["distinct_context_class_pairs"], 2)
        self.assertEqual(errors["total_occurrences"], 4)
        self.assertEqual(errors["top"][0]["context"], "metrics ctx one")
        self.assertEqual(errors["top"][0]["occurrences"], 3)

        # The overview embeds the same block; a login's audit row
        # ('auth.login', one of the security-action patterns) is
        # counted by kind in the trailing 24h.
        status, _h, overview = self.request_json(
            "GET", "/api/admin/overview", cookie=admin_cookie)
        self.assertEqual(status, 200, overview)
        self.assertEqual(overview["metrics"]["queue"]["active"], 3)
        status, _h, _b = self.request_json(
            "POST", "/api/auth/login",
            body={"email": self.ADMIN_EMAIL, "password": PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 200, _b)
        status, _h, body = self.request_json(
            "GET", "/api/admin/metrics", cookie=admin_cookie)
        self.assertEqual(
            body["security_events_by_kind_last_24h"].get("auth.login"),
            1)


# ---------------------------------------------------------------------------
# Phase 77 — the alert rules
# ---------------------------------------------------------------------------

class AlertDbBase(ObsDbBase):
    """Admin account + a configured (fake) email lane, so 'always'
    delivery really attempts sends the test can count."""

    ADMIN_EMAIL = "owner-alerts@example.com"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.environ["BREVO_API_KEY"] = "test-lane-key"
        os.environ["NOTIFY_FROM_EMAIL"] = "alerts@example.com"
        from monitoring import notify

        cls.transport = _FakeTransport()
        cls._saved_transport = notify.TRANSPORT
        notify.TRANSPORT = cls.transport

    @classmethod
    def tearDownClass(cls):
        from monitoring import notify

        notify.TRANSPORT = cls._saved_transport
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.transport.calls.clear()
        self.admin_cookie, self.admin_id, self.admin_email = \
            self.register(self.ADMIN_EMAIL)

    # ---------- shared assertions ----------

    def fired_rules(self, fired):
        return {hit["rule"]: hit for hit in fired}

    def assert_alert_delivered_once(self, rule):
        rows = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'"
            " AND status <> 'suppressed'",
            (self.admin_id,))
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["payload"]["rule"], rule)
        self.assertEqual(len(self.transport.to(self.admin_email)), 1)
        audit_row = self.db_one(
            "SELECT * FROM audit_log"
            " WHERE action = 'engineering_alert'"
            " AND target_id = %s",
            (rule,))
        self.assertIsNotNone(audit_row)
        self.assertEqual(audit_row["detail"]["rule"], rule)

    def seed_job(self, key, status, created_ago=0, started_ago=None,
                 finished_ago=None):
        t0 = datetime.now(timezone.utc)

        def ts(ago_seconds):
            if ago_seconds is None:
                return None
            return t0 - timedelta(seconds=ago_seconds)

        self.db_exec(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " created_at, started_at, finished_at)"
            " VALUES (%s, %s, %s, %s, %s, %s)",
            (self.admin_id, key, status, ts(created_ago),
             ts(started_ago), ts(finished_ago)))


class TestAlertQueueActiveDb(AlertDbBase, unittest.TestCase):

    def test_queue_buildup_active_leg_and_dedupe(self):
        from monitoring import alerts

        self.assertNotIn("queue_buildup",
                         self.fired_rules(alerts.evaluate()))
        for i in range(9):
            self.seed_job("q-%d" % i, "queued")
        self.assertNotIn("queue_buildup",
                         self.fired_rules(alerts.evaluate()))
        self.seed_job("q-9", "queued")
        fired = self.fired_rules(alerts.evaluate())
        self.assertIn("queue_buildup", fired)
        self.assertEqual(fired["queue_buildup"]["observed"], 10)
        self.assertEqual(fired["queue_buildup"]["metric"], "active_jobs")
        self.assert_alert_delivered_once("queue_buildup")
        # A second pass the same day fires again but does not email
        # again — the repeat lands 'suppressed'.
        self.assertIn("queue_buildup",
                      self.fired_rules(alerts.evaluate()))
        self.assert_alert_delivered_once("queue_buildup")
        suppressed = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'"
            " AND status = 'suppressed'",
            (self.admin_id,))
        self.assertEqual(len(suppressed), 1, suppressed)


class TestAlertQueueAgeDb(AlertDbBase, unittest.TestCase):

    def test_queue_buildup_oldest_age_leg(self):
        from monitoring import alerts

        self.seed_job("q-fresh", "queued")
        self.assertNotIn("queue_buildup",
                         self.fired_rules(alerts.evaluate()))
        self.seed_job("q-stale", "queued", created_ago=1000)
        fired = self.fired_rules(alerts.evaluate())
        self.assertIn("queue_buildup", fired)
        hit = fired["queue_buildup"]
        self.assertEqual(hit["metric"], "oldest_queued_age_seconds")
        self.assertGreaterEqual(hit["observed"], 1000)
        self.assert_alert_delivered_once("queue_buildup")


class TestAlertWorkerFailuresDb(AlertDbBase, unittest.TestCase):

    def test_dead_jobs_then_failed_cases(self):
        from monitoring import alerts

        self.seed_job("d-0", "dead", finished_ago=0)
        self.seed_job("d-1", "dead", finished_ago=0)
        self.assertNotIn("worker_failures",
                         self.fired_rules(alerts.evaluate()))
        self.seed_job("d-2", "dead", finished_ago=0)
        fired = self.fired_rules(alerts.evaluate())
        self.assertEqual(fired["worker_failures"]["metric"],
                         "dead_jobs_24h")
        self.assertEqual(fired["worker_failures"]["observed"], 3)
        self.assert_alert_delivered_once("worker_failures")

        # The cases leg of the same rule.
        self.db_exec("DELETE FROM scan_jobs")
        broker = self.db_one("SELECT slug FROM brokers LIMIT 1")["slug"]
        for i in range(5):
            self.db_exec(
                "INSERT INTO remediation_cases (user_id, broker_slug,"
                " status) VALUES (%s, %s, 'failed')",
                (self.admin_id, broker))
        fired = self.fired_rules(alerts.evaluate())
        self.assertEqual(fired["worker_failures"]["metric"],
                         "failed_cases_24h")
        self.assertEqual(fired["worker_failures"]["observed"], 5)


class TestAlertProviderOutageDb(AlertDbBase, unittest.TestCase):

    def test_unreachable_sources(self):
        from monitoring import alerts

        seed = ("INSERT INTO broker_source_checks (slug, url, state,"
                " checked_at) VALUES (%s, 'https://x.invalid',"
                " 'unreachable', now())")
        for i in range(4):
            self.db_exec(seed, ("out-%d" % i,))
        self.assertNotIn("provider_outage",
                         self.fired_rules(alerts.evaluate()))
        self.db_exec(seed, ("out-4",))
        fired = self.fired_rules(alerts.evaluate())
        self.assertEqual(fired["provider_outage"]["observed"], 5)
        self.assert_alert_delivered_once("provider_outage")


class TestAlertErrorSpikeDb(AlertDbBase, unittest.TestCase):

    def test_error_spike(self):
        from core import error_ledger
        from monitoring import alerts

        self.db_exec("DELETE FROM error_events")
        for _i in range(19):
            error_ledger.record("spike ctx", "RuntimeError",
                                "spike failure")
        self.assertNotIn("error_spike",
                         self.fired_rules(alerts.evaluate()))
        error_ledger.record("spike ctx", "RuntimeError",
                            "spike failure")
        fired = self.fired_rules(alerts.evaluate())
        self.assertGreaterEqual(fired["error_spike"]["observed"], 20)
        self.assert_alert_delivered_once("error_spike")


class TestAlertScanLatencyDb(AlertDbBase, unittest.TestCase):
    """Phase 175: the latency rule needs BOTH legs — a median at
    or over 120 s AND at least 10 completed jobs in 24 h."""

    def seed_done(self, key, duration_seconds):
        self.seed_job(key, "done", created_ago=duration_seconds + 60,
                      started_ago=duration_seconds, finished_ago=0)

    def test_latency_fires_at_sample_floor_and_dedupes(self):
        from monitoring import alerts

        # 9 slow jobs: median 180 s, but below the sample floor —
        # the rule must stay silent.
        for i in range(9):
            self.seed_done("slow-%d" % i, 180)
        self.assertNotIn("scan_latency",
                         self.fired_rules(alerts.evaluate()))
        # The 10th slow job completes the sample: median 180 >= 120.
        self.seed_done("slow-9", 180)
        fired = self.fired_rules(alerts.evaluate())
        self.assertIn("scan_latency", fired)
        hit = fired["scan_latency"]
        self.assertEqual(hit["metric"],
                         "median_scan_duration_seconds_24h")
        self.assertEqual(hit["observed"], 180)
        self.assertEqual(hit["threshold"], 120)
        self.assert_alert_delivered_once("scan_latency")
        # The audit detail carries the sample size as a flat scalar.
        audit_row = self.db_one(
            "SELECT * FROM audit_log"
            " WHERE action = 'engineering_alert'"
            " AND target_id = 'scan_latency'")
        self.assertEqual(
            audit_row["detail"]["completed_jobs_24h"], 10)
        # A second pass the same day fires again but does not email
        # again — the repeat lands 'suppressed' (dedupe discipline).
        self.assertIn("scan_latency",
                      self.fired_rules(alerts.evaluate()))
        self.assert_alert_delivered_once("scan_latency")
        suppressed = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'"
            " AND status = 'suppressed'",
            (self.admin_id,))
        self.assertEqual(len(suppressed), 1, suppressed)


class TestAlertScanLatencySampleFloorDb(AlertDbBase,
                                       unittest.TestCase):
    """A quiet system must never fire on a few extreme jobs."""

    def test_extreme_durations_below_sample_floor_stay_silent(self):
        from monitoring import alerts

        for i in range(3):
            self.seed_job("huge-%d" % i, "done", created_ago=3700,
                          started_ago=3600, finished_ago=0)
        self.assertNotIn("scan_latency",
                         self.fired_rules(alerts.evaluate()))
        rows = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'",
            (self.admin_id,))
        self.assertEqual(rows, [])


class TestAlertScanLatencyFastDb(AlertDbBase, unittest.TestCase):
    """Above the sample floor but inside the healthy band: silent."""

    def test_fast_median_stays_silent(self):
        from monitoring import alerts

        for i in range(12):
            self.seed_job("fast-%d" % i, "done", created_ago=70,
                          started_ago=10, finished_ago=0)
        self.assertNotIn("scan_latency",
                         self.fired_rules(alerts.evaluate()))
        rows = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'",
            (self.admin_id,))
        self.assertEqual(rows, [])


class TestAlertScanLatencyFlagDb(AlertDbBase, unittest.TestCase):
    """The rule rides evaluate(), which only runs from the
    scheduler tick — behind the monitoring_scheduler flag, like
    every other rule (Phase 77 placement). Flag off: the tick
    never evaluates, so no latency alert can be delivered."""

    def test_latency_rule_respects_scheduler_flag(self):
        from monitoring import alerts, scheduler

        for i in range(10):
            self.seed_job("flag-slow-%d" % i, "done",
                          created_ago=240, started_ago=180,
                          finished_ago=0)
        calls = []
        saved_evaluate = alerts.evaluate

        def counting_evaluate():
            calls.append(1)
            return saved_evaluate()

        alerts.evaluate = counting_evaluate
        os.environ["LEAKGUARD_FLAG_MONITORING_SCHEDULER"] = "off"
        try:
            self.assertEqual(scheduler.tick(), [])
            self.assertEqual(calls, [])
            rows = self.db_all(
                "SELECT * FROM notifications WHERE user_id = %s"
                " AND kind = 'engineering_alert'",
                (self.admin_id,))
            self.assertEqual(rows, [])
            # Flag back on: the same tick now evaluates and the
            # seeded breach is delivered exactly once.
            del os.environ["LEAKGUARD_FLAG_MONITORING_SCHEDULER"]
            scheduler.tick()
        finally:
            alerts.evaluate = saved_evaluate
            os.environ.pop("LEAKGUARD_FLAG_MONITORING_SCHEDULER",
                           None)
        self.assertEqual(len(calls), 1)
        self.assert_alert_delivered_once("scan_latency")


class TestSchedulerAlertGuard(unittest.TestCase):
    """No database: the tick's alerts step is guarded — a raising
    evaluator leaves the tick's result untouched."""

    def test_raising_alerts_do_not_break_tick(self):
        from monitoring import alerts, scheduler

        saved_candidates = scheduler._candidates
        saved_evaluate = alerts.evaluate

        def boom():
            raise RuntimeError("alerts unavailable")

        scheduler._candidates = lambda: []
        alerts.evaluate = boom
        try:
            self.assertEqual(scheduler.tick(), [])
        finally:
            scheduler._candidates = saved_candidates
            alerts.evaluate = saved_evaluate


if __name__ == "__main__":
    unittest.main()
