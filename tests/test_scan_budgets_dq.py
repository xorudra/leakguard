"""Scan budget engine + data-quality tests (P2-E — spec
Phases 158, 160).

Layers:

* TestBudgetSnapshotUnit — no database: budgets_snapshot()
  lists every scan budget (per-user daily scans, per-job
  discovery, per-case probe seconds, per-provider daily calls,
  route rate limits), each read from the constant that enforces
  it and carrying its source.
* TestMalformedReasonsUnit — no database: the stored-row
  contract checker (details shape, pwned_count type, dns
  summary shape, exposed_fields entries, source identity,
  confidence/reliability values).
* TestUserScanBudgetDb — pgserver + HTTP: a user under the
  daily budget creates jobs; at the budget, creation is
  refused with 429 + code scan_budget_exhausted + a plain
  message; an idempotent retry is never refused; scheduled
  (monitor-) jobs do not count against the manual budget;
  yesterday's jobs do not count; a fresh user's first scan
  always fits the real budget.
* TestDataQualityDuplicatesDb — pgserver: a seeded
  same-observation set in one job is flagged exactly (later
  copies only); the same identity in another job is NOT a
  duplicate; run ledger + rollup + no audit record for
  duplicates alone.
* TestDataQualityMalformedDb — pgserver: seeded malformed
  rows (details array, pwned_count string, dns shape,
  exposed_fields null entry, blank source identity) are
  flagged per provider; exactly one PII-free audit record.
* TestDataQualityCleanDb — pgserver: clean data yields zero
  issues, a recorded run, no audit record; maybe_run gates.
* TestMetricsBudgetsDqDb — pgserver + HTTP: the admin metrics
  block carries the budgets registry and the data_quality
  section matching the seeded run; anonymous callers get 404.
* TestSchedulerDqGuard — no database: a raising data-quality
  pass cannot break scheduler.tick().

Against local PostgreSQL provisioned with pip `pgserver`
(skips honestly when unavailable). Test accounts use unique
example.com addresses; no plaintext passwords are printed.

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
from providers import usage  # noqa: E402
from scanning import budgets, data_quality, orchestrator  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS",
            "BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")
PASSWORD = "P2E test " + "password 158"


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


class BudgetPatch:
    """Temporarily shrink the per-user daily scan budget (the
    enforcement reads the module constant at call time)."""

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.saved = budgets.USER_DAILY_SCAN_BUDGET
        budgets.USER_DAILY_SCAN_BUDGET = self.value
        return self

    def __exit__(self, *exc):
        budgets.USER_DAILY_SCAN_BUDGET = self.saved
        return False


# ---------------------------------------------------------------------------
# Unit layer — no database
# ---------------------------------------------------------------------------

class TestBudgetSnapshotUnit(unittest.TestCase):

    def test_snapshot_lists_every_budget_with_its_source(self):
        snap = budgets.budgets_snapshot()
        self.assertEqual(
            snap["per_user_daily_full_scans"]["limit"],
            budgets.USER_DAILY_SCAN_BUDGET)
        self.assertEqual(
            snap["per_job_discovery_queries"]["limit"],
            orchestrator.DISCOVERY_BUDGET)
        self.assertEqual(snap["per_job_discovery_queries"]["limit"], 6)
        self.assertEqual(
            snap["per_case_probe_seconds"]["limit"], 40.0)
        self.assertEqual(
            snap["per_provider_daily_calls"]["limits"],
            dict(usage.BUDGETS))
        limits = snap["route_rate_limits"]["limits"]
        self.assertEqual(limits["user_scans"],
                         {"limit": 10, "window_seconds": 3600})
        self.assertEqual(limits["anon_scan"]["limit"], 30)
        for section in snap.values():
            self.assertIn("source", section)
        json.dumps(snap)  # the whole registry view is JSON-safe


class TestMalformedReasonsUnit(unittest.TestCase):

    def _row(self, **overrides):
        row = {
            "details": {"pwned_count": 5},
            "exposed_fields": ["password"],
            "source_name": "Pwned Passwords",
            "source_url": None,
            "confidence": "exact",
            "reliability": "high",
        }
        row.update(overrides)
        return row

    def test_clean_row_has_no_reasons(self):
        self.assertEqual(data_quality.malformed_reasons(self._row()), [])
        dns_row = self._row(details={"dns": {"A": ["203.0.113.7"],
                                             "MX": []}})
        self.assertEqual(data_quality.malformed_reasons(dns_row), [])

    def test_details_must_be_an_object(self):
        for bad in ([1, 2], "text", 7, None):
            self.assertIn("details_not_object",
                          data_quality.malformed_reasons(
                              self._row(details=bad)), bad)

    def test_pwned_count_must_be_a_non_negative_int(self):
        for bad in ("many", 2.5, True, -1):
            self.assertIn("pwned_count_not_int",
                          data_quality.malformed_reasons(
                              self._row(details={"pwned_count": bad})),
                          bad)

    def test_dns_summary_shape(self):
        self.assertIn("dns_summary_shape",
                      data_quality.malformed_reasons(
                          self._row(details={"dns": {"A": "x"}})))
        self.assertIn("dns_summary_shape",
                      data_quality.malformed_reasons(
                          self._row(details={"dns": ["A"]})))

    def test_exposed_fields_entries(self):
        for bad in (["email", None], ["email", ""], ["email", "  "],
                    "email", None, [7]):
            self.assertIn("exposed_fields_shape",
                          data_quality.malformed_reasons(
                              self._row(exposed_fields=bad)), bad)

    def test_source_identity_required(self):
        for bad in ("", "   ", None):
            self.assertIn("source_identity_missing",
                          data_quality.malformed_reasons(
                              self._row(source_name=bad)), bad)

    def test_enum_drift(self):
        self.assertIn("confidence_value",
                      data_quality.malformed_reasons(
                          self._row(confidence="certain")))
        self.assertIn("reliability_value",
                      data_quality.malformed_reasons(
                          self._row(reliability="ultra")))


class TestSchedulerDqGuard(unittest.TestCase):
    """No database: the tick's data-quality step is guarded — a
    raising pass leaves the tick's result untouched (mirrors
    TestSchedulerAlertGuard)."""

    def test_raising_data_quality_does_not_break_tick(self):
        from monitoring import alerts, scheduler

        saved_candidates = scheduler._candidates
        saved_evaluate = alerts.evaluate
        saved_maybe_run = data_quality.maybe_run

        def boom(*args, **kwargs):
            raise RuntimeError("data quality unavailable")

        scheduler._candidates = lambda: []
        alerts.evaluate = lambda: []
        data_quality.maybe_run = boom
        try:
            self.assertEqual(scheduler.tick(), [])
        finally:
            scheduler._candidates = saved_candidates
            alerts.evaluate = saved_evaluate
            data_quality.maybe_run = saved_maybe_run


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

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
class DbBase(ServerMixin):
    """Fresh pgserver database per class, fully migrated, mock
    providers, HTTP server up."""

    ADMIN_EMAIL = "owner-p2e@example.com"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-p2e-pg-")
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
        os.environ["ADMIN_EMAILS"] = cls.ADMIN_EMAIL
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

    # ----- account helpers (HTTP, like the other suites) -----

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self, email=None):
        email = email or ("p2e-%s@example.com" % self.uniq())
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD, "policy_accepted": True},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def set_consent(self, cookie, purpose, granted):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": purpose, "granted": granted},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

    def scan_ready_user(self):
        cookie, uid, _email = self.register()
        ident = self.add_identifier(
            cookie, "email", "target-%s@example.com" % self.uniq())
        self.set_consent(cookie, "scanning", True)
        return cookie, uid, ident["id"]

    def post_scan(self, cookie, key):
        return self.request_json(
            "POST", "/api/scans", body={"idempotency_key": key},
            headers=CSRF, cookie=cookie)

    # ----- direct DB helpers -----

    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def db_rows(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            conn.execute(sql, params)

    def insert_job(self, user_id, key, created_at=None, status="done"):
        row = self.db_row(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " created_at) VALUES (%s, %s, %s, COALESCE(%s, now()))"
            " RETURNING id",
            (user_id, key, status, created_at))
        return str(row["id"])

    def insert_finding(self, job_id, user_id, identifier_id,
                       provider="FixtureProvider",
                       source_name="BreachX", source_url=None,
                       evidence_ref=None, exposed_fields=(),
                       details="{}", discovered_at=None):
        row = self.db_row(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, source_url,"
            " discovered_at, exposed_fields, confidence,"
            " reliability, evidence_ref, details)"
            " VALUES (%s, %s, %s, 'email', %s, %s, %s,"
            " COALESCE(%s, now()), %s, 'exact', 'high', %s, %s::jsonb)"
            " RETURNING id",
            (job_id, user_id, identifier_id, provider, source_name,
             source_url, discovered_at, list(exposed_fields),
             evidence_ref or (uuid.uuid4().hex * 2), details))
        return str(row["id"])

    def finding_flags(self, finding_id):
        row = self.db_row(
            "SELECT dq_duplicate, dq_malformed FROM findings"
            " WHERE id = %s", (finding_id,))
        return row["dq_duplicate"], row["dq_malformed"]


# ---------------------------------------------------------------------------
# Phase 158 — the per-user daily scan budget over HTTP
# ---------------------------------------------------------------------------

class TestUserScanBudgetDb(DbBase, unittest.TestCase):

    def test_creates_until_budget_then_refused_plainly(self):
        cookie, _uid, _iid = self.scan_ready_user()
        with BudgetPatch(3):
            status, _h, body = self.post_scan(cookie, "b-1")
            self.assertEqual(status, 201, body)
            first_id = body["job"]["id"]
            status, _h, _b = self.post_scan(cookie, "b-2")
            self.assertEqual(status, 201)
            # An idempotent retry returns the existing job and
            # consumes nothing — it must never be refused.
            status, _h, body = self.post_scan(cookie, "b-1")
            self.assertEqual(status, 200, body)
            self.assertEqual(body["job"]["id"], first_id)
            status, _h, _b = self.post_scan(cookie, "b-3")
            self.assertEqual(status, 201)
            status, _h, body = self.post_scan(cookie, "b-4")
            self.assertEqual(status, 429, body)
            error = body["error"]
            self.assertEqual(error["code"], "scan_budget_exhausted")
            self.assertIn("budget", error["message"])
            self.assertIn("midnight UTC", error["message"])
            # The refused job was NOT queued silently.
            row = self.db_row(
                "SELECT COUNT(*) AS n FROM scan_jobs"
                " WHERE idempotency_key = 'b-4'")
            self.assertEqual(row["n"], 0)

    def test_monitor_lane_jobs_do_not_count(self):
        cookie, uid, _iid = self.scan_ready_user()
        for i in range(3):
            self.insert_job(uid, "monitor-%s-%d" % (uid, i),
                            status="queued")
        with BudgetPatch(2):
            status, _h, _b = self.post_scan(cookie, "m-1")
            self.assertEqual(status, 201)
            with self.pool.connection() as conn:
                self.assertEqual(
                    budgets.manual_jobs_today(conn, uid), 1)
            status, _h, _b = self.post_scan(cookie, "m-2")
            self.assertEqual(status, 201)
            status, _h, body = self.post_scan(cookie, "m-3")
            self.assertEqual(status, 429, body)

    def test_yesterdays_jobs_do_not_count(self):
        cookie, uid, _iid = self.scan_ready_user()
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        self.insert_job(uid, "manual-old", created_at=yesterday)
        with BudgetPatch(1):
            status, _h, _b = self.post_scan(cookie, "today-1")
            self.assertEqual(status, 201)
            status, _h, body = self.post_scan(cookie, "today-2")
            self.assertEqual(status, 429, body)

    def test_fresh_users_first_scan_fits_the_real_budget(self):
        # Ungenerous budgets would break the product's first-run
        # promise; the shipped value sits far above a first day.
        self.assertGreaterEqual(budgets.USER_DAILY_SCAN_BUDGET, 10)
        cookie, _uid, _iid = self.scan_ready_user()
        status, _h, body = self.post_scan(cookie, "first-1")
        self.assertEqual(status, 201, body)


# ---------------------------------------------------------------------------
# Phase 160 — duplicates
# ---------------------------------------------------------------------------

class TestDataQualityDuplicatesDb(DbBase, unittest.TestCase):

    def test_same_observation_twice_in_one_job_flagged_exactly(self):
        _cookie, uid, iid = self.scan_ready_user()
        job1 = self.insert_job(uid, "dq-job-1")
        job2 = self.insert_job(uid, "dq-job-2")
        base = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
        same = dict(provider="DqDupProvider", source_name="BreachSame",
                    source_url="https://example.com/x",
                    evidence_ref="a" * 64)
        d1 = self.insert_finding(job1, uid, iid,
                                 discovered_at=base, **same)
        d2 = self.insert_finding(
            job1, uid, iid,
            discovered_at=base + timedelta(seconds=1), **same)
        d3 = self.insert_finding(
            job1, uid, iid,
            discovered_at=base + timedelta(seconds=2), **same)
        other = self.insert_finding(
            job1, uid, iid, provider="DqDupProvider",
            source_name="BreachOther", evidence_ref="b" * 64)
        cross_job = self.insert_finding(job2, uid, iid, **same)

        summary = data_quality.run_once()
        self.assertEqual(summary["findings_scanned"], 5)
        self.assertEqual(summary["duplicates_flagged"], 2)
        self.assertEqual(summary["malformed_flagged"], 0)
        # The first copy stands; the later copies carry the flag.
        self.assertEqual(self.finding_flags(d1), (False, False))
        self.assertEqual(self.finding_flags(d2), (True, False))
        self.assertEqual(self.finding_flags(d3), (True, False))
        self.assertEqual(self.finding_flags(other), (False, False))
        # The same identity in ANOTHER job is the monitoring
        # design, not a duplicate.
        self.assertEqual(self.finding_flags(cross_job), (False, False))

        run = self.db_row("SELECT * FROM dq_runs")
        self.assertEqual(run["duplicates_flagged"], 2)
        self.assertEqual(run["malformed_flagged"], 0)
        rollup = self.db_rows("SELECT * FROM dq_issue_rollup")
        self.assertEqual(len(rollup), 1, rollup)
        self.assertEqual(rollup[0]["provider"], "DqDupProvider")
        self.assertEqual(rollup[0]["kind"], "duplicate")
        self.assertEqual(rollup[0]["count"], 2)
        self.assertEqual(
            rollup[0]["day"], datetime.now(timezone.utc).date())

        # Duplicates alone raise no audit record (malformed does).
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM audit_log"
            " WHERE action = 'data_quality.issues'")
        self.assertEqual(row["n"], 0)

        # The run ledger gates maybe_run to ~daily.
        self.assertEqual(data_quality.maybe_run(),
                         {"skipped": True, "reason": "ran_recently"})

        with self.pool.connection() as conn:
            latest = data_quality.latest_summary(conn)
        self.assertIsNotNone(latest["last_run_at"])
        self.assertEqual(latest["duplicates_flagged"], 2)
        self.assertEqual(latest["by_provider"], [{
            "provider": "DqDupProvider", "duplicates": 2,
            "malformed": 0}])


# ---------------------------------------------------------------------------
# Phase 160 — malformed rows + the audit record
# ---------------------------------------------------------------------------

class TestDataQualityMalformedDb(DbBase, unittest.TestCase):

    def test_malformed_rows_flagged_per_provider_with_audit(self):
        _cookie, uid, iid = self.scan_ready_user()
        job = self.insert_job(uid, "dq-bad-job")
        bad = "DqBadProvider"
        m1 = self.insert_finding(job, uid, iid, provider=bad,
                                 source_name="M1", details="[1, 2]")
        m2 = self.insert_finding(
            job, uid, iid, provider=bad, source_name="M2",
            details='{"pwned_count": "many"}')
        m3 = self.insert_finding(
            job, uid, iid, provider=bad, source_name="M3",
            details='{"dns": {"A": "203.0.113.7"}}')
        m4 = self.insert_finding(
            job, uid, iid, provider=bad, source_name="M4",
            exposed_fields=["email", None])
        m5 = self.insert_finding(job, uid, iid, provider=bad,
                                 source_name="   ")
        clean = self.insert_finding(
            job, uid, iid, provider=bad, source_name="Pwned Passwords",
            exposed_fields=["password"],
            details='{"pwned_count": 3}')
        m7 = self.insert_finding(
            job, uid, iid, provider="DqOtherProvider",
            source_name="M7", details='"a string"')

        summary = data_quality.run_once()
        self.assertEqual(summary["findings_scanned"], 7)
        self.assertEqual(summary["malformed_flagged"], 6)
        self.assertEqual(summary["duplicates_flagged"], 0)
        for fid in (m1, m2, m3, m4, m5, m7):
            self.assertEqual(self.finding_flags(fid), (False, True),
                             fid)
        self.assertEqual(self.finding_flags(clean), (False, False))

        by_provider = {p["provider"]: p
                       for p in summary["by_provider"]}
        self.assertEqual(by_provider["DqBadProvider"]["malformed"], 5)
        self.assertEqual(
            by_provider["DqOtherProvider"]["malformed"], 1)
        rollup = {(r["provider"], r["kind"]): r["count"]
                  for r in self.db_rows("SELECT * FROM dq_issue_rollup")}
        self.assertEqual(
            rollup, {("DqBadProvider", "malformed"): 5,
                     ("DqOtherProvider", "malformed"): 1})

        # Exactly ONE audit record for the run, counts only.
        rows = self.db_rows(
            "SELECT detail FROM audit_log"
            " WHERE action = 'data_quality.issues'")
        self.assertEqual(len(rows), 1, rows)
        detail = rows[0]["detail"]
        self.assertEqual(detail["malformed_flagged"], 6)
        self.assertEqual(detail["duplicates_flagged"], 0)
        self.assertEqual(detail["providers_affected"], 2)


# ---------------------------------------------------------------------------
# Phase 160 — clean data
# ---------------------------------------------------------------------------

class TestDataQualityCleanDb(DbBase, unittest.TestCase):

    def test_clean_data_zero_issues_recorded_run_no_event(self):
        _cookie, uid, iid = self.scan_ready_user()
        job = self.insert_job(uid, "dq-clean-job")
        for n in range(3):
            self.insert_finding(
                job, uid, iid, provider="DqCleanProvider",
                source_name="Breach%d" % n,
                exposed_fields=["email"],
                details='{"exposed_data_attribution": "none"}')

        summary = data_quality.maybe_run()
        self.assertFalse(summary["skipped"])
        self.assertEqual(summary["findings_scanned"], 3)
        self.assertEqual(summary["duplicates_flagged"], 0)
        self.assertEqual(summary["malformed_flagged"], 0)
        row = self.db_row("SELECT COUNT(*) AS n FROM findings"
                          " WHERE dq_duplicate OR dq_malformed")
        self.assertEqual(row["n"], 0)
        run = self.db_row("SELECT * FROM dq_runs")
        self.assertEqual(run["findings_scanned"], 3)
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM audit_log"
            " WHERE action = 'data_quality.issues'")
        self.assertEqual(row["n"], 0)

        with self.pool.connection() as conn:
            latest = data_quality.latest_summary(conn)
        self.assertIsNotNone(latest["last_run_at"])
        self.assertEqual(latest["duplicates_flagged"], 0)
        self.assertEqual(latest["malformed_flagged"], 0)
        self.assertEqual(latest["by_provider"], [])


# ---------------------------------------------------------------------------
# Phases 158 + 160 — the admin metrics surface
# ---------------------------------------------------------------------------

class TestMetricsBudgetsDqDb(DbBase, unittest.TestCase):

    def test_metrics_carry_budgets_and_data_quality(self):
        admin_cookie, _aid, _e = self.register(self.ADMIN_EMAIL)
        _cookie, uid, iid = self.scan_ready_user()
        job = self.insert_job(uid, "dq-metrics-job")
        base = datetime(2026, 10, 8, 9, 0, tzinfo=timezone.utc)
        same = dict(provider="DqMetricsProvider",
                    source_name="BreachSame",
                    source_url="https://example.com/y",
                    evidence_ref="c" * 64)
        self.insert_finding(job, uid, iid, discovered_at=base, **same)
        self.insert_finding(job, uid, iid,
                            discovered_at=base + timedelta(seconds=1),
                            **same)
        self.insert_finding(
            job, uid, iid, provider="DqMetricsProvider",
            source_name="M1", details="[1, 2]")
        data_quality.run_once()

        status, _h, body = self.request_json(
            "GET", "/api/admin/metrics", cookie=admin_cookie)
        self.assertEqual(status, 200, body)
        budgets_block = body["budgets"]
        self.assertEqual(
            budgets_block["per_user_daily_full_scans"]["limit"],
            budgets.USER_DAILY_SCAN_BUDGET)
        self.assertEqual(
            budgets_block["per_job_discovery_queries"]["limit"], 6)
        self.assertEqual(
            budgets_block["per_case_probe_seconds"]["limit"], 40.0)
        # P2-D's provider section is intact alongside the new ones.
        self.assertIn("providers", body)
        dq = body["data_quality"]
        self.assertIsNotNone(dq["last_run_at"])
        self.assertEqual(dq["duplicates_flagged"], 1)
        self.assertEqual(dq["malformed_flagged"], 1)
        self.assertEqual(dq["by_provider"], [{
            "provider": "DqMetricsProvider", "duplicates": 1,
            "malformed": 1}])

        # Anonymous callers still get the house 404.
        status, _h, _b = self.request_json("GET", "/api/admin/metrics")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
