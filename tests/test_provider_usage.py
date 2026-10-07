"""Provider usage + daily budget tests (P2-D — spec Phases 66, 124).

Layers:

* TestUsageTrackerUnit — no database: the UsageTracker's
  in-memory rollup against fake persister/loader hooks — flush
  drains deltas, a failed flush merges them back (never lost,
  never doubled), UTC-day buckets stay separate, the loader
  seeds persisted counts once, budgets exhaust and reset on the
  next day, a broken loader fails open, and budget-less providers
  are never seeded or refused.
* TestBudgetGateClient — no database: through HttpClient, an
  exhausted provider is refused with status "error" /
  error_kind "budget_exhausted" BEFORE the transport is touched;
  the refusal is a health event but is NOT counted as usage; a
  circuit-open refusal is not counted either.
* TestBudgetsCoverRegistry — the BUDGETS table names exactly
  the real registry's providers, so budgets cannot drift from
  the catalogue.
* TestUsageLedgerDb — pgserver: counts persist as one rollup
  row per provider-day (upsert increments); a broken database
  never breaks a provider call; an exhausted budget surfaces
  through the scan orchestrator as outcome 'provider_error'
  with error_kind 'budget_exhausted' (honest degradation).
* TestProviderMetricsDb — pgserver + HTTP: the admin metrics
  block's providers section matches the seeded ledger against
  the real budgets (pct used, exhausted flag, budget-less row),
  scan_jobs.today aggregates per-user volume for the UTC day,
  and anonymous callers still get the house 404.
* TestAlertProviderBudgetDb / ...SilentDb — pgserver: the
  provider_budget rule fires at 100% of a budget (audit detail
  names the provider, one email, daily dedupe) and stays
  silent at 99%.

Against local PostgreSQL provisioned with pip `pgserver` (skips
honestly when unavailable). No real email: the lane transport
is a recording fake. Run:  python3 -m unittest discover -s tests
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
from datetime import date, datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from providers import usage  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS",
            "BREVO_API_KEY", "NOTIFY_FROM_EMAIL", "NOTIFY_FROM_NAME")
PASSWORD = "S66 test " + "password 456"
DAY1 = date(2026, 10, 8)
DAY2 = date(2026, 10, 9)


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


class BudgetGuard:
    """Temporarily replace usage.BUDGETS (the tracker reads it at
    call time) and restore it afterwards."""

    def __init__(self, budgets):
        self.budgets = budgets

    def __enter__(self):
        self.saved = dict(usage.BUDGETS)
        usage.BUDGETS.clear()
        usage.BUDGETS.update(self.budgets)
        return self

    def __exit__(self, *exc):
        usage.BUDGETS.clear()
        usage.BUDGETS.update(self.saved)
        return False


# ---------------------------------------------------------------------------
# Unit layer — the tracker against fake hooks
# ---------------------------------------------------------------------------

class _FakeStore:
    """In-memory stand-in for provider_usage_daily."""

    def __init__(self):
        self.rows = {}          # (provider, day) -> [calls, ok, fail]
        self.persist_calls = 0
        self.load_calls = 0
        self.fail_persist = False

    def persist(self, rows):
        self.persist_calls += 1
        if self.fail_persist:
            return False
        for provider, day, calls, succ, fail in rows:
            entry = self.rows.setdefault((provider, day), [0, 0, 0])
            entry[0] += calls
            entry[1] += succ
            entry[2] += fail
        return True

    def load(self, provider, day):
        self.load_calls += 1
        row = self.rows.get((provider, day))
        return tuple(row) if row is not None else None


class TestUsageTrackerUnit(unittest.TestCase):

    def make_tracker(self, flush_every=1000, day=DAY1):
        store = _FakeStore()
        tracker = usage.UsageTracker(
            flush_every=flush_every, today_fn=lambda: day[0])
        tracker.set_persister(store.persist)
        tracker.set_loader(store.load)
        return tracker, store

    def test_rollup_flush_and_counts(self):
        day = [DAY1]
        tracker, store = self.make_tracker(day=day)
        tracker.record("Probe", True)
        tracker.record("Probe", True)
        tracker.record("Probe", False)
        self.assertEqual(store.rows, {})  # nothing flushed yet
        self.assertEqual(tracker.counts("Probe"), (3, 2, 1))
        self.assertTrue(tracker.flush())
        self.assertEqual(store.rows[("Probe", DAY1)], [3, 2, 1])
        self.assertEqual(store.persist_calls, 1)
        # Counts survive the flush (persisted side now holds them),
        # and an empty flush does not call the persister again.
        self.assertEqual(tracker.counts("Probe"), (3, 2, 1))
        self.assertTrue(tracker.flush())
        self.assertEqual(store.persist_calls, 1)

    def test_failed_flush_merges_back_without_doubling(self):
        day = [DAY1]
        tracker, store = self.make_tracker(day=day)
        tracker.record("Probe", True)
        tracker.record("Probe", False)
        store.fail_persist = True
        self.assertFalse(tracker.flush())
        self.assertEqual(tracker.counts("Probe"), (2, 1, 1))
        store.fail_persist = False
        self.assertTrue(tracker.flush())
        self.assertEqual(store.rows[("Probe", DAY1)], [2, 1, 1])

    def test_day_buckets_stay_separate(self):
        day = [DAY1]
        tracker, store = self.make_tracker(day=day)
        tracker.record("Probe", True)
        tracker.record("Probe", True)
        day[0] = DAY2
        tracker.record("Probe", False)
        self.assertEqual(tracker.calls_today("Probe"), 1)
        self.assertTrue(tracker.flush())
        self.assertEqual(store.rows[("Probe", DAY1)], [2, 2, 0])
        self.assertEqual(store.rows[("Probe", DAY2)], [1, 0, 1])

    def test_loader_seeds_once(self):
        day = [DAY1]
        tracker, store = self.make_tracker(day=day)
        store.rows[("Probe", DAY1)] = [40, 38, 2]
        self.assertEqual(tracker.counts("Probe"), (40, 38, 2))
        tracker.record("Probe", True)
        self.assertEqual(tracker.counts("Probe"), (41, 39, 2))
        self.assertEqual(store.load_calls, 1)

    def test_exhaustion_and_next_day_reset(self):
        day = [DAY1]
        tracker, store = self.make_tracker(day=day)
        with BudgetGuard({"ProbeX": 3}):
            self.assertFalse(tracker.is_exhausted("ProbeX"))
            tracker.record("ProbeX", True)
            tracker.record("ProbeX", True)
            self.assertFalse(tracker.is_exhausted("ProbeX"))
            tracker.record("ProbeX", True)
            self.assertTrue(tracker.is_exhausted("ProbeX"))
            day[0] = DAY2
            self.assertFalse(tracker.is_exhausted("ProbeX"))

    def test_broken_loader_fails_open(self):
        day = [DAY1]
        tracker, _store = self.make_tracker(day=day)

        def boom(provider, day_):
            raise RuntimeError("ledger unreachable")

        tracker.set_loader(boom)
        with BudgetGuard({"ProbeX": 5}):
            self.assertEqual(tracker.counts("ProbeX"), (0, 0, 0))
            self.assertFalse(tracker.is_exhausted("ProbeX"))

    def test_budgetless_provider_never_seeded_or_refused(self):
        day = [DAY1]
        tracker, store = self.make_tracker(day=day)
        self.assertFalse(tracker.is_exhausted("Untracked Name"))
        self.assertEqual(store.load_calls, 0)


# ---------------------------------------------------------------------------
# Unit layer — the budget gate through HttpClient
# ---------------------------------------------------------------------------

class TestBudgetGateClient(unittest.TestCase):

    def setUp(self):
        usage.tracker.reset()
        self.guard = BudgetGuard({"BudgetProbe": 2})
        self.guard.__enter__()
        self.addCleanup(self.guard.__exit__)
        self.addCleanup(usage.tracker.reset)

    def test_refusal_after_budget_spent(self):
        from providers.base import HttpClient
        from providers.registry import HealthTracker

        calls = []

        def transport(url, headers, timeout):
            calls.append(url)
            return 200, '{"ok": true}'

        health = HealthTracker()
        client = HttpClient("BudgetProbe", health=health,
                            transport=transport,
                            sleep=lambda _s: None)
        self.assertEqual(client.get_json("https://x.invalid").status,
                         "ok")
        self.assertEqual(client.get_json("https://x.invalid").status,
                         "ok")
        refused = client.get_json("https://x.invalid")
        self.assertEqual(refused.status, "error")
        self.assertEqual(refused.error_kind, "budget_exhausted")
        self.assertEqual(refused.latency_ms, 0.0)
        # The transport was never touched for the refused call,
        # and the refusal is not usage — but IS a health event.
        self.assertEqual(len(calls), 2)
        self.assertEqual(usage.tracker.counts("BudgetProbe"),
                         (2, 2, 0))
        snap = health.snapshot("BudgetProbe")
        self.assertEqual(snap["successes"], 2)
        self.assertEqual(snap["failures"], 1)
        self.assertEqual(snap["last_error_kind"], "budget_exhausted")

    def test_circuit_open_refusal_is_not_usage(self):
        from providers.base import HttpClient
        from providers.registry import HealthTracker

        def transport(url, headers, timeout):
            return 500, "server error"

        health = HealthTracker()
        client = HttpClient("CircuitProbe", health=health,
                            transport=transport,
                            sleep=lambda _s: None,
                            max_retries=0, breaker_threshold=1)
        first = client.get_json("https://x.invalid")
        self.assertEqual(first.error_kind, "http_5xx")
        self.assertEqual(usage.tracker.counts("CircuitProbe"),
                         (1, 0, 1))
        second = client.get_json("https://x.invalid")
        self.assertEqual(second.status, "circuit_open")
        self.assertEqual(usage.tracker.counts("CircuitProbe"),
                         (1, 0, 1))


class TestBudgetsCoverRegistry(unittest.TestCase):

    def test_budgets_match_real_registry_names(self):
        from providers.registry import Registry

        names = {p.info.name for p in Registry("real").providers}
        self.assertEqual(names, set(usage.BUDGETS))
        for budget in usage.BUDGETS.values():
            self.assertGreater(budget, 0)


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

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
class UsageDbBase(ServerMixin):
    """Fresh pgserver database per class + the usage persistence
    glue installed + a configured (fake) email lane, like the
    observability suites."""

    ADMIN_EMAIL = "owner-usage@example.com"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-usage-pg-")
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
        os.environ["BREVO_API_KEY"] = "test-lane-key"
        os.environ["NOTIFY_FROM_EMAIL"] = "alerts@example.com"
        registry_mod.reset_registry()
        from db import migrate, pool
        from monitoring import notify

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        cls.transport = _FakeTransport()
        cls._saved_transport = notify.TRANSPORT
        notify.TRANSPORT = cls.transport
        from accounts import provider_usage

        provider_usage.install()
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
        from monitoring import notify

        notify.TRANSPORT = cls._saved_transport
        cls.stop_server()
        cls.pool.reset_probe_cache()
        cls._teardown_pg()

    def setUp(self):
        ratelimit.reset()
        usage.tracker.reset()
        self.transport.calls.clear()
        # The admin account is registered once per class (the
        # database is per-class; a second registration of the
        # same address would be a 409, not a fresh account).
        if getattr(type(self), "_admin", None) is None:
            type(self)._admin = self.register(self.ADMIN_EMAIL)
        self.admin_cookie, self.admin_id, self.admin_email = \
            type(self)._admin

    # ---------- helpers ----------

    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self, email=None):
        email = email or "s66-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD},
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

    def today(self):
        return datetime.now(timezone.utc).date()

    def seed_usage(self, provider, calls, successes, failures):
        self.db_exec(
            "INSERT INTO provider_usage_daily"
            " (provider, day, calls, successes, failures)"
            " VALUES (%s, %s, %s, %s, %s)",
            (provider, self.today(), calls, successes, failures))

    def seed_job(self, user_id, key, created_at):
        self.db_exec(
            "INSERT INTO scan_jobs (user_id, idempotency_key,"
            " status, created_at) VALUES (%s, %s, 'done', %s)",
            (user_id, key, created_at))


class TestUsageLedgerDb(UsageDbBase, unittest.TestCase):

    def test_rollup_increments_one_row_per_provider_day(self):
        tracker = usage.tracker
        saved_every = tracker.flush_every
        tracker.flush_every = 1
        try:
            usage.record_call("XposedOrNot", True)
            usage.record_call("XposedOrNot", True)
            usage.record_call("XposedOrNot", False)
        finally:
            tracker.flush_every = saved_every
        rows = self.db_all(
            "SELECT * FROM provider_usage_daily"
            " WHERE provider = 'XposedOrNot'")
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(
            (rows[0]["calls"], rows[0]["successes"],
             rows[0]["failures"]), (3, 2, 1))
        self.assertEqual(rows[0]["day"], self.today())

    def test_persistence_failure_never_breaks_a_provider_call(self):
        from db import pool
        from providers.base import HttpClient
        from providers.registry import HealthTracker

        tracker = usage.tracker
        saved_every = tracker.flush_every
        tracker.flush_every = 1  # force a flush attempt per call
        original = pool.connection

        def broken(dsn=None):
            raise RuntimeError("pool is down")

        pool.connection = broken
        try:
            client = HttpClient(
                "XposedOrNot", health=HealthTracker(),
                transport=lambda u, h, t: (200, '{"ok": true}'),
                sleep=lambda _s: None)
            result = client.get_json("https://x.invalid")
        finally:
            pool.connection = original
            tracker.flush_every = saved_every
        self.assertEqual(result.status, "ok")

    def test_exhausted_budget_degrades_scan_outcome(self):
        from providers.base import HttpClient
        from providers.registry import HealthTracker
        from providers.xposedornot import XposedOrNotProvider
        from scanning import orchestrator

        class _StubRegistry:
            def __init__(self, provider):
                self._provider = provider

            def get_providers(self, capability):
                return ([self._provider]
                        if capability == "email_breach" else [])

        client = HttpClient(
            "XposedOrNot", health=HealthTracker(),
            transport=lambda u, h, t: (200, '{"breaches": []}'),
            sleep=lambda _s: None)
        adapter = XposedOrNotProvider(health=None, client=client)
        registry_mod.reset_registry(_StubRegistry(adapter))
        self.addCleanup(registry_mod.reset_registry)
        record = {"id": "iid-budget-1", "kind": "email",
                  "masked": "t•••@example.com"}
        with BudgetGuard({"XposedOrNot": 2}):
            _findings, outcome, _a = orchestrator._scan_email(
                record, "test@example.com")
            self.assertEqual(outcome["outcome"], "scanned")
            _findings, outcome, _a = orchestrator._scan_email(
                record, "test@example.com")
            self.assertEqual(outcome["outcome"], "scanned")
            _findings, outcome, _a = orchestrator._scan_email(
                record, "test@example.com")
            self.assertEqual(outcome["outcome"], "provider_error")
            self.assertEqual(outcome["error_kind"],
                             "budget_exhausted")


class TestProviderMetricsDb(UsageDbBase, unittest.TestCase):

    def test_metrics_providers_and_today_volumes(self):
        budget = usage.BUDGETS["XposedOrNot"]
        self.seed_usage("XposedOrNot", budget, budget - 10, 10)
        self.seed_usage("DuckDuckGo Discovery", 250, 240, 10)
        self.seed_usage("Retired Fixture Provider", 7, 7, 0)
        now = datetime.now(timezone.utc)
        for i in range(3):
            self.seed_job(self.admin_id, "m-admin-%d" % i, now)
        _cookie2, user2_id, _e = self.register()
        self.seed_job(user2_id, "m-user2-0", now)
        self.seed_job(self.admin_id, "m-old",
                      now - timedelta(hours=25))

        status, _h, body = self.request_json(
            "GET", "/api/admin/metrics", cookie=self.admin_cookie)
        self.assertEqual(status, 200, body)
        providers = {p["provider"]: p for p in body["providers"]}
        xo = providers["XposedOrNot"]
        self.assertEqual(xo["calls"], budget)
        self.assertEqual(xo["successes"], budget - 10)
        self.assertEqual(xo["failures"], 10)
        self.assertEqual(xo["budget"], budget)
        self.assertEqual(xo["pct_used"], 100.0)
        self.assertTrue(xo["exhausted"])
        ddg = providers["DuckDuckGo Discovery"]
        self.assertEqual(ddg["pct_used"], 25.0)
        self.assertFalse(ddg["exhausted"])
        retired = providers["Retired Fixture Provider"]
        self.assertIsNone(retired["budget"])
        self.assertIsNone(retired["pct_used"])
        self.assertFalse(retired["exhausted"])
        # A budgeted provider with no usage today still appears.
        self.assertEqual(providers["Domain Intel"]["calls"], 0)

        today = body["scan_jobs"]["today"]
        self.assertEqual(today["jobs"], 4)
        self.assertEqual(today["distinct_users"], 2)
        self.assertEqual(today["max_jobs_per_user"], 3)

    def test_metrics_still_hidden_from_anonymous(self):
        status, _h, _b = self.request_json("GET", "/api/admin/metrics")
        self.assertEqual(status, 404)


class TestAlertProviderBudgetDb(UsageDbBase, unittest.TestCase):

    def test_fires_at_full_budget_names_provider_dedupes(self):
        from monitoring import alerts

        budget = usage.BUDGETS["XposedOrNot"]
        self.seed_usage("XposedOrNot", budget, budget, 0)
        fired = {hit["rule"]: hit for hit in alerts.evaluate()}
        self.assertIn("provider_budget", fired)
        hit = fired["provider_budget"]
        self.assertEqual(hit["observed"], 1)
        self.assertEqual(hit["metric"], "provider_daily_budget")

        rows = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'"
            " AND status <> 'suppressed'",
            (self.admin_id,))
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["payload"]["rule"],
                         "provider_budget")
        self.assertEqual(rows[0]["payload"]["provider"],
                         "XposedOrNot")
        self.assertEqual(len(self.transport.to(self.admin_email)), 1)
        audit_row = self.db_one(
            "SELECT * FROM audit_log"
            " WHERE action = 'engineering_alert'"
            " AND target_id = 'provider_budget'")
        self.assertIsNotNone(audit_row)
        self.assertEqual(audit_row["detail"]["provider"],
                         "XposedOrNot")
        self.assertEqual(audit_row["detail"]["exhausted_providers"],
                         "XposedOrNot")

        # Second pass the same day: fires, but does not email again.
        fired = {hit["rule"]: hit for hit in alerts.evaluate()}
        self.assertIn("provider_budget", fired)
        rows = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'"
            " AND status <> 'suppressed'",
            (self.admin_id,))
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(len(self.transport.to(self.admin_email)), 1)


class TestAlertProviderBudgetSilentDb(UsageDbBase,
                                       unittest.TestCase):

    def test_silent_at_99_percent(self):
        from monitoring import alerts

        budget = usage.BUDGETS["XposedOrNot"]
        self.seed_usage("XposedOrNot", int(budget * 0.99),
                        int(budget * 0.99), 0)
        fired = {hit["rule"]: hit for hit in alerts.evaluate()}
        self.assertNotIn("provider_budget", fired)
        rows = self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " AND kind = 'engineering_alert'",
            (self.admin_id,))
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
