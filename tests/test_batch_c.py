"""Final-spec Batch C tests — false-positive feedback (Phase 156),
dispute guidance (Phase 157), broker source change detection
(Phases 32/125-lite), the admin security-events view (Phase 62),
and the retention-tick wiring of the daily source sweep.

Layers:

* TestDisputes / TestSourceChecksUnit — offline: guidance per
  source class, the no-fabricated-links rule (every URL in
  scanning/disputes.py must appear somewhere else in the repo),
  and the registry derivation the sweep checks.
* TestFeedbackNoDb — no database: the feedback route answers the
  same clean 503 as every other account route.
* TestBatchCDb — the full behaviours against a local PostgreSQL
  (pgserver; skips honestly when unavailable): feedback persists /
  is owner-scoped / clears; a 'not_me' finding stays silent in the
  scan-completion diff and out of the Action Center count, and
  clearing restores both; the source sweep's ok/changed/
  unreachable states, 24h gate and retained hash; the admin
  overview's source_health + security_events; the retention hook.

Run:  python3 -m unittest discover -s tests
"""

import base64
import hashlib
import json
import os
import re
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
from scanning import disputes  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
ROOT = Path(__file__).resolve().parent.parent


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
# Dispute guidance (pure)
# ---------------------------------------------------------------------------

class TestDisputes(unittest.TestCase):
    def test_breach_database_guidance_is_honest(self):
        g = disputes.guidance_for({
            "provider": "XposedOrNot", "source_name": "AcmeCorp",
            "source_url": None, "remediation_eligible": False})
        self.assertEqual(g["class"], "breach_database")
        text = " ".join(g["steps"])
        self.assertIn("AcmeCorp", text)
        # The aggregator honesty line: the index did not hold the
        # data and cannot delete the original.
        self.assertIn("did not hold your data", text)
        self.assertIn("privacy team or Data Protection Officer", text)
        self.assertIsNone(g["url"])

    def test_broker_listing_points_at_the_removal_flow(self):
        g = disputes.guidance_for({
            "provider": "Username Platforms", "source_name": "SomeBroker",
            "source_url": None, "remediation_eligible": True})
        self.assertEqual(g["class"], "broker_listing")
        self.assertIn("Remove all", " ".join(g["steps"]))
        self.assertIsNone(g["url"])

    def test_broker_listing_by_registry_host(self):
        # A discovery finding served from a broker's own host is a
        # broker listing whatever provider surfaced it.
        g = disputes.guidance_for({
            "provider": "DuckDuckGo DiscoveryX", "source_name": "Spokeo",
            "source_url": "https://www.spokeo.com/someone",
            "remediation_eligible": False})
        self.assertEqual(g["class"], "broker_listing")

    def test_search_result_uses_the_existing_google_tool(self):
        g = disputes.guidance_for({
            "provider": "DuckDuckGo Discovery", "source_name": "A page",
            "source_url": "https://example.org/x",
            "remediation_eligible": False})
        self.assertEqual(g["class"], "search_result")
        self.assertEqual(
            g["url"], "https://myactivity.google.com/results-about-you")
        self.assertIn("does not delete the page", " ".join(g["steps"]))

    def test_unknown_source_gets_generic_honest_steps(self):
        g = disputes.guidance_for({
            "provider": "Something New", "source_name": "Mystery",
            "source_url": None, "remediation_eligible": False})
        self.assertEqual(g["class"], "generic")
        self.assertIn("do not have a specific dispute route",
                      " ".join(g["steps"]))
        self.assertIsNone(g["url"])

    def test_no_fabricated_links(self):
        # Every URL in scanning/disputes.py must also appear in at
        # least one OTHER repository file (the module may only reuse
        # links the product already carries).
        module_text = (ROOT / "scanning" / "disputes.py").read_text(
            encoding="utf-8")
        urls = set(re.findall(r"https?://[^\s\"'\)]+", module_text))
        self.assertTrue(urls, "expected the Google tool URL at least")
        corpus = []
        for path in ROOT.rglob("*"):
            if path.is_dir() or path.suffix not in (
                    ".py", ".json", ".html", ".js", ".md"):
                continue
            if "tests" in path.parts or "__pycache__" in path.parts \
                    or ".git" in path.parts:
                continue
            if path == ROOT / "scanning" / "disputes.py":
                continue
            try:
                corpus.append(path.read_text(
                    encoding="utf-8", errors="replace"))
            except Exception:
                pass
        joined = "\n".join(corpus)
        for url in urls:
            self.assertIn(url, joined,
                          "URL in disputes.py appears nowhere else: "
                          + url)


class TestSourceChecksUnit(unittest.TestCase):
    def test_registry_derivation_matches_brokers_json(self):
        from remediation import source_checks

        raw = json.loads((ROOT / "brokers.json").read_text(
            encoding="utf-8"))
        expected = [b for b in raw if (b.get("optout_url") or "").strip()]
        checks = source_checks.brokers_to_check()
        self.assertEqual(len(checks), len(expected))
        slugs = [c["slug"] for c in checks]
        self.assertEqual(len(slugs), len(set(slugs)))
        self.assertIn("spokeo", slugs)

    def test_maybe_run_is_inert_until_armed(self):
        from remediation import source_checks

        saved = source_checks._armed
        try:
            source_checks._armed = False
            self.assertEqual(source_checks.maybe_run(),
                             {"skipped": True, "reason": "not_armed"})
        finally:
            source_checks._armed = saved


class TestFeedbackNoDb(ServerMixin, unittest.TestCase):
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

    def test_feedback_route_is_a_clean_503_without_a_database(self):
        status, _h, body = self.request_json(
            "POST", "/api/findings/feedback",
            body={"finding_id": str(uuid.uuid4()),
                  "verdict": "not_me"},
            headers=CSRF)
        self.assertEqual(status, 503, body)
        self.assertEqual(body["error"]["code"], "db_unavailable")


# ---------------------------------------------------------------------------
# Database-backed behaviours
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestBatchCDb(ServerMixin, unittest.TestCase):
    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS + ("ADMIN_EMAILS",)).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-batch-c-pg-")
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
        email = "bc-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers", body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def db_row(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def db_all(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchall()

    def db_exec(self, sql, params=()):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).rowcount

    def insert_job(self, user_id, finished_at):
        row = self.db_row(
            "INSERT INTO scan_jobs (user_id, idempotency_key, status,"
            " score, finished_at) VALUES (%s, %s, 'done', 10, %s)"
            " RETURNING id",
            (user_id, uuid.uuid4().hex, finished_at))
        return str(row["id"])

    def insert_finding(self, job_id, user_id, identifier_id,
                       source_name="FixtureBreach",
                       provider="XposedOrNot"):
        row = self.db_row(
            "INSERT INTO findings (job_id, user_id, identifier_id,"
            " identifier_kind, provider, source_name, exposed_fields,"
            " confidence, reliability, evidence_ref)"
            " VALUES (%s, %s, %s, 'email', %s, %s, '{}', 'exact',"
            " 'high', %s) RETURNING id",
            (job_id, user_id, identifier_id, provider, source_name,
             "e" * 64))
        return str(row["id"])

    def feedback(self, cookie, finding_id, verdict):
        return self.request_json(
            "POST", "/api/findings/feedback",
            body={"finding_id": finding_id, "verdict": verdict},
            headers=CSRF, cookie=cookie)

    def get_job(self, cookie, job_id):
        status, _h, body = self.request_json(
            "GET", "/api/scans/" + job_id, cookie=cookie)
        self.assertEqual(status, 200, body)
        return body

    def notifications_for(self, user_id, kind=None):
        if kind:
            return self.db_all(
                "SELECT * FROM notifications WHERE user_id = %s"
                " AND kind = %s ORDER BY created_at, id",
                (user_id, kind))
        return self.db_all(
            "SELECT * FROM notifications WHERE user_id = %s"
            " ORDER BY created_at, id", (user_id,))

    # ---------- feedback: persistence / scoping / clearing ----------
    def test_feedback_persists_scopes_and_clears(self):
        cookie, uid, _email = self.register()
        ident = self.add_identifier(
            cookie, "email", "fb-%s@example.com" % self.uniq())
        job = self.insert_job(uid, datetime.now(timezone.utc))
        finding = self.insert_finding(job, uid, ident["id"])

        # Session + CSRF are both required: no CSRF header -> 403,
        # no session -> 401.
        status, _h, _b = self.request_json(
            "POST", "/api/findings/feedback",
            body={"finding_id": finding, "verdict": "not_me"},
            cookie=cookie)
        self.assertEqual(status, 403)
        status, _h, _b = self.feedback(None, finding, "not_me")
        self.assertEqual(status, 401)

        # Unknown verdicts are a client error, not a stored row.
        status, _h, body = self.feedback(cookie, finding, "whatever")
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"]["code"], "invalid_verdict")

        # Set + read back through the job view (with dispute data).
        status, _h, body = self.feedback(cookie, finding, "not_me")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"feedback": "not_me"})
        view = self.get_job(cookie, job)
        self.assertEqual(len(view["findings"]), 1)
        self.assertEqual(view["findings"][0]["feedback"], "not_me")
        self.assertEqual(view["findings"][0]["dispute"]["class"],
                         "breach_database")
        rows = self.db_all(
            "SELECT verdict FROM finding_feedback WHERE user_id = %s",
            (uid,))
        self.assertEqual([r["verdict"] for r in rows], ["not_me"])

        # Changing the verdict updates the same row.
        status, _h, body = self.feedback(cookie, finding, "confirmed")
        self.assertEqual(body, {"feedback": "confirmed"})
        rows = self.db_all(
            "SELECT verdict FROM finding_feedback WHERE user_id = %s",
            (uid,))
        self.assertEqual([r["verdict"] for r in rows], ["confirmed"])

        # Another user's finding answers 404 — existence is not leaked.
        cookie2, _uid2, _e2 = self.register()
        status, _h, _b = self.feedback(cookie2, finding, "not_me")
        self.assertEqual(status, 404)
        status, _h, _b = self.feedback(
            cookie, str(uuid.uuid4()), "not_me")
        self.assertEqual(status, 404)
        status, _h, _b = self.feedback(cookie, "not-a-uuid", "not_me")
        self.assertEqual(status, 404)

        # Clearing removes the verdict everywhere.
        status, _h, body = self.feedback(cookie, finding, "none")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {"feedback": None})
        view = self.get_job(cookie, job)
        self.assertIsNone(view["findings"][0]["feedback"])
        self.assertEqual(self.db_all(
            "SELECT * FROM finding_feedback WHERE user_id = %s",
            (uid,)), [])

    # ---------- feedback: diff silence + Action Center ----------
    def test_not_me_silences_diff_and_counts_until_cleared(self):
        from monitoring import events

        cookie, uid, _email = self.register()
        ident = self.add_identifier(
            cookie, "email", "diff-%s@example.com" % self.uniq())
        now = datetime.now(timezone.utc)

        # Baseline job WITH the finding; marking it 'not_me' is the
        # user disowning the exposure itself.
        job1 = self.insert_job(uid, now - timedelta(days=3))
        finding1 = self.insert_finding(job1, uid, ident["id"])
        events.handle_scan_completed(job1)  # baseline: summary only
        status, _h, body = self.feedback(cookie, finding1, "not_me")
        self.assertEqual(status, 200, body)

        # Job 2 without it: the 'resolved' side is untouched by the
        # verdict (it fires exactly as before).
        job2 = self.insert_job(uid, now - timedelta(days=2))
        events.handle_scan_completed(job2)
        self.assertEqual(
            len(self.notifications_for(uid, "finding_resolved")), 1)

        # Job 3 re-finds the same identity. Without the verdict this
        # would notify as new; with it, silence — no new_finding row
        # and a summary that counts zero new.
        job3 = self.insert_job(uid, now - timedelta(days=1))
        self.insert_finding(job3, uid, ident["id"])
        events.handle_scan_completed(job3)
        self.assertEqual(self.notifications_for(uid, "new_finding"), [])
        summaries = [n for n in self.notifications_for(uid, "scan_summary")
                     if n["payload"]["job_id"] == job3]
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["payload"]["new_count"], 0)

        # The Action Center agrees: the latest job has one finding
        # row, but the disowned one does not count.
        status, _h, ac = self.request_json(
            "GET", "/api/action-center", cookie=cookie)
        self.assertEqual(status, 200, ac)
        self.assertEqual(ac["exposure"]["findings_total"], 0)

        # Clearing restores both surfaces: the count returns, and a
        # later reappearance of the identity notifies again.
        status, _h, body = self.feedback(cookie, finding1, "none")
        self.assertEqual(body, {"feedback": None})
        status, _h, ac = self.request_json(
            "GET", "/api/action-center", cookie=cookie)
        self.assertEqual(ac["exposure"]["findings_total"], 1)

        job4 = self.insert_job(uid, now)
        job5 = self.insert_job(uid, now + timedelta(hours=1))
        self.insert_finding(job5, uid, ident["id"])
        events.handle_scan_completed(job4)  # resolves again
        events.handle_scan_completed(job5)  # ...and reappears, owned
        news = self.notifications_for(uid, "new_finding")
        self.assertEqual(len(news), 1)

    # ---------- source sweep: states, gate, retained hash ----------
    def test_source_sweep_states_gate_and_hash_retention(self):
        from remediation import source_checks

        # Order-independence: this class shares one database, and
        # another test's sweep must not pre-seed hashes.
        self.db_exec("DELETE FROM broker_source_checks")
        bodies = {}

        def stub(url):
            return 200, bodies.get(url, b"page-v1")

        total = len(source_checks.brokers_to_check())
        summary = source_checks.check_broker_sources(
            fetcher=stub, force=True)
        self.assertFalse(summary["skipped"])
        self.assertEqual(summary["checked"], total)
        self.assertEqual(summary["ok"], total)
        self.assertEqual(summary["changed"], 0)
        rows = self.db_all("SELECT * FROM broker_source_checks")
        self.assertEqual(len(rows), total)
        self.assertTrue(all(r["state"] == "ok" for r in rows))
        self.assertTrue(all(r["status"] == 200 for r in rows))

        # The 24h gate holds a second sweep back.
        gated = source_checks.check_broker_sources(fetcher=stub)
        self.assertTrue(gated["skipped"])
        self.assertEqual(gated["reason"], "recent")

        # One broker's page changes -> exactly that slug flags.
        spokeo = next(c for c in source_checks.brokers_to_check()
                      if c["slug"] == "spokeo")
        bodies[spokeo["url"]] = b"page-v2-Changed"
        summary = source_checks.check_broker_sources(
            fetcher=stub, force=True)
        self.assertEqual(summary["changed"], 1)
        self.assertEqual(summary["changed_slugs"], ["spokeo"])
        self.assertEqual(summary["ok"], total - 1)
        v2_hash = hashlib.sha256(b"page-v2-Changed").hexdigest()

        # The same broker goes unreachable: state flips, status
        # clears, but the last-seen hash is RETAINED for recovery.
        def flaky(url):
            if url == spokeo["url"]:
                raise RuntimeError("connection refused")
            return 200, bodies.get(url, b"page-v1")

        summary = source_checks.check_broker_sources(
            fetcher=flaky, force=True)
        self.assertEqual(summary["unreachable"], 1)
        self.assertEqual(summary["unreachable_slugs"], ["spokeo"])
        row = self.db_row(
            "SELECT * FROM broker_source_checks WHERE slug = 'spokeo'")
        self.assertEqual(row["state"], "unreachable")
        self.assertIsNone(row["status"])
        self.assertEqual(row["content_hash"], v2_hash)

        # Admin-facing aggregate mirrors the table.
        health = source_checks.source_health()
        self.assertEqual(health["unreachable"], 1)
        self.assertEqual(health["unreachable_slugs"], ["spokeo"])
        self.assertEqual(health["ok"], total - 1)
        self.assertIsNotNone(health["last_checked_at"])

    # ---------- admin overview: source health + security events --
    def test_admin_overview_source_health_and_security_events(self):
        from accounts import audit
        from remediation import source_checks

        cookie, uid, email = self.register()
        os.environ["ADMIN_EMAILS"] = email

        def stub(url):
            return 200, b"page"

        self.db_exec("DELETE FROM broker_source_checks")
        source_checks.check_broker_sources(fetcher=stub, force=True)
        audit.record(uid, "user", "auth.login_failed", "user", uid,
                     {"reason": "bad_password"})
        audit.record(uid, "user", "api_token.created", "api_token",
                     None, {})
        audit.record(uid, "user", "consent.changed", "consent", None,
                     {"purpose": "scanning"})

        status, _h, body = self.request_json(
            "GET", "/api/admin/overview", cookie=cookie)
        self.assertEqual(status, 200, body)
        health = body["source_health"]
        total = len(source_checks.brokers_to_check())
        self.assertEqual(health["ok"], total)
        self.assertEqual(health["changed"], 0)
        self.assertIsNotNone(health["last_checked_at"])
        actions = [e["action"] for e in body["security_events"]]
        self.assertIn("auth.login_failed", actions)
        self.assertIn("api_token.created", actions)
        self.assertNotIn("consent.changed", actions)
        for event in body["security_events"]:
            # Meta only: no detail, no actor id, nothing else.
            self.assertEqual(set(event.keys()),
                             {"action", "actor_kind", "created_at"})

        # A non-admin gets the usual invisibility: 404.
        cookie2, _uid2, _e2 = self.register()
        status, _h, _b = self.request_json(
            "GET", "/api/admin/overview", cookie=cookie2)
        self.assertEqual(status, 404)

    # ---------- retention tick hosts the sweep (armed + gated) ----
    def test_retention_loop_step_runs_the_armed_sweep(self):
        from core import retention
        from remediation import source_checks

        # The purge itself never sweeps: run_once stays network-free
        # even on a database where a sweep is due.
        self.db_exec("DELETE FROM broker_source_checks")
        counts = retention.run_once()
        self.assertNotIn("source_checks", counts)
        self.assertEqual(
            self.db_all("SELECT * FROM broker_source_checks"), [])

        # The loop's sweep step, armed and with the fetcher stubbed
        # (the module resolves its default fetcher at call time),
        # checks the whole registry exactly once...
        saved_fetcher = source_checks._default_fetcher
        source_checks._default_fetcher = lambda url: (200, b"tick")
        try:
            source_checks.arm()
            out = retention._run_source_sweep()
            total = len(source_checks.brokers_to_check())
            self.assertEqual(out, {"source_checks": total})
            # ...and the 24h gate (the table is its own stamp) holds
            # the very next tick-step back.
            out = retention._run_source_sweep()
            self.assertEqual(out, {"source_checks": 0})
            self.assertFalse(source_checks.sweep_due())
        finally:
            source_checks._default_fetcher = saved_fetcher
