"""Phases 111 + 162 — the fake broker environment and the workflow
regression harness that runs the REAL remediation lifecycle
against it.

Phase 111 ships tests/fake_broker.py: a stateful fake of a
people-search broker (listing present -> opt-out submitted ->
pending -> processed/removed; failure modes down / renamed /
persist / challenge). Phase 162 is this file's DB class: cases are
created through the real API, the REAL engine (AgentExecutor +
agent.probe_broker + agent.submit_form) runs against the fake at
the transport seam documented in fake_broker.py — nothing about
the workflow is re-implemented here — and verification uses the
real verify_case transition function.

The honesty pins, one per failure mode:

  * happy path, hand-mapped playbook (Spokeo): submitted, verify
    while the broker is still 'processing' says still_listed, and
    only after the listing is actually gone does the case reach
    verified_removed;
  * happy path, generic playbook (CheckPeople — no hand-mapped
    playbook exists for it, so agent.get_playbook derives one);
  * persist: the broker accepts and 'processes' the opt-out but
    keeps the listing — the case NEVER reaches verified_removed;
  * down: the attempt fails with the typed outcome (blocked /
    unreachable), probe trail attached;
  * renamed: the workflow reports form_not_fillable and the site
    records ZERO submissions — no fake success;
  * challenge: needs_human / captcha, the human step is never
    routed around;
  * and the harness itself never weakens SSRF: with the transport
    faked, a literal loopback URL is still refused by the
    production policy.

Fixture identity is the suites' obviously-fake person
('Zztest Personman'); the account password is the shared fixture
literal allowlisted in tests/test_secrets_hygiene.py.
"""

import ipaddress
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import pgserver as _pgserver
except ImportError:  # pragma: no cover
    _pgserver = None

import agent as agent_engine
import app
import fake_broker
from core import ssrf
from db import migrate, pool
from remediation import engine as engine_mod
from remediation import registry_seed
from remediation import service, verify as verify_mod, worker as worker_mod

PASSWORD = "test-password-123"
PERSON = "Zztest Personman"
_PUBLIC_IPS = [ipaddress.ip_address("93.184.216.34")]


class EnvGuard:
    def __init__(self, **values):
        self.values = values
        self.saved = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return False


class ServerMixin:
    def start_server(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}))

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()

    def request_json(self, method, path, payload=None, cookie=None):
        data = None
        headers = {"X-Requested-With": "fetch"}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=15) as resp:
                return resp.status, resp.headers, json.loads(
                    resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                return exc.code, exc.headers, json.loads(raw)
            except ValueError:
                return exc.code, exc.headers, {"raw": raw}


# ---------------------------------------------------------------------------
# Phase 111 — the fake environment itself (offline, no DB)
# ---------------------------------------------------------------------------

class TestFakeBrokerEnvironment(unittest.TestCase):
    def make_site(self, **kwargs):
        kwargs.setdefault("host", "www.spokeo.com")
        kwargs.setdefault("domain", "spokeo.com")
        kwargs.setdefault("name", "Spokeo")
        kwargs.setdefault("optout_path", "/optout")
        site = fake_broker.FakeBrokerSite(**kwargs)
        site.person_name = PERSON
        return site

    def test_listing_lifecycle_present_pending_removed(self):
        site = self.make_site()
        self.assertTrue(site.listing_present())
        status, _body = site.fetch(
            "POST", "https://www.spokeo.com/optout/submit",
            b"email=zztest%40example.com")
        self.assertEqual(status, 200)
        # Submitted is pending, and pending is still listed —
        # the fake must not let 'submitted' read as 'removed'.
        self.assertEqual(site.listing_state, "pending")
        self.assertTrue(site.listing_present())
        site.process_pending()
        self.assertEqual(site.listing_state, "removed")
        self.assertFalse(site.listing_present())

    def test_persist_mode_processes_but_listing_stays(self):
        site = self.make_site(mode="persist")
        site.fetch("POST", "https://www.spokeo.com/optout/submit",
                   b"email=zztest%40example.com")
        site.process_pending()
        self.assertEqual(site.listing_state, "present")
        self.assertTrue(site.listing_present())

    def test_down_mode_fails_at_transport(self):
        site = self.make_site(mode="down")
        with self.assertRaises(urllib.error.URLError):
            site.fetch("GET", "https://www.spokeo.com/optout")

    def test_optout_form_parses_with_real_formparser(self):
        # The fake's page must satisfy the REAL parsing/matching
        # code, in both hand-mapped and generic field shapes.
        for style, expected_keys in (
                ("spokeo", {"email"}),
                ("generic", {"name", "email", "city"})):
            site = self.make_site(form_style=style)
            _status, body = site.fetch(
                "GET", "https://www.spokeo.com/optout")
            parser = agent_engine.FormParser()
            parser.feed(body.decode())
            self.assertEqual(len(parser.forms), 1, style)
            payload, _unmapped = agent_engine.match_fields(
                parser.forms[0]["fields"],
                {"full_name": PERSON, "email": "zztest@example.com",
                 "city": "Pune", "phone": ""})
            self.assertTrue(
                expected_keys.issubset(set(payload)), (style, payload))
            self.assertFalse(parser.has_captcha, style)

    def test_renamed_form_maps_nothing(self):
        site = self.make_site(mode="renamed")
        _status, body = site.fetch(
            "GET", "https://www.spokeo.com/optout")
        parser = agent_engine.FormParser()
        parser.feed(body.decode())
        payload, _unmapped = agent_engine.match_fields(
            parser.forms[0]["fields"],
            {"full_name": PERSON, "email": "zztest@example.com",
             "city": "Pune", "phone": ""})
        self.assertEqual(payload, {})

    def test_challenge_page_flags_captcha_with_real_parser(self):
        site = self.make_site(mode="challenge", form_style="spokeo")
        _status, body = site.fetch(
            "GET", "https://www.spokeo.com/optout")
        parser = agent_engine.FormParser()
        parser.feed(body.decode())
        self.assertTrue(parser.has_captcha)

    def test_evidence_pages_track_the_same_state(self):
        site = self.make_site()
        self.assertIn(PERSON, site.search_page().decode())
        self.assertIn("spokeo.com",
                      site.ddg_results_page().decode())
        site.fetch("POST", "https://www.spokeo.com/optout/submit",
                   b"email=zztest%40example.com")
        site.process_pending()
        self.assertIn("no results found",
                      site.search_page().decode().lower())
        self.assertNotIn("Zztest-Personman",
                         site.ddg_results_page().decode())

    def test_transport_unknown_host_and_http_error(self):
        site = self.make_site()
        transport = fake_broker.FakeTransport([site])
        with self.assertRaises(urllib.error.URLError):
            transport("https://not-a-broker.example/optout")
        with transport("https://www.spokeo.com/optout") as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn(b"Remove your listing", resp.read())


# ---------------------------------------------------------------------------
# Phase 162 — the real lifecycle against the fake brokers
# ---------------------------------------------------------------------------

@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestFakeBrokerWorkflowDb(ServerMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uuid as _uuid
        # The pgdata directory outlives a run, so account emails
        # carry a per-run suffix — re-running the suite must not
        # collide with its own previous accounts.
        cls._run_tag = _uuid.uuid4().hex[:8]
        cls._pg = _pgserver.get_server("/tmp/leakguard-p2f-pgdata")
        cls._env = EnvGuard(
            DATABASE_URL=cls._pg.get_uri(),
            VAULT_MASTER_KEY="MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=",
            VAULT_LOOKUP_KEY="MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=")
        cls._env.__enter__()
        migrate.run_migrations()
        registry_seed.seed_brokers()

    @classmethod
    def tearDownClass(cls):
        cls._env.__exit__(None, None, None)

    def setUp(self):
        self.start_server()
        self._patches = []
        self.addCleanup(self.stop_server)
        self.addCleanup(self._stop_patches)

    def _stop_patches(self):
        for patcher in reversed(self._patches):
            patcher.stop()
        self._patches = []

    # -- harness -----------------------------------------------------
    def use_sites(self, sites):
        """Route the guarded fetch through the fake sites (the
        transport seam) and give the relay the same fake internet."""
        self._stop_patches()
        transport = fake_broker.FakeTransport(sites)
        for patcher in (
                mock.patch.object(ssrf, "resolve_host",
                                  lambda host: list(_PUBLIC_IPS)),
                mock.patch.object(ssrf, "pinned_urlopen", transport),
                mock.patch.object(agent_engine, "relay_probe",
                                  fake_broker.make_relay_probe(sites))):
            patcher.start()
            self._patches.append(patcher)
        self.executor = engine_mod.AgentExecutor(
            fetcher=fake_broker.make_verify_fetcher(sites))

    def spokeo_site(self, mode="normal"):
        site = fake_broker.FakeBrokerSite(
            host="www.spokeo.com", domain="spokeo.com", name="Spokeo",
            optout_path="/optout", form_style="spokeo", mode=mode)
        site.person_name = getattr(self, "person_name", PERSON)
        return site

    def checkpeople_site(self, mode="normal"):
        site = fake_broker.FakeBrokerSite(
            host="checkpeople.com", domain="checkpeople.com",
            name="CheckPeople", optout_path="/opt-out",
            form_style="generic", mode=mode)
        site.person_name = getattr(self, "person_name", PERSON)
        return site

    # -- account/case helpers -----------------------------------------
    def register_person(self, tag):
        email = "p2f-%s-%s@example.com" % (tag, self._run_tag)
        # Identifiers are globally unique by lookup hash (an
        # identifier owned by another account is a 409 by design),
        # so the fixture person is per-test AND per-run unique —
        # still the suites' obviously-fake Zztest Personman.
        self.person_name = "Zztest Personman %s %s" % (
            tag, self._run_tag[:4])
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            {"email": email, "password": PASSWORD})
        self.assertEqual(status, 201)
        cookie = headers.get("Set-Cookie").split(";")[0]
        user_id = body["user"]["id"]
        for kind, value in (
                ("name", self.person_name), ("email", email),
                ("address", "Pune, %s %s Example Street"
                 % (tag, self._run_tag[:4]))):
            status, _h, _b = self.request_json(
                "POST", "/api/identifiers",
                {"kind": kind, "value": value}, cookie=cookie)
            self.assertEqual(status, 201, (kind, status))
        status, _h, _b = self.request_json(
            "POST", "/api/consents",
            {"purpose": "automated_remediation", "granted": True},
            cookie=cookie)
        self.assertEqual(status, 200)
        return user_id, cookie, email

    def db(self, sql, params=()):
        with pool.connection() as conn:
            cur = conn.execute(sql, params)
            try:
                return [dict(row) for row in cur.fetchall()]
            except Exception:
                return []

    def run_and_case(self, user_id, slug):
        service.run_removal(user_id)
        rows = self.db(
            "SELECT id FROM remediation_cases"
            " WHERE user_id = %s AND broker_slug = %s",
            (user_id, slug))
        self.assertEqual(len(rows), 1)
        return str(rows[0]["id"])

    def case_row(self, case_id):
        return self.db(
            "SELECT status, reason FROM remediation_cases"
            " WHERE id = %s", (case_id,))[0]

    # -- the harness-level SSRF pin -----------------------------------
    def test_ssrf_policy_intact_under_the_harness(self):
        site = self.spokeo_site()
        self.use_sites([site])
        # The production guard still refuses literal private
        # targets outright — the fake transport changes WHERE
        # bytes come from, never WHAT is allowed.
        with self.assertRaises(ssrf.SsrfError):
            ssrf.assert_public_url("http://127.0.0.1:8080/admin")
        with self.assertRaises(ssrf.SsrfError):
            ssrf.assert_public_url("http://192.168.1.1/optout")
        # And the broker target passes the REAL validation logic
        # (resolver stubbed to a public address, per the guard's
        # documented test patch point) — it raises nothing.
        ssrf.assert_public_url("https://www.spokeo.com/optout")

    # -- happy paths ----------------------------------------------------
    def test_happy_path_hand_mapped_spokeo(self):
        user_id, _cookie, account_email = self.register_person("spokeo")
        site = self.spokeo_site()
        self.use_sites([site])
        case_id = self.run_and_case(user_id, "spokeo")
        engine_mod.process_case(case_id, self.executor)
        row = self.case_row(case_id)
        self.assertEqual(row["status"], "submitted")
        self.assertEqual(site.submissions,
                         [{"email": account_email}])
        # The broker has not processed yet: verification must keep
        # reporting the listing as present, not celebrate early.
        result = verify_mod.verify_case(user_id, case_id, self.executor)
        self.assertEqual(result["outcome"], "still_present")
        self.assertEqual(result["case"]["status"], "submitted")
        self.assertEqual(result["case"]["reason"], "still_listed")
        # The broker processes the queue; only NOW may verify pass.
        site.process_pending()
        result = verify_mod.verify_case(user_id, case_id, self.executor)
        self.assertEqual(result["outcome"], "gone")
        self.assertEqual(result["case"]["status"], "verified_removed")
        checks = self.db(
            "SELECT method, outcome FROM verification_checks"
            " WHERE case_id = %s ORDER BY checked_at, id", (case_id,))
        self.assertEqual(
            [(c["method"], c["outcome"]) for c in checks],
            [("search_index", "still_present"),
             ("search_index", "gone")])
        # Attempts exist and carry the current workflow version
        # (Phase 31, cross-checked at the DB level here).
        attempts = self.db(
            "SELECT action, result, workflow_version"
            " FROM remediation_attempts WHERE case_id = %s"
            " ORDER BY attempt_no", (case_id,))
        self.assertTrue(attempts)
        self.assertTrue(all(
            a["workflow_version"] == 1 for a in attempts), attempts)

    def test_happy_path_generic_playbook_checkpeople(self):
        # CheckPeople has NO hand-mapped playbook: agent.get_playbook
        # derives the generic http_form flow, and the case must run
        # it end-to-end exactly like a mapped broker.
        user_id, _cookie, account_email = self.register_person("generic")
        site = self.checkpeople_site()
        self.use_sites([site])
        case_id = self.run_and_case(user_id, "checkpeople")
        engine_mod.process_case(case_id, self.executor)
        self.assertEqual(self.case_row(case_id)["status"], "submitted")
        self.assertEqual(len(site.submissions), 1)
        self.assertEqual(site.submissions[0].get("name"), self.person_name)
        site.process_pending()
        result = verify_mod.verify_case(user_id, case_id, self.executor)
        self.assertEqual(result["case"]["status"], "verified_removed")

    def test_worker_claim_path_with_real_executor(self):
        # The full stack: a queued case claimed by the real worker,
        # processed by the real executor against the fake broker.
        user_id, _cookie, account_email = self.register_person("worker")
        site = self.spokeo_site()
        self.use_sites([site])
        # Test-state hygiene: the shared class DB still holds the
        # unprocessed cases of earlier tests' removal runs; park
        # them so the worker's single claim below is this test's.
        self.db("UPDATE remediation_cases SET status = 'blocked'"
                " WHERE status = 'queued'")
        self.db(
            "INSERT INTO remediation_cases (user_id, broker_slug,"
            " status) VALUES (%s, 'spokeo', 'queued')", (user_id,))
        case_id = self.db(
            "SELECT id FROM remediation_cases"
            " WHERE user_id = %s AND broker_slug = 'spokeo'",
            (user_id,))[0]["id"]
        self.assertTrue(worker_mod.run_once(self.executor))
        self.assertEqual(self.case_row(str(case_id))["status"],
                         "submitted")

    # -- honest negatives -------------------------------------------------
    def test_listing_persists_never_verified_removed(self):
        user_id, _cookie, account_email = self.register_person("persist")
        site = self.spokeo_site(mode="persist")
        self.use_sites([site])
        case_id = self.run_and_case(user_id, "spokeo")
        engine_mod.process_case(case_id, self.executor)
        self.assertEqual(self.case_row(case_id)["status"], "submitted")
        site.process_pending()  # 'processed' — and the listing stays
        result = verify_mod.verify_case(user_id, case_id, self.executor)
        self.assertEqual(result["case"]["status"], "submitted")
        self.assertEqual(result["case"]["reason"], "still_listed")
        self.assertNotEqual(self.case_row(case_id)["status"],
                            "verified_removed")

    def test_broker_down_is_a_typed_failure(self):
        user_id, _cookie, account_email = self.register_person("down")
        site = self.spokeo_site(mode="down")
        self.use_sites([site])
        case_id = self.run_and_case(user_id, "spokeo")
        engine_mod.process_case(case_id, self.executor)
        row = self.case_row(case_id)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["reason"], "unreachable")
        attempts = self.db(
            "SELECT detail FROM remediation_attempts"
            " WHERE case_id = %s AND action = 'probe'", (case_id,))
        self.assertEqual(len(attempts), 1)
        trail = attempts[0]["detail"].get("trail") or []
        # Both fetch stages honestly failed: the direct probe and
        # the relay escalation (the fake relay shares the outage);
        # the browser step is recorded as skipped — it never runs
        # on the server (Phase 137).
        self.assertEqual([t["step"] for t in trail],
                         ["http", "relay", "browser"])
        self.assertEqual(trail[-1].get("skipped"), "on_server")

    def test_renamed_form_reports_real_failure_no_submission(self):
        user_id, _cookie, account_email = self.register_person("renamed")
        site = self.spokeo_site(mode="renamed")
        self.use_sites([site])
        case_id = self.run_and_case(user_id, "spokeo")
        engine_mod.process_case(case_id, self.executor)
        row = self.case_row(case_id)
        self.assertEqual(row["status"], "blocked")
        self.assertEqual(row["reason"], "form_not_fillable")
        # No fake success: the broker never received anything.
        self.assertEqual(site.submissions, [])

    def test_challenge_page_needs_a_human(self):
        user_id, _cookie, account_email = self.register_person("challenge")
        site = self.spokeo_site(mode="challenge")
        self.use_sites([site])
        case_id = self.run_and_case(user_id, "spokeo")
        engine_mod.process_case(case_id, self.executor)
        row = self.case_row(case_id)
        self.assertEqual(row["status"], "needs_human")
        self.assertEqual(row["reason"], "captcha")
        self.assertEqual(site.submissions, [])


if __name__ == "__main__":
    unittest.main()
