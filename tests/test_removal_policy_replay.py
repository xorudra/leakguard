"""Phases 153 + 141 + 119 — the removal policy engine, the state
mapping, and dead-letter replay.

Layers:

* TestPolicyDecisions — offline, pure: the whole decision table
  of remediation/policy.py exercised as data in / data out (no
  database, no executor), including the consent-revoked branch,
  captcha -> needs_human, unreachable -> blocked, and the
  ambiguities the extraction deliberately preserved (an `ok`
  submit beats an HTTP 403; a host-guard refusal fails the case).
* TestStateMapping — offline: the Phase 141 mapping is total over
  the stored vocabulary (migration 0005's CHECK), the two
  renamed states map as the audit names them, and the two spec
  names with no internal state are declared, not invented.
* TestPolicyDb — pgserver: case payloads carry BOTH the internal
  status and its spec-facing name (list + detail, additive only),
  and a dead case / dead scan job replayed by an admin through
  POST /api/admin/replay drains through the real workers — with
  the consent safeguard, the typed refusals, the audit rows and
  the preserved attempt history asserted.

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
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent as agent_engine  # noqa: E402
import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from remediation import policy  # noqa: E402
from remediation import registry_seed  # noqa: E402
from remediation import worker as remediation_worker  # noqa: E402
from scanning import worker as scan_worker  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY",
            "LEAKGUARD_PROVIDERS", "ADMIN_EMAILS")
PASSWORD = "test-password-123"  # shared fixture, allowlisted in
# tests/test_secrets_hygiene.py


class EnvGuard:
    def __init__(self, keys):
        self.keys = keys

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in self.keys}
        for k in self.keys:
            os.environ.pop(k, None)
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
# Phase 153 — the policy decision table, as pure functions
# ---------------------------------------------------------------------------

PROFILE = {"full_name": "A B", "email": "a@b.co", "phone": "",
           "city": "Pune"}
FIELDS = agent_engine.PROFILE_FIELDS


def _probe(**kw):
    base = {"reachable": True, "status": 200, "fillable": False,
            "forms": [], "blockers": [], "payload_preview": {}}
    base.update(kw)
    return base


class TestPolicyDecisions(unittest.TestCase):

    def test_policy_version_is_declared(self):
        self.assertIsInstance(policy.POLICY_VERSION, int)
        self.assertGreaterEqual(policy.POLICY_VERSION, 1)

    def test_decision_shape(self):
        decisions = [
            policy.decide_unknown_broker(),
            policy.decide_consent(False),
            policy.decide_email(False), policy.decide_email(True),
            policy.decide_manual("browser_required"),
            policy.decide_manual(None),
            policy.decide_probe_transition("blocked", "http_403"),
            policy.decide_submit({"ok": True, "status": 200}),
            policy.decide_submit({"ok": False, "status": 403}),
            policy.decide_submit({"ok": False, "status": 500}),
        ]
        for decision in decisions:
            self.assertEqual(
                set(decision),
                {"status", "reason", "attempt", "mark_submitted"},
                decision)
            self.assertIn(decision["status"], policy.CASE_STATES)
            if decision["attempt"] is not None:
                action, result = decision["attempt"]
                self.assertIsInstance(action, str)
                self.assertIsInstance(result, str)

    def test_channel_rule(self):
        # Same table the registry seed has always applied.
        self.assertEqual(
            policy.derive_channel({"contact_email": "o@example.com"},
                                  {"automation": "http_form"}), "email")
        self.assertEqual(
            policy.derive_channel({}, {"automation": "http_form"}),
            "form")
        self.assertEqual(
            policy.derive_channel({}, {"automation": "browser_required"}),
            "manual")
        self.assertEqual(policy.derive_channel({}, None), "manual")
        # The seed's public entry point delegates to the policy.
        self.assertEqual(
            registry_seed.derive_channel({}, {"automation": "http_form"}),
            policy.derive_channel({}, {"automation": "http_form"}))

    def test_unknown_broker_fails_closed(self):
        self.assertEqual(
            policy.decide_unknown_broker(),
            {"status": "failed", "reason": "unknown_broker",
             "attempt": ("route", "failed"), "mark_submitted": False})

    def test_consent_gate(self):
        # Consent standing: no decision — the case proceeds.
        self.assertIsNone(policy.decide_consent(True))
        # Consent revoked (including mid-flight): park for the
        # human, never drop, and the withdrawal is the attempt.
        self.assertEqual(
            policy.decide_consent(False),
            {"status": "needs_human", "reason": "consent_withdrawn",
             "attempt": ("consent_check", "withdrawn"),
             "mark_submitted": False})

    def test_email_channel(self):
        self.assertEqual(
            policy.decide_email(False),
            {"status": "needs_human", "reason": "email_send_required",
             "attempt": ("letter", "generated"),
             "mark_submitted": False})
        self.assertEqual(
            policy.decide_email(True),
            {"status": "submitted", "reason": "letter_sent_by_user",
             "attempt": ("letter_confirmed", "submitted"),
             "mark_submitted": True})

    def test_manual_channel(self):
        decision = policy.decide_manual("browser_required")
        self.assertEqual(decision["status"], "needs_human")
        self.assertEqual(decision["reason"], "browser_required")
        self.assertEqual(decision["attempt"], ("route", "manual"))
        for other in ("http_form", "email_request", "", None):
            decision = policy.decide_manual(other)
            self.assertEqual(decision["reason"], "manual_only", other)

    def test_probe_decision_table(self):
        cases = [
            # A probe-level error beats every page signal.
            (_probe(error="boom"), ("blocked", "probe_error")),
            ({"error": "Unknown broker"}, ("blocked", "probe_error")),
            (None, ("blocked", "probe_error")),
            ("not-a-probe", ("blocked", "probe_error")),
            # CAPTCHA / login walls beat fillability: human steps.
            (_probe(fillable=True, blockers=[
                "CAPTCHA on the page — a human must solve this step"]),
             ("needs_human", "captcha")),
            (_probe(fillable=True, blockers=[
                "Asks for account login — removal must be done "
                "signed in"]), ("needs_human", "login_required")),
            # Unreachable: blocked, naming the HTTP status when the
            # probe has one.
            (_probe(reachable=False, status=403),
             ("blocked", "http_403")),
            (_probe(reachable=False, status=None),
             ("blocked", "unreachable")),
            # A fillable form is the one submit path.
            (_probe(fillable=True, forms=[{"fields": []}]),
             ("submit", None)),
            # Reachable but no forms at all: a browser step.
            (_probe(), ("needs_human", "browser_required")),
            # A form the profile cannot fill: the missing field is
            # named (PROFILE has no phone).
            (_probe(forms=[{"action": "https://x.example/f",
                            "fields": [{"name": "phone", "id": "",
                                        "placeholder": "",
                                        "type": "tel"}],
                            "unmapped_fields": ["phone"]}]),
             ("needs_human", "missing_field:phone")),
            # Preserved quirk: unmapped_fields play no part in
            # the missing-field scan — a form whose only signal
            # is an unmapped name blocks instead of naming it.
            (_probe(forms=[{"action": "https://x.example/f",
                            "fields": [{"name": "xyz", "id": "",
                                        "placeholder": "",
                                        "type": "text"}],
                            "unmapped_fields": ["phone"]}]),
             ("blocked", "form_not_fillable")),
            # A form the profile CAN fill but the probe could not
            # map: blocked, never a guessed submission.
            (_probe(forms=[{"action": "https://x.example/f",
                            "fields": [{"name": "email", "id": "",
                                        "placeholder": "",
                                        "type": "email"}],
                            "unmapped_fields": []}]),
             ("blocked", "form_not_fillable")),
        ]
        for probe, expected in cases:
            self.assertEqual(
                policy.decide_probe(probe, PROFILE, FIELDS),
                expected, probe)

    def test_probe_error_beats_captcha(self):
        probe = _probe(error="boom", blockers=["CAPTCHA on the page"])
        self.assertEqual(policy.decide_probe(probe, PROFILE, FIELDS),
                         ("blocked", "probe_error"))

    def test_probe_attempt_word(self):
        self.assertEqual(policy.probe_attempt_word("submit", None),
                         "fillable")
        self.assertEqual(
            policy.probe_attempt_word("needs_human", "missing_field:phone"),
            "missing_field")
        self.assertEqual(
            policy.probe_attempt_word("needs_human", "captcha"),
            "captcha")
        self.assertEqual(
            policy.probe_attempt_word("blocked", "http_403"), "blocked")

    def test_probe_transition_carries_no_attempt(self):
        for action in ("needs_human", "blocked"):
            decision = policy.decide_probe_transition(action, "some_reason")
            self.assertEqual(decision["status"], action)
            self.assertEqual(decision["reason"], "some_reason")
            self.assertIsNone(decision["attempt"])
            self.assertFalse(decision["mark_submitted"])

    def test_submit_decisions(self):
        self.assertEqual(
            policy.decide_submit({"ok": True, "status": 200}),
            {"status": "submitted", "reason": None,
             "attempt": ("submit", "submitted"), "mark_submitted": True})
        self.assertEqual(
            policy.decide_submit({"ok": False, "status": 403}),
            {"status": "blocked", "reason": "submit_http_403",
             "attempt": ("submit", "blocked"), "mark_submitted": False})
        self.assertEqual(
            policy.decide_submit({"ok": False, "status": 500}),
            {"status": "failed", "reason": "submit_failed",
             "attempt": ("submit", "failed"), "mark_submitted": False})

    def test_submit_ok_beats_403(self):
        # Preserved ambiguity: `ok` is judged before the HTTP
        # status, exactly as the engine's original branch order
        # had it — an ok 403 counts as submitted.
        decision = policy.decide_submit({"ok": True, "status": 403})
        self.assertEqual(decision["status"], "submitted")

    def test_submit_guard_refusal_fails_the_case(self):
        # The executor's host-guard refusal carries ok=False and
        # no HTTP status; preserved as submit_failed, not a block.
        decision = policy.decide_submit(
            {"ok": False, "status": None, "error": "host_guard"})
        self.assertEqual(decision["status"], "failed")
        self.assertEqual(decision["reason"], "submit_failed")


# ---------------------------------------------------------------------------
# Phase 141 — the formal state mapping
# ---------------------------------------------------------------------------

class TestStateMapping(unittest.TestCase):

    # The stored vocabulary, copied from migration
    # 0005_remediation.sql's CHECK so a drift between the code
    # mapping and the schema fails here.
    STORED = ("queued", "running", "submitted", "needs_human",
              "verified_removed", "reappeared", "failed", "blocked")

    def test_mapping_is_total_over_the_stored_vocabulary(self):
        self.assertEqual(policy.CASE_STATES, self.STORED)
        self.assertEqual(set(policy.SPEC_STATE_NAMES), set(self.STORED))
        for name in policy.SPEC_STATE_NAMES.values():
            self.assertRegex(name, r"^[A-Z][A-Z_]*$")

    def test_the_two_renamed_states(self):
        self.assertEqual(policy.spec_state_name("needs_human"),
                         "AWAITING_USER")
        self.assertEqual(policy.spec_state_name("blocked"), "REJECTED")

    def test_unrenamed_states_keep_their_word(self):
        for internal, spec in policy.SPEC_STATE_NAMES.items():
            if internal in ("needs_human", "blocked", "running"):
                continue
            self.assertEqual(spec, internal.upper(), internal)
        self.assertEqual(policy.spec_state_name("running"),
                         "IN_PROGRESS")

    def test_spec_names_without_internal_state_are_declared(self):
        self.assertEqual(
            set(policy.SPEC_STATES_WITHOUT_INTERNAL_STATE),
            {"AUTHORIZED", "NOT_STARTED"})
        # Declared, not invented: neither appears as a mapped
        # value, and no internal state claims them.
        self.assertFalse(
            set(policy.SPEC_STATE_NAMES.values())
            & set(policy.SPEC_STATES_WITHOUT_INTERNAL_STATE))
        for note in policy.SPEC_STATES_WITHOUT_INTERNAL_STATE.values():
            self.assertIn("consent", note)

    def test_unknown_status_maps_to_none(self):
        self.assertIsNone(policy.spec_state_name("not_a_state"))
        self.assertIsNone(policy.spec_state_name(None))


# ---------------------------------------------------------------------------
# pgserver: serialization carries both names; replay drains dead letters
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None

FILLABLE_FORM = [{
    "action": "https://www.spokeo.com/optout", "method": "POST",
    "fields": [{"name": "email", "type": "email", "id": "",
                "placeholder": ""}],
    "unmapped_fields": [],
}]


class StubExecutor:
    """Deterministic executor in the shape of
    tests/test_remediation.py's: fillable + ok-submit by default,
    per-broker submit overrides."""

    def __init__(self):
        self.submit_by_broker = {}

    def probe(self, profile, broker):
        return {"reachable": True, "status": 200, "fillable": True,
                "forms": FILLABLE_FORM, "blockers": [],
                "payload_preview": {"email": profile.get("email", "")},
                "via": "stub"}

    def submit(self, profile, broker, probe):
        return self.submit_by_broker.get(
            broker["name"], {"ok": True, "status": 200})


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestPolicyDb(ServerMixin, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-policy-pg-")
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
        os.environ.pop("ADMIN_EMAILS", None)

    # ---------- helpers ----------
    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "p2g-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"], email

    def make_admin(self):
        cookie, uid, email = self.register()
        os.environ["ADMIN_EMAILS"] = email
        return cookie, uid, email

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def add_full_profile(self, cookie, tag):
        self.add_identifier(cookie, "name", "Test Person %s" % tag)
        self.add_identifier(cookie, "email",
                            "person-%s@example.com" % tag)
        self.add_identifier(cookie, "address",
                            "%s Test Street, Pune, India" % tag)

    def set_consent(self, cookie, purpose, granted):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": purpose, "granted": granted},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

    def sql(self, query, params=()):
        with self.pool.connection() as conn:
            cur = conn.execute(query, params)
            if cur.description is None:  # UPDATE / DELETE / INSERT
                return []
            return cur.fetchall()

    def sql_one(self, query, params=()):
        rows = self.sql(query, params)
        return rows[0] if rows else None

    def replay(self, cookie, kind, target_id, headers=None):
        return self.request_json(
            "POST", "/api/admin/replay",
            body={"kind": kind, "id": str(target_id)},
            headers=CSRF if headers is None else headers,
            cookie=cookie)

    def drain_remediation(self, stub):
        worked = 0
        while worked < 500 and remediation_worker.run_once(stub):
            worked += 1
        return worked

    def case_for(self, cookie, broker_name):
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases", cookie=cookie)
        self.assertEqual(status, 200, body)
        for case in body["cases"]:
            if case["broker_name"] == broker_name:
                return case
        self.fail("no case for %s" % broker_name)

    def replay_audit_rows(self, target_id):
        return self.sql(
            "SELECT actor_user_id, actor_kind, action, target_kind,"
            " target_id, detail FROM audit_log"
            " WHERE action = 'admin.dead_letter_replayed'"
            " AND target_id = %s", (str(target_id),))

    # ---------- Phase 141: serialization ----------
    def test_case_payloads_carry_both_state_names(self):
        cookie, _uid, _acct = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={}, headers=CSRF,
            cookie=cookie)
        self.assertEqual(status, 200, body)
        # List payload: additive spec_status alongside status.
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases", cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertTrue(body["cases"])
        for case in body["cases"]:
            self.assertEqual(case["spec_status"],
                             policy.spec_state_name(case["status"]))
        spokeo = [c for c in body["cases"]
                  if c["broker_name"] == "Spokeo"][0]
        self.assertEqual(spokeo["status"], "queued")
        self.assertEqual(spokeo["spec_status"], "QUEUED")
        # Detail payload: the renamed states prove the mapping is
        # applied, not echoed.
        self.sql("UPDATE remediation_cases SET status = 'needs_human'"
                 " WHERE id = %s", (spokeo["id"],))
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases/%s" % spokeo["id"],
            cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["case"]["status"], "needs_human")
        self.assertEqual(body["case"]["spec_status"], "AWAITING_USER")
        self.sql("UPDATE remediation_cases SET status = 'blocked'"
                 " WHERE id = %s", (spokeo["id"],))
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases/%s" % spokeo["id"],
            cookie=cookie)
        self.assertEqual(body["case"]["spec_status"], "REJECTED")
        self.drain_remediation(StubExecutor())

    # ---------- Phase 119: the admin gate ----------
    def test_replay_gate(self):
        # Anonymous: the admin surface does not exist (404).
        status, _h, body = self.replay(None, "scan_job", uuid.uuid4())
        self.assertEqual(status, 404, body)
        self.assertEqual(body["error"]["code"], "not_found")
        # Signed in but not an admin: still 404.
        cookie, _uid, _email = self.register()
        status, _h, body = self.replay(cookie, "scan_job", uuid.uuid4())
        self.assertEqual(status, 404, body)
        # An admin without the CSRF header: refused like every
        # account mutation.
        admin_cookie, _auid, _aemail = self.make_admin()
        status, _h, body = self.request_json(
            "POST", "/api/admin/replay",
            body={"kind": "scan_job", "id": str(uuid.uuid4())},
            cookie=admin_cookie)
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "csrf_failed")

    def test_replay_validation(self):
        admin_cookie, _auid, _aemail = self.make_admin()
        status, _h, body = self.replay(admin_cookie, "widget",
                                       uuid.uuid4())
        self.assertEqual(status, 400, body)
        self.assertEqual(body["error"]["code"], "invalid_kind")
        status, _h, body = self.replay(admin_cookie, "scan_job",
                                       "not-a-uuid")
        self.assertEqual(status, 404, body)
        status, _h, body = self.replay(admin_cookie, "scan_job",
                                       uuid.uuid4())
        self.assertEqual(status, 404, body)
        self.assertEqual(body["error"]["code"], "not_found")
        status, _h, body = self.replay(admin_cookie,
                                       "remediation_case", uuid.uuid4())
        self.assertEqual(status, 404, body)

    # ---------- Phase 119: scan jobs ----------
    def _job_owner(self):
        cookie, uid, _email = self.register()
        self.add_identifier(cookie, "email",
                            "owner-%s@example.com" % self.uniq())
        self.set_consent(cookie, "scanning", True)
        return cookie, uid

    def _create_job(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/scans",
            body={"idempotency_key": uuid.uuid4().hex},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["job"]["id"]

    def _kill_job(self, job_id):
        self.sql(
            "UPDATE scan_jobs SET status = 'dead', attempts = 3,"
            " error_kind = 'provider_error', next_attempt_at = NULL,"
            " finished_at = now() WHERE id = %s", (job_id,))

    def test_dead_job_replays_and_drains(self):
        admin_cookie, admin_uid, _ae = self.make_admin()
        cookie, _uid = self._job_owner()
        job_id = self._create_job(cookie)
        self._kill_job(job_id)

        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["replay"], {"kind": "scan_job",
                                          "id": job_id,
                                          "status": "queued"})
        row = self.sql_one(
            "SELECT status, attempts, error_kind, finished_at,"
            " next_attempt_at FROM scan_jobs WHERE id = %s", (job_id,))
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["attempts"], 0)  # fresh retry budget
        self.assertIsNone(row["error_kind"])
        self.assertIsNone(row["finished_at"])
        self.assertIsNone(row["next_attempt_at"])
        # The death is preserved in the audit row, not erased.
        rows = self.replay_audit_rows(job_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(str(rows[0]["actor_user_id"]), admin_uid)
        self.assertEqual(rows[0]["actor_kind"], "admin")
        self.assertEqual(rows[0]["target_kind"], "scan_job")
        self.assertEqual(rows[0]["detail"]["prior_error_kind"],
                         "provider_error")
        self.assertEqual(rows[0]["detail"]["prior_attempts"], 3)
        # The real worker drains the replayed job to done.
        for _ in range(50):
            row = self.sql_one(
                "SELECT status FROM scan_jobs WHERE id = %s", (job_id,))
            if row["status"] == "done":
                break
            self.assertTrue(scan_worker.run_once(),
                            "worker had nothing to claim")
        self.assertEqual(row["status"], "done")

    def test_double_replay_is_a_typed_refusal(self):
        admin_cookie, _auid, _ae = self.make_admin()
        cookie, _uid = self._job_owner()
        job_id = self._create_job(cookie)
        self._kill_job(job_id)
        status, _h, _b = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 200)
        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "already_active")
        # No second queue entry: still the one row, still queued.
        rows = self.sql("SELECT id FROM scan_jobs WHERE id = %s",
                        (job_id,))
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(self.replay_audit_rows(job_id)), 1)

    def test_non_dead_job_refusals(self):
        admin_cookie, _auid, _ae = self.make_admin()
        cookie, _uid = self._job_owner()
        job_id = self._create_job(cookie)
        # Queued (never died): already active.
        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "already_active")
        # Failed is mid-retry, not a dead letter.
        self.sql("UPDATE scan_jobs SET status = 'failed', attempts = 1,"
                 " next_attempt_at = now() WHERE id = %s", (job_id,))
        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "not_dead_letter")
        # Done is terminal success, not a dead letter either.
        self.sql("UPDATE scan_jobs SET status = 'done' WHERE id = %s",
                 (job_id,))
        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "not_dead_letter")
        self.assertEqual(self.replay_audit_rows(job_id), [])

    def test_job_replay_rechecks_scanning_consent(self):
        admin_cookie, _auid, _ae = self.make_admin()
        cookie, _uid = self._job_owner()
        job_id = self._create_job(cookie)
        self._kill_job(job_id)
        self.set_consent(cookie, "scanning", False)
        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "consent_required")
        row = self.sql_one("SELECT status FROM scan_jobs WHERE id = %s",
                           (job_id,))
        self.assertEqual(row["status"], "dead")  # never resurrected
        self.assertEqual(self.replay_audit_rows(job_id), [])
        # Re-granting makes the very same replay succeed: the check
        # reads the CURRENT consent, not the consent at death.
        self.set_consent(cookie, "scanning", True)
        status, _h, _b = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 200)

    def test_monitor_job_replay_uses_monitoring_consent(self):
        admin_cookie, _auid, _ae = self.make_admin()
        cookie, uid = self._job_owner()
        self.set_consent(cookie, "monitoring", True)
        job_id = str(uuid.uuid4())
        self.sql(
            "INSERT INTO scan_jobs (id, user_id, idempotency_key,"
            " status, attempts, error_kind, finished_at)"
            " VALUES (%s, %s, %s, 'dead', 3, 'internal', now())",
            (job_id, uid, "monitor-%s-2026-01-05" % uid))
        # The monitoring lane answers to the monitoring consent:
        # revoking scanning does not block it...
        self.set_consent(cookie, "scanning", False)
        status, _h, body = self.replay(admin_cookie, "scan_job", job_id)
        self.assertEqual(status, 200, body)
        # ...and a fresh dead monitor job with monitoring revoked
        # is refused even though scanning is granted.
        job2 = str(uuid.uuid4())
        self.sql(
            "INSERT INTO scan_jobs (id, user_id, idempotency_key,"
            " status, attempts, error_kind, finished_at)"
            " VALUES (%s, %s, %s, 'dead', 3, 'internal', now())",
            (job2, uid, "monitor-%s-2026-01-12" % uid))
        self.set_consent(cookie, "scanning", True)
        self.set_consent(cookie, "monitoring", False)
        status, _h, body = self.replay(admin_cookie, "scan_job", job2)
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "consent_required")

    # ---------- Phase 119: remediation cases ----------
    def _failed_spokeo_case(self):
        """A user whose Spokeo case died by submit_failed, with its
        probe + submit attempts on record."""
        cookie, uid, _email = self.register()
        self.add_full_profile(cookie, self.uniq())
        self.set_consent(cookie, "automated_remediation", True)
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={}, headers=CSRF,
            cookie=cookie)
        self.assertEqual(status, 200, body)
        stub = StubExecutor()
        stub.submit_by_broker["Spokeo"] = {"ok": False, "status": 500}
        self.drain_remediation(stub)
        case = self.case_for(cookie, "Spokeo")
        self.assertEqual(case["status"], "failed")
        self.assertEqual(case["reason"], "submit_failed")
        return cookie, uid, case

    def _attempts(self, case_id):
        return self.sql(
            "SELECT attempt_no, action, result FROM remediation_attempts"
            " WHERE case_id = %s ORDER BY attempt_no", (case_id,))

    def test_dead_case_replays_and_drains(self):
        admin_cookie, admin_uid, _ae = self.make_admin()
        cookie, _uid, case = self._failed_spokeo_case()
        before = self._attempts(case["id"])
        self.assertGreaterEqual(len(before), 2)  # probe + submit

        status, _h, body = self.replay(admin_cookie,
                                       "remediation_case", case["id"])
        self.assertEqual(status, 200, body)
        self.assertEqual(body["replay"],
                         {"kind": "remediation_case", "id": case["id"],
                          "status": "queued"})
        row = self.sql_one(
            "SELECT status, reason FROM remediation_cases"
            " WHERE id = %s", (case["id"],))
        self.assertEqual(row["status"], "queued")
        self.assertIsNone(row["reason"])
        # History untouched by the replay itself...
        self.assertEqual(self._attempts(case["id"]), before)
        rows = self.replay_audit_rows(case["id"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(str(rows[0]["actor_user_id"]), admin_uid)
        self.assertEqual(rows[0]["target_kind"], "remediation_case")
        self.assertEqual(rows[0]["detail"]["prior_reason"],
                         "submit_failed")
        self.assertEqual(rows[0]["detail"]["broker"], "spokeo")
        # ...and the healthy worker drains it to submitted,
        # appending NEW attempts after the preserved ones.
        self.drain_remediation(StubExecutor())
        after_case = self.case_for(cookie, "Spokeo")
        self.assertEqual(after_case["status"], "submitted")
        after = self._attempts(case["id"])
        self.assertGreater(len(after), len(before))
        self.assertEqual(after[:len(before)], before)

    def test_case_replay_consent_revoked_is_refused(self):
        admin_cookie, _auid, _ae = self.make_admin()
        cookie, _uid, case = self._failed_spokeo_case()
        before = self._attempts(case["id"])
        self.set_consent(cookie, "automated_remediation", False)
        status, _h, body = self.replay(admin_cookie,
                                       "remediation_case", case["id"])
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "consent_required")
        row = self.sql_one(
            "SELECT status, reason FROM remediation_cases"
            " WHERE id = %s", (case["id"],))
        self.assertEqual(row["status"], "failed")  # stays dead
        self.assertEqual(row["reason"], "submit_failed")
        self.assertEqual(self._attempts(case["id"]), before)
        self.assertEqual(self.replay_audit_rows(case["id"]), [])

    def test_case_replay_non_dead_refusals(self):
        admin_cookie, _auid, _ae = self.make_admin()
        cookie, _uid, case = self._failed_spokeo_case()
        # A live sibling case for the same broker blocks the
        # replay (the one-live-case rule), with retry_case's code.
        sibling = str(uuid.uuid4())
        self.sql(
            "INSERT INTO remediation_cases (id, user_id, broker_slug,"
            " status) VALUES (%s, %s, 'spokeo', 'queued')",
            (sibling, _uid))
        status, _h, body = self.replay(admin_cookie,
                                       "remediation_case", case["id"])
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "not_retryable")
        # The live sibling itself, while queued, is already
        # active — the same refusal a repeated replay gets.
        status, _h, body = self.replay(admin_cookie,
                                       "remediation_case", sibling)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "already_active")
        # Submitted and verified_removed siblings are terminal
        # non-failures: not dead letters either.
        for state in ("submitted", "verified_removed"):
            self.sql("UPDATE remediation_cases SET status = %s"
                     " WHERE id = %s", (state, sibling))
            status, _h, body = self.replay(admin_cookie,
                                           "remediation_case", sibling)
            self.assertEqual(status, 409, body)
            self.assertEqual(body["error"]["code"], "not_dead_letter",
                             state)
        # Nothing above produced a replay or an audit row.
        self.assertEqual(self.replay_audit_rows(case["id"]), [])
        self.assertEqual(self.replay_audit_rows(sibling), [])
        self.sql("DELETE FROM remediation_cases WHERE id = %s",
                 (sibling,))
        self.drain_remediation(StubExecutor())
