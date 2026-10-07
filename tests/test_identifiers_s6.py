"""Identifier monitoring tests (Stage S6 — spec Phases 15–20).

Layers:

* TestDiscoveryParsing — offline: DDG HTML parsing (uddg unwrap,
  snippets, domains), junk input -> [].
* TestProvidersOffline — offline, scripted transports: username
  status classification (200 in_use / 404 not_found / 403+429
  unknown, never guessed), all-platforms-down propagates an error,
  DoH answer parsing + TXT cleaning, cert-name parsing, and the
  HttpClient's get_status + min-interval pacing.
* TestNormalizeS6 — offline (ephemeral lookup key): the confidence
  ladder (discovery weak / handle probable / domain exact),
  remediation_eligible False everywhere, and evidence + details
  provably free of the raw identifier — even when a result's title
  embeds it.
* TestVaultDomainKind — offline: domain normalization + validation.
* TestDomainsUnavailable — no database: domain routes answer 503
  after the CSRF guard, like every other account route.
* TestDomainsDb — pgserver-backed (skips honestly without it):
  the domain ownership flow end to end (add -> pending -> TXT
  verify -> verified; wrong owner 404s; delete + re-add), and the
  orchestrator with stub providers: unverified domains produce the
  domain_unverified outcome and ZERO findings, a verified domain
  yields exact DNS/cert findings, the phone fixture yields weak
  candidates, the fixture handle yields a probable finding, and a
  fat job's discovery queries stop at the budget of 6.

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

import app  # noqa: E402
from accounts import domains as domains_service  # noqa: E402
from accounts import ratelimit  # noqa: E402
from core import errors as api_errors  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from providers.base import (  # noqa: E402
    HttpClient, ProviderInfo, ProviderResult)
from providers.ddg_discovery import (  # noqa: E402
    DuckDuckGoDiscoveryProvider, parse_results)
from providers.domain_intel import (  # noqa: E402
    DomainIntelProvider, parse_answers, parse_cert_names)
from providers.mock import MockProvider  # noqa: E402
from providers.username_platforms import (  # noqa: E402
    PLATFORMS, UsernamePlatformsProvider, classify_status)
from scanning import normalize  # noqa: E402
from vault import store as vault_store  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")


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


def _client(transport, **kw):
    kw.setdefault("sleep", lambda _s: None)
    return HttpClient("TestProvider", transport=transport, **kw)


# ---------------------------------------------------------------------------
# DDG parsing
# ---------------------------------------------------------------------------

DDG_HTML = """
<html><body>
<div class="result results_links">
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fpage%3Fa%3D1&amp;rut=abc">Some Title</a>
  <a class="result__snippet" href="//duckduckgo.com/l/?uddg=x">A snippet <b>text</b> here</a>
</div>
<div class="result results_links">
  <a class="result__a" href="https://www.direct.example.net/x">Direct Result</a>
  <a class="result__snippet">Second snippet</a>
</div>
</body></html>
"""


class TestDiscoveryParsing(unittest.TestCase):
    def test_parses_links_snippets_domains(self):
        results = parse_results(DDG_HTML)
        self.assertEqual(len(results), 2)
        first, second = results
        self.assertEqual(first["url"], "https://example.org/page?a=1")
        self.assertEqual(first["domain"], "example.org")
        self.assertEqual(first["title"], "Some Title")
        self.assertEqual(first["snippet"], "A snippet text here")
        self.assertEqual(second["url"], "https://www.direct.example.net/x")
        self.assertEqual(second["domain"], "direct.example.net")
        self.assertEqual(second["snippet"], "Second snippet")

    def test_junk_yields_empty_never_crashes(self):
        self.assertEqual(parse_results(""), [])
        self.assertEqual(parse_results(None), [])
        self.assertEqual(parse_results("<html><body>nope"), [])
        self.assertEqual(parse_results("<<<not html>>>"), [])
        self.assertEqual(parse_results(
            '<a class="result__a" href="javascript:void(0)">x</a>'), [])

    def test_provider_search_uses_parser(self):
        provider = DuckDuckGoDiscoveryProvider(
            client=_client(lambda u, h, t: (200, DDG_HTML)))
        result = provider.search('"anything"')
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(result.data), 2)


# ---------------------------------------------------------------------------
# Username + domain providers, offline
# ---------------------------------------------------------------------------

class TestProvidersOffline(unittest.TestCase):
    def test_classify_status(self):
        self.assertEqual(classify_status(200), "in_use")
        self.assertEqual(classify_status(404), "not_found")
        for code in (301, 401, 403, 429, 500, None):
            self.assertEqual(classify_status(code), "unknown", code)

    def test_username_status_mapping(self):
        def transport(url, headers, timeout):
            if "github.com" in url:
                return 200, ""
            if "instagram" in url:
                return 403, ""       # bot wall -> unknown, never guessed
            if "tiktok" in url:
                return 429, ""       # rate limit -> unknown
            return 404, ""

        provider = UsernamePlatformsProvider(client=_client(transport))
        result = provider.check_username("somehandle")
        self.assertEqual(result.status, "ok")
        states = {c["platform"]: c["state"] for c in result.data}
        self.assertEqual(states["GitHub"], "in_use")
        self.assertEqual(states["GitLab"], "not_found")
        self.assertEqual(states["Instagram"], "unknown")
        self.assertEqual(states["TikTok"], "unknown")
        self.assertEqual(len(result.data), len(PLATFORMS))

    def test_username_all_down_propagates_error(self):
        from providers.base import TransportNetworkError

        def transport(url, headers, timeout):
            raise TransportNetworkError("down")

        provider = UsernamePlatformsProvider(client=_client(transport))
        result = provider.check_username("somehandle")
        self.assertNotEqual(result.status, "ok")
        self.assertEqual(result.error_kind, "network")

    def test_doh_answer_parsing(self):
        payload = {"Answer": [
            {"name": "example.com", "type": 1, "data": "93.184.216.34"},
            {"name": "example.com", "type": 1, "data": "93.184.216.35"},
        ]}
        self.assertEqual(parse_answers(payload, "A"),
                         ["93.184.216.34", "93.184.216.35"])
        txt = {"Answer": [
            {"name": "_leakguard.example.com", "type": 16,
             "data": '"leakguard-verify=ab" "cd1234"'},
        ]}
        self.assertEqual(parse_answers(txt, "TXT"),
                         ["leakguard-verify=abcd1234"])
        self.assertEqual(parse_answers({"nope": 1}, "A"), [])
        self.assertEqual(parse_answers(None, "A"), [])
        self.assertEqual(parse_answers({"Answer": "x"}, "A"), [])

    def test_cert_name_parsing(self):
        payload = [
            {"name_value": "example.com"},
            {"name_value": "www.example.com\na.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "www.example.com"},
            {"other": "ignored"},
            "junk",
        ]
        self.assertEqual(parse_cert_names(payload), [
            "*.example.com", "a.example.com", "example.com",
            "www.example.com"])
        self.assertEqual(parse_cert_names({"not": "a list"}), [])

    def test_domain_provider_txt_roundtrip(self):
        doh = {"Answer": [{"name": "_leakguard.example.com", "type": 16,
                           "data": '"leakguard-verify=ff00"'}]}
        provider = DomainIntelProvider(
            client=_client(lambda u, h, t: (200, json.dumps(doh))))
        result = provider.txt_records("_leakguard.example.com")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, ["leakguard-verify=ff00"])

    def test_get_status_and_pacing(self):
        clock = [1000.0]
        sleeps = []

        def fake_clock():
            return clock[0]

        def fake_sleep(delay):
            sleeps.append(delay)
            clock[0] += delay

        calls = []

        def transport(url, headers, timeout):
            calls.append(url)
            return 404, ""

        client = HttpClient("Paced", transport=transport,
                            sleep=fake_sleep, clock=fake_clock,
                            min_interval=1.0)
        result = client.get_status("https://x.example/a")
        # A 404 is a complete answer for a status check: ok + code.
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, 404)
        client.get_status("https://x.example/b")
        # Second call within the interval waited the full second.
        self.assertEqual(sleeps, [1.0])
        self.assertEqual(len(calls), 2)


# ---------------------------------------------------------------------------
# Normalize: the S6 confidence ladder + evidence hygiene
# ---------------------------------------------------------------------------

class TestNormalizeS6(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._env = EnvGuard(("VAULT_LOOKUP_KEY",)).__enter__()
        os.environ["VAULT_LOOKUP_KEY"] = base64.b64encode(
            b"\x02" * 32).decode()

    @classmethod
    def tearDownClass(cls):
        cls._env.__exit__()

    def test_discovery_findings_weak_and_clean(self):
        phone = "+91 98100 12345"
        results = [{
            "title": "Listing for 919810012345",  # embeds the number!
            "url": "https://listing.example.org/item/1",
            "snippet": "Call 919810012345 today",  # embeds it too!
            "domain": "listing.example.org",
        }]
        findings = normalize.discovery_findings(
            "DuckDuckGo Discovery", "ident-1", "phone", phone, results)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["confidence"], "weak")
        self.assertEqual(f["reliability"], "low")
        self.assertFalse(f["remediation_eligible"])
        self.assertEqual(f["source_name"], "listing.example.org")
        self.assertEqual(f["source_url"],
                         "https://listing.example.org/item/1")
        self.assertEqual(f["exposed_fields"], ["phone"])
        blob = json.dumps(findings)
        self.assertNotIn("919810012345", blob)
        self.assertNotIn("98100", blob)
        payload = normalize.evidence_payload(
            "DuckDuckGo Discovery", "listing.example.org", "phone",
            f["identifier_hmac"], {"source_domain": "listing.example.org"})
        self.assertEqual(normalize.canonical_evidence_ref(payload),
                         f["evidence_ref"])
        self.assertNotIn("919810012345", json.dumps(payload))

    def test_address_evidence_excludes_raw(self):
        address = "742 Evergreen Terrace, Springfield"
        results = [{"title": address, "url": "https://x.example.org/a",
                    "snippet": address, "domain": "x.example.org"}]
        findings = normalize.discovery_findings(
            "DuckDuckGo Discovery", "ident-2", "address", address,
            results)
        blob = json.dumps(findings)
        self.assertNotIn("Evergreen", blob)
        self.assertNotIn("Springfield", blob)
        self.assertEqual(findings[0]["confidence"], "weak")
        self.assertFalse(findings[0]["remediation_eligible"])

    def test_username_presence_probable_with_warning(self):
        checks = [
            {"platform": "GitHub", "url": "https://github.com/h",
             "state": "in_use"},
            {"platform": "GitLab", "url": "https://gitlab.com/h",
             "state": "not_found"},
            {"platform": "X", "url": "https://x.com/h",
             "state": "unknown"},
        ]
        findings = normalize.username_presence_findings(
            "Username Platforms", "ident-3", "somehandle", checks)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["confidence"], "probable")
        self.assertEqual(f["reliability"], "medium")
        self.assertFalse(f["remediation_eligible"])
        self.assertIn("not proof", f["details"]["note"])
        self.assertEqual(f["source_url"], "https://github.com/h")

    def test_domain_findings_exact(self):
        snapshot = {"A": ["93.184.216.34"], "MX": ["0 mail.example.org"],
                    "NS": ["a.iana-servers.net"], "TXT": ["v=spf1 -all"]}
        findings = normalize.domain_findings(
            "Domain Intel", "ident-4", "example.org", snapshot,
            ["example.org", "www.example.org", "api.example.org"])
        self.assertEqual(len(findings), 3)  # snapshot + 2 cert names
        for f in findings:
            self.assertEqual(f["confidence"], "exact")
            self.assertEqual(f["reliability"], "high")
            self.assertFalse(f["remediation_eligible"])
        snap = [f for f in findings
                if f["details"]["match_kind"] == "dns_snapshot"][0]
        self.assertEqual(snap["details"]["dns"]["A"], ["93.184.216.34"])
        self.assertEqual(snap["source_name"], "example.org")
        certs = {f["source_name"] for f in findings
                 if f["details"]["match_kind"] == "certificate_name"}
        self.assertEqual(certs, {"www.example.org", "api.example.org"})


# ---------------------------------------------------------------------------
# Vault domain kind (pure functions)
# ---------------------------------------------------------------------------

class TestVaultDomainKind(unittest.TestCase):
    def test_normalize_domain(self):
        n = vault_store.normalize
        self.assertEqual(n("domain", "Example.COM"), "example.com")
        self.assertEqual(
            n("domain", "https://user@Example.com:8080/path?q=1."),
            "example.com")
        self.assertEqual(n("domain", "  sub.example.co.uk "),
                         "sub.example.co.uk")

    def test_validate_domains(self):
        ok = domains_service.normalize_and_validate
        self.assertEqual(ok("example.com"), "example.com")
        self.assertEqual(ok("HTTPS://Example.ORG/x"), "example.org")
        for bad in ("", "localhost", "not a domain", "-bad.com",
                    "exa mple.com", "example.c", None):
            with self.assertRaises(api_errors.ApiError) as ctx:
                ok(bad)
            self.assertEqual(ctx.exception.code, "invalid_domain", bad)


# ---------------------------------------------------------------------------
# No-database layer
# ---------------------------------------------------------------------------

class TestDomainsUnavailable(ServerMixin, unittest.TestCase):
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

    def test_post_csrf_first_then_503(self):
        status, _h, body = self.request_json(
            "POST", "/api/domains", body={"domain": "example.com"})
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "csrf_failed")
        status, _h, body = self.request_json(
            "POST", "/api/domains", body={"domain": "example.com"},
            headers=CSRF)
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_reads_503(self):
        status, _h, body = self.request_json("GET", "/api/domains")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")


# ---------------------------------------------------------------------------
# DB-backed: ownership flow + orchestrator wiring (pgserver + stubs)
# ---------------------------------------------------------------------------

class StubDiscovery:
    info = ProviderInfo(name="StubDiscovery", category="test",
                        capabilities=("web_discovery",),
                        privacy="test stub")

    def __init__(self):
        self.queries = []

    def search(self, query):
        self.queries.append(query)
        if "9999999999" in query or "Evergreen" in query:
            return ProviderResult(status="ok", data=[{
                "title": "Stub listing",
                "url": "https://listing.example.org/item/1",
                "snippet": "stub",
                "domain": "listing.example.org",
            }], latency_ms=0.0)
        return ProviderResult(status="ok", data=[], latency_ms=0.0)


class StubUsernames:
    info = ProviderInfo(name="StubUsernames", category="test",
                        capabilities=("username_presence",),
                        privacy="test stub")

    def check_username(self, handle):
        handle = (handle or "").strip().lstrip("@")
        checks = [{
            "platform": name,
            "url": template.format(handle=handle),
            "state": ("in_use" if handle == "fixturehandle"
                      and name == "GitHub" else "not_found"),
        } for name, template in PLATFORMS]
        return ProviderResult(status="ok", data=checks, latency_ms=0.0)


class StubDomainIntel:
    info = ProviderInfo(name="StubDomainIntel", category="test",
                        capabilities=("domain_dns", "domain_certs"),
                        privacy="test stub")

    def __init__(self):
        self.txt_map = {}

    def txt_records(self, name):
        return ProviderResult(
            status="ok", data=list(self.txt_map.get(name, [])),
            latency_ms=0.0)

    def dns_snapshot(self, domain):
        return ProviderResult(status="ok", data={
            "A": ["192.0.2.10"], "MX": ["0 mail." + domain],
            "NS": ["ns1.example.net"], "TXT": [],
        }, latency_ms=0.0)

    def cert_names(self, domain):
        return ProviderResult(
            status="ok", data=[domain, "www." + domain], latency_ms=0.0)


class StubRegistry:
    def __init__(self, providers):
        self.providers = providers

    def get_providers(self, capability):
        return [p for p in self.providers
                if capability in p.info.capabilities]


try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestDomainsDb(ServerMixin, unittest.TestCase):
    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._env = EnvGuard(ENV_KEYS).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-s6-pg-")
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
        cls.discovery = StubDiscovery()
        cls.usernames = StubUsernames()
        cls.intel = StubDomainIntel()
        registry_mod.reset_registry(StubRegistry([
            MockProvider(), cls.discovery, cls.usernames, cls.intel]))
        from db import migrate, pool

        cls.pool = pool
        pool.reset_probe_cache()
        if not pool.db_available():
            cls._teardown_pg()
            raise unittest.SkipTest("local PostgreSQL not reachable")
        migrate.run_migrations()
        from scanning import worker

        cls.worker = worker
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
        self.discovery.queries.clear()
        self.intel.txt_map.clear()

    # ---------- helpers ----------
    def unique_email(self):
        return "s6-%s@example.com" % uuid.uuid4().hex[:16]

    def register(self):
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": self.unique_email(), "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers", body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)
        return body["identifier"]

    def add_domain(self, cookie, domain):
        return self.request_json(
            "POST", "/api/domains", body={"domain": domain},
            headers=CSRF, cookie=cookie)

    def grant_scanning(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)

    def create_job(self, cookie):
        return self.request_json(
            "POST", "/api/scans",
            body={"idempotency_key": uuid.uuid4().hex},
            headers=CSRF, cookie=cookie)

    def get_job(self, cookie, job_id):
        return self.request_json("GET", "/api/scans/" + job_id,
                                 cookie=cookie)

    def run_until_done(self, cookie, job_id):
        for _ in range(50):
            status, _h, body = self.get_job(cookie, job_id)
            self.assertEqual(status, 200, body)
            if body["job"]["status"] in ("done", "dead"):
                return body
            self.assertTrue(self.worker.run_once(),
                            "worker had nothing to claim")
        self.fail("job never finished")

    def ready_user(self, cookie_setup=None):
        cookie, _uid = self.register()
        if cookie_setup:
            cookie_setup(cookie)
        self.grant_scanning(cookie)
        return cookie

    def verify_via_stub(self, cookie, domain_row):
        self.intel.txt_map[domain_row["txt_name"]] = [
            domain_row["txt_value"]]
        status, _h, body = self.request_json(
            "POST", "/api/domains/%s/verify" % domain_row["id"],
            body={}, headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        return body["domain"]

    # ---------- domain ownership flow ----------
    def test_add_pending_verify_verified(self):
        cookie, _uid = self.register()
        status, _h, body = self.add_domain(cookie, "Example.COM")
        self.assertEqual(status, 201, body)
        row = body["domain"]
        self.assertEqual(row["domain"], "example.com")
        self.assertFalse(row["verified"])
        self.assertEqual(row["txt_name"], "_leakguard.example.com")
        self.assertTrue(row["txt_value"].startswith("leakguard-verify="))
        self.assertEqual(len(row["txt_value"]), len("leakguard-verify=")
                         + 32)

        # Re-adding is idempotent: same row, same token.
        status, _h, body = self.add_domain(cookie, "example.com")
        self.assertEqual(status, 201)
        self.assertEqual(body["domain"]["id"], row["id"])
        self.assertEqual(body["domain"]["txt_value"], row["txt_value"])

        status, _h, body = self.request_json("GET", "/api/domains",
                                             cookie=cookie)
        self.assertEqual([d["id"] for d in body["domains"]], [row["id"]])

        # No TXT record yet: verify answers 200, still pending.
        status, _h, body = self.request_json(
            "POST", "/api/domains/%s/verify" % row["id"], body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        self.assertFalse(body["domain"]["verified"])

        # Publish the token in the stub resolver: verified.
        verified = self.verify_via_stub(cookie, row)
        self.assertTrue(verified["verified"])
        self.assertIsNotNone(verified["verified_at"])

        # And again: idempotent, stays verified.
        again = self.verify_via_stub(cookie, row)
        self.assertTrue(again["verified"])

    def test_invalid_domain_and_idor(self):
        cookie_a, _uid_a = self.register()
        status, _h, body = self.add_domain(cookie_a, "not a domain")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_domain")

        status, _h, body = self.add_domain(cookie_a, "example.net")
        self.assertEqual(status, 201, body)
        row = body["domain"]

        cookie_b, _uid_b = self.register()
        # Another account cannot verify or delete A's domain: 404.
        status, _h, body = self.request_json(
            "POST", "/api/domains/%s/verify" % row["id"], body={},
            headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 404)
        status, _h, body = self.request_json(
            "DELETE", "/api/domains/%s" % row["id"],
            headers=CSRF, cookie=cookie_b)
        self.assertEqual(status, 404)
        # A random uuid is the same 404 for the owner.
        status, _h, body = self.request_json(
            "DELETE", "/api/domains/%s" % uuid.uuid4(),
            headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 404)

        # Owner deletes; the row leaves the list; re-adding works and
        # starts unverified again.
        status, _h, body = self.request_json(
            "DELETE", "/api/domains/%s" % row["id"],
            headers=CSRF, cookie=cookie_a)
        self.assertEqual(status, 200)
        self.assertTrue(body["deleted"])
        status, _h, body = self.request_json("GET", "/api/domains",
                                             cookie=cookie_a)
        self.assertEqual(body["domains"], [])
        status, _h, body = self.add_domain(cookie_a, "example.net")
        self.assertEqual(status, 201)
        self.assertFalse(body["domain"]["verified"])
        self.assertNotEqual(body["domain"]["id"], row["id"])

    # ---------- orchestrator wiring ----------
    def test_unverified_domain_scanned_never(self):
        cookie, _uid = self.register()
        status, _h, body = self.add_domain(cookie, "example.info")
        self.assertEqual(status, 201, body)
        self.grant_scanning(cookie)
        _s, _h, body = self.create_job(cookie)
        result = self.run_until_done(cookie, body["job"]["id"])
        job = result["job"]
        self.assertEqual(job["status"], "done")
        outcomes = {o["kind"]: o for o in job["summary"]["identifiers"]}
        self.assertEqual(outcomes["domain"]["outcome"],
                         "domain_unverified")
        self.assertEqual(outcomes["domain"]["findings"], 0)
        domain_findings = [f for f in result["findings"]
                           if f["identifier_kind"] == "domain"]
        self.assertEqual(domain_findings, [])

    def test_verified_domain_phone_username_scan(self):
        cookie, _uid = self.register()
        self.add_identifier(cookie, "phone", "+91 99999 99999")
        self.add_identifier(cookie, "username", "fixturehandle")
        status, _h, body = self.add_domain(cookie, "example.org")
        self.assertEqual(status, 201, body)
        self.verify_via_stub(cookie, body["domain"])
        self.grant_scanning(cookie)
        _s, _h, body = self.create_job(cookie)
        result = self.run_until_done(cookie, body["job"]["id"])
        job = result["job"]
        self.assertEqual(job["status"], "done")
        outcomes = {o["kind"]: o for o in job["summary"]["identifiers"]}
        for kind in ("phone", "username", "domain"):
            self.assertEqual(outcomes[kind]["outcome"], "scanned", kind)
        # Exactly two discovery queries: the phone's + the handle's.
        self.assertEqual(job["summary"]["discovery_queries_used"], 2)
        self.assertEqual(len(self.discovery.queries), 2)

        by_kind = {}
        for f in result["findings"]:
            by_kind.setdefault(f["identifier_kind"], []).append(f)
        phone = by_kind["phone"][0]
        self.assertEqual(phone["confidence"], "weak")
        self.assertFalse(phone["remediation_eligible"])
        handle = [f for f in by_kind["username"]
                  if f["source_name"] == "GitHub"][0]
        self.assertEqual(handle["confidence"], "probable")
        self.assertIn("not proof", handle["details"]["note"])
        domain = by_kind["domain"]
        self.assertEqual(len(domain), 2)  # DNS snapshot + www cert
        for f in domain:
            self.assertEqual(f["confidence"], "exact")
            self.assertFalse(f["remediation_eligible"])
        # The raw phone number appears NOWHERE in the job response.
        self.assertNotIn("9999999999", json.dumps(result))
        self.assertNotIn("919999999999", json.dumps(result))

    def test_address_scan_evidence_hygiene(self):
        cookie, _uid = self.register()
        address = "742 Evergreen Terrace, Springfield"
        self.add_identifier(cookie, "address", address)
        self.grant_scanning(cookie)
        _s, _h, body = self.create_job(cookie)
        result = self.run_until_done(cookie, body["job"]["id"])
        self.assertEqual(result["job"]["status"], "done")
        findings = [f for f in result["findings"]
                    if f["identifier_kind"] == "address"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "weak")
        self.assertNotIn("Evergreen", json.dumps(result))
        self.assertNotIn("Springfield", json.dumps(result))

    def test_discovery_budget_enforced(self):
        cookie, _uid = self.register()
        for i in range(5):
            self.add_identifier(cookie, "phone",
                                "+91 98111 0000%d" % i)
        for i in range(4):
            self.add_identifier(
                cookie, "name",
                "Budget Person %s %d" % (uuid.uuid4().hex[:8], i))
        self.add_identifier(cookie, "username",
                            "budgethandle%s" % uuid.uuid4().hex[:8])
        self.grant_scanning(cookie)
        _s, _h, body = self.create_job(cookie)
        result = self.run_until_done(cookie, body["job"]["id"])
        job = result["job"]
        self.assertEqual(job["status"], "done")
        # 10 candidate identifiers, one query each — the budget
        # stops discovery at exactly 6.
        self.assertEqual(len(self.discovery.queries), 6)
        self.assertEqual(job["summary"]["discovery_queries_used"], 6)
        exhausted = [o for o in job["summary"]["identifiers"]
                     if o["error_kind"] == "budget_exhausted"]
        self.assertTrue(exhausted)
        # Budget exhaustion is surfaced as degraded, never hidden.
        self.assertTrue(job["summary"]["degraded"])


if __name__ == "__main__":
    unittest.main()
