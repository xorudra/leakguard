"""Verification source map tests (the verify_sources.json data +
AgentExecutor.verify_search rewrite).

Layers:

* TestVerifySourcesData — offline integrity of the data file:
  exactly the 40 broker slugs from brokers.json, valid methods,
  a research note on every entry, direct templates that carry a
  name placeholder.
* TestConfigFor — the loader: by registry row, by bare slug,
  unmapped -> None.
* TestVerifySearchEngine — offline, fetcher stubbed: the
  search_index verdicts (present / absent / zero-hit / challenge /
  fetch failure), the direct verdicts (404 / empty-search phrase /
  name on page / blank page), template substitution + encoding,
  and the never-guess cases (method none, unmapped, no name).
* TestVerifySourcesDb — pgserver: the seed stores direct
  templates in brokers.search_url (NULL everywhere else), and the
  full verify flow — a submitted case goes verified_removed on a
  search_index 'gone', stays submitted/still_listed on
  'still_present', with check rows recording method search_index.

All fixture people are obviously fake ("Zztest Personman").
Nothing here touches the network.

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
from accounts import ratelimit  # noqa: E402
from remediation import engine as engine_mod  # noqa: E402
from remediation import registry_seed, verify_sources  # noqa: E402
from remediation import verify as verify_mod  # noqa: E402
from remediation import worker as worker_mod  # noqa: E402

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover - environment without pgserver
    _pgserver = None

ROOT = Path(__file__).resolve().parent.parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CSRF = {"X-Requested-With": "fetch"}
ENV_KEYS = ("DATABASE_URL", "VAULT_MASTER_KEY", "VAULT_LOOKUP_KEY")
PROFILE = {"full_name": "Zztest Personman", "email": "",
           "phone": "", "city": "Pune"}


def _load_json(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# DuckDuckGo HTML fixtures (modelled on the real html endpoint's
# markup: div.links > div.result > a.result__a wrapped in /l/?uddg=)
# ---------------------------------------------------------------------------

def _ddg_page(*result_urls):
    anchors = []
    for i, target in enumerate(result_urls):
        wrapped = "//duckduckgo.com/l/?uddg=%s&rut=%04d" % (
            urllib.parse.quote(target, safe=""), i)
        anchors.append(
            '<div class="result results_links web-result">'
            '<h2 class="result__title">'
            '<a class="result__a" href="%s">Result %d</a></h2>'
            '<a class="result__snippet" href="%s">snippet</a></div>'
            % (wrapped, i, wrapped))
    return ("<html><head><title>search at DuckDuckGo</title></head>"
            "<body><div class=\"links\">%s</div></body></html>"
            % "".join(anchors))


DDG_PRESENT_SPOKEO = _ddg_page(
    "https://www.spokeo.com/Zztest-Personman",
    "https://www.example.com/someone-else",
)
DDG_SUBDOMAIN = _ddg_page("https://people.spokeo.com/Zztest-Personman")
DDG_ABSENT = _ddg_page(
    "https://www.example.com/someone-else",
    "https://notspokeo.com/Zztest-Personman",
    "https://spokeo.com.evil.example/Zztest-Personman",
)
DDG_ZERO = ("<html><head><title>search at DuckDuckGo</title></head>"
            "<body><div class=\"feedback\">No results found for "
            "the search. Suggestions: check the spelling.</div>"
            "</body></html>")
DDG_CHALLENGE = ("<html><body><p>Unfortunately, bots use DuckDuckGo "
                 "too.</p><p>Please complete the following challenge "
                 "to confirm this search was made by a human.</p>"
                 "<img src=\"/assets/anomaly/images/challenge.jpg\">"
                 "</body></html>")
DDG_SHELL = ("<html><body><div id=\"root\"></div>"
             "<script src=\"/static/app.js\"></script></body></html>")

DIRECT_MARKER_PAGE = ("<html><body><h1>People Search</h1>"
                      "<p>Sorry, no results found for that name. "
                      "Try a different spelling.</p></body></html>")
DIRECT_PRESENT_PAGE = ("<html><body><div class=\"card\">"
                       "<h2>Zztest Personman</h2>"
                       "<p>Pune, India</p></div></body></html>")
DIRECT_BLANK_PAGE = "<html><body><p>Loading search&hellip;</p></body></html>"


class StubFetcher:
    """fetcher(url) -> (status, text), dispatched on a URL
    substring; records every URL it was asked for."""

    def __init__(self, routes=None, default=(None, "")):
        self.routes = routes or {}
        self.default = default
        self.calls = []

    def __call__(self, url):
        self.calls.append(url)
        for needle, response in self.routes.items():
            if needle in url:
                if isinstance(response, Exception):
                    raise response
                return response
        return self.default


# ---------------------------------------------------------------------------
# Offline: the data file
# ---------------------------------------------------------------------------

class TestVerifySourcesData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = _load_json("verify_sources.json")
        cls.brokers = _load_json("brokers.json")

    def test_covers_exactly_the_40_broker_slugs(self):
        expected = {registry_seed.slugify(b["name"])
                    for b in self.brokers}
        self.assertEqual(len(self.brokers), 40)
        self.assertEqual(set(self.data), expected)

    def test_methods_valid_and_counted(self):
        counts = {"search_index": 0, "direct": 0, "none": 0}
        for slug, cfg in self.data.items():
            self.assertIn(cfg.get("method"), counts, slug)
            counts[cfg["method"]] += 1
        self.assertEqual(counts,
                         {"search_index": 26, "direct": 2, "none": 12})

    def test_every_entry_has_domain_and_research_note(self):
        for slug, cfg in self.data.items():
            self.assertTrue(cfg.get("domain"), slug)
            self.assertIn(".", cfg["domain"], slug)
            self.assertTrue((cfg.get("note") or "").strip(), slug)

    def test_direct_entries_have_name_addressable_templates(self):
        for slug, cfg in self.data.items():
            if cfg["method"] != "direct":
                continue
            self.assertTrue(cfg.get("url"), slug)
            self.assertTrue(
                "{name}" in cfg["url"] or "{first}" in cfg["url"], slug)
            self.assertTrue(
                cfg["url"].startswith("https://" + "www." + cfg["domain"])
                or cfg["url"].startswith("https://" + cfg["domain"]),
                slug)

    def test_search_index_and_none_have_no_url(self):
        # A stored URL would end up in brokers.search_url via the
        # seed; only direct brokers may carry one.
        for slug, cfg in self.data.items():
            if cfg["method"] != "direct":
                self.assertNotIn("url", cfg, slug)

    def test_the_two_direct_brokers_are_the_confirmed_pair(self):
        direct = {slug for slug, cfg in self.data.items()
                  if cfg["method"] == "direct"}
        self.assertEqual(direct,
                         {"truepeoplesearch", "fastpeoplesearch"})


class TestConfigFor(unittest.TestCase):
    def test_by_registry_row_and_by_slug(self):
        by_row = verify_sources.config_for({"slug": "spokeo", "id": 1})
        by_slug = verify_sources.config_for("spokeo")
        self.assertEqual(by_row, by_slug)
        self.assertEqual(by_slug["method"], "search_index")

    def test_unmapped_and_empty(self):
        self.assertIsNone(verify_sources.config_for("no-such-broker"))
        self.assertIsNone(verify_sources.config_for({}))
        self.assertIsNone(verify_sources.config_for(None))

    def test_returned_config_is_a_copy(self):
        cfg = verify_sources.config_for("spokeo")
        cfg["method"] = "mutated"
        self.assertEqual(
            verify_sources.config_for("spokeo")["method"], "search_index")


# ---------------------------------------------------------------------------
# Offline: verify_search with a stubbed fetcher
# ---------------------------------------------------------------------------

class TestVerifySearchEngine(unittest.TestCase):
    def setUp(self):
        # The direct-verify path passes the SSRF DNS guard
        # (core/ssrf.py) before fetching; the guard resolves for
        # real, and this sandbox's DNS is intercepted (public
        # names land on the benchmarking range, which the guard
        # rightly rejects). Stub the guard's single resolver patch
        # point to a public address so these offline tests exercise
        # the verdict logic, not the sandbox's DNS.
        import ipaddress
        from unittest import mock

        from core import ssrf as ssrf_mod
        patcher = mock.patch.object(
            ssrf_mod, "resolve_host",
            lambda host: [ipaddress.ip_address("93.184.216.34")])
        patcher.start()
        self.addCleanup(patcher.stop)

    def executor(self, fetcher):
        return engine_mod.AgentExecutor(fetcher=fetcher)

    # ---- search_index ----
    def test_index_broker_result_is_still_present(self):
        fetcher = StubFetcher(default=(200, DDG_PRESENT_SPOKEO))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "still_present")
        self.assertEqual(result["method"], "search_index")
        self.assertTrue(result["evidence_ref"].startswith(
            "https://html.duckduckgo.com/html/?q="))
        self.assertIn("site%3Aspokeo.com", fetcher.calls[0])
        self.assertIn("%22Zztest+Personman%22", fetcher.calls[0])
        self.assertIn("Pune", fetcher.calls[0])  # city is a plain term

    def test_index_subdomain_result_counts(self):
        fetcher = StubFetcher(default=(200, DDG_SUBDOMAIN))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "still_present")

    def test_index_results_page_without_broker_is_gone(self):
        fetcher = StubFetcher(default=(200, DDG_ABSENT))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "gone")

    def test_index_zero_hit_page_is_gone(self):
        fetcher = StubFetcher(default=(200, DDG_ZERO))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "gone")

    def test_index_challenge_page_is_unknown(self):
        fetcher = StubFetcher(default=(200, DDG_CHALLENGE))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "unknown")

    def test_index_empty_shell_is_unknown(self):
        fetcher = StubFetcher(default=(200, DDG_SHELL))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "unknown")

    def test_index_fetch_failures_are_unknown(self):
        for response in ((None, ""), (403, "walled"), (503, "")):
            fetcher = StubFetcher(default=response)
            result = self.executor(fetcher).verify_search(
                PROFILE, {"slug": "spokeo"})
            self.assertEqual(result["outcome"], "unknown", response)
        fetcher = StubFetcher(default=RuntimeError("boom"))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "unknown")

    # ---- direct ----
    def test_direct_404_is_gone(self):
        fetcher = StubFetcher(default=(404, "not here"))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "truepeoplesearch"})
        self.assertEqual(result["outcome"], "gone")
        self.assertEqual(result["method"], "broker_search")

    def test_direct_no_results_phrase_is_gone(self):
        fetcher = StubFetcher(default=(200, DIRECT_MARKER_PAGE))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "fastpeoplesearch"})
        self.assertEqual(result["outcome"], "gone")

    def test_direct_name_on_page_is_still_present(self):
        fetcher = StubFetcher(default=(200, DIRECT_PRESENT_PAGE))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "truepeoplesearch"})
        self.assertEqual(result["outcome"], "still_present")

    def test_direct_blank_200_is_unknown(self):
        fetcher = StubFetcher(default=(200, DIRECT_BLANK_PAGE))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "fastpeoplesearch"})
        self.assertEqual(result["outcome"], "unknown")

    def test_direct_error_status_is_unknown(self):
        fetcher = StubFetcher(default=(403, "Access Denied"))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "fastpeoplesearch"})
        self.assertEqual(result["outcome"], "unknown")

    def test_direct_template_substitution_encodes(self):
        fetcher = StubFetcher(default=(200, DIRECT_PRESENT_PAGE))
        self.executor(fetcher).verify_search(
            PROFILE, {"slug": "truepeoplesearch"})
        self.assertEqual(
            fetcher.calls[0],
            "https://www.truepeoplesearch.com/results?"
            "name=Zztest%20Personman")
        fetcher2 = StubFetcher(default=(200, DIRECT_PRESENT_PAGE))
        self.executor(fetcher2).verify_search(
            PROFILE, {"slug": "fastpeoplesearch"})
        self.assertEqual(
            fetcher2.calls[0],
            "https://www.fastpeoplesearch.com/name/Zztest-Personman")

    # ---- the never-guess cases ----
    def test_none_broker_never_fetches(self):
        fetcher = StubFetcher(default=(200, DIRECT_PRESENT_PAGE))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "acxiom"})
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(result["method"], "none")
        self.assertEqual(fetcher.calls, [])

    def test_unmapped_broker_is_unknown(self):
        fetcher = StubFetcher(default=(200, DIRECT_PRESENT_PAGE))
        result = self.executor(fetcher).verify_search(
            PROFILE, {"slug": "no-such-broker"})
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(result["method"], "unconfigured")
        self.assertEqual(fetcher.calls, [])

    def test_no_name_in_profile_is_unknown_without_fetching(self):
        fetcher = StubFetcher(default=(200, DDG_PRESENT_SPOKEO))
        profile = dict(PROFILE, full_name="   ")
        result = self.executor(fetcher).verify_search(
            profile, {"slug": "spokeo"})
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(fetcher.calls, [])


class TestVerifyClassificationMatrix(unittest.TestCase):
    """Phase 137 — the full verify classification matrix, pinned
    state by state. TestVerifySearchEngine above pins the core
    cases; this class pins the states a reader could still doubt,
    above all the honesty rule: AMBIGUOUS evidence (timeout,
    blocked, unexpected content, guard refusal) is 'unknown',
    NEVER 'gone' (removed) and never 'still_present'. A false
    'gone' would tell a person their data was deleted when it was
    not checked at all.

    States are driven at the classifier's input seam (the injected
    fetcher), with recorded-shape pages:

      evidence                              search_index   direct
      ------------------------------------  -------------  ----------
      broker result / profile name present  still_present  still_present
      results without broker / 404 / phrase gone           gone
      fetch returns nothing (unreachable)   unknown        unknown
      transport timeout                     unknown        unknown
      HTTP 403/503 (blocked)                unknown        unknown
      200 with unexpected content           unknown        unknown
      SSRF guard refuses the target URL     (n/a)          unknown
    """

    def setUp(self):
        # Same resolver stub as TestVerifySearchEngine.setUp, for
        # the same reason: the direct path's SSRF pre-check
        # resolves for real, and this sandbox's intercepted DNS
        # would mask the verdict logic under test. The refusal
        # cell below re-patches the resolver to a private address
        # inside its own block.
        import ipaddress
        from unittest import mock

        from core import ssrf as ssrf_mod
        patcher = mock.patch.object(
            ssrf_mod, "resolve_host",
            lambda host: [ipaddress.ip_address("93.184.216.34")])
        patcher.start()
        self.addCleanup(patcher.stop)

    def executor(self, fetcher):
        return engine_mod.AgentExecutor(fetcher=fetcher)

    def test_timeouts_are_unknown_never_a_verdict(self):
        import socket
        for exc in (TimeoutError("timed out"),
                    socket.timeout("timed out")):
            for slug in ("spokeo", "fastpeoplesearch"):
                result = self.executor(
                    StubFetcher(default=exc)).verify_search(
                        PROFILE, {"slug": slug})
                self.assertEqual(result["outcome"], "unknown",
                                 (exc, slug))

    def test_blocked_statuses_are_unknown_for_direct(self):
        for status in (401, 403, 429, 500, 503):
            result = self.executor(
                StubFetcher(default=(status, "walled"))
            ).verify_search(PROFILE, {"slug": "fastpeoplesearch"})
            self.assertEqual(result["outcome"], "unknown", status)

    def test_unexpected_content_is_unknown(self):
        # A 200 page full of real but unrelated content: no broker
        # result in the index, no profile name at the broker.
        page = ("<html><body><h1>Welcome to our new homepage</h1>"
                "<p>We redesigned everything this spring.</p>"
                "</body></html>")
        for slug in ("spokeo", "fastpeoplesearch"):
            result = self.executor(
                StubFetcher(default=(200, page))).verify_search(
                    PROFILE, {"slug": slug})
            self.assertEqual(result["outcome"], "unknown", slug)

    def test_direct_ssrf_refusal_is_unknown(self):
        # If the SSRF guard refuses the verification URL itself
        # (here: the name suddenly resolves private), the outcome
        # is unknown — the fetcher is never even called.
        import ipaddress
        from unittest import mock as _mock
        from core import ssrf as ssrf_mod
        fetcher = StubFetcher(default=(200, DIRECT_PRESENT_PAGE))
        with _mock.patch.object(
                ssrf_mod, "resolve_host",
                lambda host: [ipaddress.ip_address("10.0.0.9")]):
            result = self.executor(fetcher).verify_search(
                PROFILE, {"slug": "fastpeoplesearch"})
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(fetcher.calls, [])

    def test_found_and_not_found_still_hold(self):
        # The two verdicts, restated inside the matrix so the
        # table above is executable end to end.
        self.assertEqual(
            self.executor(StubFetcher(default=(
                200, DDG_PRESENT_SPOKEO))).verify_search(
                    PROFILE, {"slug": "spokeo"})["outcome"],
            "still_present")
        self.assertEqual(
            self.executor(StubFetcher(default=(
                200, DDG_ABSENT))).verify_search(
                    PROFILE, {"slug": "spokeo"})["outcome"],
            "gone")
        self.assertEqual(
            self.executor(StubFetcher(default=(
                200, DIRECT_PRESENT_PAGE))).verify_search(
                    PROFILE, {"slug": "fastpeoplesearch"})["outcome"],
            "still_present")
        self.assertEqual(
            self.executor(StubFetcher(default=(
                200, DIRECT_MARKER_PAGE))).verify_search(
                    PROFILE, {"slug": "fastpeoplesearch"})["outcome"],
            "gone")


# ---------------------------------------------------------------------------
# pgserver: seed + the end-to-end verify flow
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


class DrainStubExecutor:
    """The worker-side stub: every form case probes fillable and
    submits cleanly, so cases reach 'submitted' deterministically."""

    FILLABLE_FORM = [{
        "action": "https://stub.invalid/optout", "method": "POST",
        "fields": [{"name": "email", "type": "email", "id": "",
                    "placeholder": ""}],
        "unmapped_fields": [],
    }]

    def probe(self, profile, broker):
        return {"reachable": True, "status": 200, "fillable": True,
                "forms": self.FILLABLE_FORM, "blockers": [],
                "payload_preview": {"email": profile.get("email", "")},
                "via": "stub"}

    def submit(self, profile, broker, probe):
        return {"ok": True, "status": 200}

    def verify_search(self, profile, broker):
        return {"outcome": "unknown", "evidence_ref": "stub://search"}


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestVerifySourcesDb(ServerMixin, unittest.TestCase):
    PASSWORD = "test-password-123"

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._saved_env = {k: os.environ.get(k) for k in ENV_KEYS}
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-verify-pg-")
        try:
            cls._pg = _pgserver.get_server(cls._pg_dir)
        except Exception:
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
        for k, v in cls._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

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

    def db_row(self, sql, params):
        with self.pool.connection() as conn:
            return conn.execute(sql, params).fetchone()

    def register(self):
        email = "ver-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def add_identifier(self, cookie, kind, value):
        status, _h, body = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": kind, "value": value},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, body)

    def submitted_cases(self, cookie):
        status, _h, body = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "automated_remediation", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        status, _h, body = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, body)
        stub = DrainStubExecutor()
        worked = 0
        while worked < 500 and worker_mod.run_once(stub):
            worked += 1
        status, _h, body = self.request_json(
            "GET", "/api/remediation/cases", cookie=cookie)
        self.assertEqual(status, 200, body)
        return {c["broker_name"]: c for c in body["cases"]}

    # ---------- seed ----------
    def test_seed_stores_only_direct_search_urls(self):
        self.assertEqual(self.seeded, 40)
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM brokers"
            " WHERE search_url IS NOT NULL", ())
        self.assertEqual(row["n"], 2)
        tps = self.db_row(
            "SELECT search_url FROM brokers"
            " WHERE slug = 'truepeoplesearch'", ())
        self.assertEqual(
            tps["search_url"],
            "https://www.truepeoplesearch.com/results?name={name}")
        fps = self.db_row(
            "SELECT search_url FROM brokers"
            " WHERE slug = 'fastpeoplesearch'", ())
        self.assertEqual(
            fps["search_url"],
            "https://www.fastpeoplesearch.com/name/{first}-{last}")
        for slug in ("spokeo", "acxiom", "whitepages"):
            row = self.db_row(
                "SELECT search_url FROM brokers WHERE slug = %s",
                (slug,))
            self.assertIsNone(row["search_url"], slug)
        # Idempotent: re-seeding keeps exactly the same picture.
        registry_seed.seed_brokers()
        row = self.db_row(
            "SELECT COUNT(*) AS n FROM brokers"
            " WHERE search_url IS NOT NULL", ())
        self.assertEqual(row["n"], 2)

    # ---------- the verify flow ----------
    def test_verify_via_search_index_end_to_end(self):
        cookie, uid = self.register()
        self.add_identifier(cookie, "name", "Zztest Personman")
        self.add_identifier(cookie, "address", "12 Test Lane, Pune, India")
        cases = self.submitted_cases(cookie)
        spokeo = cases["Spokeo"]
        truthfinder = cases["TruthFinder"]
        self.assertEqual(spokeo["status"], "submitted")
        self.assertEqual(truthfinder["status"], "submitted")

        fetcher = StubFetcher(routes={
            "spokeo": (200, DDG_ABSENT),        # index: listing gone
            "truthfinder": (200, _ddg_page(
                "https://www.truthfinder.com/Zztest-Personman")),
        })
        executor = engine_mod.AgentExecutor(fetcher=fetcher)

        result = verify_mod.verify_case(uid, spokeo["id"],
                                        executor=executor)
        self.assertEqual(result["outcome"], "gone")
        self.assertEqual(result["case"]["status"], "verified_removed")
        check = self.db_row(
            "SELECT method, outcome, evidence_ref FROM"
            " verification_checks WHERE case_id = %s",
            (spokeo["id"],))
        self.assertEqual(check["method"], "search_index")
        self.assertEqual(check["outcome"], "gone")
        self.assertTrue(check["evidence_ref"].startswith(
            "https://html.duckduckgo.com/html/?q="))

        result = verify_mod.verify_case(uid, truthfinder["id"],
                                        executor=executor)
        self.assertEqual(result["outcome"], "still_present")
        self.assertEqual(result["case"]["status"], "submitted")
        self.assertEqual(result["case"]["reason"], "still_listed")
        check = self.db_row(
            "SELECT method, outcome FROM verification_checks"
            " WHERE case_id = %s", (truthfinder["id"],))
        self.assertEqual(check["method"], "search_index")
        self.assertEqual(check["outcome"], "still_present")


if __name__ == "__main__":
    unittest.main()
