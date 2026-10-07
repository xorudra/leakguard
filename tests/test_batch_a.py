"""Final-spec Batch A tests (Phases 69, 70 depth).

* TestHstsHeaders — Strict-Transport-Security rides on EVERY
  response class the server emits: a 200 page, a 404, and an API
  error — because it is set in the one central header path
  (core/security.py via app.Handler._send).
* TestSsrfGuard — core.ssrf.assert_public_url with the resolver
  stubbed at its single patch point (core.ssrf.resolve_host):
  public passes; private / loopback / link-local / IPv6 loopback /
  mixed resolutions fail; literal private IPs fail without any
  resolution; non-http(s) schemes and unresolvable hosts fail.
* TestSsrfWiring — the guard is actually on the data-driven fetch
  paths: agent.submit_form refuses before any network I/O,
  agent.probe_broker refuses a registry URL on a private host,
  and the remediation direct-verify refuses before its fetcher
  is ever called.

Nothing here touches the network: literal IPs need no DNS, and
every hostname case runs against the stubbed resolver.

Run:  python3 -m unittest discover -s tests
"""

import ipaddress
import socket
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import agent  # noqa: E402
import app  # noqa: E402
from core import ssrf  # noqa: E402
from remediation import engine as engine_mod  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

PUBLIC = [ipaddress.ip_address("93.184.216.34")]


def stub_resolver(addresses):
    """Patch core.ssrf.resolve_host (the guard's patch point)."""
    return mock.patch.object(ssrf, "resolve_host", lambda host: addresses)


class TestHstsHeaders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
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

    def fetch(self, path):
        req = urllib.request.Request(self.base + path, method="GET")
        try:
            with OPENER.open(req, timeout=10) as resp:
                return resp.status, resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.headers

    def assert_hsts(self, path, expected_status):
        status, headers = self.fetch(path)
        self.assertEqual(status, expected_status, path)
        self.assertEqual(
            headers.get("Strict-Transport-Security"),
            "max-age=31536000; includeSubDomains", path)

    def test_hsts_on_200_page(self):
        self.assert_hsts("/", 200)

    def test_hsts_on_404(self):
        self.assert_hsts("/no-such-page-here", 404)

    def test_hsts_on_api_error(self):
        # No database in this environment, so the account route
        # answers the structured 503 db_unavailable error — an API
        # error response, not a page, and it must carry HSTS too.
        self.assert_hsts("/api/action-center", 503)


class TestSsrfGuard(unittest.TestCase):
    def test_public_host_passes(self):
        with stub_resolver(PUBLIC):
            self.assertIsNone(
                ssrf.assert_public_url("https://broker.example/optout"))

    def test_public_host_http_passes(self):
        with stub_resolver(PUBLIC):
            self.assertIsNone(
                ssrf.assert_public_url("http://broker.example/optout"))

    def test_private_resolution_rejected(self):
        with stub_resolver([ipaddress.ip_address("10.0.0.5")]):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("https://broker.example/optout")

    def test_loopback_resolution_rejected(self):
        with stub_resolver([ipaddress.ip_address("127.0.0.1")]):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("https://broker.example/optout")

    def test_link_local_resolution_rejected(self):
        # 169.254.169.254 — the cloud metadata address.
        with stub_resolver([ipaddress.ip_address("169.254.169.254")]):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("https://broker.example/optout")

    def test_ipv6_loopback_resolution_rejected(self):
        with stub_resolver([ipaddress.ip_address("::1")]):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("https://broker.example/optout")

    def test_mixed_resolution_rejected(self):
        mixed = PUBLIC + [ipaddress.ip_address("192.168.1.20")]
        with stub_resolver(mixed):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("https://broker.example/optout")

    def test_literal_private_ip_rejected_without_resolving(self):
        def explode(host):  # must never be called for literal IPs
            raise AssertionError("resolver called for a literal IP")
        with mock.patch.object(ssrf, "resolve_host", explode):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("http://192.168.0.9/admin")
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("http://[::1]/admin")

    def test_literal_public_ip_passes_without_resolving(self):
        def explode(host):
            raise AssertionError("resolver called for a literal IP")
        with mock.patch.object(ssrf, "resolve_host", explode):
            self.assertIsNone(
                ssrf.assert_public_url("https://8.8.8.8/optout"))

    def test_non_http_schemes_rejected(self):
        with stub_resolver(PUBLIC):
            for url in ("ftp://broker.example/x", "file:///etc/passwd",
                        "gopher://broker.example/"):
                with self.assertRaises(ssrf.SsrfError, msg=url):
                    ssrf.assert_public_url(url)

    def test_unresolvable_host_rejected(self):
        def dead(host):
            raise socket.gaierror("no such host")
        with mock.patch.object(ssrf, "resolve_host", dead):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url("https://gone.example/optout")

    def test_url_credentials_rejected(self):
        with stub_resolver(PUBLIC):
            with self.assertRaises(ssrf.SsrfError):
                ssrf.assert_public_url(
                    "https://user:pass@broker.example/optout")

    def test_ssrf_error_is_a_value_error(self):
        self.assertTrue(issubclass(ssrf.SsrfError, ValueError))


class TestSsrfWiring(unittest.TestCase):
    def test_submit_form_refuses_literal_private_target(self):
        result = agent.submit_form(
            "http://127.0.0.1:9/optout", "POST", {"name": "Zztest"})
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "ssrf_guard")

    def test_submit_form_refuses_host_resolving_private(self):
        with stub_resolver([ipaddress.ip_address("10.1.2.3")]):
            result = agent.submit_form(
                "https://sneaky-broker.example/submit", "POST", {})
        self.assertEqual(result["ok"], False)
        self.assertEqual(result["error"], "ssrf_guard")

    def test_probe_broker_refuses_private_registry_url(self):
        broker = {"name": "Zztest Broker",
                  "optout_url": "http://192.168.50.7/optout"}
        with mock.patch.object(agent, "load_brokers",
                               lambda: [broker]), \
                mock.patch.object(
                    agent, "get_playbook",
                    lambda b: {"automation": "http_form", "needs": []}):
            result = agent.probe_broker("Zztest Broker", {})
        self.assertFalse(result["reachable"])
        self.assertTrue(
            any("safety check" in b for b in result["blockers"]),
            result["blockers"])

    def test_direct_verify_refuses_before_fetching(self):
        calls = []

        def fetcher(url):
            calls.append(url)
            return 200, "Zztest Personman"

        executor = engine_mod.AgentExecutor(fetcher=fetcher)
        with stub_resolver([ipaddress.ip_address("172.16.0.8")]):
            result = executor.verify_search(
                {"full_name": "Zztest Personman"},
                {"slug": "truepeoplesearch"})
        self.assertEqual(result["outcome"], "unknown")
        self.assertEqual(result["method"], "broker_search")
        self.assertEqual(calls, [])  # the fetcher was never reached


if __name__ == "__main__":
    unittest.main()
