"""Stage S4 provider tests: adapter contracts, the shared HTTP helper
(timeout / retry / circuit breaker), the registry, provider health,
and mock-mode scanning. Fully offline — every network path runs through
a scripted fake transport.

Run:  python3 -m unittest discover -s tests
"""

import hashlib
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from providers import registry as registry_mod  # noqa: E402
from providers.base import (  # noqa: E402
    HttpClient, ProviderResult, TransportNetworkError, TransportTimeout)
from providers.hibp_passwords import HibpPasswordsProvider  # noqa: E402
from providers.mock import MockProvider  # noqa: E402
from providers.registry import HealthTracker, Registry  # noqa: E402
from providers.xposedornot import XposedOrNotProvider  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

LEGACY_SCAN_FIELDS = {
    "email", "breaches", "breach_count", "breach_error", "analytics",
    "password_pwned_count", "exposure_score", "sources",
}


# ---------------- fakes ----------------

class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeSleep:
    def __init__(self, clock):
        self.clock = clock
        self.delays = []

    def __call__(self, delay):
        self.delays.append(delay)
        self.clock.advance(delay)


class FakeTransport:
    """Scripted transport: each entry is ("raise", exc) or
    ("respond", status, text). Records every URL it was called with."""

    def __init__(self, script):
        self.script = list(script)
        self.urls = []

    def __call__(self, url, headers, timeout):
        self.urls.append(url)
        if not self.script:
            raise AssertionError("transport called more times than scripted")
        step = self.script.pop(0)
        if step[0] == "raise":
            raise step[1]
        return step[1], step[2]


def make_client(script, **kwargs):
    clock = FakeClock()
    sleep = FakeSleep(clock)
    transport = FakeTransport(script)
    health = HealthTracker()
    client = HttpClient("TestProvider", health=health, transport=transport,
                        sleep=sleep, clock=clock, **kwargs)
    return client, transport, sleep, clock, health


# ---------------- HttpClient: retries, errors, breaker ----------------

class TestHttpClient(unittest.TestCase):
    def test_success_json_first_try(self):
        client, transport, sleep, _clock, health = make_client(
            [("respond", 200, '{"a": 1}')])
        result = client.get_json("https://example.test/x")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, {"a": 1})
        self.assertEqual(len(transport.urls), 1)
        self.assertEqual(sleep.delays, [])
        snap = health.snapshot("TestProvider")
        self.assertEqual(snap["successes"], 1)
        self.assertEqual(snap["failures"], 0)

    def test_timeout_retried_then_success(self):
        client, transport, sleep, _clock, _h = make_client(
            [("raise", TransportTimeout("t")),
             ("respond", 200, '{"ok": true}')])
        result = client.get_json("https://example.test/x")
        self.assertEqual(result.status, "ok")
        self.assertEqual(len(transport.urls), 2)
        self.assertEqual(sleep.delays, [0.5])

    def test_network_error_retried(self):
        client, transport, sleep, _clock, _h = make_client(
            [("raise", TransportNetworkError("boom")),
             ("respond", 200, "hello")])
        result = client.get_text("https://example.test/x")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, "hello")
        self.assertEqual(sleep.delays, [0.5])

    def test_4xx_never_retried(self):
        client, transport, sleep, _clock, health = make_client(
            [("respond", 404, "nope")])
        result = client.get_json("https://example.test/x")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_kind, "http_4xx")
        self.assertEqual(len(transport.urls), 1)
        self.assertEqual(sleep.delays, [])
        self.assertEqual(health.snapshot("TestProvider")["last_error_kind"],
                         "http_4xx")

    def test_5xx_retries_exhausted(self):
        client, transport, sleep, _clock, _h = make_client(
            [("respond", 500, "x"), ("respond", 502, "x"),
             ("respond", 503, "x")])
        result = client.get_text("https://example.test/x")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_kind, "http_5xx")
        self.assertEqual(len(transport.urls), 3)
        self.assertEqual(sleep.delays, [0.5, 1.5])

    def test_timeout_status_after_exhaustion(self):
        client, _t, _s, _c, _h = make_client(
            [("raise", TransportTimeout("t"))] * 3)
        result = client.get_text("https://example.test/x")
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.error_kind, "timeout")

    def test_bad_json_is_an_error(self):
        client, transport, _s, _c, _h = make_client(
            [("respond", 200, "{not json")])
        result = client.get_json("https://example.test/x")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_kind, "bad_response")
        self.assertEqual(len(transport.urls), 1)

    def test_circuit_opens_after_three_failures_and_rejects_fast(self):
        client, transport, _s, _c, health = make_client(
            [("raise", TransportNetworkError("x"))] * 3, max_retries=0)
        for _ in range(3):
            self.assertEqual(
                client.get_text("https://example.test/x").status, "error")
        self.assertEqual(client.circuit_state(), "open")
        result = client.get_text("https://example.test/x")
        self.assertEqual(result.status, "circuit_open")
        self.assertEqual(result.error_kind, "circuit_open")
        self.assertEqual(len(transport.urls), 3)  # no 4th network call

    def test_half_open_probe_closes_on_success(self):
        script = [("raise", TransportNetworkError("x"))] * 3 + [
            ("respond", 200, "back"), ("respond", 200, "flowing")]
        client, transport, _s, clock, _h = make_client(script, max_retries=0)
        for _ in range(3):
            client.get_text("https://example.test/x")
        self.assertEqual(client.circuit_state(), "open")
        clock.advance(61)
        self.assertEqual(client.circuit_state(), "half_open")
        self.assertEqual(client.get_text("https://example.test/x").status, "ok")
        self.assertEqual(client.circuit_state(), "closed")
        self.assertEqual(client.get_text("https://example.test/x").data,
                         "flowing")

    def test_half_open_failure_reopens(self):
        script = [("raise", TransportNetworkError("x"))] * 4
        client, transport, _s, clock, _h = make_client(script, max_retries=0)
        for _ in range(3):
            client.get_text("https://example.test/x")
        clock.advance(61)
        self.assertEqual(
            client.get_text("https://example.test/x").status, "error")
        self.assertEqual(client.circuit_state(), "open")
        self.assertEqual(
            client.get_text("https://example.test/x").status, "circuit_open")
        self.assertEqual(len(transport.urls), 4)


# ---------------- adapter contracts (fake transport) ----------------

def make_provider(cls, script):
    clock = FakeClock()
    transport = FakeTransport(script)
    health = HealthTracker()
    client = HttpClient(cls.info.name, health=health, transport=transport,
                        sleep=FakeSleep(clock), clock=clock, max_retries=0)
    return cls(health=health, client=client), transport


class TestXposedOrNotAdapter(unittest.TestCase):
    def test_check_email_flattens_nested_breaches(self):
        provider, _t = make_provider(XposedOrNotProvider, [(
            "respond", 200,
            json.dumps({"breaches": [["Adobe", "LinkedIn"], ["Dropbox"]]}))])
        result = provider.check_email("someone@example.com")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, ["Adobe", "LinkedIn", "Dropbox"])

    def test_check_email_error_payload_means_clean(self):
        provider, _t = make_provider(XposedOrNotProvider, [(
            "respond", 200, json.dumps({"Error": "Not found"}))])
        result = provider.check_email("clean@example.com")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, [])

    def test_check_email_failure_propagates(self):
        provider, _t = make_provider(XposedOrNotProvider,
                                     [("respond", 503, "down")])
        result = provider.check_email("someone@example.com")
        self.assertEqual(result.status, "error")
        self.assertEqual(result.error_kind, "http_5xx")
        self.assertIsNone(result.data)

    def test_analytics_parsing(self):
        payload = {"BreachMetrics": {
            "risk": [{"risk_label": "High", "risk_score": 80}],
            "xposed_data": [{"name": "data", "children": [
                {"name": "data_emails"}, {"name": "data_passwords"}]}],
            "passwords_strength": [{"score": 3}],
        }}
        provider, _t = make_provider(XposedOrNotProvider, [(
            "respond", 200, json.dumps(payload))])
        result = provider.breach_analytics("someone@example.com")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data["risk_label"], "High")
        self.assertEqual(result.data["risk_score"], 80)
        self.assertEqual(result.data["exposed_data"], ["emails", "passwords"])
        self.assertEqual(result.data["passwords_strength"], {"score": 3})

    def test_analytics_no_metrics(self):
        provider, _t = make_provider(XposedOrNotProvider, [(
            "respond", 200, json.dumps({"BreachMetrics": None}))])
        result = provider.breach_analytics("clean@example.com")
        self.assertEqual(result.status, "ok")
        self.assertIsNone(result.data)


class TestHibpAdapter(unittest.TestCase):
    def test_check_range_sends_only_the_prefix(self):
        provider, transport = make_provider(HibpPasswordsProvider, [(
            "respond", 200, "AAAA:3\nBBBB:9")])
        result = provider.check_range("ABCDE")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, "AAAA:3\nBBBB:9")
        self.assertTrue(transport.urls[0].endswith("/range/ABCDE"))


class TestAppPasswordWrapper(unittest.TestCase):
    """app.check_password_pwned keeps the legacy contract on top of
    whatever provider the registry hands it."""

    class _Stub:
        def __init__(self, result):
            self._result = result

        def get_providers(self, capability):
            assert capability == "password_range"
            return [self]

        def check_range(self, prefix):
            return self._result

    def tearDown(self):
        registry_mod.reset_registry()

    def test_count_parsed_from_range_text(self):
        suffix = hashlib.sha1(b"hunter2").hexdigest().upper()[5:]
        text = "0" * 35 + ":1\n%s:7" % suffix
        registry_mod.reset_registry(self._Stub(
            ProviderResult(status="ok", data=text)))
        self.assertEqual(app.check_password_pwned("hunter2"), 7)
        self.assertEqual(app.check_password_pwned("some-other-password"), 0)

    def test_provider_failure_returns_none(self):
        registry_mod.reset_registry(self._Stub(
            ProviderResult(status="timeout", error_kind="timeout")))
        self.assertIsNone(app.check_password_pwned("hunter2"))


# ---------------- registry + mock contract ----------------

class TestRegistry(unittest.TestCase):
    def assert_metadata_complete(self, reg):
        self.assertTrue(reg.providers)
        for provider in reg.providers:
            info = provider.info
            self.assertTrue(info.name)
            self.assertTrue(info.category)
            self.assertTrue(info.capabilities)
            self.assertTrue(info.privacy)
            self.assertEqual(info.cost_model, "free")

    def test_real_registry_metadata_and_capabilities(self):
        reg = Registry("real")
        self.assert_metadata_complete(reg)
        self.assertEqual(
            [p.info.name for p in reg.get_providers("email_breach")],
            ["XposedOrNot"])
        self.assertEqual(
            [p.info.name for p in reg.get_providers("breach_analytics")],
            ["XposedOrNot"])
        self.assertEqual(len(reg.get_providers("password_range")), 1)
        summary = reg.summary()
        self.assertEqual(summary["mode"], "real")
        for entry in summary["providers"]:
            self.assertEqual(entry["status"], "up")
            self.assertEqual(entry["successes"], 0)
            self.assertEqual(entry["failures"], 0)
            self.assertIsNone(entry["last_latency_ms"])

    def test_mock_registry_metadata_and_status(self):
        reg = Registry("mock")
        self.assert_metadata_complete(reg)
        for capability in ("email_breach", "breach_analytics",
                           "password_range"):
            providers = reg.get_providers(capability)
            self.assertEqual(len(providers), 1)
            self.assertIsInstance(providers[0], MockProvider)
        summary = reg.summary()
        self.assertEqual(summary["mode"], "mock")
        self.assertEqual(summary["providers"][0]["status"], "mock")

    def test_mock_provider_contract(self):
        mock = MockProvider(health=HealthTracker())
        breached = mock.check_email("breached@example.com")
        self.assertEqual(breached.status, "ok")
        self.assertEqual(breached.data, ["MockBreach2024", "MockComboList"])
        self.assertEqual(mock.check_email("clean@example.com").data, [])
        analytics = mock.breach_analytics("breached@example.com")
        self.assertEqual(analytics.data["risk_score"], 72)
        self.assertIsNone(mock.breach_analytics("clean@example.com").data)
        range_result = mock.check_range("ABCDE")
        self.assertEqual(range_result.status, "ok")
        suffix = hashlib.sha1(b"mockpwned").hexdigest().upper()[5:]
        self.assertIn("%s:123456" % suffix, range_result.data)


# ---------------- HTTP surface ----------------

class ServerCase(unittest.TestCase):
    @classmethod
    def boot(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def stop(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request_json(self, method, path, body=None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=headers, method=method)
        try:
            with OPENER.open(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))


class TestProvidersHealthEndpoint(ServerCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_env = os.environ.pop("LEAKGUARD_PROVIDERS", None)
        registry_mod.reset_registry()
        cls.boot()

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        if cls._saved_env is not None:
            os.environ["LEAKGUARD_PROVIDERS"] = cls._saved_env
        registry_mod.reset_registry()

    def test_health_shape_real_mode(self):
        status, body = self.request_json("GET", "/api/providers/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "real")
        names = [p["name"] for p in body["providers"]]
        self.assertIn("XposedOrNot", names)
        for entry in body["providers"]:
            for key in ("name", "category", "capabilities", "status",
                        "successes", "failures", "last_latency_ms"):
                self.assertIn(key, entry)
            self.assertIn(entry["status"],
                          ("up", "degraded", "down", "circuit_open", "mock"))


class TestMockModeScan(ServerCase):
    @classmethod
    def setUpClass(cls):
        cls._saved_env = os.environ.get("LEAKGUARD_PROVIDERS")
        os.environ["LEAKGUARD_PROVIDERS"] = "mock"
        registry_mod.reset_registry()
        cls.boot()

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        if cls._saved_env is None:
            os.environ.pop("LEAKGUARD_PROVIDERS", None)
        else:
            os.environ["LEAKGUARD_PROVIDERS"] = cls._saved_env
        registry_mod.reset_registry()

    def test_health_reports_mock_mode(self):
        status, body = self.request_json("GET", "/api/providers/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["mode"], "mock")
        self.assertEqual(body["providers"][0]["status"], "mock")

    def test_scan_breached_fixture_exact_legacy_fields(self):
        status, body = self.request_json("POST", "/api/scan", body={
            "email": "breached@example.com", "password": "mockpwned"})
        self.assertEqual(status, 200)
        self.assertEqual(set(body.keys()), LEGACY_SCAN_FIELDS)
        self.assertEqual(body["breaches"],
                         ["MockBreach2024", "MockComboList"])
        self.assertEqual(body["breach_count"], 2)
        self.assertIsNone(body["breach_error"])
        self.assertEqual(body["analytics"]["risk_score"], 72)
        self.assertEqual(body["password_pwned_count"], 123456)
        # score: analytics 72, but pwned > 1000 forces at least 85
        self.assertEqual(body["exposure_score"], 85)
        self.assertEqual(body["sources"], [
            "XposedOrNot (email breaches)",
            "Have I Been Pwned Pwned Passwords (password, k-anonymity)"])

    def test_scan_clean_fixture(self):
        status, body = self.request_json("POST", "/api/scan", body={
            "email": "clean@example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(set(body.keys()), LEGACY_SCAN_FIELDS)
        self.assertEqual(body["breaches"], [])
        self.assertEqual(body["breach_count"], 0)
        self.assertIsNone(body["breach_error"])
        self.assertIsNone(body["analytics"])
        self.assertIsNone(body["password_pwned_count"])
        self.assertEqual(body["exposure_score"], 0)


if __name__ == "__main__":
    unittest.main()
