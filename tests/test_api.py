"""Offline API tests for LeakGuard (Stage S1 foundations).

Runs the real HTTP handler in-process on an ephemeral port. No network:
every test uses validation paths and local endpoints only, and the HTTP
client is built with an empty ProxyHandler so environment proxies can
never leak a test request outside localhost.

Run:  python3 -m unittest discover -s tests
"""

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402

# An opener that ignores http_proxy/https_proxy env vars entirely.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class ApiTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    # ---------- helpers ----------
    def request(self, method, path, body=None, raw=None):
        url = self.base + path
        data = raw
        headers = {}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with OPENER.open(req, timeout=10) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def request_json(self, method, path, body=None, raw=None):
        status, headers, payload = self.request(method, path, body=body, raw=raw)
        return status, headers, json.loads(payload.decode("utf-8"))

    def assert_security_headers(self, headers):
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(headers.get(name), value, "header %s" % name)
        csp = headers.get("Content-Security-Policy") or ""
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def assert_structured_error(self, status, headers, body, want_status, want_code):
        self.assertEqual(status, want_status)
        err = body.get("error")
        self.assertIsInstance(err, dict)
        self.assertEqual(err.get("code"), want_code)
        self.assertIsInstance(err.get("message"), str)
        self.assertTrue(err.get("message"))
        # request_id in the body must match the response header
        rid = headers.get("X-Request-Id")
        self.assertTrue(rid)
        self.assertEqual(err.get("request_id"), rid)
        self.assert_security_headers(headers)


class TestCoreEndpoints(ApiTestCase):
    def test_health(self):
        status, headers, body = self.request_json("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": True, "service": "leakguard"})
        rid = headers.get("X-Request-Id")
        self.assertTrue(rid)
        self.assertEqual(len(rid), 32)  # uuid4 hex
        int(rid, 16)
        self.assert_security_headers(headers)

    def test_home_page_and_security_headers(self):
        status, headers, payload = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers.get("Content-Type"))
        self.assertIn(b"LeakGuard", payload)
        self.assert_security_headers(headers)
        self.assertTrue(headers.get("X-Request-Id"))

    def test_head_request(self):
        # UptimeRobot regression: HEAD must not 501 (see app.py do_HEAD).
        status, headers, payload = self.request("HEAD", "/")
        self.assertEqual(status, 200)
        self.assertEqual(payload, b"")
        self.assert_security_headers(headers)

    def test_brokers_shape(self):
        status, headers, body = self.request_json("GET", "/api/brokers")
        self.assertEqual(status, 200)
        brokers = body.get("brokers")
        self.assertIsInstance(brokers, list)
        self.assertEqual(len(brokers), 40)
        for b in brokers:
            self.assertIn("name", b)
            self.assertIn("optout_url", b)

    def test_static_js_served(self):
        status, headers, payload = self.request("GET", "/static/app.js")
        self.assertEqual(status, 200)
        self.assertIn(b"errMsg", payload)  # current frontend build marker
        self.assert_security_headers(headers)


class TestStructuredErrors(ApiTestCase):
    def test_404_shape_and_request_id(self):
        status, headers, body = self.request_json("GET", "/no-such-route")
        self.assert_structured_error(status, headers, body, 404, "not_found")
        self.assertEqual(body["error"]["message"], "Not found")

    def test_bad_json_post(self):
        status, headers, body = self.request_json(
            "POST", "/api/scan", raw=b"{not json")
        self.assert_structured_error(status, headers, body, 400, "invalid_json")
        self.assertEqual(body["error"]["message"], "Invalid JSON")

    def test_non_object_json_post(self):
        status, headers, body = self.request_json(
            "POST", "/api/scan", raw=b"[1, 2, 3]")
        self.assert_structured_error(status, headers, body, 400, "invalid_json")

    def test_plan_missing_profile(self):
        status, headers, body = self.request_json("POST", "/api/agent/plan", body={})
        self.assert_structured_error(status, headers, body, 400, "missing_profile")

    def test_scan_invalid_email(self):
        status, headers, body = self.request_json(
            "POST", "/api/scan", body={"email": "not-an-email"})
        self.assert_structured_error(status, headers, body, 400, "invalid_email")

    def test_plan_success_has_no_free_lane(self):
        status, headers, body = self.request_json(
            "POST", "/api/agent/plan",
            body={"full_name": "Test Person", "email": "test@example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(len(body.get("plan", [])), 40)
        self.assertNotIn("free_lane", body)
        self.assertNotIn("free_lane", json.dumps(body))


class TestSubmitGuards(ApiTestCase):
    def test_submit_requires_confirm(self):
        status, headers, body = self.request_json(
            "POST", "/api/agent/submit",
            body={"broker": "Spokeo", "form_action": "https://www.spokeo.com/optout",
                  "method": "POST", "payload": {}})
        self.assert_structured_error(
            status, headers, body, 400, "confirmation_required")
        self.assertEqual(body["error"]["message"],
                         "Submission needs explicit confirmation")

    def test_submit_unknown_broker_host(self):
        status, headers, body = self.request_json(
            "POST", "/api/agent/submit",
            body={"confirm": True, "broker": "Spokeo",
                  "form_action": "https://evil.example.com/steal",
                  "method": "POST", "payload": {}})
        self.assert_structured_error(
            status, headers, body, 400, "unknown_broker_host")

    def test_submit_unknown_broker(self):
        status, headers, body = self.request_json(
            "POST", "/api/agent/submit",
            body={"confirm": True, "broker": "NoSuchBroker",
                  "form_action": "https://www.spokeo.com/optout",
                  "method": "POST", "payload": {}})
        self.assert_structured_error(
            status, headers, body, 400, "unknown_broker_host")

    def test_submit_bad_method(self):
        status, headers, body = self.request_json(
            "POST", "/api/agent/submit",
            body={"confirm": True, "broker": "Spokeo",
                  "form_action": "https://www.spokeo.com/optout",
                  "method": "DELETE", "payload": {}})
        self.assert_structured_error(
            status, headers, body, 400, "bad_submission")


if __name__ == "__main__":
    unittest.main()
