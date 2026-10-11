"""Launch Safety Standard G/H wave (2026-10-11) — regression pins.

* TestIdentifiersIndexPin — item 32: migration 0019 exists and
  defines the per-user identifiers index the audit found missing
  (every other per-user table already led with user_id; the list /
  export / retention queries on identifiers had no index to use).
* TestDiscoveryMetaPin — item 41: the app shell carries a meta
  description, a canonical URL and Open Graph basics (title and
  favicon already existed).
* TestBrowser404 — item 39: a browser navigation (Accept:
  text/html) to an unknown non-API path gets the readable HTML 404
  page, stamped no-store; API clients and /api/* routes keep the
  structured JSON error byte-for-byte in shape.
* TestPolicyTableFitPin — item 37: the production sweep found the
  privacy page's policy table overflowing a 320px viewport by
  18px; the small-screen CSS block must carry the fit rules (the
  live re-sweep is tools/mobile_viewport_check.py, now including
  a 320px viewport).

No pytest — unittest only, CI runs `python -m unittest discover
-s tests`. The HTTP class boots the app in-process and needs no
database: unknown routes never touch it.
"""

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
from db import migrate  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
REPO_ROOT = Path(__file__).resolve().parent.parent


class TestIdentifiersIndexPin(unittest.TestCase):
    def test_migration_0019_defines_user_index(self):
        names = [p.name for p in migrate.migration_files()]
        self.assertIn("0019_identifiers_user_idx.sql", names)
        sql = (REPO_ROOT / "db" / "migrations"
               / "0019_identifiers_user_idx.sql").read_text(
                   encoding="utf-8")
        self.assertIn("identifiers_user_created_idx", sql)
        self.assertIn("ON identifiers (user_id, created_at, id)", sql)

    def test_migration_0019_is_reversible_and_additive_only(self):
        sql = (REPO_ROOT / "db" / "migrations"
               / "0019_identifiers_user_idx.sql").read_text(
                   encoding="utf-8")
        # Comments document the undo; the only statement is the
        # additive CREATE INDEX (no DROP/ALTER anywhere).
        self.assertIn("DROP INDEX identifiers_user_created_idx", sql)
        body = "\n".join(
            line for line in sql.splitlines()
            if not line.strip().startswith("--"))
        self.assertNotIn("DROP", body)
        self.assertNotIn("ALTER", body)
        self.assertIn("CREATE INDEX", body)


class TestDiscoveryMetaPin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (REPO_ROOT / "static" / "index.html").read_text(
            encoding="utf-8")

    def test_meta_description_present(self):
        self.assertIn('<meta name="description"', self.html)

    def test_canonical_present(self):
        self.assertIn('<link rel="canonical"', self.html)
        self.assertIn("https://leakguard-hh8e.onrender.com/", self.html)

    def test_open_graph_basics_present(self):
        self.assertIn('<meta property="og:title"', self.html)
        self.assertIn('<meta property="og:description"', self.html)
        self.assertIn('<meta property="og:image"', self.html)


class TestPolicyTableFitPin(unittest.TestCase):
    def test_small_screen_policy_table_rules_exist(self):
        css = (REPO_ROOT / "static" / "style.css").read_text(
            encoding="utf-8")
        self.assertIn(".policyTable th,.policyTable td"
                      "{padding:7px 6px;overflow-wrap:anywhere}", css)


class TestBrowser404(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:%d" % cls.port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _get(self, path, headers=None):
        req = urllib.request.Request(self.base + path,
                                     headers=headers or {},
                                     method="GET")
        try:
            with OPENER.open(req, timeout=15) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()

    def test_browser_navigation_gets_html_404(self):
        status, headers, payload = self._get(
            "/no-such-page", headers={"Accept": "text/html"})
        self.assertEqual(status, 404)
        self.assertIn("text/html", headers.get("Content-Type") or "")
        self.assertIn(b"Page not found", payload)
        self.assertIn(b'href="/"', payload)
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_default_client_keeps_structured_json_404(self):
        status, headers, payload = self._get("/no-such-page")
        self.assertEqual(status, 404)
        self.assertIn("application/json",
                      headers.get("Content-Type") or "")
        body = json.loads(payload.decode("utf-8"))
        self.assertEqual(body["error"]["code"], "not_found")

    def test_api_route_keeps_json_even_for_browsers(self):
        status, headers, payload = self._get(
            "/api/no-such-thing", headers={"Accept": "text/html"})
        self.assertEqual(status, 404)
        self.assertIn("application/json",
                      headers.get("Content-Type") or "")
        body = json.loads(payload.decode("utf-8"))
        self.assertEqual(body["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
