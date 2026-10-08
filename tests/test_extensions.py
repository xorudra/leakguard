"""Extensions foundation tests (Stage S14 — spec Phases 100–104).

Layers:

* TestServingAndPwaFiles — no database: the PWA surface serves
  (manifest with the manifest media type, the service worker at
  BOTH /sw.js and /static/sw.js, icons as image/png) and /api/graph
  answers the same clean 503 as every other account route. Plus
  pure file assertions: the manifest JSON, the icon PNGs on disk
  (real dimensions, parsed from the IHDR with the stdlib), the
  service worker's rules as strings (shell list, versioned cache,
  the /api/* network-only rule), and index.html wiring.
* TestExtensionFiles — the extension as data: manifest parses,
  Manifest V3, permissions are exactly ["storage"], host
  permissions exactly the one production origin, no <all_urls>
  anywhere, no credential form fields anywhere (the extension is
  token-only by design), the only web origin referenced in code
  is the production one, and the popup/options hit the documented
  read endpoints.
* TestExtensionZip — the builder: manifest.json at the archive
  root, entries sorted with the fixed 1980 timestamp, and two
  builds byte-identical (determinism is the point of the builder).
* TestGraphDb — the graph against a local PostgreSQL provisioned
  with pip `pgserver` (skips honestly when unavailable) with mock
  providers: a seeded user's nodes/edges, masked labels only (the
  raw address appears NOWHERE in the payload), the S8-matched
  source→broker edge, Bearer-token access, and IDOR isolation.

Run:  python3 -m unittest discover -s tests
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import threading
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app  # noqa: E402
from accounts import ratelimit  # noqa: E402
from providers import registry as registry_mod  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
EXT = ROOT / "extension"
PROD_ORIGIN = "https://leakguard-hh8e.onrender.com"

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


def _png_size(path):
    data = Path(path).read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG: %s" % path
    return struct.unpack(">II", data[16:24])


# ---------------------------------------------------------------------------
# No-database layer: PWA serving + graph 503 + file assertions
# ---------------------------------------------------------------------------

class TestServingAndPwaFiles(ServerMixin, unittest.TestCase):
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

    def test_graph_503_without_database(self):
        status, _h, body = self.request_json("GET", "/api/graph")
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], "db_unavailable")

    def test_manifest_served_with_manifest_media_type(self):
        status, headers, payload = self.request(
            "GET", "/static/manifest.webmanifest")
        self.assertEqual(status, 200)
        self.assertIn("application/manifest+json",
                      headers.get("Content-Type"))
        doc = json.loads(payload.decode("utf-8"))
        self.assertEqual(doc["short_name"], "LeakGuard")

    def test_service_worker_served_at_root_and_static(self):
        for path in ("/sw.js", "/static/sw.js"):
            status, headers, payload = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn("javascript", headers.get("Content-Type"))
            self.assertIn(b"leakguard-shell-v2", payload)

    def test_icons_served_as_png(self):
        for name in ("icon-192.png", "icon-512.png"):
            status, headers, payload = self.request(
                "GET", "/static/icons/" + name)
            self.assertEqual(status, 200, name)
            self.assertEqual(headers.get("Content-Type"), "image/png")
            self.assertEqual(payload[:8], b"\x89PNG\r\n\x1a\n")

    # ----- pure file assertions -----
    def test_manifest_document(self):
        doc = json.loads(
            (STATIC / "manifest.webmanifest").read_text("utf-8"))
        self.assertEqual(doc["name"].split(" ")[0], "LeakGuard")
        self.assertEqual(doc["short_name"], "LeakGuard")
        self.assertEqual(doc["display"], "standalone")
        self.assertEqual(doc["theme_color"], "#000000")
        self.assertEqual(doc["background_color"], "#121212")
        sizes = set()
        for icon in doc["icons"]:
            self.assertTrue(icon["src"].startswith("/static/icons/"))
            sizes.add(icon["sizes"])
            w, h = _png_size(ROOT / icon["src"].lstrip("/"))
            self.assertEqual("%dx%d" % (w, h), icon["sizes"])
        self.assertEqual(sizes, {"192x192", "512x512"})

    def test_service_worker_rules(self):
        sw = (STATIC / "sw.js").read_text("utf-8")
        # Versioned cache name + the shell it may cache.
        self.assertIn('"leakguard-shell-v2"', sw)
        for shell_path in ("/", "/static/style.css", "/static/app.js",
                           "/static/manifest.webmanifest",
                           "/static/icons/icon-192.png",
                           "/static/icons/icon-512.png"):
            self.assertIn('"%s"' % shell_path, sw)
        # The hard rule: API traffic is network-only, never cached.
        self.assertIn('url.pathname.startsWith("/api/")', sw)
        self.assertIn("network-only", sw)

    def test_index_links_manifest_and_theme(self):
        html = (STATIC / "index.html").read_text("utf-8")
        self.assertIn('<link rel="manifest" '
                      'href="/static/manifest.webmanifest">', html)
        self.assertIn('<meta name="theme-color" content="#000000">', html)
        self.assertIn('id="graphWrap"', html)  # exposure map block

    def test_app_js_registers_worker_and_loads_graph(self):
        js = (STATIC / "app.js").read_text("utf-8")
        self.assertIn('navigator.serviceWorker.register("/sw.js")', js)
        self.assertIn('apiJson("/api/graph")', js)
        self.assertIn("renderGraph", js)


# ---------------------------------------------------------------------------
# The extension, as data
# ---------------------------------------------------------------------------

class TestExtensionFiles(unittest.TestCase):
    def _ext_files(self, suffixes):
        return [p for p in sorted(EXT.rglob("*"))
                if p.is_file() and p.suffix in suffixes
                and "dist" not in p.parts]

    def test_manifest_is_mv3_with_minimal_permissions(self):
        doc = json.loads((EXT / "manifest.json").read_text("utf-8"))
        self.assertEqual(doc["manifest_version"], 3)
        self.assertEqual(doc["permissions"], ["storage"])
        self.assertEqual(doc["host_permissions"],
                         [PROD_ORIGIN + "/*"])
        self.assertEqual(doc["action"]["default_popup"], "popup.html")
        self.assertEqual(doc["options_page"], "options.html")

    def test_no_all_urls_anywhere(self):
        for path in self._ext_files(
                (".json", ".js", ".html", ".css", ".md")):
            self.assertNotIn("<all_urls>", path.read_text("utf-8"),
                             str(path))

    def test_no_credential_fields_anywhere(self):
        # Token-only by design: no sign-in form fields of any kind.
        for path in self._ext_files((".json", ".js", ".html", ".css")):
            text = path.read_text("utf-8")
            self.assertNotIn('type="password"', text, str(path))
            self.assertNotIn("type='password'", text, str(path))

    def test_only_production_origin_in_code(self):
        origins = set()
        for path in self._ext_files((".json", ".js", ".html")):
            for match in re.findall(r"https?://[a-zA-Z0-9.-]+",
                                    path.read_text("utf-8")):
                origins.add(match)
        self.assertEqual(origins, {PROD_ORIGIN})

    def test_popup_and_options_use_the_read_api(self):
        shared = (EXT / "shared.js").read_text("utf-8")
        self.assertIn("chrome.storage.local", shared)
        self.assertIn('"Bearer " + token', shared)
        popup = (EXT / "popup.js").read_text("utf-8")
        self.assertIn('"/api/v1/action-center"', popup)
        self.assertIn("Open LeakGuard", (EXT / "popup.html")
                      .read_text("utf-8"))
        options_html = (EXT / "options.html").read_text("utf-8")
        self.assertIn("Privacy Center", options_html)
        self.assertIn("Test connection", options_html)
        options_js = (EXT / "options.js").read_text("utf-8")
        self.assertIn('"/api/v1/action-center"', options_js)

    def test_readme_is_honest_about_the_store(self):
        readme = (EXT / "README.md").read_text("utf-8")
        self.assertIn("Load unpacked", readme)
        self.assertIn("Developer mode", readme)
        self.assertIn("fee", readme)  # the store's paid gate, named
        self.assertIn("sideload", readme)


class TestExtensionZip(unittest.TestCase):
    def _load_builder(self):
        spec = importlib.util.spec_from_file_location(
            "build_extension_zip",
            ROOT / "tools" / "build_extension_zip.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_zip_shape_and_determinism(self):
        builder = self._load_builder()
        out = builder.build()
        first = out.read_bytes()
        with zipfile.ZipFile(out) as zf:
            names = zf.namelist()
            infos = zf.infolist()
        self.assertIn("manifest.json", names)
        self.assertEqual(names, sorted(names))
        self.assertEqual(names[0], "README.md")
        for info in infos:
            self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0),
                             info.filename)
            self.assertFalse(info.filename.startswith("dist/"))
        builder.build()
        second = out.read_bytes()
        self.assertEqual(hashlib.sha256(first).hexdigest(),
                         hashlib.sha256(second).hexdigest())


# ---------------------------------------------------------------------------
# The graph against a local PostgreSQL (pgserver) + mock providers
# ---------------------------------------------------------------------------

try:
    import pgserver as _pgserver
except Exception:  # pragma: no cover
    _pgserver = None


@unittest.skipUnless(_pgserver, "pgserver not installed")
class TestGraphDb(ServerMixin, unittest.TestCase):
    """One fresh database, one fixture owner: the identifier vault
    allows exactly one live owner per identifier value, so the
    seeded flow (breached@example.com) lives in a single test that
    walks the whole story — empty → scanned → cases → matched
    broker edge → Bearer access → IDOR."""

    PASSWORD = "correct-horse-9"

    @classmethod
    def setUpClass(cls):
        import tempfile

        keys = ENV_KEYS + ("LEAKGUARD_PROVIDERS",)
        cls._env = EnvGuard(keys).__enter__()
        cls._pg_dir = tempfile.mkdtemp(prefix="lg-graph-pg-")
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
        from remediation import registry_seed
        from scanning import worker

        cls.pool = pool
        cls.scan_worker = worker
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

    # ---------- helpers ----------
    def uniq(self):
        return uuid.uuid4().hex[:12]

    def register(self):
        email = "graph-%s@example.com" % self.uniq()
        status, headers, body = self.request_json(
            "POST", "/api/auth/register",
            body={"email": email, "password": self.PASSWORD},
            headers=CSRF)
        self.assertEqual(status, 201, body)
        return self.session_cookie(headers), body["user"]["id"]

    def graph(self, cookie=None, headers=None):
        return self.request_json("GET", "/api/graph", cookie=cookie,
                                 headers=headers)

    def test_unauthenticated_is_401(self):
        status, _h, body = self.graph()
        self.assertEqual(status, 401, body)
        self.assertEqual(body["error"]["code"], "unauthenticated")
        status, _h, body = self.graph(
            headers={"Authorization": "Bearer <redacted>"})
        self.assertEqual(status, 401, body)

    def test_seeded_graph_story(self):
        cookie, uid = self.register()

        # Fresh user: an honestly empty graph.
        status, _h, body = self.graph(cookie)
        self.assertEqual(status, 200, body)
        self.assertEqual(body, {
            "nodes": [], "edges": [],
            "propagation": {"entries": [], "rollups": []},
        })

        # Save the breached fixture address + scanning consent, scan.
        status, _h, ident = self.request_json(
            "POST", "/api/identifiers",
            body={"kind": "email", "value": "breached@example.com"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, ident)
        identifier_id = ident["identifier"]["id"]
        status, _h, _b = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "scanning", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        status, _h, job_body = self.request_json(
            "POST", "/api/scans",
            body={"idempotency_key": uuid.uuid4().hex},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, job_body)
        job_id = job_body["job"]["id"]
        for _ in range(50):
            status, _h, got = self.request_json(
                "GET", "/api/scans/" + job_id, cookie=cookie)
            self.assertEqual(status, 200, got)
            if got["job"]["status"] in ("done", "dead"):
                break
            self.assertTrue(self.scan_worker.run_once())
        self.assertEqual(got["job"]["status"], "done")

        # The graph after the scan: 1 identifier, 2 sources, 2 edges.
        status, _h, g = self.graph(cookie)
        self.assertEqual(status, 200, g)
        blob = json.dumps(g)
        self.assertNotIn("breached@example.com", blob)  # masked ONLY
        idents = [n for n in g["nodes"] if n["type"] == "identifier"]
        sources = [n for n in g["nodes"] if n["type"] == "source"]
        brokers = [n for n in g["nodes"] if n["type"] == "broker"]
        self.assertEqual(len(idents), 1)
        self.assertEqual(idents[0]["id"], "identifier:" + identifier_id)
        self.assertEqual(idents[0]["kind"], "email")
        self.assertEqual(idents[0]["label"], "b•••@example.com")
        self.assertEqual(
            sorted(n["label"] for n in sources),
            ["MockBreach2024", "MockComboList"])
        self.assertTrue(
            all(n["provider"] == "MockProvider" for n in sources))
        self.assertEqual(brokers, [])
        found_in = [e for e in g["edges"] if e["kind"] == "found_in"]
        self.assertEqual(len(found_in), 2)
        self.assertTrue(all(
            e["from"] == idents[0]["id"] for e in found_in))

        # The one removal command: a case per broker → broker nodes.
        status, _h, _b = self.request_json(
            "POST", "/api/consents",
            body={"purpose": "automated_remediation", "granted": True},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200)
        status, _h, run = self.request_json(
            "POST", "/api/remediation/run", body={},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 200, run)
        self.assertEqual(run["cases_created"], 40)
        status, _h, g = self.graph(cookie)
        brokers = [n for n in g["nodes"] if n["type"] == "broker"]
        self.assertEqual(len(brokers), 40)
        self.assertTrue(all(n["status"] == "queued" for n in brokers))
        spokeo = [n for n in brokers if n["slug"] == "spokeo"]
        self.assertEqual(len(spokeo), 1)
        self.assertEqual(spokeo[0]["label"], "Spokeo")
        # Mock breach names match no broker: still no removal edges.
        self.assertEqual(
            [e for e in g["edges"] if e["kind"] == "removal"], [])

        # A finding whose source IS the broker (the S8 rule) draws
        # the removal edge. Seeded straight into the latest job, as
        # a people-search provider's finding would land.
        with self.pool.connection() as conn:
            conn.execute(
                "INSERT INTO findings (job_id, user_id, identifier_id,"
                " identifier_kind, provider, source_name, source_url,"
                " confidence, reliability, evidence_ref)"
                " VALUES (%s, %s, %s, 'email', 'FixturePeople',"
                " 'Spokeo', 'https://www.spokeo.com/search',"
                " 'probable', 'medium', 'graph-fixture-ref')",
                (job_id, uid, identifier_id))
        status, _h, g = self.graph(cookie)
        self.assertEqual(status, 200, g)
        removal = [e for e in g["edges"] if e["kind"] == "removal"]
        self.assertEqual(removal, [{
            "from": "source:FixturePeople|Spokeo",
            "to": "broker:spokeo",
            "kind": "removal",
        }])
        spokeo_sources = [n for n in g["nodes"]
                          if n["type"] == "source"
                          and n["label"] == "Spokeo"]
        self.assertEqual(len(spokeo_sources), 1)

        # Propagation (Phases 104/152): the Spokeo source lists the
        # one matcher-accepted broker, with the queued case shown
        # as in_progress (and its exact ledger status alongside).
        # The mock breach sources match no broker and stay empty.
        prop = g["propagation"]
        by_source = {e["source"]["name"]: e for e in prop["entries"]}
        self.assertEqual(by_source["Spokeo"]["brokers"], [{
            "slug": "spokeo", "name": "Spokeo",
            "status": "in_progress", "case_status": "queued",
        }])
        self.assertEqual(by_source["MockBreach2024"]["brokers"], [])
        self.assertEqual(by_source["MockComboList"]["brokers"], [])
        self.assertEqual(len(prop["rollups"]), 1)
        self.assertEqual(prop["rollups"][0]["identifier"]["label"],
                         "b•••@example.com")
        self.assertEqual(prop["rollups"][0]["counts"], {
            "verified_removed": 0, "submitted": 0, "in_progress": 1,
            "needs_human": 0, "blocked": 0, "not_started": 0,
        })

        # Bearer access (the extension's path): same graph, no cookie.
        status, _h, tok = self.request_json(
            "POST", "/api/tokens", body={"name": "extension"},
            headers=CSRF, cookie=cookie)
        self.assertEqual(status, 201, tok)
        raw = tok["token"]
        status, _h, g2 = self.graph(
            headers={"Authorization": "Bearer " + raw})
        self.assertEqual(status, 200, g2)
        self.assertEqual(g2, g)

        # IDOR: a second user sees none of it.
        cookie_b, _uid_b = self.register()
        status, _h, gb = self.graph(cookie_b)
        self.assertEqual(status, 200, gb)
        self.assertEqual(gb, {
            "nodes": [], "edges": [],
            "propagation": {"entries": [], "rollups": []},
        })
