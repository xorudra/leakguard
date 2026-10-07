"""Phase 166 — the local browser probe's domain allowlist.

browser_probe.py drives a REAL browser, locally, against broker
pages. It may only ever visit broker domains: brokers.json +
verify_sources.json, plus the operator's explicit local config
list (LEAKGUARD_PROBE_EXTRA_DOMAINS / probe_domains.txt). These
tests pin:

  * the allowlist's contents and its matching rule (a domain or
    its subdomains — never suffix lookalikes);
  * the local config list (env var + file) feeding it;
  * probe()'s pre-flight refusal: an off-list target is refused
    BEFORE any browser launches (this works even where Playwright
    is not installed — this environment is one);
  * the in-browser guard: requests are checked inside the
    context, so a redirect (or any request) landing off the list
    is aborted and recorded in the result's 'refused' list.

Playwright is NOT installed in the test environment (by design —
the server never runs a browser; the probe is a local tool), so
the probe-flow tests inject a fake 'playwright' module into
sys.modules: just enough of the sync API for probe() to run its
real code — launch bookkeeping, the route guard, the result
assembly — against scripted navigations. The allowlist logic
itself is exercised as the pure functions it is.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

_spec = importlib.util.spec_from_file_location(
    "browser_probe_under_test", _ROOT / "browser_probe.py")
browser_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(browser_probe)


# ---------------------------------------------------------------------------
# A minimal fake Playwright (sync API surface probe() uses)
# ---------------------------------------------------------------------------

class _FakeRoute:
    def __init__(self, url):
        self.request = type("Req", (), {"url": url})()
        self.outcome = None

    def continue_(self):
        self.outcome = "continued"

    def abort(self):
        self.outcome = "aborted"


class _FakeResponse:
    def __init__(self, status):
        self.status = status


class _FakePage:
    def __init__(self, context, scenario):
        self._context = context
        self._scenario = scenario
        self.url = "about:blank"

    def goto(self, url, timeout=None, wait_until=None):
        for req_url, is_navigation in self._scenario["requests"]:
            route = _FakeRoute(req_url)
            self._context.route_handler(route)
            if route.outcome == "aborted":
                if is_navigation:
                    raise Exception("net::ERR_ABORTED at %s" % req_url)
                continue  # an aborted subresource never fails a load
            if is_navigation:
                self.url = req_url
        return _FakeResponse(self._scenario.get("status", 200))

    def wait_for_load_state(self, state, timeout=None):
        pass

    def title(self):
        return self._scenario["data"].get("title", "")

    def evaluate(self, _script):
        return self._scenario["data"]


class _FakeContext:
    def __init__(self, scenario):
        self._scenario = scenario
        self.route_handler = None

    def route(self, _pattern, handler):
        self.route_handler = handler

    def new_page(self):
        return _FakePage(self, self._scenario)

    def close(self):
        pass


class _FakeBrowser:
    def __init__(self, recorder, scenario):
        self._recorder = recorder
        self._scenario = scenario

    def new_context(self, **kwargs):
        return _FakeContext(self._scenario)

    def close(self):
        pass


class _FakeChromium:
    def __init__(self, recorder, scenario):
        self._recorder = recorder
        self._scenario = scenario

    def launch(self, **kwargs):
        self._recorder.append(kwargs)
        return _FakeBrowser(self._recorder, self._scenario)


class _FakePlaywright:
    def __init__(self, recorder, scenario):
        self.chromium = _FakeChromium(recorder, scenario)


class _FakeSyncPlaywright:
    def __init__(self, recorder, scenario):
        self._pw = _FakePlaywright(recorder, scenario)

    def __enter__(self):
        return self._pw

    def __exit__(self, *exc):
        return False


def install_fake_playwright(scenario):
    """Insert the fake playwright package into sys.modules;
    returns (recorder, restore) — recorder collects launch kwargs
    so tests can prove whether a browser was ever launched."""
    recorder = []
    pw_mod = type(sys)("playwright")
    sync_mod = type(sys)("playwright.sync_api")
    sync_mod.sync_playwright = lambda: _FakeSyncPlaywright(
        recorder, scenario)
    pw_mod.sync_api = sync_mod
    saved = {name: sys.modules.get(name)
             for name in ("playwright", "playwright.sync_api")}
    sys.modules["playwright"] = pw_mod
    sys.modules["playwright.sync_api"] = sync_mod

    def restore():
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value

    return recorder, restore


_PAGE_DATA = {
    "title": "Spokeo — opt out",
    "forms": [{"action": "https://www.spokeo.com/optout/submit",
               "method": "POST", "fields": []}],
    "hasCaptcha": False,
    "hasPassword": False,
}


# ---------------------------------------------------------------------------
# The allowlist itself
# ---------------------------------------------------------------------------

class TestAllowlistContents(unittest.TestCase):
    def test_broker_domains_present(self):
        allowed = browser_probe.allowed_domains(environ={})
        # From brokers.json (opt-out hosts, www stripped) and
        # verify_sources.json (listing domains).
        self.assertIn("spokeo.com", allowed)
        self.assertIn("fastpeoplesearch.com", allowed)
        self.assertIn("beenverified.com", allowed)
        self.assertIn("checkpeople.com", allowed)

    def test_matching_rule_domain_or_subdomain_only(self):
        allowed = {"spokeo.com"}
        self.assertTrue(browser_probe.host_allowed(
            "spokeo.com", allowed))
        self.assertTrue(browser_probe.host_allowed(
            "www.spokeo.com", allowed))
        self.assertTrue(browser_probe.host_allowed(
            "people.spokeo.com", allowed))
        self.assertFalse(browser_probe.host_allowed(
            "evilspokeo.com", allowed))
        self.assertFalse(browser_probe.host_allowed(
            "spokeo.com.evil.example", allowed))
        self.assertFalse(browser_probe.host_allowed(
            "notspokeo.com", allowed))
        self.assertFalse(browser_probe.host_allowed(
            "example.com", allowed))
        self.assertFalse(browser_probe.host_allowed("", allowed))

    def test_local_config_list_env_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "probe_domains.txt"
            cfg.write_text(
                "# my extra domains\n"
                "filedomain.test\n"
                "\n"
                "www.wwwstrip.test  # trailing comment\n",
                encoding="utf-8")
            domains = browser_probe.config_domains(
                environ={"LEAKGUARD_PROBE_EXTRA_DOMAINS":
                         "Example.ORG, extra.test"},
                config_path=cfg)
        self.assertEqual(domains, {"example.org", "extra.test",
                                   "filedomain.test",
                                   "wwwstrip.test"})

    def test_config_list_joins_the_allowlist(self):
        allowed = browser_probe.allowed_domains(
            environ={"LEAKGUARD_PROBE_EXTRA_DOMAINS": "idp.example"})
        self.assertIn("idp.example", allowed)
        self.assertIn("spokeo.com", allowed)
        self.assertTrue(browser_probe.url_allowed(
            "https://login.idp.example/callback", allowed))


# ---------------------------------------------------------------------------
# probe() enforcement
# ---------------------------------------------------------------------------

class TestProbeAllowlistEnforcement(unittest.TestCase):
    def setUp(self):
        self._saved_env = os.environ.pop(
            "LEAKGUARD_PROBE_EXTRA_DOMAINS", None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._saved_env is not None:
            os.environ["LEAKGUARD_PROBE_EXTRA_DOMAINS"] = self._saved_env

    def test_offlist_target_refused(self):
        result = browser_probe.probe("https://evil.example/optout")
        self.assertFalse(result["reachable"])
        self.assertEqual(len(result["refused"]), 1)
        self.assertEqual(result["refused"][0]["host"], "evil.example")
        self.assertTrue(any("not on the probe domain allowlist" in b
                            for b in result["blockers"]))

    def test_offlist_target_refused_before_any_launch(self):
        scenario = {"requests": [], "data": _PAGE_DATA}
        recorder, restore = install_fake_playwright(scenario)
        try:
            result = browser_probe.probe(
                "https://evil.example/optout")
        finally:
            restore()
        self.assertEqual(recorder, [])  # the browser never launched
        self.assertEqual(result["refused"][0]["host"], "evil.example")

    def test_allowlisted_domain_loads(self):
        scenario = {"requests": [("https://www.spokeo.com/optout",
                                  True)],
                    "data": _PAGE_DATA}
        recorder, restore = install_fake_playwright(scenario)
        try:
            result = browser_probe.probe(
                "https://www.spokeo.com/optout")
        finally:
            restore()
        self.assertEqual(len(recorder), 1)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["refused"], [])
        self.assertEqual(len(result["forms"]), 1)

    def test_redirect_offlist_is_refused_and_recorded(self):
        # The opt-out page 302s to a domain nobody allowlisted:
        # the navigation request to it is aborted, the load fails,
        # and the refusal is in the result — never silently followed.
        scenario = {"requests": [
            ("https://www.spokeo.com/optout", True),
            ("https://evil.example/landing", True)], "data": _PAGE_DATA}
        _recorder, restore = install_fake_playwright(scenario)
        try:
            result = browser_probe.probe(
                "https://www.spokeo.com/optout")
        finally:
            restore()
        self.assertFalse(result["reachable"])
        self.assertEqual([r["host"] for r in result["refused"]],
                         ["evil.example"])

    def test_offlist_subresource_aborted_but_page_loads(self):
        scenario = {"requests": [
            ("https://www.spokeo.com/optout", True),
            ("https://tracker.example/pixel.js", False)],
                    "data": _PAGE_DATA}
        _recorder, restore = install_fake_playwright(scenario)
        try:
            result = browser_probe.probe(
                "https://www.spokeo.com/optout")
        finally:
            restore()
        self.assertTrue(result["reachable"])
        self.assertEqual([r["host"] for r in result["refused"]],
                         ["tracker.example"])


if __name__ == "__main__":
    unittest.main()
