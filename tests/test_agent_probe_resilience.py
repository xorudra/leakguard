"""Agent probe resilience — regression tests for the false verdicts a
live owner run exposed on 2026-10-08:

* a single transient network failure (timeout / reset / slow TLS)
  hardened into a permanent "Page unreachable" verdict — the direct
  fetch now retries exactly once, and HTTP answers are never retried
  (an HTTP status is a verdict, not a transient failure);
* the relay layer's worst case (3 attempts x 45s + backoff, ~144s)
  exceeded the browser client's deep-probe window, so the client
  aborted and misreported reachable brokers (CoreLogic, LiveRamp)
  as "unreachable from the server right now" — the relay is now
  bounded to 2 attempts x 30s;
* a registry URL whose host deliberately resolves to a non-public
  address for server networks (measured live: ClustrMaps publishes
  a loopback address) got only safety-check jargon — the blocker now
  explains the cause in plain words.

unittest-style (CI runs unittest discover without pytest).
"""

import unittest
import urllib.error
import urllib.request
from unittest import mock

import agent


BROKER = {"name": "Zztest Broker",
          "optout_url": "https://broker.example/optout"}
FORM_HTML = (b'<html><body><form action="/optout" method="POST">'
             b'<input type="email" name="email"></form></body></html>')


class FakeResponse:
    def __init__(self, status=200, body=b""):
        self.status = status
        self._body = body

    def read(self, _n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def patched_probe(opener):
    """Run probe_broker with the guard cleared and a stubbed fetcher."""
    return mock.patch.object(agent, "load_brokers", lambda: [BROKER]), \
        mock.patch.object(agent, "get_playbook",
                          lambda b: {"automation": "http_form",
                                     "needs": []}), \
        mock.patch.object(agent, "_url_guard_error", lambda url: None), \
        mock.patch.object(agent._ssrf, "pinned_urlopen", opener), \
        mock.patch("time.sleep", lambda _s: None)


class TestDirectFetchRetry(unittest.TestCase):
    def test_transient_failure_is_retried_once_and_recovers(self):
        calls = []

        def opener(req, timeout=15):
            calls.append(1)
            if len(calls) == 1:
                raise urllib.error.URLError("timed out")
            return FakeResponse(200, FORM_HTML)

        patches = patched_probe(opener)
        for p in patches:
            p.start()
        try:
            result = agent.probe_broker("Zztest Broker", {})
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(len(calls), 2)
        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 200)

    def test_persistent_failure_stops_after_one_retry(self):
        calls = []

        def opener(req, timeout=15):
            calls.append(1)
            raise urllib.error.URLError("connection reset")

        patches = patched_probe(opener)
        for p in patches:
            p.start()
        try:
            result = agent.probe_broker("Zztest Broker", {})
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(len(calls), 2)
        self.assertFalse(result["reachable"])
        self.assertTrue(any("Page unreachable" in b
                            for b in result["blockers"]))

    def test_http_error_is_a_verdict_and_never_retried(self):
        calls = []

        def opener(req, timeout=15):
            calls.append(1)
            raise urllib.error.HTTPError(
                "https://broker.example/optout", 403, "Forbidden",
                None, None)

        patches = patched_probe(opener)
        for p in patches:
            p.start()
        try:
            result = agent.probe_broker("Zztest Broker", {})
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], 403)
        self.assertTrue(any("HTTP 403" in b
                            for b in result["blockers"]))


class TestRelayBounds(unittest.TestCase):
    def test_relay_gives_up_after_two_attempts(self):
        calls = []

        def fake_urlopen(req, timeout=30):
            calls.append(timeout)
            raise urllib.error.URLError("relay down")

        with mock.patch("urllib.request.urlopen", fake_urlopen), \
                mock.patch("time.sleep", lambda _s: None):
            out = agent.relay_probe("https://broker.example/optout", {})
        self.assertEqual(calls, [30, 30])
        self.assertFalse(out["reachable"])
        self.assertTrue(any("Relay reader could not fetch" in b
                            for b in out["blockers"]))


class TestGuardClassification(unittest.TestCase):
    def _probe_with_url(self, url):
        broker = {"name": "Zztest Broker", "optout_url": url}
        with mock.patch.object(agent, "load_brokers",
                               lambda: [broker]), \
                mock.patch.object(
                    agent, "get_playbook",
                    lambda b: {"automation": "http_form", "needs": []}):
            return agent.probe_broker("Zztest Broker", {})

    def test_non_public_resolution_is_explained_plainly(self):
        result = self._probe_with_url("http://192.168.50.7/optout")
        self.assertFalse(result["reachable"])
        self.assertTrue(
            any("deliberately refuses server networks" in b
                and "safety check" in b for b in result["blockers"]),
            result["blockers"])

    def test_other_guard_refusals_keep_the_generic_wording(self):
        result = self._probe_with_url("ftp://broker.example/optout")
        self.assertFalse(result["reachable"])
        self.assertTrue(
            any("did not pass the outbound safety check" in b
                for b in result["blockers"]), result["blockers"])
        self.assertFalse(
            any("deliberately refuses" in b
                for b in result["blockers"]), result["blockers"])


if __name__ == "__main__":
    unittest.main()
