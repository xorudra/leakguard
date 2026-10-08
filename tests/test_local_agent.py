"""Local runner (local_agent.py) — the one-click on-device run.

Loaded by file path (it is an entry script, not a package module)
with every IO seam stubbed: no network, no browser, no real
console. Pins the behaviours the owner ordered on 2026-10-08:
fillable forms are submitted automatically after ONE typed YES,
email brokers get ready-to-send .eml letters, human-only brokers
are walked through in the browser, and refusing the confirmation
sends nothing at all.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent


def _load_runner():
    spec = importlib.util.spec_from_file_location(
        "local_agent_under_test", REPO / "local_agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PLAN = [
    {"broker": "FormBroker", "optout_url": "https://form.example/optout",
     "contact_email": "", "automation": "form", "flow": [], "needs": []},
    {"broker": "MailBroker", "optout_url": "https://mail.example/optout",
     "contact_email": "privacy@mail.example", "automation": "email",
     "flow": [], "needs": []},
    {"broker": "WallBroker", "optout_url": "https://wall.example/optout",
     "contact_email": "", "automation": "manual", "flow": [], "needs": []},
]

PROFILE = {"full_name": "Rudra", "email": "rudra@example.com",
           "phone": "", "city": "Jaipur, India"}


def _probe(name, _profile):
    if name == "FormBroker":
        return {"reachable": True, "status": 200,
                "forms": [{"action": "https://form.example/optout",
                           "method": "post"}],
                "payload_preview": {"email": "rudra@example.com"},
                "blockers": []}
    if name == "WallBroker":
        return {"reachable": True, "status": 200, "forms": [],
                "payload_preview": None, "blockers": ["captcha"]}
    return {"reachable": True, "status": 200, "forms": [],
            "payload_preview": None, "blockers": []}


class TestLocalRunner(unittest.TestCase):
    def setUp(self):
        self.mod = _load_runner()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(
            self.mod.agent_engine, "build_plan", return_value=PLAN)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_full_run_submits_writes_and_guides(self):
        submits, opens = [], []
        answers = iter(["yes"])
        results = self.mod.run(
            PROFILE, out_dir=self.tmp.name, probe_fn=_probe,
            submit_fn=lambda a, m, p: submits.append((a, m, p))
            or {"status": 200},
            open_fn=opens.append,
            input_fn=lambda prompt="": next(answers),
            print_fn=lambda *a: None)
        by = {r["broker"]: r for r in results}
        self.assertEqual(by["FormBroker"]["outcome"], "submitted")
        self.assertEqual(by["FormBroker"]["submit_status"], 200)
        self.assertEqual(len(submits), 1)
        self.assertEqual(by["MailBroker"]["outcome"], "letter_written")
        eml = Path(self.tmp.name) / "leakguard-letters" / "mailbroker.eml"
        self.assertTrue(eml.exists())
        text = eml.read_text(encoding="utf-8")
        self.assertIn("To: privacy@mail.example", text)
        self.assertIn("Request for erasure of my personal data", text)
        self.assertIn("Rudra", text)
        self.assertEqual(by["WallBroker"]["outcome"], "needs_you")
        self.assertEqual(opens, ["https://wall.example/optout"])
        report = json.loads(
            (Path(self.tmp.name) / "leakguard-run-report.json")
            .read_text(encoding="utf-8"))
        self.assertEqual(len(report["results"]), 3)
        # Probe internals (the payload carries the user's details)
        # never land in the report.
        self.assertNotIn("_payload", json.dumps(report))

    def test_refusing_confirmation_sends_nothing(self):
        submits = []
        results = self.mod.run(
            PROFILE, out_dir=self.tmp.name, probe_fn=_probe,
            submit_fn=lambda a, m, p: submits.append((a, m, p)),
            open_fn=lambda url: None,
            input_fn=lambda prompt="": "no",
            print_fn=lambda *a: None)
        self.assertEqual(submits, [])
        self.assertTrue(
            all(r["outcome"] == "aborted_by_user" for r in results))
        self.assertFalse(
            (Path(self.tmp.name) / "leakguard-letters").exists())

    def test_probe_only_sends_nothing_and_never_asks(self):
        def forbidden(prompt=""):
            raise AssertionError("probe-only must not ask")

        results = self.mod.run(
            PROFILE, out_dir=self.tmp.name, probe_fn=_probe,
            probe_only=True, submit_fn=lambda a, m, p: None,
            open_fn=lambda url: None, input_fn=forbidden,
            print_fn=lambda *a: None)
        by = {r["broker"]: r for r in results}
        self.assertEqual(by["FormBroker"]["route"], "form")
        self.assertEqual(by["MailBroker"]["route"], "email")
        self.assertEqual(by["WallBroker"]["route"], "human")
        self.assertNotIn("outcome", by["FormBroker"])

    def test_letter_text_carries_the_legal_request(self):
        body = self.mod.letter_text("MailBroker", PROFILE)
        self.assertIn("DPDP Act 2023", body)
        self.assertIn("Rudra", body)
        self.assertIn("rudra@example.com", body)
        self.assertIn("MailBroker", body)


if __name__ == "__main__":
    unittest.main()
