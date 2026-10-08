"""Public-copy claim guards (Real-World Validation, Wave 1 fix loop).

The 2026-10-08 claims audit (docs/reviews/2026-10-08-claims-audit-
working.md) found 8 PARTIAL claims — wording that overstated what the
implementation demonstrates — and each was rewritten to the honest
form. These tests pin the corrected wording in static/index.html and
README.md so a future copy edit cannot silently re-introduce the
overstatements. They read files only; no database is involved.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _flat(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    return re.sub(r"\s+", " ", text)


class TestIndexCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = _flat("static/index.html")
        cls.lower = cls.page.lower()

    def test_no_free_forever_promise(self):
        # Present-day cost is ₹0; "forever" promises a future no code
        # can demonstrate (it rests on third-party free tiers).
        self.assertNotIn("free forever", self.lower)
        self.assertIn("free — no card, no paid tier", self.page)
        self.assertIn("Free, like everything here.", self.page)

    def test_footer_scopes_storage_claim_to_quick_scan(self):
        # Account scans/findings ARE stored (the /trust page says so);
        # the footer may only claim the anonymous Quick Scan stores
        # nothing.
        self.assertNotIn("No scan data is stored on this server", self.page)
        self.assertIn("Anonymous Quick Scan stores nothing on this server.",
                      self.page)

    def test_password_hint_states_the_real_boundary(self):
        # The password IS posted to LeakGuard's own server over HTTPS;
        # the protection is server-side hashing + k-anonymity.
        self.assertNotIn("never leaves this page in plain form", self.page)
        self.assertNotIn("never sent or stored", self.page)
        self.assertIn("only the first 5 characters of the hash ever leave "
                      "it", self.page)
        self.assertIn("never stored or logged", self.page)

    def test_agent_mode_names_the_handed_back_steps(self):
        self.assertNotIn("nothing else for you to do", self.page)
        self.assertIn("pressing Send on the email-broker letters", self.page)
        self.assertIn("CAPTCHA or sign-in", self.page)

    def test_passkey_claim_is_resistant_not_absolute(self):
        self.assertNotIn("cannot be phished or leaked", self.page)
        self.assertIn("phishing-resistant by design", self.page)

    def test_quick_scan_seconds_claim_carries_wake_caveat(self):
        self.assertIn("can take about a minute", self.page)


class TestReadmeCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = _flat("README.md")

    def test_submit_confirmation_described_as_shipped(self):
        # One press confirms the run; the per-call confirm flag is an
        # API contract, not a per-broker user confirmation.
        self.assertNotIn("explicit per-broker confirmation", self.readme)
        self.assertIn("one press confirms the run", self.readme)

    def test_browser_probe_row_carries_hosted_qualifier(self):
        # Playwright is an optional install; the hosted deep pass is
        # HTTP + relay and reports that honestly.
        self.assertIn("on the hosted service the deep pass uses HTTP + "
                      "relay", self.readme)


if __name__ == "__main__":
    unittest.main()
