"""MockProvider — canned, deterministic fixtures (spec Phase 110).

Activated with LEAKGUARD_PROVIDERS=mock. Makes NO network calls and
touches NO real data. Its status is always reported as "mock" in
/api/providers/health, and the health payload carries "mode": "mock",
so fixture results can never silently pretend to be real.

Fixtures:
  * breached@example.com -> two breaches + High/72 analytics
  * shared-a@example.com / shared-b@example.com -> the SAME single
    breach ("SharedFixtureBreach"), no analytics — the Stage S5
    correlation fixture: one source exposing two identifiers at once
  * any other email      -> clean (no breaches, no analytics)
  * the password "mockpwned" -> pwned 123,456 times (served through
    the same range-text contract as the real HIBP adapter: the text
    contains that password's SHA-1 suffix with its count)
"""

import hashlib

from .base import Provider, ProviderInfo, ProviderResult

BREACHED_EMAIL = "breached@example.com"
BREACHED_BREACHES = ["MockBreach2024", "MockComboList"]
BREACHED_ANALYTICS = {
    "risk_label": "High",
    "risk_score": 72,
    "exposed_data": ["email addresses", "passwords"],
    "passwords_strength": None,
}
PWNED_PASSWORD = "mockpwned"
PWNED_COUNT = 123456
SHARED_EMAILS = ("shared-a@example.com", "shared-b@example.com")
SHARED_BREACHES = ["SharedFixtureBreach"]


def _range_text():
    suffix = hashlib.sha1(PWNED_PASSWORD.encode("utf-8")).hexdigest().upper()[5:]
    decoy = "0" * 35
    return "\n".join([
        "%s:7" % decoy,
        "%s:%d" % (suffix, PWNED_COUNT),
        "%s:2" % ("F" * 35),
    ])


class MockProvider(Provider):
    info = ProviderInfo(
        name="MockProvider",
        category="mock",
        capabilities=("email_breach", "breach_analytics", "password_range"),
        privacy=("Canned local fixtures for tests and demos. No network "
                 "calls, no real data, results are invented."),
    )
    is_mock = True

    def __init__(self, health=None):
        super().__init__(health=health, client=None)

    def _ok(self, data):
        if self.health is not None:
            self.health.record(self.info.name, True, 0.0, None)
        return ProviderResult(status="ok", data=data, latency_ms=0.0)

    def check_email(self, email):
        email = (email or "").strip().lower()
        if email == BREACHED_EMAIL:
            return self._ok(list(BREACHED_BREACHES))
        if email in SHARED_EMAILS:
            return self._ok(list(SHARED_BREACHES))
        return self._ok([])

    def breach_analytics(self, email):
        if (email or "").strip().lower() == BREACHED_EMAIL:
            return self._ok(dict(BREACHED_ANALYTICS))
        return self._ok(None)

    def check_range(self, prefix):
        # The prefix is ignored: the fixture text always answers with
        # the canned suffix lines, exactly like a real range response.
        return self._ok(_range_text())
