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

Stage S6 fixtures live in the three Mock*Provider classes below
(one per real S6 provider, so mock mode exercises the same registry
shapes as production):
  * a discovery query containing ten 9s (the fixture phone number)
    -> one people-fixture.example.com hit; everything else -> []
  * the username "fixturehandle" -> GitHub "in_use", all other
    platforms "not_found"; any other handle -> all "not_found"
  * the domain example.com -> a canned DNS snapshot and certificate
    names; TXT lookups -> [] (verification tests stub their own)
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


# ---------------------------------------------------------------------------
# Stage S6 fixtures
# ---------------------------------------------------------------------------

FIXTURE_PHONE_MARKER = "9999999999"   # ten 9s, in the search query
FIXTURE_PHONE_HIT = {
    "title": "Fixture People Listing",
    "url": "https://people-fixture.example.com/listing/1",
    "snippet": "A canned fixture listing (not a real page).",
    "domain": "people-fixture.example.com",
}
FIXTURE_HANDLE = "fixturehandle"
FIXTURE_DOMAIN = "example.com"
FIXTURE_DNS = {
    "A": ["93.184.216.34"],
    "MX": ["0 mail.example.com"],
    "NS": ["a.iana-servers.net", "b.iana-servers.net"],
    "TXT": ["v=spf1 -all"],
}
FIXTURE_CERTS = ["example.com", "www.example.com"]


def _fixture_ok(health, name, data):
    if health is not None:
        health.record(name, True, 0.0, None)
    return ProviderResult(status="ok", data=data, latency_ms=0.0)


class MockDiscoveryProvider(Provider):
    info = ProviderInfo(
        name="MockDiscovery",
        category="mock",
        capabilities=("web_discovery",),
        privacy="Canned local fixtures. No network calls, no real data.",
    )
    is_mock = True

    def __init__(self, health=None):
        super().__init__(health=health, client=None)

    def search(self, query):
        data = ([dict(FIXTURE_PHONE_HIT)]
                if FIXTURE_PHONE_MARKER in (query or "") else [])
        return _fixture_ok(self.health, self.info.name, data)


class MockUsernameProvider(Provider):
    info = ProviderInfo(
        name="MockUsernamePlatforms",
        category="mock",
        capabilities=("username_presence",),
        privacy="Canned local fixtures. No network calls, no real data.",
    )
    is_mock = True

    def __init__(self, health=None):
        super().__init__(health=health, client=None)

    def check_username(self, handle):
        from .username_platforms import PLATFORMS

        handle = (handle or "").strip().lstrip("@")
        checks = []
        for name, template in PLATFORMS:
            state = ("in_use" if handle == FIXTURE_HANDLE
                     and name == "GitHub" else "not_found")
            checks.append({
                "platform": name,
                "url": template.format(handle=handle),
                "state": state,
            })
        return _fixture_ok(self.health, self.info.name, checks)


class MockDomainIntelProvider(Provider):
    info = ProviderInfo(
        name="MockDomainIntel",
        category="mock",
        capabilities=("domain_dns", "domain_certs"),
        privacy="Canned local fixtures. No network calls, no real data.",
    )
    is_mock = True

    def __init__(self, health=None):
        super().__init__(health=health, client=None)

    def txt_records(self, name):
        return _fixture_ok(self.health, self.info.name, [])

    def dns_snapshot(self, domain):
        data = ({rtype: list(values)
                 for rtype, values in FIXTURE_DNS.items()}
                if (domain or "").strip().lower() == FIXTURE_DOMAIN
                else {})
        return _fixture_ok(self.health, self.info.name, data)

    def cert_names(self, domain):
        data = (list(FIXTURE_CERTS)
                if (domain or "").strip().lower() == FIXTURE_DOMAIN
                else [])
        return _fixture_ok(self.health, self.info.name, data)
