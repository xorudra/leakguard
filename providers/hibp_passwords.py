"""Have I Been Pwned — Pwned Passwords range adapter.

k-anonymity, exactly as before Stage S4: the ONLY thing that ever
leaves this server is the first 5 characters of the password's SHA-1
hash. The suffix comparison happens locally in app.check_password_pwned
against the range text this adapter returns.
"""

from .base import Provider, ProviderInfo

RANGE = "https://api.pwnedpasswords.com/range/{prefix}"
UA = {"User-Agent": "LeakGuard/1.0 (+https://github.com/xorudra/leakguard)"}


class HibpPasswordsProvider(Provider):
    info = ProviderInfo(
        name="Have I Been Pwned Pwned Passwords",
        category="password_breach",
        capabilities=("password_range",),
        privacy=("k-anonymity: only the first 5 characters of the "
                 "password's SHA-1 hash are sent to the API. The "
                 "password and the full hash never leave this server; "
                 "the suffix match is computed locally."),
    )

    def check_range(self, prefix):
        """ProviderResult with data = the raw range response text
        (lines of SUFFIX:COUNT) for a 5-char hash prefix."""
        return self.client.get_text(RANGE.format(prefix=prefix), headers=UA)
