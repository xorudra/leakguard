"""Username presence checks (Stage S6, spec Phase 16).

For each platform in the curated PLATFORMS list, the handle's PUBLIC
profile URL is requested and its HTTP status classifies the handle:

  200        -> "in_use"    a public profile exists under this handle
  404        -> "not_found" the platform says no such profile
  anything   -> "unknown"   the platform refused to say (403 bot
  else                      walls, 429 rate limits, 5xx, timeouts) —
                            NEVER guessed in either direction

HONESTY CONTRACT: an "in_use" result means an account with this
exact handle exists. It is NOT proof the account belongs to the
person who saved the handle — handles are not unique to a person,
and common handles are usually strangers. Callers label these
findings confidence "probable" at best, with that warning attached.

POLITENESS: checks run through the shared HttpClient with a
1-second minimum interval, the base retry/breaker policy, and no
login of any kind. Platforms whose profiles are login-walled
(LinkedIn) are deliberately absent from the list.
"""

import urllib.parse

from .base import Provider, ProviderInfo, ProviderResult

UA = {"User-Agent": "LeakGuard/1.0 (+https://github.com/xorudra/leakguard)"}

# (platform name, public profile URL template) — data-driven; the
# handle is substituted URL-quoted. Only platforms whose profile
# pages answer plainly for logged-out visitors belong here.
PLATFORMS = (
    ("GitHub", "https://github.com/{handle}"),
    ("GitLab", "https://gitlab.com/{handle}"),
    ("Instagram", "https://www.instagram.com/{handle}/"),
    ("X", "https://x.com/{handle}"),
    ("Facebook", "https://www.facebook.com/{handle}"),
    ("Reddit", "https://www.reddit.com/user/{handle}"),
    ("YouTube", "https://www.youtube.com/@{handle}"),
    ("TikTok", "https://www.tiktok.com/@{handle}"),
    ("Twitch", "https://www.twitch.tv/{handle}"),
    ("Steam", "https://steamcommunity.com/id/{handle}"),
    ("Medium", "https://medium.com/@{handle}"),
    ("Dev.to", "https://dev.to/{handle}"),
    ("Keybase", "https://keybase.io/{handle}"),
)


def classify_status(code):
    """HTTP status -> presence state. The pure heart of this module:
    only 200 and 404 say anything at all, and 200 says 'a profile
    exists', never 'it is you'."""
    if code == 200:
        return "in_use"
    if code == 404:
        return "not_found"
    return "unknown"


class UsernamePlatformsProvider(Provider):
    info = ProviderInfo(
        name="Username Platforms",
        category="username_presence",
        capabilities=("username_presence",),
        privacy=("Only the handle is sent, as part of the public "
                 "profile URL requested from each platform. No login, "
                 "no cookies. A platform reporting a profile exists "
                 "under a handle does not prove whose it is."),
    )

    def check_username(self, handle):
        """ProviderResult with data = [{platform, url, state}] for
        every platform checked. The result status is "ok" when at
        least one platform answered definitively (200/404); when
        every platform was unreachable or refused, the first error
        is propagated so the caller reports an honest failure
        instead of an empty-looking 'checked'."""
        handle = (handle or "").strip().lstrip("@")
        checks = []
        first_error = None
        answered = False
        for name, template in PLATFORMS:
            url = template.format(
                handle=urllib.parse.quote(handle, safe=""))
            result = self.client.get_status(url, headers=UA)
            if result.status == "ok":
                answered = True
                state = classify_status(result.data)
            else:
                if first_error is None:
                    first_error = result
                state = "unknown"
            checks.append({"platform": name, "url": url, "state": state})
        if not answered and first_error is not None:
            return first_error
        return ProviderResult(status="ok", data=checks, latency_ms=0.0)
