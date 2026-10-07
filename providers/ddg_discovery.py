"""DuckDuckGo public-web discovery (Stage S6, spec Phase 20).

Searches the public web for a quoted identifier (phone number, name,
address, handle) through DuckDuckGo's keyless HTML endpoint and
returns candidate result pages: {title, url, snippet, domain}.

HONESTY CONTRACT: a search hit is a public MENTION, nothing more.
A page containing the same digits or the same name is a lead for the
owner to review — it is never treated as proof the page is about
them. Callers must label these results confidence "weak" (the
orchestrator/normalize layer does).

PRIVACY, stated plainly: web search is impossible without sending the
query. The exact quoted text (e.g. the phone number) goes to
DuckDuckGo over HTTPS. Nothing is sent anywhere else, and LeakGuard
stores only the same normalized finding shape as every other source
— the identifier itself never enters a finding or evidence payload.

POLITENESS: one provider, one shared HttpClient with a 1-second
minimum interval between calls, bounded retries and a circuit
breaker. No logins, no robots bypass, no scraping behind walls —
this endpoint is DuckDuckGo's public results page.

PARSING is defensive: DuckDuckGo's markup varies and is untrusted
input. Anchors with class "result__a" carry result links (wrapped in
a /l/?uddg= redirect whose decoded target is the real URL); anchors
with class "result__snippet" carry snippets in document order. Any
unexpected shape yields [] — discovery degrades to "no mentions
found", it never crashes a scan.
"""

import urllib.parse
from html.parser import HTMLParser

from .base import Provider, ProviderInfo, ProviderResult

ENDPOINT = "https://html.duckduckgo.com/html/?q={query}"
UA = {"User-Agent": "LeakGuard/1.0 (+https://github.com/xorudra/leakguard)"}
MAX_RESULTS = 10


class _ResultParser(HTMLParser):
    """Collects (href, text) for result links and snippets, in order."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []       # [(href, title_text)]
        self.snippets = []    # [snippet_text]
        self._mode = None     # "link" | "snippet" | None
        self._href = None
        self._chunks = []

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        attr = dict(attrs)
        classes = (attr.get("class") or "").split()
        if "result__a" in classes:
            self._mode, self._href, self._chunks = "link", attr.get("href"), []
        elif "result__snippet" in classes:
            self._mode, self._href, self._chunks = "snippet", None, []

    def handle_data(self, data):
        if self._mode is not None:
            self._chunks.append(data)

    def handle_endtag(self, tag):
        if tag != "a" or self._mode is None:
            return
        text = " ".join("".join(self._chunks).split())
        if self._mode == "link":
            self.links.append((self._href, text))
        else:
            self.snippets.append(text)
        self._mode, self._href, self._chunks = None, None, []


def _real_url(href):
    """Unwrap a DuckDuckGo redirect href to the result's real URL.
    Returns None for anything that is not an http(s) target."""
    if not href:
        return None
    try:
        parsed = urllib.parse.urlparse(href)
        if parsed.netloc.endswith("duckduckgo.com") and parsed.path == "/l/":
            target = urllib.parse.parse_qs(parsed.query).get("uddg", [None])[0]
            if target:
                parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        return urllib.parse.urlunparse(parsed)
    except Exception:
        return None


def parse_results(html_text):
    """Parse DDG HTML into [{title, url, snippet, domain}] — public
    for tests. Any malformed input yields []."""
    if not html_text or not isinstance(html_text, str):
        return []
    parser = _ResultParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        return []
    results = []
    for idx, (href, title) in enumerate(parser.links):
        url = _real_url(href)
        if url is None:
            continue
        domain = urllib.parse.urlparse(url).netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        results.append({
            "title": title or domain,
            "url": url,
            "snippet": parser.snippets[idx] if idx < len(parser.snippets) else "",
            "domain": domain,
        })
        if len(results) >= MAX_RESULTS:
            break
    return results


class DuckDuckGoDiscoveryProvider(Provider):
    info = ProviderInfo(
        name="DuckDuckGo Discovery",
        category="web_discovery",
        capabilities=("web_discovery",),
        privacy=("The search text itself — the exact phone number, "
                 "name, address or handle being checked, in quotes — "
                 "is sent to DuckDuckGo over HTTPS, because a web "
                 "search cannot run without it. Results are public "
                 "page mentions: leads to review, never proof that a "
                 "page is about the searcher."),
    )

    def search(self, query):
        """ProviderResult with data = [{title, url, snippet, domain}]
        (possibly empty), or a non-ok status on failure. A syntactically
        fine but unparseable page is an ok result with no hits."""
        url = ENDPOINT.format(query=urllib.parse.quote_plus(query))
        result = self.client.get_text(url, headers=UA)
        if result.status != "ok":
            return result
        return ProviderResult(status="ok",
                              data=parse_results(result.data),
                              latency_ms=result.latency_ms)
