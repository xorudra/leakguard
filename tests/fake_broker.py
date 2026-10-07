"""Fake broker environment (spec Phase 111) — TEST SUPPORT ONLY.

Nothing in the shipped application imports this module; it lives
under tests/ precisely so the fake can never become a production
code path.

What it models
--------------
A people-search data broker, the way the playbooks meet one:

  * a person listing — present until a removal actually lands;
  * an opt-out flow — GET the opt-out page (an HTML form), POST the
    form, the request goes PENDING, and only when the broker
    processes it (site.process_pending()) does the listing come
    down. Submission is not removal, in the fake exactly as in the
    product's honesty rules;
  * the broker's own search page (for 'direct' verification) and a
    DuckDuckGo-shaped results builder (for 'search_index'
    verification), both driven by the SAME listing state — the
    evidence can never disagree with the site;
  * switchable failure modes:
        "down"      every fetch fails at transport level (the site
                    is unreachable; the relay reader fails too);
        "renamed"   the opt-out form's fields are renamed to opaque
                    names nothing maps onto — the workflow must
                    report its real failure (form_not_fillable),
                    never invent a submission;
        "persist"   opt-outs are accepted and "processed", but the
                    listing stays up — verification must keep
                    saying still_present;
        "challenge" the opt-out page is a CAPTCHA challenge page —
                    a human step, never routed around.

The seam (why the harness is honest)
------------------------------------
The fake replaces ONLY the network transport, at the two points
the codebase itself designates:

  * core.ssrf.pinned_urlopen — the guarded fetch every data-driven
    outbound call funnels through (agent.probe_broker,
    agent.submit_form, the verification default fetcher). The
    harness swaps in FakeTransport, which routes by host into the
    registered FakeBrokerSites and answers in-process. Everything
    above the transport runs UNMODIFIED: the SSRF pre-checks
    (agent._url_is_public), the host guard in AgentExecutor.submit,
    FormParser, match_fields, interpret_probe, the staged probe
    strategy, process_case, verify_case.
  * core.ssrf.resolve_host — documented in core/ssrf.py as "the
    single patch point" for tests; the harness stubs it to one
    public address so the REAL validation logic in
    assert_public_url / _validated_addresses runs and passes on
    its merits. Production SSRF policy is never weakened: the
    pinned fetcher still refuses literal private addresses under
    the harness (a test asserts exactly that), and no production
    file changes.

The one component the harness re-implements is the relay reader
(agent.relay_probe): in production it is a third-party public
relay fetched over the internet, which a test cannot call. The
fake relay (FakeBrokerSite-based, see make_relay_probe) honours
the same contract — fetch the page from a different vantage,
parse forms with agent's own FormParser + match_fields, report
challenges — but reads from the fake sites through the same
transport, so "the site is down" fails the relay too.

Usage: see tests/test_fake_broker_e2e.py.
"""

import io
import re
import urllib.error
import urllib.parse

import agent as agent_engine

# The relay/DDG endpoints the production code fetches, as hosts —
# the fake transport/fetcher route on these.
DDG_HOST = "html.duckduckgo.com"


class FakeResponse:
    """The slice of urllib's response contract the guarded call
    sites use: .status, .read(n), and the context-manager protocol
    (pinned_urlopen results are used with `with`)."""

    def __init__(self, status, body):
        self.status = status
        self._stream = io.BytesIO(body)

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._stream.close()
        return False


# ---------------------------------------------------------------------------
# Page shapes
# ---------------------------------------------------------------------------

def _page(title, body):
    return ("<html><head><title>%s</title></head><body>%s</body>"
            "</html>" % (title, body)).encode("utf-8")


def _optout_form(action, fields):
    inputs = "".join(
        '<label>%s <input type="%s" name="%s" placeholder="%s">'
        "</label>" % (label, ftype, name, placeholder)
        for label, ftype, name, placeholder in fields)
    return ('<form action="%s" method="POST">%s'
            '<input type="submit" value="Remove my data"></form>'
            % (action, inputs))


# Field shapes per playbook style. The names/placeholders are what
# agent.PROFILE_FIELDS matches against — exactly the contract a
# real broker page presents.
_GENERIC_FIELDS = [
    ("Full name", "text", "name", "Your full name"),
    ("Email", "email", "email", "Email address"),
    ("City", "text", "city", "City"),
]
_SPOKEO_FIELDS = [
    ("Listing URL", "text", "listing_url", "Your listing URL"),
    ("Email", "email", "email", "Email address"),
]
# Renamed-mode fields: opaque names AND neutral placeholders, so
# neither the name/id nor the placeholder text maps onto any
# profile semantic — the honest "the broker changed its form".
_RENAMED_FIELDS = [
    ("Field one", "text", "f_9x1", "Required"),
    ("Field two", "email", "f_9x2", "Required"),
]

_FORM_STYLES = {"generic": _GENERIC_FIELDS, "spokeo": _SPOKEO_FIELDS}


class FakeBrokerSite:
    """One fake broker. `host` is the broker's real host as the
    registry knows it (e.g. 'www.spokeo.com'); `domain` its bare
    listing domain (e.g. 'spokeo.com'). `optout_path` mirrors the
    registry's opt-out URL path; submissions land on
    optout_path + '/submit'."""

    MODES = ("normal", "down", "renamed", "persist", "challenge")

    def __init__(self, *, host, domain, name, optout_path,
                 form_style="generic", mode="normal"):
        if mode not in self.MODES:
            raise ValueError("unknown fake broker mode: %r" % mode)
        self.host = host
        self.domain = domain
        self.name = name
        self.optout_path = optout_path
        self.form_style = form_style
        self.mode = mode
        # Listing lifecycle: present -> pending -> removed. The
        # only way out of "present" is an accepted opt-out POST;
        # the only way out of "pending" is process_pending().
        self.listing_state = "present"
        self.submissions = []   # payload dicts, in arrival order
        self.requests = []      # (method, path) the site has seen
        # The listed person's name, set by the harness once the
        # profile exists (the site is built before anyone registers).
        self.person_name = ""

    # -- listing state ------------------------------------------------
    def listing_present(self):
        """What any evidence source must say right now: a pending
        removal is still a live listing."""
        return self.listing_state in ("present", "pending")

    def process_pending(self):
        """The broker works its queue. In 'persist' mode the
        request is 'processed' and the listing stays — the
        dishonest-broker case verification exists to catch."""
        if self.listing_state != "pending":
            return
        self.listing_state = ("present" if self.mode == "persist"
                              else "removed")

    # -- request handling ----------------------------------------------
    def fetch(self, method, url, data=None):
        """Transport-level fetch of THIS site: returns
        (status, body_bytes); raises URLError in 'down' mode (a
        transport failure, exactly what a dead site looks like to
        the guarded fetchers)."""
        if self.mode == "down":
            raise urllib.error.URLError(
                "fake broker is down (connection refused)")
        parsed = urllib.parse.urlparse(url)
        return self.handle(method, parsed.path, parsed.query, data)

    def handle(self, method, path, query="", data=None):
        self.requests.append((method, path))
        if method == "GET" and path == self.optout_path:
            return 200, self._optout_page()
        if method == "POST" and path == self.optout_path + "/submit":
            return self._accept_submission(data)
        if method == "GET":
            return 200, self.search_page()
        return 404, _page("Not found", "<p>Not found</p>")

    def _optout_page(self):
        if self.mode == "challenge":
            # A challenge wall: the form exists behind a CAPTCHA.
            # FormParser flags any 'recaptcha' markup, and the
            # engine treats CAPTCHA as a human step at every layer.
            return _page(
                "%s — verify you are human" % self.name,
                "<h1>One more step</h1>"
                "<p>Please complete the check below to reach the "
                "removal form.</p>"
                '<div class="g-recaptcha" '
                'data-sitekey="fake-sitekey"></div>'
                + _optout_form(self._submit_url(),
                               _FORM_STYLES[self.form_style]))
        fields = (_RENAMED_FIELDS if self.mode == "renamed"
                  else _FORM_STYLES[self.form_style])
        return _page(
            "%s — opt out" % self.name,
            "<h1>Remove your listing</h1>"
            "<p>Tell us who you are and we will remove your "
            "profile.</p>" + _optout_form(self._submit_url(), fields))

    def _submit_url(self):
        return "https://%s%s/submit" % (self.host, self.optout_path)

    def _accept_submission(self, data):
        payload = dict(urllib.parse.parse_qsl(
            (data or b"").decode("utf-8", "replace")))
        self.submissions.append(payload)
        if self.listing_state == "present":
            self.listing_state = "pending"
        return 200, _page(
            "%s — request received" % self.name,
            "<h1>Thank you</h1><p>Your removal request was "
            "received. Listings are usually removed within "
            "24-48 hours.</p>")

    # -- evidence pages --------------------------------------------------
    def search_page(self):
        """The broker's own search results for the listed person —
        what a 'direct' verification fetch reads. Name-agnostic by
        design: the fake holds exactly one listing, so its search
        answers about that listing."""
        if self.listing_present():
            return _page(
                "%s — search results" % self.name,
                '<div class="card"><h2>%s</h2>'
                "<p>Your listing is live on %s.</p></div>"
                % (self.person_name, self.name))
        return _page(
            "%s — search results" % self.name,
            "<p>Sorry, no results found for that name. "
            "Try a different spelling.</p>")

    def ddg_results_page(self):
        """A DuckDuckGo HTML results page (the recorded shape the
        production parser consumes: div.links > result__a anchors
        wrapped in /l/?uddg=) whose broker-domain content reflects
        THIS site's listing state — for 'search_index'
        verification."""
        anchors = []
        if self.listing_present():
            target = "https://www.%s/%s" % (
                self.domain, (self.person_name or "listing").replace(
                    " ", "-"))
            wrapped = "//duckduckgo.com/l/?uddg=%s&rut=0001" % (
                urllib.parse.quote(target, safe=""))
            anchors.append(
                '<div class="result results_links web-result">'
                '<h2 class="result__title">'
                '<a class="result__a" href="%s">%s on %s</a></h2>'
                '<a class="result__snippet" href="%s">snippet</a>'
                "</div>" % (wrapped, self.person_name, self.name,
                            wrapped))
        else:
            anchors.append(
                '<div class="result results_links web-result">'
                '<h2 class="result__title">'
                '<a class="result__a" '
                'href="//duckduckgo.com/l/?uddg=https%3A%2F%2F'
                'www.example.com%2Fsomeone-else&rut=0002">'
                "Someone else</a></h2></div>")
        return _page("search at DuckDuckGo",
                     '<div class="links">%s</div>' % "".join(anchors))


# ---------------------------------------------------------------------------
# Transport + fetchers (the harness seams)
# ---------------------------------------------------------------------------

class FakeTransport:
    """pinned_urlopen stand-in: routes by host into the registered
    sites and answers in-process. Unknown hosts are a transport
    failure (URLError) — the fake internet contains only the fake
    brokers, so production code can never "accidentally" reach
    anything real through it. HTTP error statuses raise HTTPError,
    exactly as urllib does for the real pinned opener."""

    def __init__(self, sites):
        self.sites = {}
        for site in sites:
            self.sites[site.host] = site
            # The bare domain answers too (brokers' www and bare
            # hosts serve the same site in the real world).
            self.sites.setdefault(site.domain, site)
        self.requests = []

    def __call__(self, req, timeout=None):
        url = getattr(req, "full_url", req)
        method = (req.get_method() if hasattr(req, "get_method")
                  else "GET")
        data = getattr(req, "data", None)
        self.requests.append((method, url))
        host = urllib.parse.urlparse(url).hostname or ""
        site = self.sites.get(host)
        if site is None:
            raise urllib.error.URLError(
                "fake transport: unknown host %r" % host)
        status, body = site.fetch(method, url, data)
        if status >= 400:
            raise urllib.error.HTTPError(
                url, status, "fake broker HTTP %d" % status, {},
                io.BytesIO(body))
        return FakeResponse(status, body)


def make_verify_fetcher(sites):
    """The AgentExecutor fetcher(url) -> (status, text) seam,
    backed by the fake sites: DuckDuckGo queries are answered with
    the queried site's DDG-shaped results page (the domain is read
    out of the site: query the production code built); broker URLs
    are served by the site itself (the 'direct' path). Anything
    else is a transport failure (None, '')."""
    by_domain = {}
    transport = FakeTransport(sites)
    for site in sites:
        by_domain[site.domain] = site

    def fetcher(url):
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        if host == DDG_HOST:
            query = urllib.parse.parse_qs(parsed.query).get(
                "q", [""])[0]
            match = re.search(r"site:([a-z0-9.-]+)", query)
            site = by_domain.get(match.group(1)) if match else None
            if site is None or site.mode == "down":
                return None, ""
            return 200, site.ddg_results_page().decode(
                "utf-8", "replace")
        try:
            with transport(url) as resp:
                return resp.status, resp.read().decode(
                    "utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except Exception:
            return None, ""

    return fetcher


def make_relay_probe(sites):
    """agent.relay_probe stand-in honouring the production relay's
    contract (see the module docstring for why the relay itself is
    re-implemented): fetch the page through the fake transport,
    detect the challenge wall, parse forms with agent's own
    FormParser + match_fields."""
    transport = FakeTransport(sites)

    def relay_probe(url, profile=None):
        profile = profile or {}
        out = {"via": "relay", "reachable": False, "status": None,
               "forms": [], "blockers": [], "challenge": False,
               "payload_preview": {}, "title": ""}
        try:
            with transport(url) as resp:
                out["status"] = resp.status
                html = resp.read(1024 * 1024).decode(
                    "utf-8", "replace")
        except urllib.error.HTTPError as exc:
            out["status"] = exc.code
            out["blockers"].append(
                "Relay reader could not fetch the page either")
            return out
        except Exception:
            out["blockers"].append(
                "Relay reader could not fetch the page either")
            return out
        low = html.lower()
        match = re.search(r"<title[^>]*>(.*?)</title>", html,
                          re.I | re.S)
        if match:
            out["title"] = re.sub(
                r"\s+", " ", match.group(1)).strip()[:120]
        if ("just a moment" in low[:3000]
                or "checking your browser" in low[:3000]):
            out["challenge"] = True
            out["blockers"].append(
                "Cloudflare challenge page even via the relay reader")
            return out
        out["reachable"] = True
        parser = agent_engine.FormParser()
        try:
            parser.feed(html)
        except Exception:
            pass
        if parser.has_captcha:
            out["blockers"].append(
                "CAPTCHA on the page — a human must solve this step")
        for form in parser.forms[:3]:
            payload, unmapped = agent_engine.match_fields(
                form["fields"], profile)
            out["forms"].append({
                "action": (urllib.parse.urljoin(url, form["action"])
                           if form["action"] else url),
                "method": form["method"],
                "fields": form["fields"],
                "unmapped_fields": unmapped,
            })
            if payload and not out["payload_preview"]:
                out["payload_preview"] = payload
        if not out["forms"]:
            out["blockers"].append(
                "Relay fetched the page but found no readable form")
        return out

    return relay_probe
