"""Dispute / correction guidance for a finding (spec Phase 157).

A finding is a claim by a source, and sources are sometimes wrong.
This module answers "I want to dispute or correct this" with honest,
source-specific steps. It is deliberately STATIC: no generated
links, no invented contacts. The only URL in this module is
Google's "Results about you" page, which the product already links
from static/index.html — a test asserts every URL here also appears
somewhere else in the repository, so a fabricated link cannot
sneak in.

The guidance never promises an outcome: only the organisation
behind a source can correct or delete its record, and the steps say
who that is for each source class:

* breach_database — the record comes from a breach at the named
  company. Breach indexes (XposedOrNot, Have I Been Pwned) did not
  hold the data and cannot delete the original; the breached
  company can say what it holds and correct its own records.
* broker_listing — a people-search / data-broker listing: the
  removal flow (Remove all / the case queue) IS the dispute route,
  and brokers correct wrong details through the same opt-out
  channel.
* search_result — a public web/search result: LeakGuard cannot ask
  a search engine to change its index for someone else; Google's
  own tool is the route for personal results there.
* generic — anything else: the source organisation is the only
  party that can correct its record; its privacy policy carries
  the privacy contact.
"""

import json
import urllib.parse
from pathlib import Path

# Already linked from static/index.html (the "Google exposure"
# card). Reused here — never invent a second spelling of it.
GOOGLE_RESULTS_ABOUT_YOU_URL = \
    "https://myactivity.google.com/results-about-you"

_BREACH_PROVIDERS = frozenset((
    "XposedOrNot",
    "Have I Been Pwned Pwned Passwords",
    "HIBP",
))
_SEARCH_PROVIDERS = frozenset(("DuckDuckGo Discovery",))

_BROKERS_PATH = Path(__file__).resolve().parent.parent / "brokers.json"
_broker_hosts_cache = None


def _broker_hosts():
    """Hosts of the broker registry's opt-out pages (brokers.json).
    A finding served from one of these hosts is a broker listing
    whatever provider surfaced it."""
    global _broker_hosts_cache
    if _broker_hosts_cache is None:
        hosts = set()
        try:
            brokers = json.loads(
                _BROKERS_PATH.read_text(encoding="utf-8"))
        except Exception:
            brokers = []
        for broker in brokers if isinstance(brokers, list) else []:
            for key in ("optout_url", "alt_optout_url"):
                host = urllib.parse.urlparse(
                    str(broker.get(key) or "")).netloc.casefold()
                host = host.split("@")[-1].split(":")[0]
                if host:
                    hosts.add(host)
        _broker_hosts_cache = hosts
    return _broker_hosts_cache


def _host_of(url):
    if not url:
        return ""
    host = urllib.parse.urlparse(str(url)).netloc.casefold()
    return host.split("@")[-1].split(":")[0]


def _get(finding, key, default=None):
    try:
        value = finding.get(key, default)
    except AttributeError:
        value = getattr(finding, key, default)
    return default if value is None else value


def source_class_for(finding):
    """The dispute class of one finding row/dict:
    'breach_database' | 'broker_listing' | 'search_result' |
    'generic'. Pure and deterministic — same finding, same class."""
    provider = _get(finding, "provider", "")
    if provider in _BREACH_PROVIDERS:
        return "breach_database"
    if provider in _SEARCH_PROVIDERS:
        return "search_result"
    if _get(finding, "remediation_eligible", False):
        return "broker_listing"
    host = _host_of(_get(finding, "source_url", ""))
    if host:
        for broker_host in _broker_hosts():
            if host == broker_host or host.endswith("." + broker_host):
                return "broker_listing"
    return "generic"


def guidance_for(finding):
    """{"class", "heading", "steps", "url", "url_label"} for one
    finding. Steps are plain language and claim nothing LeakGuard
    cannot do itself."""
    cls = source_class_for(finding)
    source_name = str(_get(finding, "source_name", "") or "this source")
    if cls == "breach_database":
        return {
            "class": cls,
            "heading": "Dispute or correct this",
            "steps": [
                "This record comes from a data breach reported as "
                "“%s”. The company that was breached is the one that "
                "held your data." % source_name,
                "To dispute or correct it, contact that company's "
                "privacy team or Data Protection Officer — their "
                "privacy policy lists the address — and ask what "
                "personal data of yours they hold, and to correct "
                "or delete it.",
                "The breach database that reported this to LeakGuard "
                "only indexes breach records: it did not hold your "
                "data itself, and it cannot delete the original "
                "record at the breached company.",
                "If this record is simply not about you, mark it "
                "“Not me” and LeakGuard will stop counting and "
                "alerting on it.",
            ],
            "url": None,
            "url_label": None,
        }
    if cls == "broker_listing":
        return {
            "class": cls,
            "heading": "Dispute or correct this",
            "steps": [
                "This is a listing held by a people-search / data "
                "broker (%s)." % source_name,
                "The dispute route is the removal flow itself: use "
                "“Remove all” above, or open this broker's case in "
                "your removal queue — LeakGuard sends the opt-out "
                "request for brokers that accept one.",
                "If the listing's details are wrong rather than not "
                "yours at all, say so in that same opt-out: brokers "
                "correct listings through the opt-out channel, and "
                "the case in your queue tracks their answer.",
            ],
            "url": None,
            "url_label": None,
        }
    if cls == "search_result":
        return {
            "class": cls,
            "heading": "Dispute or correct this",
            "steps": [
                "This was found in public search results, not in a "
                "database LeakGuard can ask to change — a search "
                "engine indexes pages it does not own.",
                "For personal results about you in Google Search, "
                "Google's “Results about you” tool lets you ask for "
                "results showing your contact details to be removed "
                "from Google Search.",
                "Removing a result from a search index does not "
                "delete the page it points to — for that, the site "
                "showing the page is the party to contact.",
            ],
            "url": GOOGLE_RESULTS_ABOUT_YOU_URL,
            "url_label": "Open Google “Results about you”",
        }
    return {
        "class": cls,
        "heading": "Dispute or correct this",
        "steps": [
            "We do not have a specific dispute route for this "
            "source yet, so here is the honest general one.",
            "This record comes from %s. Only the organisation "
            "behind that source can correct or delete its record — "
            "its privacy policy lists a contact for privacy "
            "requests." % source_name,
            "If this record is simply not about you, mark it "
            "“Not me” and LeakGuard will stop counting and alerting "
            "on it.",
        ],
        "url": None,
        "url_label": None,
    }
