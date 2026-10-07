"""Domain intelligence: public DNS + certificate transparency
(Stage S6, spec Phases 19, 58).

Two factual public sources, no scraping:

* DNS-over-HTTPS (Cloudflare's resolver, application/dns-json):
  A / MX / NS / TXT snapshots for a domain, and TXT lookups for an
  arbitrary name — the latter is what ownership verification reads
  (the _leakguard.<domain> record).
* crt.sh certificate transparency: the hostnames that have ever
  appeared on certificates for a domain.

HONESTY CONTRACT: DNS answers and certificate names are FACTS about
public infrastructure (labelled confidence "exact" by callers), but
a certificate name existing is not an exposure verdict — the
orchestrator reports these neutrally, as the domain owner's own
public footprint. This provider is only ever pointed at domains the
owner has VERIFIED (the domains service enforces that before any
snapshot is taken); the TXT lookup is the verification mechanism
itself and is the one exception.
"""

import re
import urllib.parse

from .base import Provider, ProviderInfo, ProviderResult

DOH = "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"
CRT = "https://crt.sh/?q={query}&output=json"
UA = {"User-Agent": "LeakGuard/1.0 (+https://github.com/xorudra/leakguard)"}
DOH_HEADERS = {"Accept": "application/dns-json",
               "User-Agent": UA["User-Agent"]}
SNAPSHOT_TYPES = ("A", "MX", "NS", "TXT")


def _clean_txt(data):
    """One DoH TXT answer's data field -> the record text. DoH renders
    TXT as one or more quoted chunks ('"leakguard-verify=ab" "cd"');
    the record is the concatenation of the quoted chunks ONLY (the
    whitespace between chunks is presentation, not data)."""
    text = str(data or "")
    if '"' in text:
        return "".join(re.findall(r'"([^"]*)"', text))
    return text


def parse_answers(payload, rtype):
    """The Answer records of one DoH payload for one record type,
    as display strings (TXT records cleaned). Defensive: any
    unexpected shape yields []. Public for tests."""
    if not isinstance(payload, dict):
        return []
    answers = payload.get("Answer")
    if not isinstance(answers, list):
        return []
    out = []
    for entry in answers:
        if not isinstance(entry, dict) or "data" not in entry:
            continue
        data = entry["data"]
        out.append(_clean_txt(data) if rtype == "TXT" else str(data))
    return out


def parse_cert_names(payload):
    """crt.sh JSON -> sorted distinct hostnames from name_value
    fields (which may hold several newline-separated names, and
    wildcard '*.example.com' entries — wildcards are kept: they are
    real certificate names). Defensive: unexpected shapes yield []."""
    if not isinstance(payload, list):
        return []
    names = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("name_value")
        if not isinstance(raw, str):
            continue
        for name in raw.splitlines():
            name = name.strip().lower().rstrip(".")
            if name:
                names.add(name)
    return sorted(names)


class DomainIntelProvider(Provider):
    info = ProviderInfo(
        name="Domain Intel",
        category="domain_intel",
        capabilities=("domain_dns", "domain_certs"),
        privacy=("Only the domain name is sent, to Cloudflare's "
                 "public DNS-over-HTTPS resolver and to crt.sh "
                 "certificate transparency — both answer with public "
                 "infrastructure data. Snapshots are taken only for "
                 "domains the owner has verified."),
    )

    def _doh(self, name, rtype):
        url = DOH.format(name=urllib.parse.quote(name, safe=""),
                         rtype=rtype)
        return self.client.get_json(url, headers=DOH_HEADERS)

    def txt_records(self, name):
        """ProviderResult with data = [TXT record texts] for a fully
        qualified name ([] when none exist)."""
        result = self._doh(name, "TXT")
        if result.status != "ok":
            return result
        return ProviderResult(status="ok",
                              data=parse_answers(result.data, "TXT"),
                              latency_ms=result.latency_ms)

    def dns_snapshot(self, domain):
        """ProviderResult with data = {"A": [...], "MX": [...],
        "NS": [...], "TXT": [...]}. A record type that fails is
        simply absent from the dict — callers treat missing as
        'unknown', never as 'empty'; a total failure propagates."""
        snapshot = {}
        first_error = None
        for rtype in SNAPSHOT_TYPES:
            result = self._doh(domain, rtype)
            if result.status == "ok":
                snapshot[rtype] = parse_answers(result.data, rtype)
            elif first_error is None:
                first_error = result
        if not snapshot and first_error is not None:
            return first_error
        return ProviderResult(status="ok", data=snapshot, latency_ms=0.0)

    def cert_names(self, domain):
        """ProviderResult with data = sorted distinct certificate
        hostnames for the domain (apex included)."""
        url = CRT.format(
            query=urllib.parse.quote("%%.%s" % domain, safe=""))
        result = self.client.get_json(url, headers=UA)
        if result.status != "ok":
            return result
        return ProviderResult(status="ok",
                              data=parse_cert_names(result.data),
                              latency_ms=result.latency_ms)
