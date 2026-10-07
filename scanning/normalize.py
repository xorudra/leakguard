"""Provider results -> normalized findings (spec Phase 21).

One finding per breach, in the findings-table shape (see
db/migrations/0003_scans.sql). Every finding carries:

* confidence  — email breaches confirmed by the provider for the
                exact address are "exact"; nothing here invents
                weaker/stronger grades than the source supports.
* reliability — from the static source table below; unknown sources
                default to "low" (conservative, never flattering).
* evidence_ref— SHA-256 hex of the canonical JSON (sorted keys,
                compact separators) of {provider, source_name,
                identifier_kind, identifier_hmac, excerpt}. The only
                identifier component is the vault LOOKUP HMAC of the
                value — the raw identifier NEVER appears in the
                payload, so an evidence reference can be stored,
                compared and shown without exposing what was scanned.
* remediation_eligible — False for breach-database findings: a
                breach cannot be "removed" by a removal request
                (that is the product's honest limit); broker /
                people-search findings in later stages are the
                eligible kind.

Password findings (from the interactive k-anonymity check only —
scan jobs never see passwords) contain a pwned COUNT in details and
nothing else about the password: no password, no hash prefix, no
hash suffix, ever.

Stage S6 finding types follow the same evidence rules, with the
confidence ladder the stage's honesty contract demands: public-web
mentions are "weak", a registered exact handle is "probable" (with a
not-proof note on the finding), public DNS/certificate facts for a
verified domain are "exact". None of them is remediation-eligible.
"""

import hashlib
import json

from vault import store as vault_store

# Static source reliability (spec Phase 23). Keys are provider
# registry names; "HIBP" is kept as an alias for the passwords API.
RELIABILITY = {
    "XposedOrNot": "high",
    "Have I Been Pwned Pwned Passwords": "high",
    "HIBP": "high",
    "Domain Intel": "high",
    "Username Platforms": "medium",
    "DuckDuckGo Discovery": "low",
    "MockProvider": "low",
}
DEFAULT_RELIABILITY = "low"

PASSWORD_SOURCE_NAME = "Pwned Passwords"


def reliability_for(provider_name):
    return RELIABILITY.get(provider_name, DEFAULT_RELIABILITY)


def canonical_evidence_ref(payload):
    """SHA-256 hex of a payload's canonical JSON form."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def evidence_payload(provider, source_name, identifier_kind,
                     identifier_hmac_hex, excerpt):
    """The exact dict an evidence_ref commits to. Exposed for tests:
    the raw identifier value must never be a member of this payload —
    only its keyed lookup HMAC."""
    return {
        "provider": provider,
        "source_name": source_name,
        "identifier_kind": identifier_kind,
        "identifier_hmac": identifier_hmac_hex,
        "excerpt": excerpt,
    }


def _identifier_hmac_hex(kind, value, lookup_key):
    return vault_store.lookup_hmac(kind, value, lookup_key).hex()


def email_findings(provider_name, identifier_id, identifier_kind,
                   identifier_value, breaches, analytics,
                   lookup_key=None):
    """One finding per breach name for an email identifier.

    exposed_fields come from the address-level analytics when the
    provider supplied them (analytics describe the data exposed for
    THIS address across its breaches, so they are attributable to
    each of its breach findings); without analytics the fields are
    honestly empty. source_date / source_url stay None — the
    check-email payload carries neither, and inventing them is
    fabrication."""
    exposed = []
    if analytics and isinstance(analytics.get("exposed_data"), list):
        exposed = [str(x) for x in analytics["exposed_data"]]
    hmac_hex = _identifier_hmac_hex(identifier_kind, identifier_value,
                                    lookup_key)
    findings = []
    for name in breaches or []:
        excerpt = {"breach": name, "exposed_fields": sorted(exposed)}
        findings.append({
            "identifier_id": identifier_id,
            "identifier_kind": identifier_kind,
            "identifier_hmac": hmac_hex,
            "provider": provider_name,
            "source_name": str(name),
            "source_url": None,
            "source_date": None,
            "exposed_fields": list(exposed),
            "confidence": "exact",
            "reliability": reliability_for(provider_name),
            "evidence_ref": canonical_evidence_ref(evidence_payload(
                provider_name, str(name), identifier_kind, hmac_hex,
                excerpt)),
            "remediation_eligible": False,
            "details": {
                "exposed_data_attribution": "analytics" if exposed
                else "none",
            },
        })
    return findings


def _finding(provider_name, identifier_id, identifier_kind, hmac_hex,
             source_name, source_url, exposed_fields, confidence,
             excerpt, details):
    """Shared skeleton for the Stage S6 finding types. Every S6 type
    is remediation_eligible=False: a public mention, a registered
    handle or a DNS record is never something a broker removal
    request deletes — the eligible kind arrives with Stage S7."""
    return {
        "identifier_id": identifier_id,
        "identifier_kind": identifier_kind,
        "identifier_hmac": hmac_hex,
        "provider": provider_name,
        "source_name": source_name,
        "source_url": source_url,
        "source_date": None,
        "exposed_fields": list(exposed_fields),
        "confidence": confidence,
        "reliability": reliability_for(provider_name),
        "evidence_ref": canonical_evidence_ref(evidence_payload(
            provider_name, source_name, identifier_kind, hmac_hex,
            excerpt)),
        "remediation_eligible": False,
        "details": details,
    }


def discovery_findings(provider_name, identifier_id, identifier_kind,
                       identifier_value, results, lookup_key=None):
    """Public-web mentions of a phone / name / address / username
    (Stage S6, spec Phases 15, 17, 18, 20).

    Confidence is "weak" BY CONSTRUCTION: a search engine returning a
    page that contains the same digits or words proves nothing about
    whose page it is. Neither the excerpt nor details carry the
    result's title or snippet — both routinely embed the searched
    text itself, and the raw identifier never enters a finding (see
    module docstring). The source URL is kept: it is the public page,
    the thing the owner needs in order to review the lead."""
    hmac_hex = _identifier_hmac_hex(identifier_kind, identifier_value,
                                    lookup_key)
    findings = []
    for result in results or []:
        domain = str(result.get("domain") or "unknown source")
        findings.append(_finding(
            provider_name, identifier_id, identifier_kind, hmac_hex,
            source_name=domain,
            source_url=result.get("url"),
            exposed_fields=[identifier_kind],
            confidence="weak",
            excerpt={"source_domain": domain},
            details={
                "match_kind": "public_web_mention",
                "note": ("A public web page mentions this detail. A "
                         "mention is a lead to review — not proof the "
                         "page is about you."),
            }))
    return findings


def username_presence_findings(provider_name, identifier_id,
                               identifier_value, checks,
                               lookup_key=None):
    """One finding per platform where the exact handle is registered
    (Stage S6, spec Phase 16). Confidence "probable" — the middle
    grade, on purpose: the handle EXISTS, but a handle match is not
    proof the account belongs to the person who saved it, and the
    note on every finding says so."""
    hmac_hex = _identifier_hmac_hex("username", identifier_value,
                                    lookup_key)
    findings = []
    for check in checks or []:
        if check.get("state") != "in_use":
            continue
        platform = str(check.get("platform") or "Unknown platform")
        findings.append(_finding(
            provider_name, identifier_id, "username", hmac_hex,
            source_name=platform,
            source_url=check.get("url"),
            exposed_fields=["username"],
            confidence="probable",
            excerpt={"platform": platform},
            details={
                "match_kind": "handle_registered",
                "note": ("An account with this exact handle exists on "
                         "%s. A handle match is not proof it belongs "
                         "to you — handles are not unique to a "
                         "person." % platform),
            }))
    return findings


def domain_findings(provider_name, identifier_id, identifier_value,
                    snapshot, cert_names, lookup_key=None):
    """Public DNS + certificate facts for a VERIFIED domain (Stage
    S6, spec Phase 19). Confidence "exact": these are the domain's
    own public records, reported neutrally — a certificate name or
    an MX record is footprint, not a verdict. The snapshot finding
    carries the A/MX/NS summary in details; certificates get one
    finding per distinct name beyond the apex."""
    hmac_hex = _identifier_hmac_hex("domain", identifier_value,
                                    lookup_key)
    domain = vault_store.normalize("domain", identifier_value)
    findings = []
    if snapshot:
        summary = {rtype: list(snapshot.get(rtype) or [])
                   for rtype in ("A", "MX", "NS")}
        findings.append(_finding(
            provider_name, identifier_id, "domain", hmac_hex,
            source_name=domain,
            source_url=None,
            exposed_fields=["domain"],
            confidence="exact",
            excerpt={"record": "dns_snapshot"},
            details={
                "match_kind": "dns_snapshot",
                "dns": summary,
                "note": ("Public DNS records for your verified "
                         "domain, exactly as resolvers see them."),
            }))
    for name in cert_names or []:
        name = str(name).strip().lower().rstrip(".")
        if not name or name == domain:
            continue
        findings.append(_finding(
            provider_name, identifier_id, "domain", hmac_hex,
            source_name=name,
            source_url="https://crt.sh/?q=" + name,
            exposed_fields=["domain"],
            confidence="exact",
            excerpt={"cert_name": name},
            details={
                "match_kind": "certificate_name",
                "note": ("This hostname appears on a public "
                         "certificate issued for your verified "
                         "domain (certificate transparency logs)."),
            }))
    return findings


def password_finding(provider_name, identifier_id, pwned_count,
                     identifier_kind="password"):
    """The finding for a password the k-anonymity check has seen in
    breach data. details holds ONLY the sighting count — no password
    material of any kind exists to put here."""
    excerpt = {"pwned_count": int(pwned_count)}
    return {
        "identifier_id": identifier_id,
        "identifier_kind": identifier_kind,
        "identifier_hmac": None,
        "provider": provider_name,
        "source_name": PASSWORD_SOURCE_NAME,
        "source_url": None,
        "source_date": None,
        "exposed_fields": ["password"],
        "confidence": "exact",
        "reliability": reliability_for(provider_name),
        "evidence_ref": canonical_evidence_ref(evidence_payload(
            provider_name, PASSWORD_SOURCE_NAME, identifier_kind, None,
            excerpt)),
        "remediation_eligible": False,
        "details": {"pwned_count": int(pwned_count)},
    }
