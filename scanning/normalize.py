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
