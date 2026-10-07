"""Erasure letters for email-channel brokers (spec Phase 33).

Port of the anonymous flow's letter generator (static/app.js
makeLetter) so the signed-in engine can produce the same letter
server-side. The legal text structure is identical: the same three
laws, the same citations, the same asks. The letter is the USER's own
letter — it carries their name and email because they will send it
from their own mailbox (brokers only accept requests from the data
subject's own address). It is stored only in the case's attempt
detail and returned only to that user in their human-action queue;
it is never logged.
"""

LAWS = {
    "dpdp": {
        "cite": "Section 12 of India's Digital Personal Data Protection Act, 2023",
        "ask": "erase my personal data, and cause any processor you shared it with to erase it as well, unless retention is required by law",
    },
    "gdpr": {
        "cite": "Article 17 of the General Data Protection Regulation (GDPR)",
        "ask": "erase my personal data without undue delay, and inform any third parties you disclosed it to of this erasure request",
    },
    "ccpa": {
        "cite": "the California Consumer Privacy Act (CCPA), including my right to delete and to opt out of the sale of my personal information",
        "ask": "delete my personal data, direct your service providers to delete it, and stop selling or sharing it",
    },
}

SUBJECT = "Request for erasure of my personal data"

# Mirrors the anonymous UI's default law (the first lgLaw option).
DEFAULT_LAW = "dpdp"


def make_letter(broker_name, full_name, email, city, law=DEFAULT_LAW):
    """The letter body, byte-structured like static/app.js makeLetter
    (minus its To:/Subject: header lines, which travel separately in
    the email dict). Missing profile fields fall back to the same
    bracketed placeholders the anonymous generator uses."""
    law_info = LAWS.get(law) or LAWS[DEFAULT_LAW]
    name = (full_name or "").strip() or "[Your full name]"
    mail = (email or "").strip() or "[Your email]"
    place = (city or "").strip() or "[Your city, country]"
    target = broker_name or "your company"
    lines = [
        "To: Data Protection / Privacy Team, " + target,
        "",
        "Dear Sir/Madam,",
        "",
        "My name is " + name + ". I am writing to exercise my right under "
        + law_info["cite"] + ".",
        "",
        "I request that you " + law_info["ask"] + ". This includes, but is not limited to, any profile,",
        "listing or record associated with:",
        "",
        "  Name:  " + name,
        "  Email: " + mail,
        "  Location: " + place,
        "",
        "Please also add my details to your suppression list so my data is not re-added",
        "from your data sources in the future.",
        "",
        "Please confirm in writing, to the email address above, once the erasure is",
        "complete, and tell me if you need any information from me to verify my identity.",
        "",
        "Thank you.",
        "",
        name,
        mail,
    ]
    return "\n".join(lines)


def letter_for_broker(broker, profile, law=DEFAULT_LAW):
    """A ready-to-send email dict {to, subject, body} for one broker.

    `broker` is a brokers-table row (dict) or any mapping with
    name/contact_email; `profile` is the engine's assembled profile
    {full_name, email, phone, city}."""
    return {
        "to": broker.get("contact_email") or "",
        "subject": SUBJECT,
        "body": make_letter(
            broker.get("name"), profile.get("full_name"),
            profile.get("email"), profile.get("city"), law=law),
    }
