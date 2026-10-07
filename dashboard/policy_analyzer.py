"""Deterministic privacy-policy keyword analyzer (spec Phase 102).

This is a signed-in convenience tool, not a legal review and not an
AI feature. It searches supplied policy text for a fixed set of
plain-language phrases and reports only whether those phrases were
found. A "found" result means the words are present; it does NOT
prove that a company follows its policy, and a "not_found" result
does NOT prove that a right or practice is absent in law or in the
full document.

For a URL, the fetch is deliberately narrow: the SSRF guard runs
before the request, redirects are re-checked, the timeout is five
seconds, and at most 256 KiB is read. HTML is reduced to text with
the standard-library parser; script/style content is discarded.
Only short matched key phrases (never more than eight words) are
returned, never passages from the supplied policy.
"""

import re
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

from core import errors, ssrf

DISCLAIMER = (
    "Automated keyword checklist — not legal advice and not a "
    "safety guarantee."
)
MAX_TEXT_BYTES = 64 * 1024
MAX_FETCH_BYTES = 256 * 1024
FETCH_TIMEOUT_SECONDS = 5
_USER_AGENT = {"User-Agent": "LeakGuard Policy Analyzer/1.0"}


def _compile(pattern):
    return re.compile(pattern, re.IGNORECASE)


# Each check has clear ("strong") phrases and related ("weak") words.
# A weak match alone is reported as "unclear": the topic is mentioned,
# but the text does not make the specific statement the check looks
# for. Patterns are written to keep their own matches short; the
# phrase trimmer below enforces the eight-word ceiling regardless.
_CHECKS = (
    {
        "id": "sale_sharing",
        "label": "Selling or sharing personal information",
        "strong": (
            r"\bdo not sell(?: or share)? (?:my|your) personal information\b",
            r"\bsale of (?:your )?personal (?:information|data)\b",
            r"\bsell(?:s|ing)? (?:your )?personal (?:information|data)\b",
            r"\bshar(?:e|es|ing) (?:your )?personal (?:information|data)\b",
        ),
        "weak": (r"\b(?:sell|sold|sale|share|sharing)\b",),
        "found": "A clear selling or sharing phrase appears.",
        "unclear": "Selling or sharing is mentioned, but no clear statement was found.",
    },
    {
        "id": "advertising_tracking",
        "label": "Advertising and tracking",
        "strong": (
            r"\btargeted advertising\b",
            r"\badvertising (?:partners|cookies)\b",
            r"\btracking technologies\b",
            r"\bmarketing cookies\b",
            r"\bweb beacons\b",
            r"\bpersonali[sz]ed ads\b",
        ),
        "weak": (r"\b(?:advertising|tracking|cookies|analytics)\b",),
        "found": "A clear advertising or tracking phrase appears.",
        "unclear": "Advertising, tracking, cookies or analytics are mentioned without a clearer phrase.",
    },
    {
        "id": "retention",
        "label": "How long information is kept",
        "strong": (
            r"\bretain (?:your )?(?:personal )?(?:data|information) for \d+ (?:days|months|years)\b",
            r"\bkeep (?:your )?(?:personal )?(?:data|information) for \d+ (?:days|months|years)\b",
            r"\bretention period (?:is|of) \d+ (?:days|months|years)\b",
            r"\bdelete (?:your )?(?:personal )?(?:data|information) after \d+ (?:days|months|years)\b",
            r"\bfor as long as your account is active\b",
        ),
        "weak": (r"\b(?:retain|retention|keep|store|stored|storage)\b",),
        "found": "A specific retention period or retention rule appears.",
        "unclear": "Keeping or storing information is mentioned, but no period or rule was found.",
    },
    {
        "id": "user_rights",
        "label": "Your rights to access, correct or delete information",
        "strong": (
            r"\bright to (?:access|delete|correct|erase|rectify)\b",
            r"\brequest (?:access to|deletion of|correction of) (?:your )?(?:data|information)\b",
            r"\baccess, correct,? or delete\b",
            r"\byou may (?:access|delete|correct|erase) (?:your )?(?:data|information)\b",
        ),
        "weak": (r"\b(?:access|delete|deletion|correct|correction|erase)\b",),
        "found": "A clear access, correction or deletion right appears.",
        "unclear": "Access, correction or deletion is mentioned, but not as a clear right or request route.",
    },
    {
        "id": "contact",
        "label": "How to contact the company about privacy",
        "strong": (
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            r"\bcontact us at\b",
            r"\bemail us at\b",
            r"\bdata protection officer\b",
            r"\bprivacy (?:team|office) at\b",
            r"\bwrite to us at\b",
        ),
        "weak": (r"\bcontact\b",),
        "found": "A privacy contact method or contact phrase appears.",
        "unclear": "Contact is mentioned, but no method or privacy contact was found.",
    },
    {
        "id": "security_practices",
        "label": "Security practices",
        "strong": (
            r"\bencryption\b",
            r"\bencrypted (?:in transit|at rest)\b",
            r"\baccess controls\b",
            r"\bsecurity measures\b",
            r"\bsafeguards\b",
            r"\btwo-factor authentication\b",
            r"\bprotect against unauthorized access\b",
        ),
        "weak": (r"\b(?:security|secure|protect|protection)\b",),
        "found": "A specific security practice is named.",
        "unclear": "Security is mentioned, but no specific practice was found.",
    },
    {
        "id": "children",
        "label": "Children's information",
        "strong": (
            r"\bchildren under (?:the age of )?\d+\b",
            r"\bnot intended for children\b",
            r"\bchild(?:ren)?'s personal (?:data|information)\b",
            r"\bdata of minors\b",
        ),
        "weak": (r"\b(?:children|child|minor|minors)\b",),
        "found": "Children's information is specifically addressed.",
        "unclear": "Children are mentioned, but the treatment of their information is not clear.",
    },
    {
        "id": "policy_changes",
        "label": "Notice when the policy changes",
        "strong": (
            r"\bwe may update this (?:privacy )?policy\b",
            r"\bnotify you of (?:any )?(?:material )?changes\b",
            r"\bchanges to this (?:privacy )?policy\b",
            r"\bpost (?:any )?changes to this policy\b",
        ),
        "weak": (r"\b(?:update|updates|change|changes|notice)\b",),
        "found": "A policy-change or change-notice phrase appears.",
        "unclear": "Updates or notices are mentioned, but not clearly for policy changes.",
    },
    {
        "id": "third_party_sharing",
        "label": "Sharing with other companies or service providers",
        "strong": (
            r"\bshare (?:information|data) with third parties\b",
            r"\bdisclose (?:information|data) to service providers\b",
            r"\bprovide (?:information|data) to business partners\b",
            r"\bthird parties may (?:access|collect|receive)\b",
            r"\bservice providers (?:that|who) (?:process|access|use)\b",
        ),
        "weak": (r"\b(?:third parties|third-party|service providers|business partners|affiliates)\b",),
        "found": "A clear third-party or service-provider sharing phrase appears.",
        "unclear": "Other companies or providers are mentioned, but the sharing statement is not clear.",
    },
)

for _check in _CHECKS:
    _check["strong"] = tuple(_compile(p) for p in _check["strong"])
    _check["weak"] = tuple(_compile(p) for p in _check["weak"])


class _PolicyTextExtractor(HTMLParser):
    """Small HTML-to-text reducer for fetched policy pages."""

    _SKIP_TAGS = frozenset(("script", "style", "noscript", "template"))
    _BLOCK_TAGS = frozenset((
        "address", "article", "aside", "blockquote", "br", "div",
        "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header",
        "li", "main", "nav", "p", "section", "table", "tr",
    ))

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif not self._skip_depth and tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif not self._skip_depth and tag in self._BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(data)

    def text(self):
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()


def strip_html(document):
    """Return visible text from an HTML document (or plain text)."""
    if "<" not in document or ">" not in document:
        return re.sub(r"\s+", " ", document).strip()
    parser = _PolicyTextExtractor()
    try:
        parser.feed(document)
        parser.close()
        return parser.text()
    except Exception:
        # A malformed document should not turn a keyword checklist
        # into a server error; fall back to removing tag-shaped text.
        return re.sub(r"\s+", " ", re.sub(r"<[^>]*>", " ", document)).strip()


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-run the SSRF guard for every redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ssrf.assert_public_url(newurl)
        return super().redirect_request(
            req, fp, code, msg, headers, newurl)


_FETCH_OPENER = ssrf.pinned_opener(_GuardedRedirectHandler())


def fetch_url(url):
    """Fetch `url` under the Phase 102 limits.

    Returns (status, decoded body). The SSRF guard runs before the
    request and inside the redirect handler, and the opener's
    connections are pinned (core.ssrf): every hop — initial and
    redirect — is resolved and validated inside its own connect(),
    so no check can be raced by a DNS rebinding. HTTP error
    statuses are returned to the caller, which turns them into one
    honest fetch failure rather than analyzing an error page as
    if it were a policy.
    """
    ssrf.assert_public_url(url)
    req = urllib.request.Request(url, headers=_USER_AGENT)
    try:
        with _FETCH_OPENER.open(
                req, timeout=FETCH_TIMEOUT_SECONDS) as resp:
            raw = resp.read(MAX_FETCH_BYTES + 1)
            status = resp.status
            charset = "utf-8"
            try:
                charset = resp.headers.get_content_charset() or charset
            except Exception:
                pass
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(MAX_FETCH_BYTES + 1)
        except Exception:
            raw = b""
        status = exc.code
        charset = "utf-8"
    except ssrf.SsrfError as exc:
        raise errors.bad_request(
            "policy_url_not_public",
            "That policy address cannot be fetched safely") from exc
    except errors.ApiError:
        raise
    except Exception as exc:
        raise errors.bad_request(
            "policy_fetch_failed",
            "That policy page could not be fetched") from exc
    if len(raw) > MAX_FETCH_BYTES:
        raise errors.payload_too_large(
            "That policy page is larger than 256 KB")
    return status, raw.decode(charset, "replace")


def _coerce_fetch_result(result):
    if isinstance(result, tuple) and len(result) == 2:
        return result
    return 200, result


def _short_phrase(match):
    phrase = re.sub(r"\s+", " ", match.group(0)).strip(" .,;:()[]{}\"'")
    words = phrase.split()
    if len(words) > 8:
        phrase = " ".join(words[:8])
    return phrase


def _first_match(patterns, text):
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match
    return None


def _stats(text):
    words = re.findall(r"[A-Za-z0-9]+(?:['’-][A-Za-z0-9]+)*", text)
    sentence_chunks = [
        chunk for chunk in re.split(r"[.!?]+", text)
        if re.search(r"[A-Za-z0-9]", chunk)
    ]
    sentences = len(sentence_chunks) or (1 if words else 0)
    average = round(len(words) / sentences, 1) if sentences else 0.0
    return {
        "characters": len(text),
        "word_count": len(words),
        "sentence_count": sentences,
        "average_sentence_words": average,
    }


def analyze_text(text, source):
    """Run the fixed keyword checklist over already-obtained text."""
    checks = []
    for check in _CHECKS:
        strong = _first_match(check["strong"], text)
        if strong:
            status = "found"
            phrase = _short_phrase(strong)
            note = check["found"]
        else:
            weak = _first_match(check["weak"], text)
            if weak:
                status = "unclear"
                phrase = _short_phrase(weak)
                note = check["unclear"]
            else:
                status = "not_found"
                phrase = None
                note = "No matching phrase was found in the text supplied."
        checks.append({
            "id": check["id"],
            "label": check["label"],
            "status": status,
            "matched_phrase": phrase,
            "note": note,
        })
    return {
        "tool": "privacy_policy_analyzer",
        "method": "deterministic_keyword_heuristics",
        "disclaimer": DISCLAIMER,
        "source": source,
        "stats": _stats(text),
        "checks": checks,
    }


def analyze_payload(payload, fetcher=None):
    """Validate one API payload and return the analyzer result.

    Exactly one of `text` and `url` must be present and non-empty.
    `fetcher` is injectable for tests; the production fetcher is the
    guarded, capped function above.
    """
    if not isinstance(payload, dict):
        raise errors.invalid_json()
    text = payload.get("text")
    url = payload.get("url")
    has_text = isinstance(text, str) and bool(text.strip())
    has_url = isinstance(url, str) and bool(url.strip())
    if has_text == has_url:
        raise errors.bad_request(
            "policy_input_required",
            "Paste a policy or give one policy page address — not both")
    if has_text:
        if len(text.encode("utf-8", "replace")) > MAX_TEXT_BYTES:
            raise errors.payload_too_large(
                "Pasted policy text is larger than 64 KB")
        return analyze_text(text.strip(), {"type": "text"})

    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise errors.bad_request(
            "policy_url_invalid", "Give a complete http or https address")
    # The guard runs here as well as inside the fetcher, so an
    # injected fetcher can never become an unguarded fetch path.
    try:
        ssrf.assert_public_url(url)
    except ssrf.SsrfError as exc:
        raise errors.bad_request(
            "policy_url_not_public",
            "That policy address cannot be fetched safely") from exc
    fetch = fetcher or fetch_url
    status, body = _coerce_fetch_result(fetch(url))
    if status is not None and not (200 <= int(status) < 300):
        raise errors.bad_request(
            "policy_fetch_failed",
            "That policy page could not be fetched")
    if isinstance(body, bytes):
        if len(body) > MAX_FETCH_BYTES:
            raise errors.payload_too_large(
                "That policy page is larger than 256 KB")
        body = body.decode("utf-8", "replace")
    body = str(body or "")
    if len(body.encode("utf-8", "replace")) > MAX_FETCH_BYTES:
        raise errors.payload_too_large(
            "That policy page is larger than 256 KB")
    text_from_page = strip_html(body)
    if not text_from_page:
        raise errors.bad_request(
            "policy_text_empty",
            "No readable policy text was found at that address")
    return analyze_text(
        text_from_page,
        {"type": "url", "host": parsed.hostname})
