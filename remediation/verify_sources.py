"""Verification source map (verify_sources.json).

Case verification (remediation/verify.py via AgentExecutor.
verify_search) answers 'gone' / 'still_present' only from evidence.
Where that evidence lives depends on the broker, and it is data,
not code: verify_sources.json sits next to brokers.json and maps
every broker slug (registry_seed.slugify) to one of:

  search_index  the broker's own site is JS/bot-walled from
                servers, but its listing pages are publicly
                indexed — evidence is a site:-scoped search query
                (see engine._verify_via_index);
  direct        the broker's search is server-rendered and
                name-addressable: 'url' is a template with
                {name} / {first} / {last} / {city} placeholders
                and 'no_results' lists the page's empty-search
                phrases (see engine._verify_direct);
  none          B2B / credit brokers: removal is a suppression
                election and no public person listing exists, so
                verification is unverifiable by design — the
                engine answers 'unknown', never a guess.

Every entry carries a one-line 'note' recording the research basis
for its method. The file is loaded once and cached; the cache is
process-local and read-only after first load.
"""

import json
from pathlib import Path

_PATH = Path(__file__).resolve().parent.parent / "verify_sources.json"

_cache = None


def _load():
    global _cache
    if _cache is None:
        try:
            data = json.loads(_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        _cache = data if isinstance(data, dict) else {}
    return _cache


def config_for(broker_row_or_slug):
    """The verify-source config for a broker registry row (dict
    with a 'slug') or a bare slug string. Returns a copy of the
    config dict, or None when the slug is not mapped."""
    if isinstance(broker_row_or_slug, dict):
        slug = broker_row_or_slug.get("slug")
    else:
        slug = broker_row_or_slug
    if not slug:
        return None
    cfg = _load().get(str(slug))
    return dict(cfg) if isinstance(cfg, dict) else None


def _reset_cache():
    """Test hook: forget the parsed file so the next lookup
    re-reads it from disk."""
    global _cache
    _cache = None
