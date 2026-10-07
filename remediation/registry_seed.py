"""Broker registry seeding + DB-backed broker list (spec Phases
30, 31, 134).

brokers.json (+ playbooks.json) remains the source the seed reads —
the same data agent.py uses — and the registry is an idempotent
upsert: re-running it (at every app startup, guarded exactly like
migrations) refreshes public broker facts without touching
workflow_version, which only moves when a broker's flow is
deliberately re-mapped.

search_url is seeded from verify_sources.json (the verification
source map): only 'direct' brokers — whose search is
server-rendered and name-addressable — get their URL template
stored; every other broker's search_url stays NULL, because for
them verification reads the search index (or is impossible by
design) and there is no broker search URL to record.

Channel derivation (documented rule, applied in this order):
  1. the broker record carries a contact_email  -> 'email'
     (an official email channel exists; for walled brokers it is the
     route that actually works — see the BeenVerified playbook)
  2. the broker's playbook has a fillable flow  -> 'form'
     (agent.get_playbook's automation == 'http_form'; this includes
     the generic flow agent.py derives for unmapped brokers, which
     the anonymous agent really does probe and submit)
  3. otherwise                                  -> 'manual'
     (browser_required playbooks, email-only playbooks without a
     published contact address — a human finishes these)

GET /api/brokers serves from this table when a database is
configured and seeded, and falls back to brokers.json otherwise;
the response shape is byte-identical either way (list_brokers_public
rebuilds the file's exact dicts, including the optional
alt_optout_url / contact_email / contact_email_alt keys).
"""

import re

import agent as agent_engine
from db import pool
from remediation import policy, verify_sources

_NON_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name):
    """Stable broker slug: lowercase, runs of non-alphanumerics become
    single hyphens ('Data Axle (InfoUSA)' -> 'data-axle-infousa')."""
    return _NON_SLUG_RE.sub("-", str(name or "").lower()).strip("-")


def derive_channel(broker, playbook):
    """The channel rule documented in this module's docstring.

    The rule itself lives in remediation/policy.py (Phase 153 —
    channel derivation is a policy decision); this entry point
    stays because the seed and its tests have always called it
    here."""
    return policy.derive_channel(broker, playbook)


def seed_brokers():
    """Upsert every broker from brokers.json into the brokers table.
    Returns the number of brokers seeded. Raises when no database is
    configured — startup callers use seed_brokers_if_configured()."""
    brokers = agent_engine.load_brokers()
    count = 0
    with pool.connection() as conn:
        for position, broker in enumerate(brokers):
            playbook = agent_engine.get_playbook(broker)
            slug = slugify(broker["name"])
            verify_cfg = verify_sources.config_for(slug)
            search_url = (
                verify_cfg.get("url")
                if verify_cfg and verify_cfg.get("method") == "direct"
                else None
            )
            conn.execute(
                "INSERT INTO brokers (slug, name, category, region,"
                " optout_url, alt_optout_url, search_url, method_notes,"
                " contact_email, contact_email_alt, channel, position)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                " ON CONFLICT (slug) DO UPDATE SET"
                " name = EXCLUDED.name, category = EXCLUDED.category,"
                " region = EXCLUDED.region,"
                " optout_url = EXCLUDED.optout_url,"
                " alt_optout_url = EXCLUDED.alt_optout_url,"
                " search_url = EXCLUDED.search_url,"
                " method_notes = EXCLUDED.method_notes,"
                " contact_email = EXCLUDED.contact_email,"
                " contact_email_alt = EXCLUDED.contact_email_alt,"
                " channel = EXCLUDED.channel,"
                " position = EXCLUDED.position, active = true,"
                " updated_at = now()",
                (
                    slug,
                    broker["name"],
                    broker.get("type") or "",
                    broker.get("region") or "",
                    broker["optout_url"],
                    broker.get("alt_optout_url"),
                    search_url,
                    broker.get("method") or "",
                    broker.get("contact_email"),
                    broker.get("contact_email_alt"),
                    derive_channel(broker, playbook),
                    position,
                ),
            )
            count += 1
    return count


def seed_brokers_if_configured():
    """Startup helper (app.main): seed when a database is configured,
    stay silent otherwise. Returns the seeded count or 0; exceptions
    from a configured-but-broken database propagate so the caller
    can log them (boot continues regardless)."""
    if not pool.configured():
        return 0
    return seed_brokers()


def _public_file_shape(row):
    """Rebuild the exact brokers.json dict for one registry row."""
    out = {
        "method": row["method_notes"],
        "name": row["name"],
        "optout_url": row["optout_url"],
        "region": row["region"],
        "type": row["category"],
    }
    if row.get("alt_optout_url"):
        out["alt_optout_url"] = row["alt_optout_url"]
    if row.get("contact_email"):
        out["contact_email"] = row["contact_email"]
    if row.get("contact_email_alt"):
        out["contact_email_alt"] = row["contact_email_alt"]
    return out


def list_brokers_public():
    """The /api/brokers payload list from the registry, or None when
    the registry is not the source to use (no database configured,
    table empty, or any database error — the caller falls back to
    brokers.json so the anonymous page never breaks)."""
    if not pool.configured():
        return None
    try:
        with pool.connection() as conn:
            rows = conn.execute(
                "SELECT name, category, region, optout_url,"
                " alt_optout_url, method_notes, contact_email,"
                " contact_email_alt FROM brokers WHERE active = true"
                " ORDER BY position, slug",
            ).fetchall()
    except Exception:
        return None
    if not rows:
        return None
    return [_public_file_shape(row) for row in rows]


def get_broker(slug):
    """One registry row (dict) by slug, or None."""
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT slug, name, category, region, optout_url,"
            " alt_optout_url, search_url, method_notes, contact_email,"
            " contact_email_alt, channel, workflow_version, active"
            " FROM brokers WHERE slug = %s",
            (slug,),
        ).fetchone()
    return dict(row) if row is not None else None
