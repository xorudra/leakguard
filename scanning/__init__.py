"""Scanning engine (Stage S5 — spec Phases 11, 12, 13, 14, 21–27).

Turns a signed-in user's saved identifiers into a durable, auditable
full-profile scan:

* risk.py        — the deterministic risk engine v2. The anonymous
                   Quick Scan's legacy exposure score lives here now
                   (single source of truth); every score carries a
                   plain-language explanation of its components.
* normalize.py   — provider results -> normalized finding dicts with
                   confidence, source reliability and a SHA-256
                   evidence reference that never contains the raw
                   identifier value.
* correlation.py — per-identifier clusters + shared-source notes.
                   Weak signals are labelled "probable", never facts.
* orchestrator.py— runs one scan job end to end against the vault.
* worker.py      — the in-process job worker: claim / retry with
                   backoff / dead-letter, stale-job recovery.
* jobs.py        — the user-scoped job API service behind
                   /api/scans (consent-gated, idempotent).

Honesty rules for the whole package: jobs never check passwords
(passwords are never stored, so there is nothing to check with);
identifiers without a provider yet are reported as exactly that —
no_provider_yet — never as "clean"; a provider outage degrades a
job, it never fabricates results.
"""
