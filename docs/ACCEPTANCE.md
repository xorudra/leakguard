# LeakGuard — Security & Privacy Acceptance Index

*Spec Phases 147 (security acceptance) + 148 (privacy acceptance).
This document makes **no new claims**: it is an index from each
acceptance area to the evidence that already exists, so a reviewer
can check any claim from one page. Where evidence is a production
check, it was run against https://leakguard-hh8e.onrender.com on
2026-10-07 (the stage E2Es recorded in `CURRENT_STATE.md` and
`MIGRATION_PLAN.md`).*

## How acceptance is run

* **Every change:** the full test suite locally, then CI
  (`.github/workflows/tests.yml` — same suite on push/PR and a
  weekly run) must be green before deploy.
* **Every deploy:** the post-deploy checklist in
  `MIGRATION_PLAN.md` §10 — health (`db: "ok"`) → providers health
  → anonymous baseline parity → the change's own production E2E on
  a throwaway, self-deleted account → admin counts sanity →
  UptimeRobot confirmation.
* **Per-phase status:** `PHASE_STATUS.md` — all 181 phases with
  tier, status, evidence and gaps. `CURRENT_STATE.md` is the
  system inventory those claims rest on.

## Security acceptance

| Area | Evidence |
|---|---|
| Authentication (Argon2id, sessions, reset, TOTP) | `accounts/`; security inventory `CURRENT_STATE.md` §D; tests `tests/test_accounts.py`; Stage S3/S8 production E2Es |
| Authorization / IDOR (owner-scoped everything, foreign ids → 404) | `PHASE_STATUS.md` Phase 5; `tests/test_orgs_admin.py`, `tests/test_api_tokens.py`; production IDOR probes per stage |
| Encryption & key separation (vault envelope, HMAC lookups) | `vault/`; `tests/test_vault.py`; Phase 3 DONE |
| SSRF (host allowlist + DNS-resolution guard, rebinding residual documented) | `core/ssrf.py`; Phase 70 DONE; `tests/test_batch_a.py` |
| Security headers incl. HSTS | `core/security.py`; Phase 69 DONE; production header check |
| Rate limiting (incl. the last-X-Forwarded-For-hop keying fix) | `core/ratelimit.py`; `tests/test_hardening.py`; live 429 + spoof probes (Stage S12/S12.1) |
| Least-privilege database role (app is DML-only; migrations on the owner connection) | Phase 73 DONE; `tests/test_migration_split.py`; production register/scan/delete E2E under the app role |
| Backups & restore actually tested | Phases 78/170 DONE; drill numbers in `docs/DISASTER_RECOVERY.md` |
| Dependency pinning + CI | `requirements.lock`; `.github/workflows/tests.yml`; Phases 106/107 DONE |
| Emergency controls (kill switches) | `core/flags.py`; Phase 120/122 DONE; procedure in README → Operations and `docs/INCIDENT_RESPONSE.md` |
| Security regression suite | The full suite's security tests are part of every run — Phase 171 DONE |

## Privacy acceptance

| Area | Evidence |
|---|---|
| Nothing stored by the anonymous Quick Scan | `app.py` scan route; `CURRENT_STATE.md` §F; baseline parity below |
| Identifier values never in API output (masked only) / logs PII-free | `vault/` masking; `core/logging_setup.py`; audit PII filter `accounts/audit.py`; `CURRENT_STATE.md` §E data inventory |
| Password checks leak nothing (k-anonymity, 5-char prefix only) | `providers/hibp_passwords.py`; `tests/test_providers.py` asserts only the prefix leaves the server; Phase 14 DONE |
| Evidence references commit to HMAC-keyed payloads, never raw identifiers | `scanning/normalize.py`; Phase 24 DONE |
| Export is owner-only, password-rechecked, and the only plaintext exit | `accounts/privacy.py`; Phase 49 DONE; export E2Es |
| Deletion cascades + 30-day hard purge, audit survives PII-free | `core/retention.py`; `tests/test_hardening.py` (29d untouched / 31d purged across all tables); Phases 50/169 DONE |
| Consent gates scanning, monitoring, remediation, notifications — re-checked at execution, withdrawal stops everything | `accounts/consents.py`; Phase 6 DONE; `tests/test_remediation.py` (withdrawn consent = zero external calls) |
| Admin sees counts only, never user data | `accounts/admin.py` privacy contract; whole-audit-table serialization test asserts no email/identifier/token appears |
| No exhaustive-coverage or unverified-removal claims anywhere in product copy | `/trust`; claim review Phases 176/177 DONE |
| Privacy regression suite | `tests/test_vault.py`, `tests/test_accounts.py`, `tests/test_hardening.py` in every suite run — Phase 172 DONE |

## Production baselines (the acceptance yardstick)

Unchanged from the pre-upgrade product, re-verified at S15 and at
every deploy since (MIGRATION_PLAN.md §10 checklist):

* `test@example.com` → **214 breaches**, exposure score **100**
* password `"password"` → pwned **52,372,427** times (k-anonymity)
* A clean address → **0** breaches
