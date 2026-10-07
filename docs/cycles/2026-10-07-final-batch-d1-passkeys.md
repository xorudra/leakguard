# Cycle report — Final-spec Batch D1: passkeys

Commit: `9c01b08`. Date: 2026-10-07.

## CURRENT PHASE

Final Remaining Implementation — Batch D1: Phase 4
(Authentication — WebAuthn passkeys).

## PRIORITY TIER

P0 (Phase 4 is the authentication phase; passkeys were its one
open item).

## STATUS

Complete. Optional passkeys are live: users can register a
passkey and sign in with it discoverably, with user verification
required. Password + TOTP remain fully supported.

## WHAT WAS AUDITED

Authentication before this batch: Argon2id passwords, sessions,
TOTP MFA, and the reset flow — all live. The Final spec asked
for a phishing-resistant second factor / passwordless option;
no WebAuthn code existed, and the standard library has no CBOR
or WebAuthn support, so the ceremony had to be implemented
against the spec directly.

## WHAT WAS IMPLEMENTED

- `accounts/webauthn.py`: the full ceremony — registration and
  authentication options/verify, database-backed challenges
  (single-use, expiring), attestation format `none` only,
  signature verification for ES256 and RS256, a clone policy
  on the signature counter, and discoverable (resident-key)
  sign-in with user verification required.
- `accounts/cbor.py`: a minimal CBOR decoder covering exactly
  what attestation and assertion parsing needs — nothing more.
- `db/migrations/0011_passkeys.sql`: credential storage
  (credential id, public key, counter, transports, timestamps).
- UI: passkey management and a passkey sign-in button in
  `static/index.html` / `static/app.js`, driven by the
  browser's WebAuthn API.
- Retention wiring so passkey challenges are cleaned up with
  the other short-lived auth state.

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- Attestation formats beyond `none`: no enterprise attestation
  policy exists for a free consumer product; accepting only
  `none` keeps verification honest and the surface small.
- Passkey sign-in does **not** stack TOTP afterwards: the
  passkey ceremony with required user verification is itself
  the multi-factor proof (possession + biometric/PIN). This is
  a documented design decision, recorded here and in the Phase 4
  row — not an oversight.

## FILES CREATED

- `accounts/webauthn.py`, `accounts/cbor.py`
- `db/migrations/0011_passkeys.sql`
- `tests/test_webauthn.py`

## FILES MODIFIED

- `app.py` (passkey routes), `accounts/admin.py`,
  `core/retention.py`
- `static/app.js`, `static/index.html`
- `README.md`, `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

`0011_passkeys.sql` — passkey credentials + challenges
(additive, idempotent).

## API ROUTES

- `POST /api/auth/passkey/register/options`
- `POST /api/auth/passkey/register/verify`
- `POST /api/auth/passkey/login/options`
- `POST /api/auth/passkey/login/verify`
- `GET /api/auth/passkeys`, `DELETE /api/auth/passkeys/<id>`

## TESTS ADDED

`tests/test_webauthn.py` — 26 tests: CBOR round-trips, challenge
lifecycle (issue, expiry, single-use), registration and
assertion verification with generated ES256/RS256 keys, counter
clone rejection, UV enforcement, and the route-level flows.

## TESTS RUN

Full suite run before deploy (per-batch totals not recorded; the
program-close suite was 410 passed, 19 skipped).

## RESULTS

Phase 4 moved to DONE. Live check after deploy: passkey login
options answer on production with the relying party id set to
the production host, `userVerification` required, and an empty
allow-credentials list (discoverable flow) — re-verified in the
v2.1 reconciliation sweep.

## SECURITY CONTROLS

Phishing resistance by construction: credentials are bound to
the relying party, challenges are server-issued, single-use and
short-lived, signature counters detect cloned authenticators,
and user verification is required — a password-only fallback
cannot be forced by a hostile page.

## PRIVACY CONTROLS

The server stores a public key and a counter — nothing
biometric ever leaves the user's authenticator, and nothing
new about the user is collected.

## DEPLOYMENT STATUS

Deployed to production in the Final-spec sequence (see Batch A
report); migration 0011 applied at startup on deploy.

## KNOWN LIMITATIONS

Attestation `none` means the server cannot distinguish
authenticator models — accepted for this product. Synced
passkeys (cloud keychains) make the counter signal advisory
rather than absolute; the clone policy is recorded as such.

## RISKS

Hand-rolled CBOR/WebAuthn parsing is security-critical code;
it is deliberately minimal and covered by generated-key tests,
but it carries more implementation risk than a library would —
there is no maintained stdlib alternative, and the product's
zero-dependency rule (three pip packages) left no other route.

## NEXT PHASE

Batch D2 — privacy-policy analyzer, propagation view, public
trust pages.
