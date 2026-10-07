# Cycle report — Final-spec Batch A: transport security, SSRF guard, dependency lock, CI

Commits: `5b14b08` (code), `e4fcb45` (CI workflow, via the GitHub
web editor). Date: 2026-10-07.

## CURRENT PHASE

Final Remaining Implementation — Batch A: Phase 69 (Security
headers), Phase 70 (SSRF protection), Phase 107 (Dependency
security), Phase 106 (CI/CD).

## PRIORITY TIER

P0 (Phases 69, 70, 107); P2 (Phase 106).

## STATUS

Complete. Phases 69 and 107 closed; Phase 70's guard landed with one
documented residual (DNS rebinding between resolution check and
connect), closed later by the post-audit P0 program; CI live.

## WHAT WAS AUDITED

The Phase 0 audit of the Final spec (commit `e419cd6`) found:
responses carried CSP, X-Frame-Options and Referrer-Policy but no
HSTS; broker/provider fetches resolved a hostname and then fetched
it with no validation of the resolved addresses; the three runtime
dependencies were version-ranged in `requirements.txt` with no
lock file; and there was no CI — the suite ran only by hand.

## WHAT WAS IMPLEMENTED

- HSTS added to the central `SECURITY_HEADERS` in
  `core/security.py`: `max-age=31536000; includeSubDomains`.
- New `core/ssrf.py`: a DNS-resolution guard for outbound fetches —
  http/https only, the host must resolve entirely to public
  addresses (private, loopback, link-local and multicast answers
  are refused). Wired into the agent fetch path (`agent.py`) and
  the remediation engine (`remediation/engine.py`).
- `requirements.lock`: an exact-version snapshot of the resolved
  dependency set (12 packages), generated in a throwaway venv via
  `pip freeze`; the regeneration procedure is recorded in the
  lock file's header and the README supply-chain note.
- CI: `.github/workflows/tests.yml` runs the full unittest suite on
  push, on pull requests, and weekly (Python 3.12,
  `pip install -r requirements.txt pgserver`, plus a
  `node --check` of the frontend bundle).

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- HSTS `preload`: the owner has not made that browser-vendor
  commitment; recorded in the Phase 69 row.
- Connection pinning for the SSRF guard: resolve-then-fetch leaves
  a rebinding window; accepted at this batch as a documented
  residual in a defense-in-depth control (the fetch targets are
  registry-defined broker endpoints), and scheduled as the
  audit's top fix. Closed 2026-10-07 by the post-audit P0 program.
- Hash pinning in the lock: versions are pinned exactly, artifact
  hashes are not (recorded in the Phase 107 row).

## FILES CREATED

- `core/ssrf.py`
- `requirements.lock`
- `tests/test_batch_a.py`
- `.github/workflows/tests.yml` (commit `e4fcb45`, created through
  the GitHub web editor — the repo push credential lacks the
  workflow scope, so workflow files cannot be pushed from here)

## FILES MODIFIED

- `core/security.py` (HSTS), `core/__init__.py`
- `agent.py`, `remediation/engine.py` (SSRF guard wiring)
- `tests/test_verify_sources.py`
- `README.md`, `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

None.

## API ROUTES

None added or changed.

## TESTS ADDED

`tests/test_batch_a.py` — 20 tests, including the security headers
proven on a 200 response, a 404, and an API error response, and the
SSRF guard's refusal shapes. Additions to
`tests/test_verify_sources.py`.

## TESTS RUN

Full suite run before deploy (per-batch totals not recorded in the
commit record; the Final-spec program's suite at its close was
410 passed, 19 skipped — see the v2.1 reconciliation report).

## RESULTS

Phases 69 and 107 moved to DONE in `PHASE_STATUS.md`; Phase 70's
guard layer landed (its DONE rests on this batch plus the later
pinning fix — see the post-audit P0 report). CI run #1 passed
(recorded in the Phase 180 row of `PHASE_STATUS.md`).

## SECURITY CONTROLS

HSTS on every response class; SSRF resolution validation on
data-driven fetches; exact-pin dependency snapshot reducing
supply-chain drift.

## PRIVACY CONTROLS

None changed in this batch.

## DEPLOYMENT STATUS

Deployed to production through the Final-spec deploy sequence
(manual Render deploys, latest commit only, per
`MIGRATION_PLAN.md` §9); the sequence ended on commit `b0a7a8f`
(production deploy `dep-db34ec9srm7s73e32480`). Per-batch deploy
ids were not recorded.

## KNOWN LIMITATIONS

The SSRF guard's rebinding residual (above) until the P0 pinning
fix; the lock pins versions, not hashes; CI cannot be edited via
the repo credential (web editor only).

## RISKS

A hostile DNS answer swapped between check and connect could
still reach a non-public address (the residual); weekly CI is the
only drift alarm for the dependency ranges.

## NEXT PHASE

Batch A.1 — migration-credential split (Phases 73/78/170).
