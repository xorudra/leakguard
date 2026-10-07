# Cycle report — P1-A verification batch: Privacy Center walk + mobile viewport check

Commit: `5c2dabb`. Date: 2026-10-07. The first P1 cycle after
the P0 program closed, run under the owner's "continue with
the P1 work" direction.

## CURRENT PHASE

Phase 48 (Privacy Center, UNVERIFIED → DONE) and Phase 97
(Responsive mobile, UNVERIFIED → DONE) — the two P1 phases
whose only gap was missing verification evidence.

## PRIORITY TIER

P1 (both phases).

## STATUS

Complete. Both phases verified against the real product — the
Privacy Center by an end-to-end walk in the suite, the mobile
layout by a scripted viewport check against the live staging
site, 12 of 12 checks passing. A CI failure this cycle
surfaced was diagnosed and fixed in the same commit.

## WHAT WAS AUDITED

- Phase 48's claim: the Privacy Center (identifiers, consents,
  monitoring, timeline, notifications, export, deletion,
  household, API tokens) works as one continuous user journey
  — it had only ever been tested section by section.
- Phase 97's claim: the responsive layout holds on a phone —
  tested by hand during the Sentinel stages, never by a
  repeatable check, and the headless browser on this machine
  cannot open local pages, so a live target and a relay were
  needed (the repo's existing relay tooling).

## WHAT WAS IMPLEMENTED

Verification deliverables (no product behaviour changed):

- `tests/test_privacy_center_walk.py` — 3 tests walking every
  Privacy Center section as one journey on a throwaway
  account: identifiers (add / list / delete; masked values
  asserted, plaintext asserted absent), consents (read, grant,
  re-read), household (member add + identifier assignment),
  monitoring settings (cadence + pause/resume), timeline,
  notifications, API tokens (create / list / revoke, and the
  revoked credential then refused), the exposure graph (exact
  key shape, no plaintext), export behind password re-auth,
  and account deletion closing the walk.
- `tools/mobile_viewport_check.py` — a Playwright + Chromium
  check run through the repo relay against the **live staging
  site**, at 360×740 and 768×1024, across six pages (`/`,
  `/privacy`, `/terms`, `/support`, `/trust`, `/reset`):
  HTTP 200, no horizontal overflow (scroll width equals
  viewport width), header visible, no visible element wider
  than the viewport.
- The CI fix (below), in `tests/test_secrets_hygiene.py`:
  two exact-string allowlist entries with stated reasons.

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- No CSS changes: the viewport check passed 12/12 as-is;
  touching the stylesheet to "improve" a passing layout was
  out of scope.
- No screenshots or visual-diff harness: the check is
  geometric (overflow, visibility, widths) — the level of
  evidence the phase required, kept dependency-light.

## FILES CREATED

- `tests/test_privacy_center_walk.py`
- `tools/mobile_viewport_check.py`

## FILES MODIFIED

- `tests/test_secrets_hygiene.py` (allowlist additions)
- `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

None.

## API ROUTES

None added or changed. (Routes were exercised, not modified —
the walk covers the Privacy Center's full surface.)

## TESTS ADDED

`tests/test_privacy_center_walk.py` — 3 tests (the journey is
one continuous flow per test, by design). The viewport check
is a tool, not a suite test: it needs a live site and a real
browser, so it runs on demand rather than in CI.

## TESTS RUN

Full suite at this commit: **441 passed** (commit record),
19 skipped. The viewport check ran live against staging:
**12/12 PASS** (6 pages × 2 viewport sizes).

## RESULTS

Phases 48 and 97 moved UNVERIFIED → DONE. Scoreboard after
this cycle: 131 DONE / 31 PARTIAL / 1 MISSING / 4 UNVERIFIED /
14 NOT APPLICABLE. (The next cycle, Phase 25, brought the
count to 132 DONE / 30 PARTIAL — the scoreboard recorded in
`CURRENT_STATE.md` §G.)
The cycle also produced a durable lesson, recorded in
`AGENTS.md`: the secrets-hygiene guard scans only *tracked*
files, so a new test file with credential-shaped fixture
strings passes locally while untracked and fails the moment
it is committed — guard fixtures must be allowlisted in the
same commit, and the guard should be run against the
committed tree before claiming green.

## SECURITY CONTROLS

Verified, not changed: the walk asserts masked-only
identifier display, re-auth on export, and that a revoked API
credential is refused. The hygiene-guard fix weakened nothing:
allowlist entries are exact strings with reasons, per the
guard's own rules.

## PRIVACY CONTROLS

Verified: plaintext identifiers never appear in Privacy
Center responses (asserted absent, not merely unobserved),
and the deletion step of the walk ends the account's data
with it.

## DEPLOYMENT STATUS

No deployment — tests and tooling only. The verification
targets were the already-deployed staging service (viewport
check) and the local suite database (walk).

## KNOWN LIMITATIONS

The viewport check covers two sizes and six pages; it is a
geometry check, not a usability study, and it must be re-run
manually after layout changes. The walk runs against the
test database, not production — production account flows are
covered by the per-deploy throwaway E2E instead.

## RISKS

The CI-red discovery mechanism deserves naming: GitHub CI had
gone red on the two P0 docs/fix commits (`0489cf8`,
`b72a072`) because the hygiene guard flagged the walk test's
own fixture strings once they became tracked — and nobody
was watching CI, so the red sat unnoticed until this cycle.
The fix landed here; *watching* CI after each push is the
process gap this exposes, carried into the next cycles'
discipline.

## NEXT PHASE

P1-B — Phase 25 (stored finding lifecycle state), then
Phase 149 (per-cycle report files — this series).
