# Cycle report — Staging environment creation

Platform work on Render + Neon; the repository record is docs
commit `520a692`. Date: 2026-10-07.

## CURRENT PHASE

Phase 109 (Environments) — the Final-spec program's staging
environment, implementing the `MIGRATION_PLAN.md` §9 rule:
deploy to staging first, run the acceptance smoke, then
promote the same commit to production.

## PRIORITY TIER

P2.

## STATUS

Complete. `https://leakguard-staging.onrender.com` is live on
its own database branch with its own vault keys, manual
deploys only, and no email lane.

## WHAT WAS AUDITED

Production was the only environment: every deploy was a
production event, and the rollback plan (Phase 174) had
nowhere safe to rehearse. The migration-credential split
(Batch A.1) had already separated owner/app database access,
which a branch database also needs. Two platform behaviours
had to be discovered before the setup could work — see
Results.

## WHAT WAS IMPLEMENTED

- Neon branch database `staging` (branch
  `br-long-unit-az6wvyyw` on the `leakguard` project,
  auto-delete set to Never), branched from production.
- Render service `leakguard-staging`
  (`srv-db34g7vlk1mc739dgp9g`), built from the same public
  repository, **manual deploys only** — staging never moves
  unless someone deploys it.
- Staging connects to its branch through the branch's
  **direct** endpoint (see Results for why).
- Staging has its **own vault keys** (separate master and
  lookup key files, mode 600, git-ignored — the ignore rule
  was completed in the v2.1 reconciliation commit `8803686`
  after the audit caught the gap).
- First staging deploy: commit `b0a7a8f` (deploy
  `dep-db34n9d9fdbs739vetc0`, live 19:09 IST) — the same
  commit production was running, so staging started as a true
  mirror.

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- **No email lane on staging**: no Brevo variables are set.
  A staging box that can send real mail is a footgun; mail
  flows are verified on production's throwaway accounts
  instead (owner-accepted, recorded in the Phase 109 row).
- No auto-deploy: a staging environment that silently tracks
  main cannot rehearse a *specific* commit, which is its
  whole purpose (proven in the Phase 174 rehearsal).

## FILES CREATED

None in the repository — the environment lives on Render and
Neon. (Documents updated in `520a692`: `CURRENT_STATE.md`,
`PHASE_STATUS.md`.)

## FILES MODIFIED

- `CURRENT_STATE.md`, `PHASE_STATUS.md` (commit `520a692`)
- `.gitignore` gained the staging key-file pattern in commit
  `8803686` (reconciliation cycle).

## DATABASE MIGRATIONS

No new migrations. The branch database carries the same
migration set as production (`0001`–`0011` at creation), applied
by the app's startup migration path on its own branch
credentials.

## API ROUTES

None — staging serves the same routes as production by
construction (same commit).

## TESTS ADDED

None. Environments are verified by smoke checks, not unit
tests.

## TESTS RUN

Staging smoke after the first deploy: health answered with the
database reporting ok; a register → delete throwaway-account
cycle passed on the branch database. The full suite was
unaffected (no code changed).

## RESULTS

Phase 109 moved to DONE; scoreboard at the docs commit:
133 DONE / 33 PARTIAL / 1 NOT_DONE / 11 CUT / 3 NA.
Two durable platform lessons were recorded in `AGENTS.md`:
(a) Neon **branch** databases must be reached from Render via
the direct endpoint — the branch's pooled endpoint failed with
a bare connection error while the branch itself was healthy
(the production branch's pooled endpoint works fine);
(b) vault keys must be standard base64 — the loader validates
strictly, and a URL-safe key silently disables accounts while
health still reports the database as ok.

## SECURITY CONTROLS

Separate vault keys per environment: staging data (all of it
throwaway) is encrypted under keys production never uses, and
staging holds no production user data beyond the branch
snapshot it was created from — a branch the owner can delete
at any time.

## PRIVACY CONTROLS

The branch was created from production, so the staging
database initially contained production-shaped data under
staging-only keys; the mitigation is procedural and recorded:
staging accounts are throwaway, no email lane exists to leak
notifications, and the branch is deletable in one action.

## DEPLOYMENT STATUS

Staging live on `b0a7a8f` at cycle close. Staging has since
become the mandatory first stop of the deploy sequence
(staging deploy → smoke → promote the same commit), first
exercised end-to-end by the post-audit P0 program.

## KNOWN LIMITATIONS

Staging shares the Render account's free instance hours with
production and sleeps when idle, like production. Free-tier
branch storage bounds how long the branch can accumulate
history.

## RISKS

A forgotten staging service still costs shared free hours;
a stale staging (left on an old commit) can mislead a smoke
check — the deploy sequence therefore always names the commit
it promotes.

## NEXT PHASE

Spec v2.1 live/repository reconciliation (Phases 173/180) —
which used this environment as one of its two pinned data
points.
