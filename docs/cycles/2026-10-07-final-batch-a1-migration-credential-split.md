# Cycle report — Final-spec Batch A.1: migration-credential split

Commit: `595b453`. Date: 2026-10-07.

## CURRENT PHASE

Final Remaining Implementation — Batch A.1: Phase 73 (Database
security), Phase 78 (Backups), Phase 170 (Restore tests).

## PRIORITY TIER

P0 (all three phases).

## STATUS

Complete. Migrations no longer run on the serving credential; the
least-privilege app role serves production; the point-in-time
restore drill was executed and recorded.

## WHAT WAS AUDITED

Before this batch, one database connection string served both
purposes: startup migrations (DDL) and request serving (DML). A
serving credential with DDL rights widens the blast radius of any
application bug. Separately, Neon's point-in-time restore — the
product's only backup mechanism — had never been test-restored.

## WHAT WAS IMPLEMENTED

- Credential split: `db/pool.py` gained a migration DSN read from
  the `MIGRATION_DATABASE_URL` environment variable (owner-level),
  and `db/migrate.py` runs migrations over that connection only.
  Request serving uses the least-privilege `leakguard_app` role
  (DML only, no DDL) via `DATABASE_URL`.
- `render.yaml` declares the new variable; README's Operations
  section documents which credential does what.
- Restore drill (Phase 170): a Neon branch created from
  point-in-time restore showed 19 public tables, 40 brokers,
  8 migrations, 15 users; the drill branch was deleted after
  verification. The drill is the Phase 78 backup evidence.

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- No second backup copy outside Neon PITR: the free plan offers
  no export lane worth the name; the single-mechanism risk is
  carried openly in `CURRENT_STATE.md` §H item 1.
- No automated restore scheduling: the drill is a recorded,
  repeatable manual procedure (`docs/DISASTER_RECOVERY.md`).

## FILES CREATED

- `tests/test_migration_split.py`

## FILES MODIFIED

- `db/pool.py`, `db/migrate.py`, `app.py`
- `render.yaml`, `.gitignore`
- `README.md`, `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

No new migration files. The batch changes *which credential runs*
the existing migrations (`0001`–`0008` at the time): owner-level
for DDL at startup, app role for everything else.

## API ROUTES

None added or changed.

## TESTS ADDED

`tests/test_migration_split.py` — 14 tests, including a pgserver
reproduction of the restricted role's DDL refusal (the app role
cannot create tables; migrations over the owner connection can).

## TESTS RUN

Full suite run before deploy (per-batch totals not recorded; the
program-close suite was 410 passed, 19 skipped).

## RESULTS

Phases 73, 78 and 170 moved to DONE. Production register / scan /
delete end-to-end checks passed on the app role afterwards —
proof the serving role has exactly the DML it needs (recorded in
the Phase 73 row).

## SECURITY CONTROLS

Least-privilege database access: the credential the web process
holds cannot alter schema. DDL authority exists only in the
migration path's environment variable.

## PRIVACY CONTROLS

None changed. The restore drill verified counts only (tables,
brokers, migrations, users) — no user data was read or copied.

## DEPLOYMENT STATUS

Deployed to production in the Final-spec sequence (see Batch A
report); the split is live: production health and account flows
run on `leakguard_app`, migrations on the owner connection.

## KNOWN LIMITATIONS

Backups remain a single platform mechanism (Neon free-plan PITR);
its console-visible history window bounds the recovery point.

## RISKS

If the owner-level migration variable is ever set to the app role
by mistake, startup migrations fail loudly (by design) rather
than silently skipping — an availability risk, not a data risk.

## NEXT PHASE

Batch B — API versioning, privacy export hardening, scan priority
queue, feature flags, monitoring pause.
