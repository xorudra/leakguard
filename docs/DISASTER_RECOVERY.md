# LeakGuard — Disaster Recovery Runbook

*Spec Phases 79 + the database half of 174. Code and configuration
rollback live in ROLLBACK.md; incident handling lives in
INCIDENT_RESPONSE.md. This document is only about getting the
**data** back.*

## What backs up where

| Thing | Where | Mechanism |
|---|---|---|
| All application data (users, vault ciphertext, findings, cases, notifications, audit) | Neon Postgres, project `leakguard` | Neon platform point-in-time restore (PITR) — the **free plan's** history window, whatever the Neon console shows for the project at the time |
| Code | GitHub (`xorudra/leakguard`) | Git history; production runs a named commit |
| Configuration | Render dashboard | Environment variables (values exist nowhere in the repo — see ROLLBACK.md for the variable inventory) |
| Secrets | Render env + the operator's mode-600 local copies | Re-entered from those copies if the dashboard itself is lost |

There is no second database and no self-managed backup job: the
Neon platform restore is the backup. That is a deliberate free-tier
trade and it is stated here, not hidden.

## Recovery objectives — stated honestly

* **RPO** (how much data a restore can lose): bounded by Neon's
  free-plan point-in-time window — check the console for the
  project's actual earliest restore point before quoting any
  number. Anything written after the chosen restore point is gone.
* **RTO** (how long recovery takes): the drill below suggests the
  branch-and-verify part takes minutes and the full procedure —
  branch, verify, repoint, redeploy, verify — under an hour
  end-to-end. That is a drill observation, not a guarantee.

## Restore drill evidence (2026-10-07)

A branch was created from Neon's point-in-time restore and checked
before anything depended on it:

* **19 public tables** present
* **40 brokers** in the registry
* **8 migrations** applied (the full set at drill time)
* **15 users** present

The drill branch was deleted after verification. Conclusion drawn
then and still the working assumption: a PITR branch is readable
and complete. Re-run this drill after any major schema change —
a backup that has not been restored lately is a hope, not a backup.

## Restore procedure

Use this when the production branch is corrupted, damaged by a bad
deploy/migration, or must be abandoned.

1. **Freeze writes.** Switch off registration, account scans,
   removal runs and the monitoring scheduler (INCIDENT_RESPONSE.md
   → kill switches) so nothing writes to the damaged database
   while you work — and so nobody mistakes the old database's
   state for current truth afterwards.
2. **Pick the restore point.** In the Neon console (project
   `leakguard`), choose the latest point *before* the damage.
   When in doubt, earlier beats cleverer.
3. **Create a branch from that point** (Neon console → Branches →
   create from point-in-time). Branches are copy-on-write: the
   damaged branch is untouched and remains available for
   forensics.
4. **Verify the branch before pointing anything at it** (SQL
   editor on the new branch):
   * table count: `SELECT count(*) FROM information_schema.tables WHERE table_schema='public';`
   * brokers: `SELECT count(*) FROM brokers;` (expect 40)
   * migrations: `SELECT count(*) FROM schema_migrations;`
     (expect the full applied set for the code you are about to run)
   * users: `SELECT count(*) FROM users;` (sanity, not an exact number)
   If these do not line up, stop — pick another restore point.
5. **Repoint the app.** Get the new branch's connection strings
   from the Neon console:
   * `DATABASE_URL` — the **least-privilege `leakguard_app`** role
     connection for the new branch,
   * `MIGRATION_DATABASE_URL` — the **owner** connection for the
     new branch.
   Set both in Render → Environment. (The app role's grants are
   per-branch in Neon; if the role does not exist on the restored
   branch, create it and grant DML on all tables/sequences exactly
   as in the original setup before redeploying — the app refuses
   nothing else, but it cannot write without them.)
6. **Redeploy** (Render → Manual Deploy → latest commit) and watch
   the boot: migrations must run clean over the owner connection.
7. **Verify recovery:** `/api/health` reports `db: "ok"`; sign in
   as the owner; the admin overview counts match step 4's numbers;
   run one scan; confirm the timeline/notifications look sane.
8. **Unfreeze** the flags you switched off in step 1.
9. **Clean up deliberately:** keep the damaged branch until the
   post-incident review is done (it is the evidence), then delete
   it in the console and say so in the review.

## What a restore does NOT bring back

* Anything written after the restore point (registrations, scans,
  feedback, cases created since) — RPO above.
* Email already sent by Brevo (sent is sent).
* Broker-side state: a removal the broker processed against the
  old timeline still happened; the restored case ledger may
  re-verify and correct itself on the next checks — that is the
  verification system doing its job.
