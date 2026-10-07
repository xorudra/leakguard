# LeakGuard — Rollback Plan

*Spec Phase 174. Three kinds of rollback, in the order you will
usually want them: code, configuration, database. Incident handling
is INCIDENT_RESPONSE.md; data recovery is DISASTER_RECOVERY.md.*

## 1. Code rollback

Production runs a named commit of `main` (GitHub). Render
auto-deploy does not fire for this service — every deploy is
manual, which also makes rollback a deliberate act:

* **Fast path (Render):** Dashboard → the service → **Manual
  Deploy → pick the previous known-good commit → Deploy.** The
  service's deploy history shows exactly which commits ran and
  when; roll back to the last one that was verified live.
* **Git path (when the bad commit must leave `main`):**
  `git revert <bad-commit>` (a new commit that undoes it — never
  force-push a rewritten `main`), push, then Manual Deploy the
  revert commit. CI runs the suite on the push; a red CI means the
  revert itself is wrong — stop and think instead of deploying.

Rules:
* A rollback does **not** roll back the database by itself. If the
  bad deploy applied a migration, read §3 before deciding the code
  rollback is sufficient.
* After any rollback, verify like a deploy: `/api/health`,
  sign-in, one scan, admin overview.

## 2. Configuration rollback

Configuration is environment variables. **Values are deliberately
absent from this table** (and from the repo): each variable's
source of truth is listed instead, which is where a rollback gets
the previous value from.

| Variable | What it does | Source of truth for the value |
|---|---|---|
| `DATABASE_URL` | Runtime DB connection — the least-privilege `leakguard_app` role | Neon console (connection string for the role) |
| `MIGRATION_DATABASE_URL` | Owner-level DB connection, used **only** at boot to apply migrations | Neon console (owner connection string) |
| `VAULT_MASTER_KEY` | Encrypts/decrypts every stored identifier and account email (AES-256-GCM envelope) | Operator's mode-600 local copy — **changing this without re-encrypting the data makes the vault unreadable** (see INCIDENT_RESPONSE.md → rotation) |
| `VAULT_LOOKUP_KEY` | HMAC key for identifier/email lookups (separate from the master key) | Operator's mode-600 local copy — same caution as the master key |
| `BREVO_API_KEY` | Email lane credential (password resets, notifications) | Brevo dashboard |
| `NOTIFY_FROM_EMAIL` | Sender address for product email | The Brevo-verified sender |
| `NOTIFY_FROM_NAME` | Sender display name | Product name: `LeakGuard` |
| `ADMIN_EMAILS` | Comma-separated owner addresses; the only way the Admin card/overview exists | The owner's own address(es) |
| `LEAKGUARD_PROVIDERS` | `mock` switches providers to the mock set (staging/tests); unset = real providers | Deployment choice — production leaves it unset |
| `LEAKGUARD_FLAG_REGISTRATION` / `..._ACCOUNT_SCANS` / `..._REMOVAL_RUNS` / `..._MONITORING_SCHEDULER` | Emergency kill switches (`core/flags.py`), default ON | Set only during an incident; rollback = remove the variable |
| `PYTHON_VERSION` | Runtime pin (declared in `render.yaml`) | `render.yaml` |

Config rollback procedure: set the variable back to its previous
value from the source of truth → "Save, rebuild, and deploy" →
verify `/api/health` and the specific behaviour the variable
governs. There is no config history in the dashboard — if a
previous value matters, it must come from the source of truth
above, which is why secrets keep an operator-side copy.

## 3. Database rollback

**Policy: migrations are additive, and rollback is forward-fix.**
Every migration in `db/migrations/` only adds (tables, columns
with defaults, indexes) — old code runs fine against a newer
schema, so a code rollback (§1) almost never needs a schema
rollback. Dropping/altering in a migration is not done; if a
migration itself is ever destructive by necessity, that change
requires its own written reversal plan *before* it ships.

If the data itself is damaged (bad writes, corrupted rows), do
**not** hand-write reversal SQL against production in a hurry.
The escape hatch is the point-in-time restore in
DISASTER_RECOVERY.md: branch from before the damage, verify,
repoint, redeploy. Its cost is the RPO stated there; its virtue
is that every step is checkable before it becomes true.

---

## Rehearsal record — 2026-10-07 (Phase 174)

The application rollback procedure above was rehearsed end to end on
the staging service (`leakguard-staging`), the same mechanism
production uses:

1. **Roll back:** Manual Deploy → "Deploy a specific commit" →
   `83b9acc` (the Phase 70 commit). Deploy `dep-db36d91srm7s73c0v8j0`
   — **Live / Deploy succeeded**; the service header confirmed
   "Last successfully deployed commit 83b9acc".
2. **Verify:** staging health returned `{"ok": true, "db": "ok"}`
   on the rolled-back commit.
3. **Roll forward:** Manual Deploy → "Deploy latest commit" →
   `bc39b2f`. Deploy `dep-db36dqm7bikc73bqooeg` — **Live / Deploy
   succeeded**; staging ends the rehearsal on the same commit it
   started on, health `db: "ok"`.

Note: deploying a specific commit makes Render display "Auto-Deploy
has been disabled" on that service. Both LeakGuard services are
deployed manually by policy, so this changes nothing operationally —
but expect to see it after any future specific-commit deploy.
