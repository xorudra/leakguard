# LeakGuard — Incident Response Runbook

*Spec Phase 80. Written 2026-10-07 against the system as it actually
runs: one Render web service, Neon Postgres, Brevo email lane. If a
step here ever disagrees with the running system, the system is the
truth and this document is the bug — fix the document in the same
change that fixes the system.*

## Severity ladder

| Sev | Meaning | Examples |
|---|---|---|
| SEV-1 | User data exposed, or exposure plausibly ongoing | Another user's data visible; vault/lookup keys leaked; database reachable with stolen credentials |
| SEV-2 | A core protection is down or lying | Scans failing platform-wide; removals submitting to the wrong place; notifications revealing data they should not |
| SEV-3 | Degraded but honest | A provider is down (findings report the gap, nothing is invented); email lane exhausted for the day; elevated error rates |
| SEV-4 | Cosmetic / single-user | One user's case stuck; a page renders wrong |

SEV-1 and SEV-2 page the owner immediately. SEV-3/4 go in the log
and get fixed in normal work.

## First 30 minutes (any SEV-1/2)

1. **Stop the bleeding first, investigate second.** Use the kill
   switches (§ below) to switch off exactly the capability that is
   misbehaving — registration, account scans, removal runs, or the
   monitoring scheduler — instead of taking the whole site down.
   The anonymous Quick Scan has no switch and stays up.
2. **Snapshot the evidence.** Note the time (IST), what was
   observed, and the request ids from the structured logs
   (`X-Request-Id` is on every response). Copy the relevant audit
   rows (Admin → audit, or `audit_log`) into the incident record.
   The audit trail is exempt from the retention worker by design
   (`core/retention.py` never touches `audit_log`), so this is
   about fixing the evidence in one place, not beating a
   retention clock — but logs on the platform are not forever,
   so capture the request ids while they are at hand.
3. **Check the blast radius in the admin overview** — user counts,
   case counts by status, and the security-events view (latest
   logins, login failures, password resets, token changes,
   exports, deletions) for signs the problem is account-shaped.
4. **Decide containment vs. continuity.** If credentials or keys
   may be compromised, rotate them (§ rotation) — rotation beats
   observation once exposure is plausible.
5. **Write the timeline down as it happens** (a plain text file):
   times, observations, actions. Memory is not an incident record.

## Kill switches (emergency controls)

`core/flags.py` — one environment variable per capability, read on
every check, default ON. On Render: **Environment → set the
variable → "Save, rebuild, and deploy"**.

| Variable | Off stops |
|---|---|
| `LEAKGUARD_FLAG_REGISTRATION=off` | New account creation (`POST /api/auth/register` answers 503 `feature_disabled`) |
| `LEAKGUARD_FLAG_ACCOUNT_SCANS=off` | Account full scans (`POST /api/scans`) |
| `LEAKGUARD_FLAG_REMOVAL_RUNS=off` | New removal runs (`POST /api/remediation/run`) |
| `LEAKGUARD_FLAG_MONITORING_SCHEDULER=off` | The hourly monitoring scheduler's tick |

The admin overview shows the current flag state, so confirm the
switch landed there after the redeploy. To restore: remove the
variable (or set it to anything but `0/false/off/no`) and redeploy.
Full procedure: README → Operations → Feature flags.

**What the flags do NOT stop** (know this before you rely on
them): the flags gate exactly the four entry points above.
Removal cases already queued keep draining through the remediation
worker until the queue empties — `LEAKGUARD_FLAG_REMOVAL_RUNS`
stops *new* runs, not in-flight work. User-triggered verification
checks run synchronously inside the request that asks for them,
and the daily broker source sweep (hosted by the retention tick,
fetching the fixed broker-registry hosts through the pinned,
SSRF-guarded fetcher) has no flag at all. For those surfaces the
containment controls are the ones built into the fetch path
itself — host allowlists, `core/ssrf.py` connection pinning — plus,
if a single broker is the problem, deactivating that broker
(`brokers.active`) so no surface targets it. A full stop of every
fetching surface at once requires a deploy, not a flag.

## Rotation — when to rotate what

Rotate on suspicion, not just on proof: a key that *might* be out
is treated as out.

| Secret | Where it lives | Rotate how | Notes |
|---|---|---|---|
| Vault master key (`VAULT_MASTER_KEY`) | Render env | **Planned maintenance only.** Every stored identifier/email is encrypted under it; changing the value without migrating the data makes the vault unreadable. Procedure outline: pause the four flag-gated capabilities (registration, account scans, removal runs, monitoring scheduler — note the flags do not freeze *all* writes; logins and Privacy Center changes still write, so schedule this in a quiet window) → decrypt all vault rows with the old key and re-encrypt under the new one with an owner-run script → swap the env var → redeploy → verify a sign-in + export. There is no automated rotation tooling today — treat this as a deliberate, rehearsed operation, never an improvisation mid-incident unless the key is confirmed leaked (then unreadable data beats leaked data: rotate first, recover from backup second — see DISASTER_RECOVERY.md) |
| Vault lookup key (`VAULT_LOOKUP_KEY`) | Render env | Same maintenance shape as the master key: identifier/email *lookups* are HMACs under this key, so rows must be re-keyed in the same pass or accounts can no longer be found by email |
| App DB role password (`leakguard_app`, in `DATABASE_URL`) | Neon console (Roles) + Render env | Set a new password for the role in the Neon SQL editor/console → update `DATABASE_URL` → redeploy → `/api/health` must report `db: "ok"` |
| Owner DB connection (`MIGRATION_DATABASE_URL`) | Neon console + Render env | Same as above for the owner role; used only at boot for migrations, so a bad value shows up as a failed deploy/boot, not a runtime outage |
| Brevo API key (`BREVO_API_KEY`) | Brevo dashboard + Render env | Create a new key in Brevo → update the env var → redeploy → trigger a password-reset email to a test account to prove the lane |
| GitHub PAT (operator's push credential) | GitHub settings + the operator's stored copy | Revoke the old token in GitHub → create a replacement with `repo` scope → update the stored copy → verify with a no-op `git push --dry-run` |
| A user's password | The account itself | Never reset a user's password by hand in the database. Use the product's reset flow; a reset revokes all of that user's sessions by design |

Session/token fallout: password resets revoke the account's
sessions (built in). There is no "revoke all sessions platform-
wide" button — for a platform-wide event, rotating the vault keys
is the nuclear option above; otherwise flag off the affected
capability and work the timeline.

## Communicating with users — the honesty rules

These are product rules, not PR advice; they bind incident comms
exactly as they bind the UI copy:

* **Never claim a removal happened that evidence does not show.**
  A case is removed when verification says so (`verified_removed`)
  — a submitted request is "submitted", nothing more.
* **Never claim a breach — or the absence of one — beyond the
  evidence.** Say what was observed, when, and what is still
  unknown. "We are investigating" is a complete sentence when it
  is the truth.
* **Never soften with invented scope.** Do not write "a small
  number of users" unless a query produced that number.
* Say what affected users should *do* (e.g. reset their password —
  the flow is self-service) and what has already been done for
  them.
* One channel, plain words, no shorthand. Update the same message
  as facts change instead of issuing corrections elsewhere.

## After the incident

1. Restore every flag you switched off; confirm in the admin
   overview.
2. Verify the basics end to end: `/api/health` (`db: "ok"`),
   sign-in, one scan, the admin overview.
3. **Post-incident review within a few days, while it is fresh:**
   timeline, root cause, what the monitoring did and did not catch,
   and the concrete changes that would prevent or shrink a repeat.
   File the changes as work items — a review that produces no
   change is a diary entry.
4. If user data was involved, record what the audit trail shows
   (it is PII-free by construction, so it can be quoted in the
   review verbatim).
