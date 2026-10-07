# LeakGuard → Sentinel — Migration Plan (Phase 0 output)

*Companion to CURRENT_STATE.md · Source spec: "LeakGuard Sentinel Complete
Upgrade Master Prompt", Phases 0–180 (owner-supplied PDF, 2026-10-07).*

## Guiding adaptations (owner constraints override spec where they conflict)

*Owner additions, 2026-10-07 (not in the PDF — these outrank it):*
- **Free for the owner AND free for users.** No running costs, no paywalls, no
  pricing tiers anywhere until the owner explicitly says "make it paid".
  Spec Phase 105 (business model) is deferred until that order.
- **AI rule:** AI may be involved only if its token usage is free **and**
  unlimited. No such source exists (every free lane has quotas), so **AI is
  NOT involved**: spec Phases 51–56, 163–165 and the Phase 121 kill switch are
  cut, and the existing optional free-lane hook in the agent is removed in
  Stage 1. The platform is 100% deterministic scripts.
- **Standing go (2026-10-07):** owner ordered the whole upgrade — stages run
  back-to-back (DSRclone pattern), verified + pushed + reported per stage.

1. **₹0 forever:** Render free web service + **Neon or Supabase free Postgres**
   (owner picks; both have real free tiers, unlike Render's trial Postgres).
   Workers/scheduler run **in-process** in the modular monolith (spec rule 13
   allows this) — no paid worker services.
2. **Zero Claude tokens per run, ever** (see AI rule above).
3. **Incremental, always-live:** every stage ships to the same Render service and
   is verified on the live site before the next begins. Existing routes keep
   working until their replacement is proven (spec Phases 133–137).
4. **Name:** spec renames the platform "Sentinel" — *owner decision pending*;
   until decided, the product stays **LeakGuard** in UI, repo and URLs.

## Stage map (spec phases grouped into shippable stages)

| Stage | Spec phases | Deliverable |
|---|---|---|
| **S0 — Audit** ✅ | 0 | CURRENT_STATE.md + this plan |
| **S1 — Foundations** ✅ `c1845b5`| 1, 86–89, 69–70, 75 | Modular restructure (api/domain/providers/remediation packages), structured errors, request IDs, security headers, SSRF hardening, secure logging — same behaviour, new skeleton |
| **S2 — Data** ✅ `28e4a0f`| 2, 73, 3 | Postgres (free host) + migrations; encrypted identifier vault (envelope encryption, HMAC lookup, masking) |
| **S3 — Accounts** ✅ `ef2aa47`| 4, 5, 6, 48–50 | Auth (Argon2id, sessions, reset, TOTP), authorization/IDOR guards, consent records, privacy center, export + account deletion |
| **S4 — Providers** ✅ `938a9a2`| 8, 9, 10, 110, 118 | Provider adapters + registry + health/circuit breaking; XposedOrNot & HIBP become the first two adapters; mock providers for tests |
| **S5 — Scanning** ✅ `70735ff`| 11, 12, 13, 14, 21–27 | Scan orchestrator + in-process job queue (retries, idempotency, DLQ), normalized findings, correlation, reliability, evidence, risk engine v2 |
| **S6 — Identifiers** ✅ `6f70a63`| 15–20 | Phone, username, name, address, domain (ownership-verified) monitoring + public-web discovery within terms/robots |
| **S7 — Remediation v2** ✅ `c8a9718` + perf `b54a167`/`adb9136`| 30–39, 153–157, 162, 167 | Broker registry + workflow versioning, remediation engine with idempotent attempts, **verification & reappearance** (never claim removal without evidence), human-review queue, CAPTCHA → HUMAN_ACTION_REQUIRED |
| **S8 — Monitoring** ✅ `72d4b77` (email lane proven live via Brevo)| 41–47, 158–160 | Continuous monitoring, scheduler, change detection, notifications with dedupe, history/timeline |
| **S9 — Dashboard** ✅ `3a10b0f`| 28, 29, 90–99, 138–143 | Full Protection dashboard + action center, final Quick Scan / Full Protection UX (Spotify theme language preserved), accessibility, mobile |
| **S10 — AI** | 51–56, 121, 163–165 | **CUT by the owner's AI rule** (free + unlimited tokens don't exist). Revisit only if that changes; prompt-injection defense principles still apply to all external content handling in S4–S8 |
| **S11 — Orgs & Admin** ✅ `798d9b7`| 57–62 | Organizations, domain verification, family profiles, admin panel, audit logging, security events |
| **S12 — Hardening** ✅ `69ea6a0` + `56fb831`| 63–68, 71, 72, 74, 76–80, 106–109, 115–120, 122–125 | Rate limiting, abuse/enumeration protection, cost control, caching, retention worker, observability, backups/DR, incident response, feature flags, emergency controls |
| **S13 — Trust & API** ✅ `7237780`| 81–85, 126–132 | Legal/privacy architecture, policy/terms/trust center, reports, support, subprocessors, data residency, documentation |
| **S14 — Extensions** ✅ `8c2ba6e`| 100–104 | Browser-extension foundation, mobile foundation, privacy-policy analyzer, exposure graph + propagation |
| **S15 — Acceptance** ✅ this commit| 105, 112–114, 145–152, 161, 166, 168–180 | Business model, full test matrices (functional/security/privacy/performance), contract + broker-workflow tests, final acceptance, readiness, rollback plan, limitations register, capability-claim review, cleanup + architecture review |

## Sequencing rules

- S1→S3 must land before anything stores user data; consent (in S3) precedes all
  monitoring (S6/S8). Verification (S7) precedes any "removed" claim anywhere.
- Each stage: implement → local test → push → Manual Deploy → live verification →
  report, mirroring the workflow already used for v1–v2.5.
- Stages are independently valuable: stopping after any stage leaves a working,
  strictly better product.

## Owner decisions (all made 2026-10-07)

1. **Name: LeakGuard** — no rebrand; "Sentinel" survives only as the spec's
   codename in these docs.
2. **Database: Neon free** — account created by Muse on the owner's API email
   (same pattern as the other freemium providers); connection string lives in a
   600-permission file on the VM, never in git or chat.
3. **Go pattern: standing go** — stages run back-to-back, DSRclone pattern.
4. **Core UX law (owner, 2026-10-07):** the user enters their details ONCE →
   LeakGuard fetches their leaked data → the user gives ONE command
   ("remove all") → LeakGuard completes it. No stage may add manual chores
   (extra forms, per-item management, dashboards-as-homework) on top of that
   flow; accounts and monitoring exist to make that flow automatic
   (saved details → automatic re-scans → same one-command remediation),
   never to make the user operate the product.

## Outcome (2026-10-07)

All stages shipped and verified live on https://leakguard-hh8e.onrender.com
(Render free + Neon free + Brevo free; running cost ₹0). Every stage was
verified by the parent agent independently — own test-suite run plus a
production end-to-end check — never on the builder's word alone. Final
suite: 275 tests. Production baselines unchanged from the pre-upgrade
product: test@example.com → 214 breaches, exposure score 100; password
"password" → pwned 52,372,427×.

Known gaps (honest register):
1. Per-broker verification search sources are not mapped yet, so the
   case-level Verify action answers "unknown" in production (never a
   guess). Monitoring diffs already report findings appearing and
   disappearing across scans, and reappearance detection is wired.
2. Most people-search brokers wall datacenter IPs (27 of 40 cases in
   the production acceptance run classified blocked with reasons);
   those cases carry next steps, and the older local-agent path
   (user's own device/IP) remains the practical route for them.
3. Brevo free tier caps email at 300/day — ample now; the first
   scaling ceiling if the user base grows.
4. Render free sleeps when idle (~50s wake) and shares free hours
   across the owner's services.
