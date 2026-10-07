# LeakGuard → Sentinel — Migration Plan (Phase 0 output)

*Companion to CURRENT_STATE.md · Source spec: "LeakGuard Sentinel Complete
Upgrade Master Prompt", Phases 0–180 (owner-supplied PDF, 2026-10-07).*

## Guiding adaptations (owner constraints override spec where they conflict)

1. **₹0 forever:** Render free web service + **Neon or Supabase free Postgres**
   (owner picks; both have real free tiers, unlike Render's trial Postgres).
   Workers/scheduler run **in-process** in the modular monolith (spec rule 13
   allows this) — no paid worker services.
2. **Zero Claude tokens per run, ever.** AI phases (51–56) use only the owner's
   FreeLLMAPI free-lane gateway, off by default, behind the Phase 121 kill switch.
3. **Incremental, always-live:** every stage ships to the same Render service and
   is verified on the live site before the next begins. Existing routes keep
   working until their replacement is proven (spec Phases 133–137).
4. **Name:** spec renames the platform "Sentinel" — *owner decision pending*;
   until decided, the product stays **LeakGuard** in UI, repo and URLs.

## Stage map (spec phases grouped into shippable stages)

| Stage | Spec phases | Deliverable |
|---|---|---|
| **S0 — Audit** ✅ | 0 | CURRENT_STATE.md + this plan |
| **S1 — Foundations** | 1, 86–89, 69–70, 75 | Modular restructure (api/domain/providers/remediation packages), structured errors, request IDs, security headers, SSRF hardening, secure logging — same behaviour, new skeleton |
| **S2 — Data** | 2, 73, 3 | Postgres (free host) + migrations; encrypted identifier vault (envelope encryption, HMAC lookup, masking) |
| **S3 — Accounts** | 4, 5, 6, 48–50 | Auth (Argon2id, sessions, reset, TOTP), authorization/IDOR guards, consent records, privacy center, export + account deletion |
| **S4 — Providers** | 8, 9, 10, 110, 118 | Provider adapters + registry + health/circuit breaking; XposedOrNot & HIBP become the first two adapters; mock providers for tests |
| **S5 — Scanning** | 11, 12, 13, 14, 21–27 | Scan orchestrator + in-process job queue (retries, idempotency, DLQ), normalized findings, correlation, reliability, evidence, risk engine v2 |
| **S6 — Identifiers** | 15–20 | Phone, username, name, address, domain (ownership-verified) monitoring + public-web discovery within terms/robots |
| **S7 — Remediation v2** | 30–39, 153–157, 162, 167 | Broker registry + workflow versioning, remediation engine with idempotent attempts, **verification & reappearance** (never claim removal without evidence), human-review queue, CAPTCHA → HUMAN_ACTION_REQUIRED |
| **S8 — Monitoring** | 41–47, 158–160 | Continuous monitoring, scheduler, change detection, notifications with dedupe, history/timeline |
| **S9 — Dashboard** | 28, 29, 90–99, 138–143 | Full Protection dashboard + action center, final Quick Scan / Full Protection UX (Spotify theme language preserved), accessibility, mobile |
| **S10 — AI (free-lane)** | 51–56, 121, 163–165 | Assistant + remediation agent on FreeLLMAPI only, confirmation gates, prompt-injection defense, audit, kill switch |
| **S11 — Orgs & Admin** | 57–62 | Organizations, domain verification, family profiles, admin panel, audit logging, security events |
| **S12 — Hardening** | 63–68, 71, 72, 74, 76–80, 106–109, 115–120, 122–125 | Rate limiting, abuse/enumeration protection, cost control, caching, retention worker, observability, backups/DR, incident response, feature flags, emergency controls |
| **S13 — Trust & API** | 81–85, 126–132 | Legal/privacy architecture, policy/terms/trust center, reports, support, subprocessors, data residency, documentation |
| **S14 — Extensions** | 100–104 | Browser-extension foundation, mobile foundation, privacy-policy analyzer, exposure graph + propagation |
| **S15 — Acceptance** | 105, 112–114, 145–152, 161, 166, 168–180 | Business model, full test matrices (functional/security/privacy/performance), contract + broker-workflow tests, final acceptance, readiness, rollback plan, limitations register, capability-claim review, cleanup + architecture review |

## Sequencing rules

- S1→S3 must land before anything stores user data; consent (in S3) precedes all
  monitoring (S6/S8). Verification (S7) precedes any "removed" claim anywhere.
- Each stage: implement → local test → push → Manual Deploy → live verification →
  report, mirroring the workflow already used for v1–v2.5.
- Stages are independently valuable: stopping after any stage leaves a working,
  strictly better product.

## Open decisions for the owner

1. **Name:** keep LeakGuard, or rebrand to Sentinel per the spec?
2. **Database host:** Neon free or Supabase free (account on the owner's
   API-keys email, like the other freemium providers)?
3. **Go pattern:** standing go for all stages (DSRclone pattern) or stage-by-stage approval?
