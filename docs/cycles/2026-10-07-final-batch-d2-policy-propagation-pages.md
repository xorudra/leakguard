# Cycle report — Final-spec Batch D2: policy analyzer, propagation, trust pages

Commit: `56c14e5`. Date: 2026-10-07. This was the final code
commit of the Final-spec program — the commit production ran
until the post-audit P0 program.

## CURRENT PHASE

Final Remaining Implementation — Batch D2: Phase 102 (Privacy
policy analyzer), Phase 104 (Source propagation), Phase 152
(Propagation analysis), Phase 82 (Privacy policy), Phase 83
(Terms), Phase 126 (Support), Phase 128 (Bug bounty
foundation), Phase 129 (Data residency).

## PRIORITY TIER

P3 (all eight phases).

## STATUS

Complete. A deterministic policy analyzer, a propagation view
computed only from evidence the product already holds, and the
public trust pages are live.

## WHAT WAS AUDITED

The spec's remaining P3 surface: users had no way to sanity-check
a third party's privacy policy; the exposure graph showed
sources but not how a source's data reaches brokers; and the
product's honesty commitments (what is stored, where it lives,
how to disclose a bug, how to get support) lived in README
prose rather than on public pages.

## WHAT WAS IMPLEMENTED

- Policy analyzer (Phase 102): `dashboard/policy_analyzer.py`
  + `POST /api/tools/policy-analyzer` (signed-in). A
  deterministic keyword checklist — 9 checks, each answered
  found / unclear / not found with matched phrases capped at
  8 words, plus length and readability statistics and a plain
  disclaimer. Fetching a policy by URL goes through the SSRF
  guard with a 5-second timeout and a 256KB cap. No AI, per
  the owner rule.
- Propagation (Phases 104/152): `GET /api/graph` gained a
  `propagation` section (`dashboard/graph.py`): per source,
  only the brokers the Stage 8 matcher accepts, with case
  status normalized from the ledger (no case →
  `not_started`); per-identifier rollups in the UI under the
  heading "Brokers LeakGuard can act on for this source".
- Public pages (Phases 82/83/126): standalone `/privacy`,
  `/terms` and `/support` routes with matching sections in the
  app shell. The privacy page states what is stored, the
  vault/HMAC scheme, Quick Scan retention (no server record;
  the browser-local summary is disclosed), a processor table,
  and retention/export/deletion, effective 7 Oct 2026. Terms
  state the own/authorized-data rule and make no removal
  guarantee — breach copies cannot be recalled. Support routes
  to GitHub Issues with a never-send list (passwords, keys,
  exports) and promises best effort, no SLA.
- Trust page additions (Phases 128/129): a Responsible
  disclosure section (scope = live site + public repo,
  good-faith safe-harbor wording, and the plain statement that
  no paid bounty is offered) and a "Where data lives" section
  (app on Render Oregon, US; database on Neon AWS
  ap-southeast-1, Singapore; fixed locations, honestly stated
  as not user-configurable).

## WHAT WAS DELIBERATELY NOT IMPLEMENTED

- No propagation claims beyond the matcher: the view never
  asserts a broker *got* data from a source — only that
  LeakGuard can act on that broker for that source, and the
  case status if a case exists. Spread/causality theatre was
  explicitly rejected.
- No AI summarization of policies: the owner rule admits AI
  only if free *and* unlimited; no such tier exists. The
  checklist is deterministic and says so.

## FILES CREATED

- `dashboard/policy_analyzer.py`
- `tests/test_batch_d2.py`

## FILES MODIFIED

- `app.py` (analyzer route, pages), `dashboard/graph.py`
- `static/app.js`, `static/index.html`, `static/style.css`
- `tests/test_extensions.py`
- `PHASE_STATUS.md`, `CURRENT_STATE.md`

## DATABASE MIGRATIONS

None.

## API ROUTES

- `POST /api/tools/policy-analyzer` (new, signed-in).
- `GET /api/graph` (response gained the `propagation` section).
- `GET /privacy`, `GET /terms`, `GET /support` (new pages).

## TESTS ADDED

`tests/test_batch_d2.py` — 13 tests: analyzer verdicts on
fixture policies, SSRF-guarded fetch behaviour, propagation
status mapping (including `not_started`), page serving, and
copy honesty assertions (the tests pin the disclosure and
residency wording so it cannot silently soften). Additions to
`tests/test_extensions.py`.

## TESTS RUN

Full suite run before deploy (per-batch totals not recorded;
the program-close suite was 410 passed, 19 skipped).

## RESULTS

Phases 82, 83, 102, 104, 126, 128, 129, 152 moved to DONE.
The Final-spec implementation program closed with this batch;
the remaining work was environments and reconciliation
(Phases 109/173/180) and then the owner's audit.

## SECURITY CONTROLS

The analyzer's URL fetch inherits the SSRF guard, timeout and
size cap; the tool is signed-in only, so it is not an open
fetch proxy.

## PRIVACY CONTROLS

The pages are the control: stored-data inventory, processor
table, residency and retention are now public, test-pinned
claims. The propagation view shows a user only their own
sources, brokers and case states.

## DEPLOYMENT STATUS

Deployed to production as deploy `dep-db34ec9srm7s73e32480`
(live 18:50 IST, pinned by the v2.1 reconciliation) and to
staging as `dep-db34n9d9fdbs739vetc0`. All four pages returned
200 in the reconciliation sweep.

## KNOWN LIMITATIONS

A keyword checklist cannot judge a policy's meaning; the tool
labels itself a checklist and shows its matched phrases so the
user can judge. Propagation is only as current as the latest
scan and the case ledger.

## RISKS

Public honesty pages are commitments: wording drift would be a
product bug, which is why the copy is test-pinned.

## NEXT PHASE

Environments and gates — staging creation (Phase 109), then
the spec v2.1 live/repository reconciliation (Phases 173/180).
