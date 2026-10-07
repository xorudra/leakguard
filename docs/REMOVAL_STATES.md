# Removal case states — the formal mapping (Phase 141)

LeakGuard's removal cases are stored with the product's internal
state names (the CHECK in migration `0005_remediation.sql`). The
spec's lifecycle vocabulary names two of those states differently
and opens with two states this product does not store. Rather
than rename persisted states — which would mean migrating stored
rows, the CHECK constraint, notification copy and client code for
zero user benefit — this document publishes the formal mapping
between the two vocabularies. The mapping is also code:
`remediation/policy.py` carries it as `SPEC_STATE_NAMES` (covered
by `POLICY_VERSION`), and every case payload the API returns
carries both names — the internal `status` and the spec-facing
`spec_status`, added alongside it; no field was renamed.

## The mapping

| Internal state | Spec-facing name | What it means |
| --- | --- | --- |
| `queued` | `QUEUED` | Case created, waiting for the removal worker. |
| `running` | `IN_PROGRESS` | The worker is acting on the case right now. |
| `submitted` | `SUBMITTED` | A removal request was sent (form submitted, or the user sent the erasure letter themselves). Submitted never means the data is gone. |
| `needs_human` | `AWAITING_USER` | Parked on a step only the user can take: solve a CAPTCHA, sign in, send the letter, supply a missing detail. |
| `blocked` | `REJECTED` | The broker's side refused or could not be reached (HTTP 403, unreachable, an unfillable form), so the request could not be carried through. |
| `verified_removed` | `VERIFIED_REMOVED` | A later verification check found the listing gone. The only state in which the UI says "Removed". |
| `reappeared` | `REAPPEARED` | A case that had verified as removed was found listed again. |
| `failed` | `FAILED` | The case died in processing (a failed submission, an unknown broker, an internal error). An admin can replay it — see below. |

## Spec names with no internal state

Two names in the spec's lifecycle have no stored counterpart, by
design:

* **AUTHORIZED** — expressed as consent-gated case creation.
  Cases are created only after the owner grants the
  *Automatic removal* (`automated_remediation`) consent;
  `POST /api/remediation/run` refuses without it, and the worker
  re-checks the same consent before acting on a case.
  Authorization is a precondition for a case to exist, not a
  state a case sits in.
* **NOT_STARTED** — the same gate from the other side: a broker
  the user has not (or not yet) authorized removal for simply has
  no case. Cases spring into existence already `queued`, so
  there is no stored pre-start state.

No states were invented to fill these slots: the stored
vocabulary is exactly the eight rows in migration 0005, and the
test suite asserts the mapping covers precisely those eight.

## Dead letters and replay

`failed` is the removal case's dead-letter state, and a scan job's
is the persisted `dead` status (after its three-attempt budget).
An admin can return one dead letter to `queued` at a time via
`POST /api/admin/replay`; the replay re-checks the owner's
*current* consent for the lane (a case whose removal consent was
revoked after it died is refused, never resurrected), preserves
the attempt history untouched, and writes an audit row recording
what died and why. See `accounts/admin.py` (`replay_dead_letter`)
for the exact semantics.
