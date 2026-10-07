-- 0012_finding_lifecycle.sql — stored canonical lifecycle state on
-- findings (spec Phase 25).
--
-- Until now a finding's lifecycle (is this exposure current, gone,
-- back again?) was DERIVED per read: the monitoring hook diffed
-- consecutive completed scan jobs, the Action Center counted the
-- latest job's rows, and findings.status itself just stayed 'open'
-- forever. This migration stores the state on the row instead:
--
--   lifecycle_state        'open' | 'resolved' | 'reappeared'
--   lifecycle_changed_at   when the state last actually changed
--                          (NULL = never recorded; see backfill)
--
-- The single writer is monitoring/diff.py's apply_lifecycle() /
-- resolve_for_broker() (scan-completion transitions + the
-- remediation verified_removed flip). findings.status keeps its
-- existing meaning and is NOT repurposed; user feedback
-- (finding_feedback, 0010) stays a separate axis.
--
-- Backfill — conservative by construction. An identity is
-- (identifier_id, provider, source_name) per monitoring/diff.py,
-- and every row of an identity takes the same state, matching the
-- writer's invariant. Only 'resolved' is backfilled; everything
-- else starts 'open':
--
--   (a) Absence: the identity appears in some completed ('done')
--       scan job but NOT in the user's latest completed job — the
--       same observation the old diff called resolved. The stamp
--       is the finished_at of the first completed job after the
--       identity's last appearance (the moment the runtime writer
--       would have recorded the change).
--   (b) Verified removal: a remediation case for the user is
--       currently 'verified_removed' and the finding's source name
--       matches the case's broker by name or slug (case-insensitive
--       equality — the subset of the runtime's conservative broker
--       matcher that plain SQL can express exactly). The stamp is
--       the case's updated_at (set when the case flipped). Findings
--       matched to a verified case only via the broker's host are
--       NOT backfilled resolved — that match is not expressible in
--       SQL without guessing, so those rows start 'open' and the
--       runtime writer settles them on the next completed cycle.
--
-- 'reappeared' is never backfilled: whether an exposure vanished
-- and returned historically cannot be told from stored rows
-- without guessing (an intermediate job may have been degraded),
-- so those identities start 'open' and earn 'reappeared' from the
-- writer on the next resolved -> present transition.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL
    DEFAULT 'open'
    CHECK (lifecycle_state IN ('open', 'resolved', 'reappeared'));

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS lifecycle_changed_at timestamptz NULL;

-- (b) verified-removal class first, so (a) can keep its stamp via
-- COALESCE when both classes claim the same identity.
WITH verified_resolved AS (
    SELECT f.user_id, f.identifier_id, f.provider, f.source_name,
           MAX(c.updated_at) AS resolved_at
    FROM findings f
    JOIN remediation_cases c
      ON c.user_id = f.user_id AND c.status = 'verified_removed'
    JOIN brokers b ON b.slug = c.broker_slug
    WHERE lower(f.source_name) = lower(b.name)
       OR lower(f.source_name) = lower(b.slug)
    GROUP BY 1, 2, 3, 4
)
UPDATE findings f
SET lifecycle_state = 'resolved',
    lifecycle_changed_at = vr.resolved_at
FROM verified_resolved vr
WHERE f.user_id = vr.user_id
  AND f.identifier_id IS NOT DISTINCT FROM vr.identifier_id
  AND f.provider = vr.provider
  AND f.source_name = vr.source_name;

-- (a) absence from the user's latest completed scan job.
WITH latest_job AS (
    SELECT DISTINCT ON (user_id) user_id, id
    FROM scan_jobs
    WHERE status = 'done' AND finished_at IS NOT NULL
    ORDER BY user_id, finished_at DESC, created_at DESC
),
identity_last_seen AS (
    SELECT f.user_id, f.identifier_id, f.provider, f.source_name,
           MAX(j.finished_at) AS last_seen_at
    FROM findings f
    JOIN scan_jobs j ON j.id = f.job_id
         AND j.status = 'done' AND j.finished_at IS NOT NULL
    GROUP BY 1, 2, 3, 4
),
absent_resolved AS (
    SELECT ils.user_id, ils.identifier_id, ils.provider,
           ils.source_name,
           (SELECT MIN(j.finished_at) FROM scan_jobs j
             WHERE j.user_id = ils.user_id AND j.status = 'done'
               AND j.finished_at IS NOT NULL
               AND j.finished_at > ils.last_seen_at) AS resolved_at
    FROM identity_last_seen ils
    JOIN latest_job lj ON lj.user_id = ils.user_id
    WHERE NOT EXISTS (
        SELECT 1 FROM findings f2
        WHERE f2.job_id = lj.id
          AND f2.identifier_id IS NOT DISTINCT FROM ils.identifier_id
          AND f2.provider = ils.provider
          AND f2.source_name = ils.source_name)
)
UPDATE findings f
SET lifecycle_state = 'resolved',
    lifecycle_changed_at = COALESCE(f.lifecycle_changed_at,
                                    ar.resolved_at)
FROM absent_resolved ar
WHERE f.user_id = ar.user_id
  AND f.identifier_id IS NOT DISTINCT FROM ar.identifier_id
  AND f.provider = ar.provider
  AND f.source_name = ar.source_name;
