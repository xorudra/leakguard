-- 0018_consent_policy_version.sql — the registration policy
-- acceptance carries WHICH policy version was accepted (Launch
-- Safety Standard F26 fix, 2026-10-10: consent is captured at the
-- point of collection, not only seeded afterwards).
--
-- The consents ledger's integer `version` is the per-purpose
-- append counter; it cannot hold a policy edition. This nullable
-- column carries the accepted policy's effective-date version
-- (e.g. '2026-10-07') on the 'policy_acceptance' rows written by
-- accounts/consents.record_policy_acceptance(). It stays NULL on
-- every capability-purpose row (scanning / monitoring / ...),
-- where it has no meaning.

ALTER TABLE consents
    ADD COLUMN IF NOT EXISTS policy_version text NULL;
