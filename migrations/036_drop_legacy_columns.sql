-- +goose Up

-- Drop the pre-AAD/pre-event-log compatibility surface in one shot.
-- This is a destructive cleanup: any environment that has not completed
-- the prior backfill MUST run `make db-reset` before applying. The
-- previous startup migrations (cmd/server/migrate_aad.go, the webhook
-- BackfillEncryptedSigningSecrets one-shot) are deleted in the same
-- commit as this migration.

-- 1) webhook_events.domain_event_id: drop pre-event-log rows, then NOT NULL.
--    Every new delivery row written since the audit log refactor (O2)
--    carries a domain_event_id; only orphaned rows from the pre-O2
--    schema can be NULL here.
DELETE FROM webhook_events WHERE domain_event_id IS NULL;
ALTER TABLE webhook_events
    ALTER COLUMN domain_event_id SET NOT NULL;

-- 2) webhook_endpoints: drop the plaintext signing_secret column,
--    then promote signing_secret_encrypted to NOT NULL. Order matters:
--    NOT NULL goes LAST so any unbackfilled row fails loudly via the
--    DROP COLUMN before the encrypted column's constraint disappears
--    its sibling.
ALTER TABLE webhook_endpoints
    DROP COLUMN signing_secret;
ALTER TABLE webhook_endpoints
    ALTER COLUMN signing_secret_encrypted SET NOT NULL;

-- 3) identities: drop the encrypted recovery-codes blob. New TOTP
--    enrollments have written per-row to recovery_codes since PR-4.5;
--    pre-PR-4.5 codes were ported by the deleted startup migration.
ALTER TABLE identities
    DROP COLUMN recovery_codes_enc;

-- +goose Down

ALTER TABLE identities
    ADD COLUMN recovery_codes_enc bytea;

ALTER TABLE webhook_endpoints
    ALTER COLUMN signing_secret_encrypted DROP NOT NULL;
ALTER TABLE webhook_endpoints
    ADD COLUMN signing_secret text;

ALTER TABLE webhook_events
    ALTER COLUMN domain_event_id DROP NOT NULL;
