-- +goose Up

-- Webhook signing secret encryption (PR-3.2):
--
-- Move from plaintext signing_secret to AES-GCM-encrypted at rest.
-- A DB compromise no longer leaks signing secrets that let an
-- attacker forge signed webhook payloads to customer endpoints.
--
-- Backfill: existing rows have plaintext in signing_secret; this
-- migration cannot decrypt because Postgres does not have access to
-- the master key. Instead, the new column starts NULL and a startup
-- one-shot in cmd/server/serve.go encrypts any rows where
-- signing_secret_encrypted IS NULL AND signing_secret IS NOT NULL.
-- After backfill the plaintext column can be dropped in a follow-up
-- migration.

ALTER TABLE webhook_endpoints
    ADD COLUMN signing_secret_encrypted bytea;

-- The plaintext column stays nullable temporarily so the backfill
-- helper can detect "still needs migration". A follow-up migration
-- drops it once the production fleet has rolled over.
ALTER TABLE webhook_endpoints
    ALTER COLUMN signing_secret DROP NOT NULL;

-- +goose Down

ALTER TABLE webhook_endpoints
    ALTER COLUMN signing_secret SET NOT NULL;

ALTER TABLE webhook_endpoints
    DROP COLUMN IF EXISTS signing_secret_encrypted;
