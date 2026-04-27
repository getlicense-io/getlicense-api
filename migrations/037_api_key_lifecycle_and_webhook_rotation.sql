-- +goose Up

ALTER TABLE api_keys
    ADD COLUMN last_used_at timestamptz,
    ADD COLUMN last_used_ip inet,
    ADD COLUMN last_used_user_agent_hash text,
    ADD COLUMN created_by_identity_id uuid REFERENCES identities(id) ON DELETE SET NULL,
    ADD COLUMN created_by_api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revoked_by_identity_id uuid REFERENCES identities(id) ON DELETE SET NULL,
    ADD COLUMN revoked_reason text,
    ADD COLUMN permissions text[] NOT NULL DEFAULT '{}',
    ADD COLUMN ip_allowlist cidr[] NOT NULL DEFAULT '{}';

CREATE INDEX idx_api_keys_revoked_at ON api_keys (revoked_at);

ALTER TABLE webhook_endpoints
    ADD COLUMN previous_signing_secret_encrypted bytea,
    ADD COLUMN previous_signing_secret_expires_at timestamptz;

-- +goose Down

ALTER TABLE webhook_endpoints
    DROP COLUMN IF EXISTS previous_signing_secret_expires_at,
    DROP COLUMN IF EXISTS previous_signing_secret_encrypted;

DROP INDEX IF EXISTS idx_api_keys_revoked_at;

ALTER TABLE api_keys
    DROP COLUMN IF EXISTS ip_allowlist,
    DROP COLUMN IF EXISTS permissions,
    DROP COLUMN IF EXISTS revoked_reason,
    DROP COLUMN IF EXISTS revoked_by_identity_id,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS created_by_api_key_id,
    DROP COLUMN IF EXISTS created_by_identity_id,
    DROP COLUMN IF EXISTS last_used_user_agent_hash,
    DROP COLUMN IF EXISTS last_used_ip,
    DROP COLUMN IF EXISTS last_used_at;
