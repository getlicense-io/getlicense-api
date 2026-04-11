-- +goose Up
CREATE TABLE machines (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    license_id UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL, hostname TEXT, metadata JSONB,
    last_seen_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (license_id, fingerprint)
);
CREATE INDEX idx_machines_account_id ON machines (account_id);
CREATE INDEX idx_machines_license_id ON machines (license_id);
-- +goose Down
DROP TABLE IF EXISTS machines;
