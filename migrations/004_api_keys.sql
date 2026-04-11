-- +goose Up
CREATE TABLE api_keys (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id UUID REFERENCES products(id) ON DELETE CASCADE,
    prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, scope TEXT NOT NULL DEFAULT 'account_wide',
    label TEXT, environment TEXT NOT NULL DEFAULT 'live', expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_account_id ON api_keys (account_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
-- +goose Down
DROP TABLE IF EXISTS api_keys;
