-- +goose Up
CREATE TABLE products (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL, slug TEXT NOT NULL, public_key TEXT NOT NULL, private_key_enc BYTEA NOT NULL,
    validation_ttl INTEGER NOT NULL DEFAULT 86400, grace_period INTEGER NOT NULL DEFAULT 604800,
    metadata JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, slug)
);
CREATE INDEX idx_products_account_id ON products (account_id);
-- +goose Down
DROP TABLE IF EXISTS products;
