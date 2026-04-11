-- +goose Up
CREATE TABLE licenses (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, token TEXT NOT NULL,
    license_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    max_machines INTEGER, max_seats INTEGER, entitlements JSONB,
    licensee_name TEXT, licensee_email TEXT, expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_licenses_account_id ON licenses (account_id);
CREATE INDEX idx_licenses_product_id ON licenses (product_id);
CREATE INDEX idx_licenses_status ON licenses (status);
CREATE INDEX idx_licenses_active_expiry ON licenses (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;
-- +goose Down
DROP TABLE IF EXISTS licenses;
