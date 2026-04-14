-- +goose Up
-- Identities are global login records. One row per human.
-- Email is unique globally — a single human has one login across all
-- their accounts. Memberships join identities to accounts (see 016).
CREATE TABLE identities (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret_enc BYTEA,
    totp_enabled_at TIMESTAMPTZ,
    recovery_codes_enc BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_identities_email ON identities (lower(email));

-- +goose Down
DROP TABLE IF EXISTS identities;
