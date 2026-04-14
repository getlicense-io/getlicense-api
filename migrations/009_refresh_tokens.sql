-- +goose Up
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_tokens_identity_id ON refresh_tokens (identity_id);

-- +goose Down
DROP TABLE IF EXISTS refresh_tokens;
