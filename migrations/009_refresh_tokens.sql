-- +goose Up
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);
-- +goose Down
DROP TABLE IF EXISTS refresh_tokens;
