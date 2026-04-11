-- +goose Up
CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url TEXT NOT NULL, events TEXT[] NOT NULL DEFAULT '{}', signing_secret TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_endpoints_account_id ON webhook_endpoints (account_id);
-- +goose Down
DROP TABLE IF EXISTS webhook_endpoints;
