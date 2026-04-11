-- +goose Up
CREATE TABLE webhook_events (
    id UUID PRIMARY KEY, account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL, payload JSONB NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0, last_attempted_at TIMESTAMPTZ,
    response_status INTEGER, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_webhook_events_endpoint_id ON webhook_events (endpoint_id);
CREATE INDEX idx_webhook_events_status ON webhook_events (status);
-- +goose Down
DROP TABLE IF EXISTS webhook_events;
