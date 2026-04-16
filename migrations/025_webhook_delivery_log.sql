-- +goose Up

ALTER TABLE webhook_events
    ADD COLUMN domain_event_id        uuid REFERENCES domain_events(id),
    ADD COLUMN response_body          text,
    ADD COLUMN response_body_truncated boolean NOT NULL DEFAULT false,
    ADD COLUMN response_headers       jsonb,
    ADD COLUMN next_retry_at          timestamptz;

CREATE INDEX webhook_events_endpoint_created
    ON webhook_events (endpoint_id, created_at DESC, id DESC);

-- +goose Down

DROP INDEX IF EXISTS webhook_events_endpoint_created;

ALTER TABLE webhook_events
    DROP COLUMN IF EXISTS next_retry_at,
    DROP COLUMN IF EXISTS response_headers,
    DROP COLUMN IF EXISTS response_body_truncated,
    DROP COLUMN IF EXISTS response_body,
    DROP COLUMN IF EXISTS domain_event_id;
