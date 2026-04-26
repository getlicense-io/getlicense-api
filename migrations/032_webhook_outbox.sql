-- +goose Up

-- Webhook delivery durability (PR-3.1):
--
-- Move from "spawn a goroutine per delivery" to a durable outbox
-- that a bounded worker pool consumes via FOR UPDATE SKIP LOCKED.
-- The webhook_events table itself becomes the queue; this migration
-- adds the claim columns + a singleton dispatcher checkpoint table
-- to suppress duplicate enqueue across restarts. Idempotency is
-- best-effort (NOT enforced by a unique index — see NOTE block
-- below); webhook delivery remains at-least-once by contract.
--
-- Restart safety: rows persist across restarts; in-flight rows whose
-- claim_expires_at has passed are released by a startup sweeper and
-- picked up by the next worker. No in-memory state is load-bearing.

ALTER TABLE webhook_events
    ADD COLUMN claim_token uuid,
    ADD COLUMN claim_expires_at timestamptz,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT NOW();

-- NOTE: an earlier draft of this migration created a unique partial
-- index on (domain_event_id, endpoint_id) for dispatcher idempotency.
-- That index conflicted with two real workflows:
--   1. POST /v1/webhooks/:id/deliveries/:id/redeliver — operator
--      action that creates a NEW pending row for the same
--      (domain_event_id, endpoint_id) by design.
--   2. Backoff retries — a row that's mid-retry (status='pending',
--      attempts > 0) would collide with a fresh redeliver.
-- Webhook delivery is at-least-once by industry contract anyway —
-- consumers MUST be prepared for duplicate event IDs. The dispatcher's
-- durable checkpoint (webhook_dispatcher_checkpoint) prevents the
-- common-case replay; the rare crash-mid-fanout window may produce
-- a few duplicates which the consumer dedupes via the envelope's
-- event id. Ship without the unique constraint.

-- Workers poll for rows where status='pending' AND next_retry_at <=
-- NOW() AND claim_token IS NULL. Index on next_retry_at lets the
-- planner short-circuit fast on an empty queue.
CREATE INDEX idx_webhook_events_pending_retry
    ON webhook_events (next_retry_at)
    WHERE status = 'pending';

-- Singleton checkpoint table for the background dispatcher loop.
-- Stores the last domain_event_id that was successfully fanned out
-- to the outbox. The CHECK + PK ensure exactly one row exists for
-- the lifetime of the database.
--
-- Replaces the in-memory `var lastProcessedID core.DomainEventID`
-- in background.go — restart with empty in-memory state used to
-- replay every domain_event from the beginning, creating duplicate
-- webhook_events rows. The checkpoint is the ONLY duplicate-suppression
-- mechanism; the partial unique index hinted at in earlier drafts
-- of this migration was deliberately not shipped (see the NOTE block
-- above). The crash-before-checkpoint window may produce a few
-- duplicate rows; consumers MUST dedupe by envelope.id (the stable
-- domain_event_id) per the at-least-once webhook contract.
CREATE TABLE webhook_dispatcher_checkpoint (
    singleton boolean PRIMARY KEY DEFAULT true,
    last_domain_event_id uuid,
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    CHECK (singleton = true)
);

INSERT INTO webhook_dispatcher_checkpoint (singleton, last_domain_event_id)
VALUES (true, NULL);

-- +goose Down

DROP TABLE IF EXISTS webhook_dispatcher_checkpoint;

DROP INDEX IF EXISTS idx_webhook_events_pending_retry;

ALTER TABLE webhook_events
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS claim_expires_at,
    DROP COLUMN IF EXISTS claim_token;
