-- Column order below matches the shared sqlcgen.WebhookEndpoint and
-- sqlcgen.WebhookEvent structs in models.go. Matching order lets sqlc
-- reuse the shared types for all :one/:many queries instead of emitting
-- per-query *Row structs.
--
-- WebhookEndpoint: id, account_id, url, events, signing_secret, active,
--                  created_at, environment
-- WebhookEvent:    id, account_id, endpoint_id, event_type, payload,
--                  status, attempts, last_attempted_at, response_status,
--                  created_at, environment, domain_event_id,
--                  response_body, response_body_truncated,
--                  response_headers, next_retry_at

-- name: CreateWebhookEndpoint :exec
INSERT INTO webhook_endpoints (
    id, account_id, url, events, signing_secret, active,
    created_at, environment
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetWebhookEndpointByID :one
SELECT id, account_id, url, events, signing_secret, active,
       created_at, environment
FROM webhook_endpoints WHERE id = $1;

-- name: ListWebhookEndpoints :many
SELECT id, account_id, url, events, signing_secret, active,
       created_at, environment
FROM webhook_endpoints
WHERE (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: DeleteWebhookEndpoint :execrows
DELETE FROM webhook_endpoints WHERE id = $1;

-- name: GetActiveWebhookEndpointsByEvent :many
-- sqlc.arg is the event type string; events = '{}' means "all events subscribed".
SELECT id, account_id, url, events, signing_secret, active,
       created_at, environment
FROM webhook_endpoints
WHERE active = true
  AND (sqlc.arg('event_type')::text = ANY(events) OR events = '{}');

-- name: CreateWebhookEvent :exec
INSERT INTO webhook_events (
    id, account_id, endpoint_id, event_type, payload,
    status, attempts, last_attempted_at, response_status,
    created_at, environment, domain_event_id,
    response_body, response_body_truncated,
    response_headers, next_retry_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12,
    $13, $14,
    $15, $16
);

-- name: UpdateWebhookEventStatus :exec
UPDATE webhook_events SET
    status = $2,
    attempts = $3,
    last_attempted_at = NOW(),
    response_status = $4,
    response_body = $5,
    response_body_truncated = $6,
    response_headers = $7,
    next_retry_at = $8
WHERE id = $1;

-- name: GetWebhookEventByID :one
SELECT id, account_id, endpoint_id, event_type, payload,
       status, attempts, last_attempted_at, response_status,
       created_at, environment, domain_event_id,
       response_body, response_body_truncated,
       response_headers, next_retry_at
FROM webhook_events WHERE id = $1;

-- name: ListWebhookEventsByEndpoint :many
SELECT id, account_id, endpoint_id, event_type, payload,
       status, attempts, last_attempted_at, response_status,
       created_at, environment, domain_event_id,
       response_body, response_body_truncated,
       response_headers, next_retry_at
FROM webhook_events
WHERE endpoint_id = sqlc.arg('endpoint_id')
  AND (sqlc.narg('event_type')::text IS NULL OR event_type = sqlc.narg('event_type')::text)
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');
