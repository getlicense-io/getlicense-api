-- Column order below matches the shared sqlcgen.WebhookEndpoint and
-- sqlcgen.WebhookEvent structs in models.go. Matching order lets sqlc
-- reuse the shared types for all :one/:many queries instead of emitting
-- per-query *Row structs.
--
-- WebhookEndpoint: id, account_id, url, events, active, created_at,
--                  environment, signing_secret_encrypted,
--                  previous_signing_secret_encrypted,
--                  previous_signing_secret_expires_at
-- WebhookEvent:    id, account_id, endpoint_id, event_type, payload,
--                  status, attempts, last_attempted_at, response_status,
--                  created_at, environment, domain_event_id,
--                  response_body, response_body_truncated,
--                  response_headers, next_retry_at,
--                  claim_token, claim_expires_at, updated_at
-- Migration 032 appended (claim_token, claim_expires_at, updated_at)
-- for the outbox worker — they're plumbing for the queue, not part
-- of the public domain.WebhookEvent type. Selecting them here keeps
-- the shared sqlcgen.WebhookEvent struct in lockstep with the table.

-- name: CreateWebhookEndpoint :exec
INSERT INTO webhook_endpoints (
    id, account_id, url, events, signing_secret_encrypted, active,
    created_at, environment
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetWebhookEndpointByID :one
SELECT id, account_id, url, events, active,
       created_at, environment, signing_secret_encrypted,
       previous_signing_secret_encrypted, previous_signing_secret_expires_at
FROM webhook_endpoints WHERE id = $1;

-- name: ListWebhookEndpoints :many
SELECT id, account_id, url, events, active,
       created_at, environment, signing_secret_encrypted,
       previous_signing_secret_encrypted, previous_signing_secret_expires_at
FROM webhook_endpoints
WHERE (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: DeleteWebhookEndpoint :execrows
DELETE FROM webhook_endpoints WHERE id = $1;

-- name: GetActiveWebhookEndpointsByEvent :many
-- sqlc.arg is the event type string; events = '{}' means "all events subscribed".
SELECT id, account_id, url, events, active,
       created_at, environment, signing_secret_encrypted,
       previous_signing_secret_encrypted, previous_signing_secret_expires_at
FROM webhook_endpoints
WHERE active = true
  AND (sqlc.arg('event_type')::text = ANY(events) OR events = '{}');

-- name: RotateWebhookEndpointSigningSecret :execrows
-- Move the old current secret into the previous slot, then store a
-- fresh current secret. Receivers may verify with either secret until
-- previous_signing_secret_expires_at.
UPDATE webhook_endpoints
SET signing_secret_encrypted = sqlc.arg('current_encrypted')::bytea,
    previous_signing_secret_encrypted = sqlc.arg('previous_encrypted')::bytea,
    previous_signing_secret_expires_at = sqlc.arg('previous_expires_at')::timestamptz
WHERE id = sqlc.arg('id')::uuid;

-- name: FinishWebhookEndpointSigningSecretRotation :execrows
UPDATE webhook_endpoints
SET previous_signing_secret_encrypted = NULL,
    previous_signing_secret_expires_at = NULL
WHERE id = sqlc.arg('id')::uuid;

-- name: CreateWebhookEvent :exec
INSERT INTO webhook_events (
    id, account_id, endpoint_id, event_type, payload,
    status, attempts, last_attempted_at, response_status,
    created_at, environment, domain_event_id,
    response_body, response_body_truncated,
    response_headers, next_retry_at,
    claim_token, claim_expires_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12,
    $13, $14,
    $15, $16,
    sqlc.narg('claim_token')::uuid, sqlc.narg('claim_expires_at')::timestamptz
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
       response_headers, next_retry_at,
       claim_token, claim_expires_at, updated_at
FROM webhook_events WHERE id = $1;

-- name: ListWebhookEventsByEndpoint :many
SELECT id, account_id, endpoint_id, event_type, payload,
       status, attempts, last_attempted_at, response_status,
       created_at, environment, domain_event_id,
       response_body, response_body_truncated,
       response_headers, next_retry_at,
       claim_token, claim_expires_at, updated_at
FROM webhook_events
WHERE endpoint_id = sqlc.arg('endpoint_id')
  AND (sqlc.narg('event_type')::text IS NULL OR event_type = sqlc.narg('event_type')::text)
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ClaimNextWebhookEvent :one
-- Atomic claim: select the next pending event whose retry time has
-- passed (or never set), lock it via SKIP LOCKED so concurrent
-- workers don't race, then update it with our claim token + expiry
-- and return the row. The accompanying endpoint must be loaded by
-- the caller via GetWebhookEndpointByID inside a tenant tx.
--
-- Runs under the explicit app.system_context='true' GUC (set by
-- WithSystemContext) so the webhook_events RLS policy permits the
-- cross-tenant claim.
--
-- A successful claim is the worker's authorization to perform the
-- HTTP POST. Other workers that arrive while we hold the claim see
-- the row as locked (SKIP LOCKED). When we Mark{Delivered,Failed}
-- we atomically release the claim (claim_token = NULL) so a future
-- retry can be claimed cleanly.
--
-- Returns ErrNoRows when the queue is empty — the worker sleeps
-- briefly and tries again.
WITH claimed AS (
    SELECT id FROM webhook_events
    WHERE status = 'pending'
      AND claim_token IS NULL
      AND (next_retry_at IS NULL OR next_retry_at <= NOW())
    ORDER BY next_retry_at NULLS FIRST, created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE webhook_events we
SET claim_token = sqlc.arg('claim_token')::uuid,
    claim_expires_at = sqlc.arg('claim_expires_at')::timestamptz,
    updated_at = NOW()
FROM claimed c
WHERE we.id = c.id
RETURNING we.id, we.account_id, we.endpoint_id, we.event_type, we.payload,
          we.status, we.attempts, we.last_attempted_at, we.response_status,
          we.created_at, we.environment, we.domain_event_id,
          we.response_body, we.response_body_truncated, we.response_headers,
          we.next_retry_at,
          we.claim_token, we.claim_expires_at, we.updated_at;

-- name: ReleaseStaleWebhookClaims :execrows
-- Worker died mid-delivery -> claim_expires_at passed -> next worker
-- sweep frees the row by clearing claim_token. Idempotent: if no
-- rows are stale, returns 0.
--
-- Called once at startup (recovery sweep) AND periodically by the
-- worker pool itself so a long-running pod that loses workers can
-- self-heal without restart. Runs under WithSystemContext.
UPDATE webhook_events
SET claim_token = NULL,
    claim_expires_at = NULL,
    updated_at = NOW()
WHERE claim_token IS NOT NULL
  AND claim_expires_at < NOW();

-- name: MarkWebhookEventDelivered :execrows
-- Successful delivery: clear the claim, set status=delivered,
-- record the HTTP response details. The next_retry_at column is
-- nulled out — delivered rows aren't retried.
--
-- The claim_token predicate gates the write so a worker whose
-- claim has already expired (and been reissued by ReleaseStaleClaims
-- to another worker) cannot overwrite the legitimate worker's state.
-- Returns affected rowcount; 0 means the claim was lost — caller
-- should log and skip without erroring.
UPDATE webhook_events
SET status = 'delivered',
    attempts = sqlc.arg('attempts')::int,
    last_attempted_at = NOW(),
    response_status = sqlc.narg('response_status')::int,
    response_body = sqlc.narg('response_body')::text,
    response_body_truncated = sqlc.arg('response_body_truncated')::boolean,
    response_headers = sqlc.narg('response_headers')::jsonb,
    next_retry_at = NULL,
    claim_token = NULL,
    claim_expires_at = NULL,
    updated_at = NOW()
WHERE id = sqlc.arg('id')::uuid
  AND claim_token = sqlc.arg('claim_token')::uuid;

-- name: MarkWebhookEventFailedRetry :execrows
-- Failed but more retries remain: clear the claim, leave
-- status=pending, set next_retry_at so the worker won't immediately
-- re-claim the row. The retry backoff schedule is computed
-- application-side from the attempt count.
--
-- Same claim_token predicate as MarkWebhookEventDelivered: refuses
-- the update if another worker has reclaimed the row in the interim.
UPDATE webhook_events
SET status = 'pending',
    attempts = sqlc.arg('attempts')::int,
    last_attempted_at = NOW(),
    response_status = sqlc.narg('response_status')::int,
    response_body = sqlc.narg('response_body')::text,
    response_body_truncated = sqlc.arg('response_body_truncated')::boolean,
    response_headers = sqlc.narg('response_headers')::jsonb,
    next_retry_at = sqlc.arg('next_retry_at')::timestamptz,
    claim_token = NULL,
    claim_expires_at = NULL,
    updated_at = NOW()
WHERE id = sqlc.arg('id')::uuid
  AND claim_token = sqlc.arg('claim_token')::uuid;

-- name: MarkWebhookEventFailedFinal :execrows
-- All retries exhausted (or unrecoverable HTTP status): set
-- status=failed and clear the claim. Row stays for audit; never
-- re-attempted unless an operator does a manual redeliver.
--
-- Same claim_token predicate as MarkWebhookEventDelivered: refuses
-- the update if another worker has reclaimed the row in the interim.
UPDATE webhook_events
SET status = 'failed',
    attempts = sqlc.arg('attempts')::int,
    last_attempted_at = NOW(),
    response_status = sqlc.narg('response_status')::int,
    response_body = sqlc.narg('response_body')::text,
    response_body_truncated = sqlc.arg('response_body_truncated')::boolean,
    response_headers = sqlc.narg('response_headers')::jsonb,
    next_retry_at = NULL,
    claim_token = NULL,
    claim_expires_at = NULL,
    updated_at = NOW()
WHERE id = sqlc.arg('id')::uuid
  AND claim_token = sqlc.arg('claim_token')::uuid;

-- name: GetWebhookDispatcherCheckpoint :one
-- Reads the singleton checkpoint row. Returns NULL last_domain_event_id
-- on a fresh install; the dispatcher treats this as "process from the
-- beginning" via DomainEventRepository.ListSince(zero, ...).
--
-- Runs under WithSystemContext.
SELECT last_domain_event_id, updated_at
FROM webhook_dispatcher_checkpoint
WHERE singleton = true;

-- name: UpdateWebhookDispatcherCheckpoint :exec
-- Advances the checkpoint after the dispatcher fans out a batch.
-- The CHECK constraint guarantees we touch the singleton row.
UPDATE webhook_dispatcher_checkpoint
SET last_domain_event_id = sqlc.arg('last_domain_event_id')::uuid,
    updated_at = NOW()
WHERE singleton = true;
