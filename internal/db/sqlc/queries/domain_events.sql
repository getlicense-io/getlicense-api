-- Column order below matches the shared sqlcgen.DomainEvent struct in
-- models.go. Matching order lets sqlc reuse the shared type for all
-- :one/:many queries instead of emitting per-query *Row structs.
--
-- DomainEvent: id, account_id, environment, event_type, resource_type,
--              resource_id, acting_account_id, identity_id, actor_label,
--              actor_kind, api_key_id, grant_id, request_id, ip_address,
--              payload, created_at

-- name: CreateDomainEvent :exec
INSERT INTO domain_events (
    id, account_id, environment, event_type, resource_type,
    resource_id, acting_account_id, identity_id, actor_label,
    actor_kind, api_key_id, grant_id, request_id, ip_address,
    payload, created_at
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12, $13, $14,
    $15, $16
);

-- name: GetDomainEventByID :one
SELECT id, account_id, environment, event_type, resource_type,
       resource_id, acting_account_id, identity_id, actor_label,
       actor_kind, api_key_id, grant_id, request_id, ip_address,
       payload, created_at
FROM domain_events WHERE id = $1;

-- name: ListDomainEvents :many
-- 7 optional filters (resource_type, resource_id, event_type,
-- identity_id, grant_id, from_ts, to_ts) + cursor keyset pagination.
SELECT id, account_id, environment, event_type, resource_type,
       resource_id, acting_account_id, identity_id, actor_label,
       actor_kind, api_key_id, grant_id, request_id, ip_address,
       payload, created_at
FROM domain_events
WHERE (sqlc.narg('resource_type')::text IS NULL OR resource_type = sqlc.narg('resource_type')::text)
  AND (sqlc.narg('resource_id')::text   IS NULL OR resource_id   = sqlc.narg('resource_id')::text)
  AND (sqlc.narg('event_type')::text    IS NULL OR event_type    = sqlc.narg('event_type')::text)
  AND (sqlc.narg('identity_id')::uuid   IS NULL OR identity_id   = sqlc.narg('identity_id')::uuid)
  AND (sqlc.narg('grant_id')::uuid      IS NULL OR grant_id      = sqlc.narg('grant_id')::uuid)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at  >= sqlc.narg('from_ts')::timestamptz)
  AND (sqlc.narg('to_ts')::timestamptz   IS NULL OR created_at  <= sqlc.narg('to_ts')::timestamptz)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ListDomainEventsSince :many
-- Background webhook-fanout consumer: returns events with id > $1
-- (uuid v7 comparable), ordered by id ASC. Runs outside any RLS tx —
-- the adapter passes r.pool directly instead of conn(ctx, r.pool).
SELECT id, account_id, environment, event_type, resource_type,
       resource_id, acting_account_id, identity_id, actor_label,
       actor_kind, api_key_id, grant_id, request_id, ip_address,
       payload, created_at
FROM domain_events
WHERE id > $1
ORDER BY id ASC
LIMIT $2;
