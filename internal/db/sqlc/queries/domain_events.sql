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
-- 7 optional user filters (resource_type, resource_id, event_type,
-- identity_id, grant_id, from_ts, to_ts) + keyset cursor + one
-- auth-injected product restriction (restrict_license_product_id).
-- When restrict_license_product_id is non-NULL, the result set is
-- narrowed to license.* events whose license belongs to that product
-- AND non-license events are dropped. resource_id is compared as text
-- against licenses.id::text to avoid a UUID cast against non-UUID
-- resource_ids (grant/invitation/webhook events store non-UUID ids).
-- The subquery inherits the outer RLS context, so tenant isolation
-- follows the licenses policy automatically.
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
  AND (sqlc.narg('restrict_license_product_id')::uuid IS NULL
       OR (resource_type = 'license'
           AND resource_id IN (
               SELECT id::text FROM licenses
               WHERE product_id = sqlc.narg('restrict_license_product_id')::uuid
           )))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: CountDomainEventsFiltered :one
-- COUNT(*) of events matching the same filter set as ListDomainEvents
-- (excluding the cursor tuple, which is paging-only). Used by the CSV
-- export pre-cap check so the server can refuse oversized exports with
-- 413 before streaming.
SELECT COUNT(*) FROM domain_events
WHERE (sqlc.narg('resource_type')::text IS NULL OR resource_type = sqlc.narg('resource_type')::text)
  AND (sqlc.narg('resource_id')::text   IS NULL OR resource_id   = sqlc.narg('resource_id')::text)
  AND (sqlc.narg('event_type')::text    IS NULL OR event_type    = sqlc.narg('event_type')::text)
  AND (sqlc.narg('identity_id')::uuid   IS NULL OR identity_id   = sqlc.narg('identity_id')::uuid)
  AND (sqlc.narg('grant_id')::uuid      IS NULL OR grant_id      = sqlc.narg('grant_id')::uuid)
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR created_at  >= sqlc.narg('from_ts')::timestamptz)
  AND (sqlc.narg('to_ts')::timestamptz   IS NULL OR created_at  <= sqlc.narg('to_ts')::timestamptz)
  AND (sqlc.narg('restrict_license_product_id')::uuid IS NULL
       OR (resource_type = 'license'
           AND resource_id IN (
               SELECT id::text FROM licenses
               WHERE product_id = sqlc.narg('restrict_license_product_id')::uuid
           )));

-- name: CountDomainEventsByDay :many
-- Returns daily event-count buckets within the [from, to] range
-- for the current tenant. RLS scopes by account+env. The bucket
-- is the UTC day computed as date_trunc('day', created_at) cast
-- explicitly to timestamptz so sqlc.yaml's timestamptz override
-- maps the column to time.Time (without the cast sqlc infers
-- pgtype.Interval). The repo formats the day as yyyy-mm-dd.
SELECT date_trunc('day', created_at)::timestamptz AS day, COUNT(*) AS count
FROM domain_events
WHERE created_at BETWEEN sqlc.arg('from_ts')::timestamptz AND sqlc.arg('to_ts')::timestamptz
GROUP BY 1
ORDER BY 1;

-- name: ListDomainEventsSince :many
-- Background webhook-fanout consumer: returns events with id > $1
-- (uuid v7 comparable), ordered by id ASC. Runs outside any RLS tx —
-- the adapter passes r.pool directly instead of conn(ctx, r.pool).
SELECT id, account_id, environment, event_type, resource_type,
       resource_id, acting_account_id, identity_id, actor_label,
       actor_kind, api_key_id, grant_id, request_id, ip_address,
       payload, created_at
FROM domain_events
WHERE id > sqlc.arg('after_id')
ORDER BY id ASC
LIMIT sqlc.arg('limit_rows');
