-- Column order matches sqlcgen.Channel (id, vendor_account_id,
-- partner_account_id, name, description, status, draft_first_product,
-- created_at, updated_at, closed_at) so sqlc reuses the shared Channel
-- type for plain :one/:many queries. JOIN variants append vendor/partner
-- name+slug alias columns, which diverges from the sqlcgen.Channel shape,
-- so sqlc emits per-query *Row structs.

-- name: CreateChannel :exec
-- Column order matches sqlcgen.Channel so no per-query struct is emitted.
-- closed_at is always NULL on creation; description and draft_first_product
-- are optional (NULL if not provided). Must be called inside a
-- WithTargetAccount context scoped to the vendor account so RLS allows the
-- INSERT. Callers must populate channel_id on the linked grant row in the
-- same transaction.
INSERT INTO channels (
    id, vendor_account_id, partner_account_id, name, description,
    status, draft_first_product, created_at, updated_at, closed_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, NULL
);

-- name: GetChannelByID :one
-- Single-channel read with vendor + partner AccountSummary columns
-- joined in. Partner JOIN is LEFT because channel may be in draft state
-- with null partner_account_id. The service layer uses this on
-- GET /v1/channels/:id so the UI can render account names without a
-- second lookup. Column ordering diverges from sqlcgen.Channel (base
-- fields + four alias columns), so sqlc emits a per-query row struct.
SELECT
    c.id, c.vendor_account_id, c.partner_account_id, c.name, c.description,
    c.status, c.draft_first_product, c.created_at, c.updated_at, c.closed_at,
    v.name AS vendor_name,
    v.slug AS vendor_slug,
    p.name AS partner_name,
    p.slug AS partner_slug
FROM channels c
JOIN accounts v ON v.id = c.vendor_account_id
LEFT JOIN accounts p ON p.id = c.partner_account_id
WHERE c.id = sqlc.arg('id')::uuid;

-- name: ListChannelsByVendor :many
-- Vendor-side filterable list. status_filter and partner_filter are
-- optional; cursor pagination with (created_at DESC, id DESC) ordering.
-- Used by GET /v1/channels to list all channels for the vendor account.
SELECT
    c.id, c.vendor_account_id, c.partner_account_id, c.name, c.description,
    c.status, c.draft_first_product, c.created_at, c.updated_at, c.closed_at,
    v.name AS vendor_name,
    v.slug AS vendor_slug,
    p.name AS partner_name,
    p.slug AS partner_slug
FROM channels c
JOIN accounts v ON v.id = c.vendor_account_id
LEFT JOIN accounts p ON p.id = c.partner_account_id
WHERE c.vendor_account_id = sqlc.arg('vendor_account_id')::uuid
  AND (sqlc.narg('status_filter')::text IS NULL OR c.status = sqlc.narg('status_filter')::text)
  AND (sqlc.narg('partner_filter')::uuid IS NULL OR c.partner_account_id = sqlc.narg('partner_filter')::uuid)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (c.created_at, c.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY c.created_at DESC, c.id DESC
LIMIT sqlc.arg('limit_plus_one')::int;
