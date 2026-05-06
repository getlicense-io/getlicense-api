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

-- name: ListChannelsByPartner :many
-- Partner-side filterable list. status_filter is optional; cursor pagination
-- with (created_at DESC, id DESC) ordering. Used by GET /v1/partner/channels
-- to list all channels the partner account belongs to.
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
WHERE c.partner_account_id = sqlc.arg('partner_account_id')::uuid
  AND (sqlc.narg('status_filter')::text IS NULL OR c.status = sqlc.narg('status_filter')::text)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (c.created_at, c.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY c.created_at DESC, c.id DESC
LIMIT sqlc.arg('limit_plus_one')::int;

-- name: ListChannelProducts :many
-- Returns one row per non-terminal grant under the channel, with product
-- summary embedded. Terminal statuses (revoked, left, expired) are excluded
-- so the channel-product API only surfaces active offerings. Cursor pagination
-- with (created_at DESC, id DESC) ordering.
SELECT
    g.id, g.channel_id, g.product_id, g.status,
    g.capabilities, g.constraints,
    g.created_at, g.updated_at,
    p.name AS product_name,
    p.slug AS product_slug
FROM grants g
JOIN products p ON p.id = g.product_id
WHERE g.channel_id = sqlc.arg('channel_id')::uuid
  AND g.status NOT IN ('revoked', 'left', 'expired')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (g.created_at, g.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY g.created_at DESC, g.id DESC
LIMIT sqlc.arg('limit_plus_one')::int;

-- name: CountChannelProducts :one
-- Returns total and active grant counts for a channel, excluding terminal
-- statuses from both counts (revoked/left/expired grants are ignored).
SELECT
    COUNT(*) FILTER (WHERE g.status NOT IN ('revoked','left','expired'))::bigint AS total,
    COUNT(*) FILTER (WHERE g.status = 'active')::bigint AS active
FROM grants g
WHERE g.channel_id = sqlc.arg('channel_id')::uuid;

-- name: CountChannelLicenses :one
-- Returns total and this-month license counts across the channel's grants.
-- is_partner=true scopes to licenses created by the caller account;
-- is_partner=false bypasses the filter so the vendor sees all licenses.
SELECT
    COUNT(*)::bigint AS total,
    COUNT(*) FILTER (WHERE l.created_at >= sqlc.arg('since_month')::timestamptz)::bigint AS this_month
FROM licenses l
JOIN grants g ON g.id = l.grant_id
WHERE g.channel_id = sqlc.arg('channel_id')::uuid
  AND (NOT sqlc.arg('is_partner')::bool OR l.created_by_account_id = sqlc.arg('caller_account_id')::uuid);

-- name: CountChannelCustomers :one
-- Returns distinct customer count across the channel's licenses.
-- is_partner=true scopes to licenses created by the caller account;
-- is_partner=false bypasses the filter so the vendor sees all customers.
SELECT COUNT(DISTINCT l.customer_id)::bigint
FROM licenses l
JOIN grants g ON g.id = l.grant_id
WHERE g.channel_id = sqlc.arg('channel_id')::uuid
  AND (NOT sqlc.arg('is_partner')::bool OR l.created_by_account_id = sqlc.arg('caller_account_id')::uuid);
