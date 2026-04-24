-- Column order matches sqlcgen.Grant (id, grantor_account_id,
-- grantee_account_id, status, product_id, capabilities, constraints,
-- invitation_id, expires_at, accepted_at, created_at, updated_at,
-- label, metadata) so sqlc reuses the shared Grant type for the
-- plain :one/:many queries. JOIN variants emit per-query *Row structs
-- because they append grantor/grantee name+slug alias columns.

-- name: CreateGrant :exec
INSERT INTO grants (
    id, grantor_account_id, grantee_account_id, status, product_id,
    capabilities, constraints, invitation_id,
    expires_at, accepted_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetGrantByID :one
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at,
       label, metadata
FROM grants WHERE id = $1;

-- name: GetGrantByIDWithAccounts :one
-- Single-grant read with grantor + grantee AccountSummary columns
-- joined in. The service layer uses this on GET /v1/grants/:id so the
-- UI can render account names without a second lookup. Column ordering
-- mirrors the grants table; the four alias columns at the end diverge
-- from sqlcgen.Grant, so sqlc emits a per-query row struct.
SELECT
    g.id, g.grantor_account_id, g.grantee_account_id, g.status, g.product_id,
    g.capabilities, g.constraints, g.invitation_id,
    g.expires_at, g.accepted_at, g.created_at, g.updated_at,
    g.label, g.metadata,
    grantor.name AS grantor_name,
    grantor.slug AS grantor_slug,
    grantee.name AS grantee_name,
    grantee.slug AS grantee_slug
FROM grants g
JOIN accounts grantor ON grantor.id = g.grantor_account_id
JOIN accounts grantee ON grantee.id = g.grantee_account_id
WHERE g.id = sqlc.arg('id')::uuid;

-- name: ListGrantsByGrantor :many
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at,
       label, metadata
FROM grants
WHERE grantor_account_id = sqlc.arg('grantor_account_id')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ListGrantsByGrantee :many
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at,
       label, metadata
FROM grants
WHERE grantee_account_id = sqlc.arg('grantee_account_id')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ListGrantsByGrantorFiltered :many
-- Grantor-side filterable list. product_id, grantee_account_id, and
-- statuses are optional; include_terminal=false filters out terminal
-- statuses (revoked, left, expired). The cursor tuple uses the
-- (created_at, id) compound ordering consistent with every other
-- paginated list.
SELECT
    g.id, g.grantor_account_id, g.grantee_account_id, g.status, g.product_id,
    g.capabilities, g.constraints, g.invitation_id,
    g.expires_at, g.accepted_at, g.created_at, g.updated_at,
    g.label, g.metadata,
    grantor.name AS grantor_name,
    grantor.slug AS grantor_slug,
    grantee.name AS grantee_name,
    grantee.slug AS grantee_slug
FROM grants g
JOIN accounts grantor ON grantor.id = g.grantor_account_id
JOIN accounts grantee ON grantee.id = g.grantee_account_id
WHERE g.grantor_account_id = sqlc.arg('grantor_account_id')::uuid
  AND (sqlc.narg('product_id')::uuid IS NULL OR g.product_id = sqlc.narg('product_id')::uuid)
  AND (sqlc.narg('grantee_account_id')::uuid IS NULL OR g.grantee_account_id = sqlc.narg('grantee_account_id')::uuid)
  AND (sqlc.narg('statuses')::text[] IS NULL OR g.status = ANY(sqlc.narg('statuses')::text[]))
  AND (sqlc.arg('include_terminal')::bool OR g.status NOT IN ('revoked','left','expired'))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (g.created_at, g.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY g.created_at DESC, g.id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ListGrantsByGranteeFiltered :many
-- Grantee-side symmetric filterable list. Same semantics as
-- ListGrantsByGrantorFiltered, but scoped to the grantee account and
-- filterable by grantor_account_id instead of grantee_account_id.
SELECT
    g.id, g.grantor_account_id, g.grantee_account_id, g.status, g.product_id,
    g.capabilities, g.constraints, g.invitation_id,
    g.expires_at, g.accepted_at, g.created_at, g.updated_at,
    g.label, g.metadata,
    grantor.name AS grantor_name,
    grantor.slug AS grantor_slug,
    grantee.name AS grantee_name,
    grantee.slug AS grantee_slug
FROM grants g
JOIN accounts grantor ON grantor.id = g.grantor_account_id
JOIN accounts grantee ON grantee.id = g.grantee_account_id
WHERE g.grantee_account_id = sqlc.arg('grantee_account_id')::uuid
  AND (sqlc.narg('product_id')::uuid IS NULL OR g.product_id = sqlc.narg('product_id')::uuid)
  AND (sqlc.narg('grantor_account_id')::uuid IS NULL OR g.grantor_account_id = sqlc.narg('grantor_account_id')::uuid)
  AND (sqlc.narg('statuses')::text[] IS NULL OR g.status = ANY(sqlc.narg('statuses')::text[]))
  AND (sqlc.arg('include_terminal')::bool OR g.status NOT IN ('revoked','left','expired'))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (g.created_at, g.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY g.created_at DESC, g.id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateGrantStatus :exec
UPDATE grants SET status = $2, updated_at = NOW() WHERE id = $1;

-- name: MarkGrantAccepted :exec
UPDATE grants SET status = 'active', accepted_at = $2, updated_at = NOW() WHERE id = $1;

-- name: UpdateGrant :exec
-- Partial update used by PATCH /v1/grants/:id. All filter columns use
-- sqlc.narg with explicit casts so Postgres can infer the type from
-- the NULL literal. COALESCE leaves untouched fields alone. For
-- nullable columns whose NULL is a meaningful clear-intent
-- (expires_at, label), we pair the value narg with a *_set bool so
-- the caller can distinguish "leave alone" from "set to NULL".
-- Capabilities / constraints / metadata are never NULL at the schema
-- level, so COALESCE is sufficient there. Callers MUST pre-validate
-- inputs — empty capabilities and oversized label/metadata are
-- rejected at the service layer before this query runs.
UPDATE grants
SET
    capabilities = COALESCE(sqlc.narg('capabilities')::text[], capabilities),
    constraints  = COALESCE(sqlc.narg('constraints')::jsonb, constraints),
    expires_at   = CASE WHEN sqlc.narg('expires_at_set')::bool THEN sqlc.narg('expires_at')::timestamptz ELSE expires_at END,
    label        = CASE WHEN sqlc.narg('label_set')::bool THEN sqlc.narg('label')::text ELSE label END,
    metadata     = COALESCE(sqlc.narg('metadata')::jsonb, metadata),
    updated_at   = NOW()
WHERE id = sqlc.arg('id')::uuid;

-- name: CountLicensesByGrantInPeriod :one
SELECT COUNT(*) FROM licenses WHERE grant_id = $1 AND created_at >= $2;

-- name: CountLicensesByGrant :one
-- All-time license count for a grant. Used to surface total issuance
-- on GET /v1/grants/:id alongside the monthly count derived from
-- CountLicensesByGrantInPeriod.
SELECT COUNT(*)::int FROM licenses WHERE grant_id = sqlc.arg('grant_id')::uuid;

-- name: CountDistinctCustomersByGrant :one
-- Distinct-customer count for grant usage reporting. customer_id is
-- NOT NULL on licenses (enforced by L4), so no NULL-guard needed.
SELECT COUNT(DISTINCT customer_id)::int FROM licenses
WHERE grant_id = sqlc.arg('grant_id')::uuid;

-- name: GetGrantUsage :one
-- Single-pass aggregate surfacing the three grant usage counters. One
-- round trip + one index scan instead of three separate COUNTs. Powers
-- the `usage` field on GET /v1/grants/:id.
SELECT
    COUNT(*)::int AS licenses_total,
    COUNT(*) FILTER (WHERE created_at >= sqlc.arg('since')::timestamptz)::int AS licenses_since,
    COUNT(DISTINCT customer_id)::int AS customers_total
FROM licenses
WHERE grant_id = sqlc.arg('grant_id')::uuid;

-- name: ListExpirableGrants :many
-- Returns grants whose expires_at has passed but whose status is
-- still non-terminal. Used by the expire_grants background job. Runs
-- without tenant context — passes through the NULLIF escape hatch in
-- the tenant_grants RLS policy. Column order matches sqlcgen.Grant so
-- sqlc reuses the shared struct.
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at,
       label, metadata
FROM grants
WHERE expires_at IS NOT NULL
  AND expires_at < sqlc.arg('now')::timestamptz
  AND status IN ('pending','active','suspended')
ORDER BY expires_at ASC
LIMIT sqlc.arg('limit_rows');
