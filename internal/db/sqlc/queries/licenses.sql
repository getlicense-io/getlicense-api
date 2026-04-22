-- Column order below matches the shared sqlcgen.License struct in
-- models.go (id, account_id, product_id, key_prefix, key_hash, token,
-- status, expires_at, created_at, updated_at, environment, grant_id,
-- created_by_account_id, created_by_identity_id, policy_id, overrides,
-- first_activated_at, customer_id). Matching order lets sqlc reuse the
-- shared License type for all :one/:many queries instead of emitting
-- per-query *Row structs.

-- name: CreateLicense :exec
INSERT INTO licenses (
    id, account_id, product_id, key_prefix, key_hash, token,
    status, expires_at, created_at, updated_at, environment,
    grant_id, created_by_account_id, created_by_identity_id,
    policy_id, overrides, first_activated_at, customer_id
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
);

-- name: GetLicenseByID :one
SELECT id, account_id, product_id, key_prefix, key_hash, token,
       status, expires_at, created_at, updated_at, environment,
       grant_id, created_by_account_id, created_by_identity_id,
       policy_id, overrides, first_activated_at, customer_id
FROM licenses WHERE id = $1;

-- name: GetLicenseByIDForUpdate :one
SELECT id, account_id, product_id, key_prefix, key_hash, token,
       status, expires_at, created_at, updated_at, environment,
       grant_id, created_by_account_id, created_by_identity_id,
       policy_id, overrides, first_activated_at, customer_id
FROM licenses WHERE id = $1 FOR UPDATE;

-- name: GetLicenseByKeyHash :one
SELECT id, account_id, product_id, key_prefix, key_hash, token,
       status, expires_at, created_at, updated_at, environment,
       grant_id, created_by_account_id, created_by_identity_id,
       policy_id, overrides, first_activated_at, customer_id
FROM licenses WHERE key_hash = $1;

-- name: ListLicenses :many
-- Unified paginated list. product_id, status, customer_id, q and the
-- cursor tuple are all optional via sqlc.narg NULL-guards. The q filter
-- matches key_prefix OR the referenced customer's name/email via an
-- EXISTS subquery; the subquery inherits the outer RLS context so
-- customer visibility matches the licenses scope automatically.
SELECT id, account_id, product_id, key_prefix, key_hash, token,
       status, expires_at, created_at, updated_at, environment,
       grant_id, created_by_account_id, created_by_identity_id,
       policy_id, overrides, first_activated_at, customer_id
FROM licenses
WHERE
  (sqlc.narg('product_id')::uuid IS NULL
       OR product_id = sqlc.narg('product_id')::uuid)
  AND (sqlc.narg('status')::text IS NULL
       OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('customer_id')::uuid IS NULL
       OR customer_id = sqlc.narg('customer_id')::uuid)
  AND (sqlc.narg('q')::text IS NULL
       OR LOWER(key_prefix) LIKE '%' || LOWER(sqlc.narg('q')::text) || '%'
       OR EXISTS (
           SELECT 1 FROM customers c
           WHERE c.id = licenses.customer_id
             AND (LOWER(COALESCE(c.name, '')) LIKE '%' || LOWER(sqlc.narg('q')::text) || '%'
                  OR LOWER(c.email) LIKE '%' || LOWER(sqlc.narg('q')::text) || '%')
       ))
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateLicense :one
UPDATE licenses SET
    policy_id          = $2,
    overrides          = $3,
    customer_id        = $4,
    expires_at         = $5,
    first_activated_at = $6,
    updated_at         = NOW()
WHERE id = $1
RETURNING id, account_id, product_id, key_prefix, key_hash, token,
          status, expires_at, created_at, updated_at, environment,
          grant_id, created_by_account_id, created_by_identity_id,
          policy_id, overrides, first_activated_at, customer_id;

-- name: UpdateLicenseStatusFromTo :one
-- Atomic from→to transition. Returns the new updated_at. Caller
-- disambiguates ErrNoRows ("not found" vs "stale from status") via a
-- follow-up LicenseExists query in the same tx.
UPDATE licenses SET
    status     = sqlc.arg('new_status')::text,
    updated_at = NOW()
WHERE id = sqlc.arg('id')
  AND status = sqlc.arg('expected_status')::text
RETURNING updated_at;

-- name: LicenseExists :one
SELECT EXISTS(SELECT 1 FROM licenses WHERE id = $1);

-- name: CountBlockingLicensesByProduct :one
-- Counts only active + suspended licenses (blocking product deletion);
-- revoked / expired / inactive do not block.
SELECT COUNT(*) FROM licenses
WHERE product_id = $1 AND status IN ('active', 'suspended');

-- name: CountsByProductStatus :many
SELECT status, COUNT(*)::int AS count FROM licenses
WHERE product_id = $1 GROUP BY status;

-- name: BulkRevokeLicensesByProduct :execrows
UPDATE licenses SET status = 'revoked', updated_at = NOW()
WHERE product_id = $1 AND status IN ('active', 'suspended');

-- name: HasBlockingLicenses :one
SELECT EXISTS(SELECT 1 FROM licenses WHERE status IN ('active', 'suspended') LIMIT 1);

-- name: ExpireActiveLicenses :many
-- UPDATE FROM policies to select active licenses past their expiry
-- whose policy opts into REVOKE_ACCESS. RESTRICT / MAINTAIN strategies
-- leave the license in 'active'; their effective expired-ness is
-- computed at validate time via policy.EvaluateExpiration.
--
-- Column list is spelled out with the `l.` alias so (a) the JOIN's
-- shared column names (id/account_id/created_at/updated_at) don't emit
-- "ambiguous" errors and (b) the ordering matches sqlcgen.License so
-- sqlc reuses the shared model instead of emitting a per-query Row.
UPDATE licenses l SET status = 'expired', updated_at = NOW()
FROM policies p
WHERE l.policy_id = p.id
  AND l.status = 'active'
  AND l.expires_at IS NOT NULL
  AND l.expires_at < NOW()
  AND p.expiration_strategy = 'REVOKE_ACCESS'
RETURNING
    l.id, l.account_id, l.product_id, l.key_prefix, l.key_hash, l.token,
    l.status, l.expires_at, l.created_at, l.updated_at, l.environment,
    l.grant_id, l.created_by_account_id, l.created_by_identity_id,
    l.policy_id, l.overrides, l.first_activated_at, l.customer_id;
