-- name: CreateEntitlement :exec
INSERT INTO entitlements (id, account_id, code, name, metadata, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetEntitlementByID :one
SELECT id, account_id, code, name, metadata, created_at, updated_at
FROM entitlements WHERE id = $1;

-- name: GetEntitlementsByCodes :many
-- Case-insensitive lookup against the entitlements_account_code_ci index
-- on (account_id, lower(code)). Caller is expected to pre-lowercase codes
-- but we apply lower(code) on the column to keep the index usable.
SELECT id, account_id, code, name, metadata, created_at, updated_at
FROM entitlements
WHERE account_id = sqlc.arg('account_id')
  AND lower(code) = ANY(sqlc.arg('codes')::text[]);

-- name: ListEntitlements :many
SELECT id, account_id, code, name, metadata, created_at, updated_at
FROM entitlements
WHERE account_id = sqlc.arg('account_id')
  AND (sqlc.narg('code_prefix')::text IS NULL
       OR lower(code) LIKE lower(sqlc.narg('code_prefix')::text) || '%')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateEntitlement :one
UPDATE entitlements SET
    name       = $2,
    metadata   = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING id, account_id, code, name, metadata, created_at, updated_at;

-- name: DeleteEntitlement :execrows
DELETE FROM entitlements WHERE id = $1;

-- name: AttachEntitlementToPolicy :exec
INSERT INTO policy_entitlements (policy_id, entitlement_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DetachEntitlementsFromPolicy :exec
DELETE FROM policy_entitlements
WHERE policy_id = sqlc.arg('policy_id')
  AND entitlement_id = ANY(sqlc.arg('entitlement_ids')::uuid[]);

-- name: DeleteAllPolicyEntitlements :exec
DELETE FROM policy_entitlements WHERE policy_id = $1;

-- name: ListPolicyEntitlementCodes :many
SELECT e.code FROM entitlements e
JOIN policy_entitlements pe ON pe.entitlement_id = e.id
WHERE pe.policy_id = $1
ORDER BY e.code ASC;

-- name: AttachEntitlementToLicense :exec
INSERT INTO license_entitlements (license_id, entitlement_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: DetachEntitlementsFromLicense :exec
DELETE FROM license_entitlements
WHERE license_id = sqlc.arg('license_id')
  AND entitlement_id = ANY(sqlc.arg('entitlement_ids')::uuid[]);

-- name: DeleteAllLicenseEntitlements :exec
DELETE FROM license_entitlements WHERE license_id = $1;

-- name: ListLicenseEntitlementCodes :many
SELECT e.code FROM entitlements e
JOIN license_entitlements le ON le.entitlement_id = e.id
WHERE le.license_id = $1
ORDER BY e.code ASC;

-- name: ResolveEffectiveEntitlements :many
SELECT DISTINCT e.code FROM entitlements e
WHERE e.id IN (
    SELECT pe.entitlement_id FROM policy_entitlements pe
    JOIN licenses l ON l.policy_id = pe.policy_id
    WHERE l.id = $1
    UNION
    SELECT le.entitlement_id FROM license_entitlements le
    WHERE le.license_id = $1
)
ORDER BY e.code ASC;
