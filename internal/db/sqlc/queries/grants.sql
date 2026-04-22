-- name: CreateGrant :exec
INSERT INTO grants (
    id, grantor_account_id, grantee_account_id, status, product_id,
    capabilities, constraints, invitation_id,
    expires_at, accepted_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetGrantByID :one
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at
FROM grants WHERE id = $1;

-- name: ListGrantsByGrantor :many
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at
FROM grants
WHERE grantor_account_id = sqlc.arg('grantor_account_id')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ListGrantsByGrantee :many
SELECT id, grantor_account_id, grantee_account_id, status, product_id,
       capabilities, constraints, invitation_id,
       expires_at, accepted_at, created_at, updated_at
FROM grants
WHERE grantee_account_id = sqlc.arg('grantee_account_id')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateGrantStatus :exec
UPDATE grants SET status = $2, updated_at = NOW() WHERE id = $1;

-- name: MarkGrantAccepted :exec
UPDATE grants SET status = 'active', accepted_at = $2, updated_at = NOW() WHERE id = $1;

-- name: CountLicensesByGrantInPeriod :one
SELECT COUNT(*) FROM licenses WHERE grant_id = $1 AND created_at >= $2;
