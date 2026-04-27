-- name: CreateAPIKey :exec
INSERT INTO api_keys (
    id, account_id, product_id, prefix, key_hash, scope, label, environment,
    expires_at, created_at, created_by_identity_id, created_by_api_key_id,
    permissions, ip_allowlist
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8,
    $9, $10, $11, $12,
    $13, $14
);

-- name: GetAPIKeyByHash :one
SELECT id, account_id, product_id, prefix, key_hash, scope, label, environment,
       expires_at, created_at, last_used_at, last_used_ip,
       last_used_user_agent_hash, created_by_identity_id,
       created_by_api_key_id, revoked_at, revoked_by_identity_id,
       revoked_reason, permissions, ip_allowlist
FROM api_keys WHERE key_hash = $1;

-- name: ListAPIKeysByAccountAndEnv :many
SELECT id, account_id, product_id, prefix, key_hash, scope, label, environment,
       expires_at, created_at, last_used_at, last_used_ip,
       last_used_user_agent_hash, created_by_identity_id,
       created_by_api_key_id, revoked_at, revoked_by_identity_id,
       revoked_reason, permissions, ip_allowlist
FROM api_keys
WHERE environment = $1
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: RevokeAPIKey :execrows
UPDATE api_keys
SET revoked_at = sqlc.arg('revoked_at')::timestamptz,
    revoked_by_identity_id = sqlc.narg('revoked_by_identity_id')::uuid,
    revoked_reason = sqlc.narg('revoked_reason')::text
WHERE id = sqlc.arg('id')::uuid
  AND revoked_at IS NULL;

-- name: RecordAPIKeyUse :exec
UPDATE api_keys
SET last_used_at = sqlc.arg('last_used_at')::timestamptz,
    last_used_ip = sqlc.narg('last_used_ip')::inet,
    last_used_user_agent_hash = sqlc.narg('last_used_user_agent_hash')::text
WHERE id = sqlc.arg('id')::uuid;
