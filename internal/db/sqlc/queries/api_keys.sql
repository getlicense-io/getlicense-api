-- name: CreateAPIKey :exec
INSERT INTO api_keys (id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetAPIKeyByHash :one
SELECT id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at
FROM api_keys WHERE key_hash = $1;

-- name: ListAPIKeysByAccountAndEnv :many
SELECT id, account_id, product_id, prefix, key_hash, scope, label, environment, expires_at, created_at
FROM api_keys
WHERE environment = $1
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: DeleteAPIKey :execrows
DELETE FROM api_keys WHERE id = $1;
