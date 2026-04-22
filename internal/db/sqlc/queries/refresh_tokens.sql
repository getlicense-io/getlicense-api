-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, identity_id, token_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetRefreshTokenByHash :one
SELECT id, identity_id, token_hash, expires_at, created_at
FROM refresh_tokens WHERE token_hash = $1;

-- name: DeleteRefreshTokenByHash :exec
DELETE FROM refresh_tokens WHERE token_hash = $1;

-- name: DeleteRefreshTokensByIdentity :exec
DELETE FROM refresh_tokens WHERE identity_id = $1;
