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

-- name: ConsumeRefreshToken :one
-- Atomically remove a refresh token row, returning identity_id when
-- the token existed AND was unexpired. Returns ErrNoRows when the
-- token was already consumed, expired, or never existed.
--
-- Used by auth.Service.Refresh to close the rotation race: two
-- concurrent refresh requests with the same token race on this DELETE,
-- and only one gets the identity_id back. The other returns ErrNoRows
-- and the service rejects with ErrAuthenticationRequired.
DELETE FROM refresh_tokens
WHERE token_hash = $1
  AND expires_at > NOW()
RETURNING identity_id;
