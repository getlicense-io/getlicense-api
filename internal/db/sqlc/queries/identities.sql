-- name: CreateIdentity :exec
INSERT INTO identities (id, email, password_hash, totp_secret_enc, totp_enabled_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetIdentityByID :one
SELECT id, email, password_hash, totp_secret_enc, totp_enabled_at, created_at, updated_at
FROM identities WHERE id = $1;

-- name: GetIdentityByEmail :one
SELECT id, email, password_hash, totp_secret_enc, totp_enabled_at, created_at, updated_at
FROM identities WHERE lower(email) = lower($1);

-- name: UpdateIdentity :one
UPDATE identities
SET email = $2, password_hash = $3, totp_secret_enc = $4,
    totp_enabled_at = $5, updated_at = NOW()
WHERE id = $1
RETURNING updated_at;

-- name: UpdateIdentityPassword :exec
UPDATE identities SET password_hash = $2, updated_at = NOW() WHERE id = $1;

-- name: UpdateIdentityTOTP :exec
UPDATE identities
SET totp_secret_enc = $2, totp_enabled_at = $3, updated_at = NOW()
WHERE id = $1;
