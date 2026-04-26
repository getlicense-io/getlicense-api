-- name: InsertRevokedJTI :exec
INSERT INTO revoked_jtis (jti, identity_id, expires_at, reason)
VALUES (sqlc.arg('jti')::uuid,
        sqlc.arg('identity_id')::uuid,
        sqlc.arg('expires_at')::timestamptz,
        sqlc.arg('reason')::text)
ON CONFLICT (jti) DO NOTHING;

-- name: IsJTIRevoked :one
SELECT EXISTS (
    SELECT 1 FROM revoked_jtis
    WHERE jti = sqlc.arg('jti')::uuid AND expires_at > NOW()
) AS revoked;

-- name: SweepExpiredRevokedJTIs :execrows
DELETE FROM revoked_jtis WHERE expires_at <= NOW();

-- name: SetIdentitySessionInvalidation :exec
INSERT INTO identity_session_invalidations (identity_id, min_iat)
VALUES (sqlc.arg('identity_id')::uuid, sqlc.arg('min_iat')::timestamptz)
ON CONFLICT (identity_id) DO UPDATE
   SET min_iat    = EXCLUDED.min_iat,
       updated_at = NOW();

-- name: GetIdentitySessionMinIAT :one
SELECT min_iat FROM identity_session_invalidations
WHERE identity_id = sqlc.arg('identity_id')::uuid;
