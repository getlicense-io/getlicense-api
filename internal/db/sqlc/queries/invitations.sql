-- name: CreateInvitation :exec
INSERT INTO invitations (
    id, kind, email, token_hash,
    account_id, role_id, grant_draft,
    created_by_identity_id, created_by_account_id,
    expires_at, accepted_at, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetInvitationByID :one
SELECT id, kind, email, token_hash,
       account_id, role_id, grant_draft,
       created_by_identity_id, created_by_account_id,
       expires_at, accepted_at, created_at
FROM invitations WHERE id = $1;

-- name: GetInvitationByTokenHash :one
SELECT id, kind, email, token_hash,
       account_id, role_id, grant_draft,
       created_by_identity_id, created_by_account_id,
       expires_at, accepted_at, created_at
FROM invitations WHERE token_hash = $1;

-- name: ListInvitationsByAccount :many
SELECT id, kind, email, token_hash,
       account_id, role_id, grant_draft,
       created_by_identity_id, created_by_account_id,
       expires_at, accepted_at, created_at
FROM invitations
WHERE (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: MarkInvitationAccepted :exec
UPDATE invitations SET accepted_at = $2 WHERE id = $1;

-- name: DeleteInvitation :exec
DELETE FROM invitations WHERE id = $1;
