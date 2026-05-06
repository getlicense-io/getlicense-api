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
       expires_at, accepted_at, created_at, channel_id
FROM invitations WHERE id = $1;

-- name: GetInvitationByTokenHash :one
SELECT id, kind, email, token_hash,
       account_id, role_id, grant_draft,
       created_by_identity_id, created_by_account_id,
       expires_at, accepted_at, created_at, channel_id
FROM invitations WHERE token_hash = $1;

-- name: ListInvitationsByAccount :many
SELECT id, kind, email, token_hash,
       account_id, role_id, grant_draft,
       created_by_identity_id, created_by_account_id,
       expires_at, accepted_at, created_at, channel_id
FROM invitations
WHERE (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: MarkInvitationAccepted :exec
UPDATE invitations SET accepted_at = $2 WHERE id = $1;

-- name: DeleteInvitation :exec
DELETE FROM invitations WHERE id = $1;

-- name: ListInvitationsByAccountFiltered :many
-- Cursor-paginated invitations scoped by the current RLS account,
-- optionally filtered by kind and computed status. Status is not a
-- stored column -- it's derived from (accepted_at, expires_at, now):
--   pending  = accepted_at IS NULL AND expires_at >= now
--   accepted = accepted_at IS NOT NULL
--   expired  = accepted_at IS NULL AND expires_at <  now
-- The adapter passes the desired status set as a text[]; NULL means
-- "no status filter". Column order for the invitation columns matches
-- sqlcgen.Invitation so the adapter can reuse the same row->domain
-- translation seam. Extra creator_name / creator_slug alias columns
-- force sqlc to emit a per-query *Row struct, which is fine.
SELECT
    i.id, i.kind, i.email, i.token_hash,
    i.account_id, i.role_id, i.grant_draft,
    i.created_by_identity_id, i.created_by_account_id,
    i.expires_at, i.accepted_at, i.created_at, i.channel_id,
    creator.name AS creator_name,
    creator.slug AS creator_slug
FROM invitations i
JOIN accounts creator ON creator.id = i.created_by_account_id
WHERE (sqlc.narg('kind')::text IS NULL OR i.kind = sqlc.narg('kind')::text)
  AND (sqlc.narg('statuses')::text[] IS NULL OR (
       ('pending'  = ANY(sqlc.narg('statuses')::text[]) AND i.accepted_at IS NULL AND i.expires_at >= sqlc.arg('now')::timestamptz)
    OR ('accepted' = ANY(sqlc.narg('statuses')::text[]) AND i.accepted_at IS NOT NULL)
    OR ('expired'  = ANY(sqlc.narg('statuses')::text[]) AND i.accepted_at IS NULL AND i.expires_at <  sqlc.arg('now')::timestamptz)
  ))
  AND (sqlc.narg('created_by_identity_id')::uuid IS NULL
       OR i.created_by_identity_id = sqlc.narg('created_by_identity_id')::uuid)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (i.created_at, i.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY i.created_at DESC, i.id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: GetInvitationByIDWithCreator :one
-- Single-invitation read with creator account name+slug joined in,
-- used by GET /v1/invitations/:id so the UI can render the creator
-- without a second lookup. Alias columns at the end diverge from
-- sqlcgen.Invitation; sqlc emits a per-query row struct.
SELECT
    i.id, i.kind, i.email, i.token_hash,
    i.account_id, i.role_id, i.grant_draft,
    i.created_by_identity_id, i.created_by_account_id,
    i.expires_at, i.accepted_at, i.created_at, i.channel_id,
    creator.name AS creator_name,
    creator.slug AS creator_slug
FROM invitations i
JOIN accounts creator ON creator.id = i.created_by_account_id
WHERE i.id = sqlc.arg('id')::uuid;

-- name: UpdateInvitationTokenHash :exec
-- Used by POST /v1/invitations/:id/resend: rotate the token hash so
-- the previous token is invalidated.
UPDATE invitations
SET token_hash = sqlc.arg('token_hash')::text
WHERE id = sqlc.arg('id')::uuid;

-- name: HasActiveGrantInvitation :one
-- True iff a PENDING, UNEXPIRED grant-kind invitation already exists
-- for the same (created_by_account_id, lower(email), product_id).
-- Backed by the partial index idx_invitations_grant_dup_guard from
-- migration 030. product_id is extracted from the grant_draft JSON
-- (stored as a text string under the "product_id" key), so the arg
-- is passed as text rather than uuid to match the index expression
-- ((grant_draft->>'product_id')).
-- Used by invitation.Service.CreateGrant to reject duplicates before
-- insert (best-effort; a narrow concurrent-insert race is acceptable).
SELECT EXISTS (
    SELECT 1 FROM invitations
    WHERE created_by_account_id = sqlc.arg('account_id')::uuid
      AND lower(email) = sqlc.arg('email_lower')::text
      AND kind = 'grant'
      AND accepted_at IS NULL
      AND expires_at > NOW()
      AND grant_draft->>'product_id' = sqlc.arg('product_id')::text
) AS has_active;
