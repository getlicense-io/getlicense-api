-- name: CreateAccountMembership :exec
INSERT INTO account_memberships (
    id, account_id, identity_id, role_id, status,
    invited_by_identity_id, joined_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetAccountMembershipByID :one
SELECT id, account_id, identity_id, role_id, status,
       invited_by_identity_id, joined_at, created_at, updated_at
FROM account_memberships WHERE id = $1;

-- name: GetAccountMembershipByIDWithRole :one
-- Returns both membership and joined role columns. sqlc generates a
-- custom Row struct; aliases keep field names legible.
SELECT
    m.id                      AS membership_id,
    m.account_id              AS membership_account_id,
    m.identity_id             AS membership_identity_id,
    m.role_id                 AS membership_role_id,
    m.status                  AS membership_status,
    m.invited_by_identity_id  AS membership_invited_by_identity_id,
    m.joined_at               AS membership_joined_at,
    m.created_at              AS membership_created_at,
    m.updated_at              AS membership_updated_at,
    r.id                      AS role_id_full,
    r.account_id              AS role_account_id,
    r.slug                    AS role_slug,
    r.name                    AS role_name,
    r.permissions             AS role_permissions,
    r.created_at              AS role_created_at,
    r.updated_at              AS role_updated_at
FROM account_memberships m
JOIN roles r ON r.id = m.role_id
WHERE m.id = $1;

-- name: GetAccountMembershipByIdentityAndAccount :one
SELECT id, account_id, identity_id, role_id, status,
       invited_by_identity_id, joined_at, created_at, updated_at
FROM account_memberships
WHERE identity_id = $1 AND account_id = $2;

-- name: ListAccountMembershipsByIdentity :many
-- Cross-tenant: returns memberships across all accounts for the identity.
SELECT id, account_id, identity_id, role_id, status,
       invited_by_identity_id, joined_at, created_at, updated_at
FROM account_memberships
WHERE identity_id = $1 AND status = 'active'
ORDER BY created_at ASC;

-- name: ListAccountMembershipsByAccount :many
SELECT id, account_id, identity_id, role_id, status,
       invited_by_identity_id, joined_at, created_at, updated_at
FROM account_memberships
WHERE (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateAccountMembershipRole :exec
UPDATE account_memberships SET role_id = $2, updated_at = NOW() WHERE id = $1;

-- name: UpdateAccountMembershipStatus :exec
UPDATE account_memberships SET status = $2, updated_at = NOW() WHERE id = $1;

-- name: DeleteAccountMembership :exec
DELETE FROM account_memberships WHERE id = $1;

-- name: CountAccountOwners :one
-- Cross-tenant last-owner guard. Matches only the preset owner role
-- (r.account_id IS NULL) so custom roles named 'owner' don't count.
SELECT COUNT(*) FROM account_memberships m
JOIN roles r ON r.id = m.role_id
WHERE m.account_id = $1
  AND m.status = 'active'
  AND r.slug = 'owner'
  AND r.account_id IS NULL;
