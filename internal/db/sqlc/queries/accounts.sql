-- name: CreateAccount :exec
INSERT INTO accounts (id, name, slug, created_at)
VALUES ($1, $2, $3, $4);

-- name: GetAccountByID :one
SELECT id, name, slug, created_at
FROM accounts
WHERE id = $1;

-- name: GetAccountBySlug :one
SELECT id, name, slug, created_at
FROM accounts
WHERE slug = $1;

-- name: GetAccountIfAccessible :one
-- Returns the account row only if the caller has a relationship that
-- permits seeing the AccountSummary: (a) membership in the target
-- account, or (b) a non-terminal grant (pending/active/suspended)
-- between the caller and target in either direction. Callers pass
-- their own acting account id and identity id. Runs outside tenant
-- RLS — the access predicate is explicit and the query reads across
-- tenant boundaries, so the session must NOT have
-- app.current_account_id pinned.
SELECT a.id, a.name, a.slug, a.created_at
FROM accounts a
WHERE a.id = sqlc.arg('target_id')::uuid
  AND (
    EXISTS (
        SELECT 1 FROM account_memberships m
        WHERE m.account_id = a.id
          AND m.identity_id = sqlc.arg('caller_identity_id')::uuid
    )
    OR EXISTS (
        SELECT 1 FROM grants g
        WHERE g.status IN ('pending','active','suspended')
          AND (
              (g.grantor_account_id = sqlc.arg('caller_account_id')::uuid AND g.grantee_account_id = a.id)
              OR (g.grantor_account_id = a.id AND g.grantee_account_id = sqlc.arg('caller_account_id')::uuid)
          )
    )
  );
