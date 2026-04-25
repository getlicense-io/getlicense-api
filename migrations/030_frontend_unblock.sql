-- +goose Up

-- Frontend unblock batch (2026-04-24).
-- 1. Seed the new user:list permission on every preset role that already
--    sees other read permissions (matches the metrics:read / events:read /
--    policy:read distribution).
-- 2. Add a partial index supporting the duplicate-grant-invitation guard.
--
-- No table schema changes. api_keys.scope and api_keys.product_id already
-- exist from migration 004_api_keys.sql.
--
-- Note: roles.permissions is a TEXT[] (see migration 016), not jsonb, so
-- this migration uses array_cat / array_remove and the '= ANY()'
-- idempotency guard — matching the seed pattern in migrations 020, 024,
-- and 029.

UPDATE roles
SET permissions = array_cat(permissions, ARRAY['user:list']),
    updated_at  = NOW()
WHERE account_id IS NULL
  AND slug IN ('owner', 'admin', 'developer', 'operator', 'read_only')
  AND NOT ('user:list' = ANY(permissions));

CREATE INDEX idx_invitations_grant_dup_guard
  ON invitations (created_by_account_id, lower(email), ((grant_draft->>'product_id')))
  WHERE kind = 'grant' AND accepted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_invitations_grant_dup_guard;

UPDATE roles
SET permissions = array_remove(permissions, 'user:list'),
    updated_at  = NOW()
WHERE account_id IS NULL
  AND slug IN ('owner', 'admin', 'developer', 'operator', 'read_only');
