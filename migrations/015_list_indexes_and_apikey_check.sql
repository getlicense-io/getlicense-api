-- +goose Up

-- Ordered pagination indexes. The dashboard list endpoints sort by
-- (created_at DESC, id DESC) and page via LIMIT/OFFSET. Without these
-- composites, Postgres has to fall back to scanning an account/product
-- index and sorting in memory, which is O(N log N) per request and
-- wastes work beyond the first page. These indexes let the planner
-- walk directly in order and stop at the LIMIT.
CREATE INDEX IF NOT EXISTS idx_licenses_product_created
    ON licenses (product_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_licenses_account_created
    ON licenses (account_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_api_keys_account_env_created
    ON api_keys (account_id, environment, created_at DESC, id DESC);

-- Close a latent RLS gap on api_keys: the original tenant_api_keys
-- policy from 010_rls_policies.sql uses only a USING clause with no
-- WITH CHECK, so a write operation (INSERT or UPDATE) is only subject
-- to the column-level constraints, not the tenant policy. In practice
-- the app always sets app.current_account_id before writing, but the
-- WITH CHECK makes the invariant enforceable at the DB boundary.
-- We only constrain account_id; environment is intentionally left out
-- so a live-authenticated caller can still create/delete test keys
-- (same as the existing USING clause).
DROP POLICY IF EXISTS tenant_api_keys ON api_keys;
CREATE POLICY tenant_api_keys ON api_keys
  USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
  )
  WITH CHECK (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
  );

-- +goose Down

DROP INDEX IF EXISTS idx_licenses_product_created;
DROP INDEX IF EXISTS idx_licenses_account_created;
DROP INDEX IF EXISTS idx_api_keys_account_env_created;

DROP POLICY IF EXISTS tenant_api_keys ON api_keys;
CREATE POLICY tenant_api_keys ON api_keys USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);
