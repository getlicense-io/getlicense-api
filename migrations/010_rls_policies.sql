-- +goose Up
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE machines ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;

-- Identities and refresh_tokens are GLOBAL — no RLS, guarded at the
-- service layer only. Identities join across accounts; refresh_tokens
-- are keyed on the identity and only visible via it.
-- roles and account_memberships get RLS in migration 016 (after their
-- CREATE TABLE statements).

CREATE POLICY tenant_api_keys ON api_keys USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_products ON products USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_licenses ON licenses USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_machines ON machines USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);
CREATE POLICY tenant_webhook_events ON webhook_events USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

-- +goose Down
DROP POLICY IF EXISTS tenant_api_keys ON api_keys;
DROP POLICY IF EXISTS tenant_products ON products;
DROP POLICY IF EXISTS tenant_licenses ON licenses;
DROP POLICY IF EXISTS tenant_machines ON machines;
DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
ALTER TABLE api_keys DISABLE ROW LEVEL SECURITY;
ALTER TABLE products DISABLE ROW LEVEL SECURITY;
ALTER TABLE licenses DISABLE ROW LEVEL SECURITY;
ALTER TABLE machines DISABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints DISABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events DISABLE ROW LEVEL SECURITY;
