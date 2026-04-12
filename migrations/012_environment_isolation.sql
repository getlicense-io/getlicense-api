-- +goose Up

-- Add environment column to tenant-scoped tables.
ALTER TABLE licenses ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE machines ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE webhook_endpoints ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';
ALTER TABLE webhook_events ADD COLUMN environment TEXT NOT NULL DEFAULT 'live';

-- Recreate RLS policies to include environment filtering.
DROP POLICY IF EXISTS tenant_licenses ON licenses;
CREATE POLICY tenant_licenses ON licenses USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

DROP POLICY IF EXISTS tenant_machines ON machines;
CREATE POLICY tenant_machines ON machines USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
CREATE POLICY tenant_webhook_events ON webhook_events USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

-- +goose Down

-- Restore original policies (account_id only).
DROP POLICY IF EXISTS tenant_licenses ON licenses;
CREATE POLICY tenant_licenses ON licenses USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_machines ON machines;
CREATE POLICY tenant_machines ON machines USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_webhook_endpoints ON webhook_endpoints;
CREATE POLICY tenant_webhook_endpoints ON webhook_endpoints USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_webhook_events ON webhook_events;
CREATE POLICY tenant_webhook_events ON webhook_events USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

ALTER TABLE licenses DROP COLUMN IF EXISTS environment;
ALTER TABLE machines DROP COLUMN IF EXISTS environment;
ALTER TABLE webhook_endpoints DROP COLUMN IF EXISTS environment;
ALTER TABLE webhook_events DROP COLUMN IF EXISTS environment;
