-- +goose Up

-- Policies: own all license lifecycle configuration. Account-scoped,
-- product-scoped, environment-agnostic.
CREATE TABLE policies (
    id                          UUID PRIMARY KEY,
    account_id                  UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    product_id                  UUID NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    name                        TEXT NOT NULL,
    is_default                  BOOLEAN NOT NULL DEFAULT false,

    duration_seconds            INTEGER,
    expiration_strategy         TEXT NOT NULL DEFAULT 'REVOKE_ACCESS'
        CHECK (expiration_strategy IN ('MAINTAIN_ACCESS','RESTRICT_ACCESS','REVOKE_ACCESS')),
    expiration_basis            TEXT NOT NULL DEFAULT 'FROM_CREATION'
        CHECK (expiration_basis IN ('FROM_CREATION','FROM_FIRST_ACTIVATION')),

    max_machines                INTEGER,
    max_seats                   INTEGER,
    floating                    BOOLEAN NOT NULL DEFAULT false,
    strict                      BOOLEAN NOT NULL DEFAULT false,

    require_checkout            BOOLEAN NOT NULL DEFAULT false,
    checkout_interval_sec       INTEGER NOT NULL DEFAULT 86400,
    max_checkout_duration_sec   INTEGER NOT NULL DEFAULT 604800,

    component_matching_strategy TEXT NOT NULL DEFAULT 'MATCH_ANY'
        CHECK (component_matching_strategy IN ('MATCH_ANY','MATCH_TWO','MATCH_ALL')),

    metadata                    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX policies_default_per_product
    ON policies (product_id) WHERE is_default = true;

CREATE INDEX policies_account_product_created
    ON policies (account_id, product_id, created_at DESC, id DESC);

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;

CREATE POLICY policies_tenant ON policies
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);

-- Licenses: add policy_id, overrides, first_activated_at; drop
-- legacy raw-config columns.
ALTER TABLE licenses
    ADD COLUMN policy_id           UUID REFERENCES policies(id),
    ADD COLUMN overrides           JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN first_activated_at  TIMESTAMPTZ,
    DROP COLUMN IF EXISTS max_machines,
    DROP COLUMN IF EXISTS max_seats,
    DROP COLUMN IF EXISTS license_type,
    DROP COLUMN IF EXISTS entitlements;

CREATE INDEX licenses_policy ON licenses (policy_id);

-- Hard cutover: dev DB is wiped. No backfill. policy_id is NOT NULL from
-- the start of any post-migration row.
ALTER TABLE licenses ALTER COLUMN policy_id SET NOT NULL;

-- Products: drop legacy per-product config that now lives on policies.
ALTER TABLE products
    DROP COLUMN IF EXISTS validation_ttl,
    DROP COLUMN IF EXISTS grace_period,
    DROP COLUMN IF EXISTS heartbeat_timeout;

-- Seed new permissions onto preset roles. Migration 016 stores
-- permissions as a TEXT[] column on the roles table (no separate
-- role_permissions table), so we append with array_cat.
UPDATE roles
SET permissions = array_cat(permissions, ARRAY['policy:read','policy:write','policy:delete']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer');

UPDATE roles
SET permissions = array_cat(permissions, ARRAY['policy:read']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug = 'operator';

-- +goose Down
DROP POLICY IF EXISTS policies_tenant ON policies;
ALTER TABLE policies NO FORCE ROW LEVEL SECURITY;
ALTER TABLE policies DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS licenses_policy;
ALTER TABLE licenses
    DROP COLUMN IF EXISTS first_activated_at,
    DROP COLUMN IF EXISTS overrides,
    DROP COLUMN IF EXISTS policy_id;

-- Restore the legacy raw-config columns that the Up block dropped.
-- Release 1 shape (migration 005_licenses.sql): max_machines nullable
-- integer, license_type NOT NULL text (no default historically), and
-- entitlements nullable jsonb (no default). A working DEFAULT is added
-- here so ADD COLUMN ... NOT NULL succeeds on any rows that survived
-- the Up via backfill; 'perpetual' matches the Release 1 value used
-- throughout the e2e suite and OpenAPI enum.
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS max_machines integer,
    ADD COLUMN IF NOT EXISTS max_seats integer,
    ADD COLUMN IF NOT EXISTS license_type text NOT NULL DEFAULT 'perpetual',
    ADD COLUMN IF NOT EXISTS entitlements jsonb;

DROP TABLE IF EXISTS policies;

UPDATE roles
SET permissions = array_remove(array_remove(array_remove(permissions,'policy:read'),'policy:write'),'policy:delete'),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer','operator');

ALTER TABLE products
    ADD COLUMN IF NOT EXISTS validation_ttl    INTEGER NOT NULL DEFAULT 3600,
    ADD COLUMN IF NOT EXISTS grace_period      INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS heartbeat_timeout INTEGER;
