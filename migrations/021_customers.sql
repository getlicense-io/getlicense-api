-- +goose Up

-- Customers: end-user records owned by the vendor account. Account-scoped,
-- environment-agnostic (matches policies/products, not licenses/machines).
CREATE TABLE customers (
    id                    UUID PRIMARY KEY,
    account_id            UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email                 TEXT NOT NULL,
    name                  TEXT,
    metadata              JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Attribution: which account created this customer record.
    -- NULL = created by the owning account directly.
    -- Non-NULL = created by a grantee account acting under a grant on account_id.
    created_by_account_id UUID REFERENCES accounts(id) ON DELETE SET NULL,

    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX customers_account_email_ci
    ON customers (account_id, lower(email));

CREATE INDEX customers_account_created
    ON customers (account_id, created_at DESC, id DESC);

CREATE INDEX customers_account_created_by
    ON customers (account_id, created_by_account_id);

ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers FORCE ROW LEVEL SECURITY;

CREATE POLICY customers_tenant ON customers
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);

-- Licenses: add customer_id NOT NULL FK, drop licensee_name / licensee_email.
ALTER TABLE licenses
    ADD COLUMN customer_id UUID REFERENCES customers(id),
    DROP COLUMN IF EXISTS licensee_name,
    DROP COLUMN IF EXISTS licensee_email;

-- Hard cutover: dev DB is wiped. No backfill. Set NOT NULL immediately.
ALTER TABLE licenses ALTER COLUMN customer_id SET NOT NULL;

CREATE INDEX licenses_customer ON licenses (customer_id);

-- Seed new RBAC permissions onto preset roles.
UPDATE roles
SET permissions = array_cat(permissions, ARRAY['customer:read','customer:write','customer:delete']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer');

UPDATE roles
SET permissions = array_cat(permissions, ARRAY['customer:read']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug = 'operator';

-- +goose Down

-- Restore licensee columns for a clean rollback.
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS licensee_name  TEXT,
    ADD COLUMN IF NOT EXISTS licensee_email TEXT;

DROP INDEX IF EXISTS licenses_customer;

ALTER TABLE licenses
    DROP COLUMN IF EXISTS customer_id;

DROP POLICY IF EXISTS customers_tenant ON customers;
ALTER TABLE customers NO FORCE ROW LEVEL SECURITY;
ALTER TABLE customers DISABLE ROW LEVEL SECURITY;

DROP TABLE IF EXISTS customers;

UPDATE roles
SET permissions = array_remove(array_remove(array_remove(permissions,'customer:read'),'customer:write'),'customer:delete'),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer','operator');
