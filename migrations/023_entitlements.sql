-- +goose Up

-- Entitlements registry: named feature/capability codes owned by an account.
-- Account-scoped, environment-agnostic (like customers and policies).
CREATE TABLE entitlements (
    id          UUID PRIMARY KEY,
    account_id  UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code        TEXT NOT NULL,
    name        TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX entitlements_account_code_ci
    ON entitlements (account_id, lower(code));

CREATE INDEX entitlements_account_created
    ON entitlements (account_id, created_at DESC, id DESC);

ALTER TABLE entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE entitlements FORCE ROW LEVEL SECURITY;

CREATE POLICY entitlements_tenant ON entitlements
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);

-- Policy entitlements: join table linking policies to entitlements.
-- ON DELETE RESTRICT on entitlement_id prevents deleting an in-use entitlement.
-- ON DELETE CASCADE on policy_id cleans up when a policy is deleted.
CREATE TABLE policy_entitlements (
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    entitlement_id  UUID NOT NULL REFERENCES entitlements(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, entitlement_id)
);

ALTER TABLE policy_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_entitlements FORCE ROW LEVEL SECURITY;

CREATE POLICY policy_entitlements_tenant ON policy_entitlements
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR EXISTS (
    SELECT 1 FROM policies
    WHERE policies.id = policy_entitlements.policy_id
      AND policies.account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
  )
);

-- License entitlements: join table linking licenses to entitlements.
-- Same FK constraints as policy_entitlements.
CREATE TABLE license_entitlements (
    license_id      UUID NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
    entitlement_id  UUID NOT NULL REFERENCES entitlements(id) ON DELETE RESTRICT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (license_id, entitlement_id)
);

ALTER TABLE license_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_entitlements FORCE ROW LEVEL SECURITY;

CREATE POLICY license_entitlements_tenant ON license_entitlements
USING (
  NULLIF(current_setting('app.current_account_id', true), '') IS NULL
  OR EXISTS (
    SELECT 1 FROM licenses
    WHERE licenses.id = license_entitlements.license_id
      AND licenses.account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
  )
);

-- Seed RBAC permissions for entitlements onto preset roles.
UPDATE roles
SET permissions = array_cat(permissions, ARRAY['entitlement:read','entitlement:write','entitlement:delete']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer');

UPDATE roles
SET permissions = array_cat(permissions, ARRAY['entitlement:read']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug = 'operator';

-- +goose Down

DROP POLICY IF EXISTS license_entitlements_tenant ON license_entitlements;
ALTER TABLE license_entitlements NO FORCE ROW LEVEL SECURITY;
ALTER TABLE license_entitlements DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS license_entitlements;

DROP POLICY IF EXISTS policy_entitlements_tenant ON policy_entitlements;
ALTER TABLE policy_entitlements NO FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_entitlements DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS policy_entitlements;

DROP POLICY IF EXISTS entitlements_tenant ON entitlements;
ALTER TABLE entitlements NO FORCE ROW LEVEL SECURITY;
ALTER TABLE entitlements DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS entitlements;

UPDATE roles
SET permissions = array_remove(array_remove(array_remove(permissions,'entitlement:read'),'entitlement:write'),'entitlement:delete'),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer','operator');
