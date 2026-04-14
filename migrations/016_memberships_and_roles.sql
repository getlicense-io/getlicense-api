-- +goose Up
-- Roles bundle permission strings. account_id NULL = system preset
-- (visible to every account, read-only). account_id NOT NULL = custom
-- per-account role (v2 UI; schema is ready now).
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT roles_slug_scope_unique UNIQUE NULLS NOT DISTINCT (account_id, slug)
);
CREATE INDEX idx_roles_account_id ON roles (account_id);

-- Account memberships join identities to accounts with a role.
CREATE TABLE account_memberships (
    id UUID PRIMARY KEY,
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    invited_by_identity_id UUID REFERENCES identities(id) ON DELETE SET NULL,
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_memberships_unique UNIQUE (account_id, identity_id)
);
CREATE INDEX idx_account_memberships_identity_id ON account_memberships (identity_id);
CREATE INDEX idx_account_memberships_account_id ON account_memberships (account_id);

-- Seed preset roles. account_id = NULL so every account sees them.
-- Permissions list is intentionally flat and greppable.
INSERT INTO roles (id, account_id, slug, name, permissions) VALUES
    (gen_random_uuid(), NULL, 'owner', 'Owner', ARRAY[
        'license:create','license:read','license:update','license:suspend','license:revoke',
        'machine:read','machine:deactivate',
        'product:create','product:read','product:update','product:delete',
        'apikey:create','apikey:read','apikey:revoke',
        'webhook:create','webhook:read','webhook:update','webhook:delete',
        'environment:create','environment:read','environment:delete',
        'user:invite','user:remove','user:change_role',
        'grant:issue','grant:revoke','grant:accept','grant:use',
        'metrics:read','events:read',
        'billing:read','billing:manage',
        'account:update','account:delete'
    ]),
    (gen_random_uuid(), NULL, 'admin', 'Admin', ARRAY[
        'license:create','license:read','license:update','license:suspend','license:revoke',
        'machine:read','machine:deactivate',
        'product:create','product:read','product:update','product:delete',
        'apikey:create','apikey:read','apikey:revoke',
        'webhook:create','webhook:read','webhook:update','webhook:delete',
        'environment:create','environment:read','environment:delete',
        'user:invite','user:remove','user:change_role',
        'grant:issue','grant:revoke','grant:accept','grant:use',
        'metrics:read','events:read',
        'billing:read',
        'account:update'
    ]),
    (gen_random_uuid(), NULL, 'developer', 'Developer', ARRAY[
        'license:read',
        'machine:read',
        'product:create','product:read','product:update','product:delete',
        'apikey:create','apikey:read','apikey:revoke',
        'webhook:create','webhook:read','webhook:update','webhook:delete',
        'environment:read',
        'metrics:read','events:read'
    ]),
    (gen_random_uuid(), NULL, 'operator', 'Operator', ARRAY[
        'license:create','license:read','license:update','license:suspend','license:revoke',
        'machine:read','machine:deactivate',
        'product:read',
        'environment:read',
        'metrics:read','events:read',
        'grant:use'
    ]),
    (gen_random_uuid(), NULL, 'read_only', 'Read Only', ARRAY[
        'license:read','machine:read','product:read','apikey:read','webhook:read',
        'environment:read','metrics:read','events:read'
    ]);

-- RLS for roles and account_memberships — must live here (after CREATE TABLE)
-- because migration 010 runs before this migration.
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_memberships ENABLE ROW LEVEL SECURITY;

-- Roles: preset rows (account_id NULL) are readable by every tenant.
-- Custom rows are scoped to their owning account.
CREATE POLICY tenant_roles ON roles USING (
    account_id IS NULL
    OR NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

CREATE POLICY tenant_account_memberships ON account_memberships USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

ALTER TABLE roles FORCE ROW LEVEL SECURITY;
ALTER TABLE account_memberships FORCE ROW LEVEL SECURITY;

-- +goose Down
DROP POLICY IF EXISTS tenant_account_memberships ON account_memberships;
DROP POLICY IF EXISTS tenant_roles ON roles;
ALTER TABLE account_memberships NO FORCE ROW LEVEL SECURITY;
ALTER TABLE roles NO FORCE ROW LEVEL SECURITY;
ALTER TABLE account_memberships DISABLE ROW LEVEL SECURITY;
ALTER TABLE roles DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS account_memberships;
DROP TABLE IF EXISTS roles;
