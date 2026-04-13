-- +goose Up

-- Per-account environment metadata. Account-scoped RLS only (not
-- env-filtered) because this table defines the envs themselves.
-- Tenant-scoped tables keep their `environment TEXT` column; the
-- slug here is the stable identifier, not an FK target.
CREATE TABLE environments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT 'radio',
    color TEXT NOT NULL DEFAULT 'emerald',
    position INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, slug),
    -- Mirrors core.environmentSlugRegex in Go.
    CONSTRAINT environments_slug_format
        CHECK (slug ~ '^[a-z][a-z0-9-]{0,31}$')
);

CREATE INDEX environments_account_id_position_idx
    ON environments (account_id, position);

ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_environments ON environments USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
);

-- Backfill defaults for existing accounts. New signups are seeded by
-- environment.DefaultEnvironments in auth.Service.Signup.
INSERT INTO environments (account_id, slug, name, description, icon, color, position)
SELECT id, 'live', 'Live', 'Production data', 'radio', 'emerald', 0 FROM accounts
ON CONFLICT (account_id, slug) DO NOTHING;

INSERT INTO environments (account_id, slug, name, description, icon, color, position)
SELECT id, 'test', 'Test', 'Sandbox · safe to break', 'flask-conical', 'amber', 1 FROM accounts
ON CONFLICT (account_id, slug) DO NOTHING;

-- +goose Down
DROP POLICY IF EXISTS tenant_environments ON environments;
DROP TABLE IF EXISTS environments;
