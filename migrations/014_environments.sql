-- +goose Up

-- `environments` is the per-account metadata table for data partitions.
-- Historically the set was a fixed two-value enum (`live`, `test`);
-- accounts may now define up to three environments with custom slug,
-- name, description, icon, and color.
--
-- This table is intentionally NOT scoped by `app.current_environment`:
-- it IS the metadata *about* environments, not data stored *within*
-- one. RLS filters by account only. Existing tenant-scoped tables keep
-- their `environment TEXT` column and are not foreign-keyed here — the
-- slug is the stable identifier and an environment row is metadata
-- joined in at display time.
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
    -- Matches core.environmentSlugRegex in Go: lowercase ASCII letters,
    -- digits, and hyphens; must start with a letter; 1-32 characters.
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

-- Seed the two default environments for every existing account. New
-- accounts get these seeded by the AuthService signup flow (same
-- transaction as the account insert). `ON CONFLICT DO NOTHING` makes
-- the migration idempotent.
INSERT INTO environments (account_id, slug, name, description, icon, color, position)
SELECT id, 'live', 'Live', 'Production data', 'radio', 'emerald', 0 FROM accounts
ON CONFLICT (account_id, slug) DO NOTHING;

INSERT INTO environments (account_id, slug, name, description, icon, color, position)
SELECT id, 'test', 'Test', 'Sandbox · safe to break', 'flask-conical', 'amber', 1 FROM accounts
ON CONFLICT (account_id, slug) DO NOTHING;

-- +goose Down
DROP POLICY IF EXISTS tenant_environments ON environments;
DROP TABLE IF EXISTS environments;
