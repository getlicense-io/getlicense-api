-- +goose Up
-- Grants let one account (grantor) delegate capabilities to another
-- account (grantee) without sharing credentials. Phase 7 implements
-- the grant lifecycle (issue, accept, suspend, revoke) and uses grants
-- to scope license creation to the grantor's product catalog.
CREATE TABLE grants (
    id UUID PRIMARY KEY,
    grantor_account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    grantee_account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended','revoked')),

    -- Capabilities are an ordered list of permission tokens the grantee
    -- is allowed to exercise on the grantor's behalf, e.g. 'license.create'.
    capabilities TEXT[] NOT NULL DEFAULT '{}',

    -- Constraints is a free-form JSON blob used by the grant service to
    -- enforce business rules (max_licenses, allowed_products, etc.).
    -- NULL means no additional constraints beyond the capabilities list.
    constraints JSONB,

    -- Invitation that originated this grant, if any.
    invitation_id UUID REFERENCES invitations(id) ON DELETE SET NULL,

    environment TEXT NOT NULL,
    accepted_at TIMESTAMPTZ,
    suspended_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT grants_different_accounts CHECK (grantor_account_id <> grantee_account_id)
);

CREATE INDEX idx_grants_grantor ON grants (grantor_account_id, created_at DESC, id DESC);
CREATE INDEX idx_grants_grantee ON grants (grantee_account_id, created_at DESC, id DESC);

-- RLS: both grantor and grantee must be able to read the grant row.
-- The OR-branch policy uses the NULLIF escape hatch so background jobs
-- (no tenant context) and global lookups pass through.
ALTER TABLE grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_grants ON grants USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR grantor_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
    OR grantee_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

-- Add attribution columns to licenses so grant-issued licenses can be
-- traced back to the originating grant and the issuing account.
-- Three-step NOT NULL backfill: add nullable → fill → set NOT NULL.
ALTER TABLE licenses
    ADD COLUMN grant_id UUID REFERENCES grants(id) ON DELETE SET NULL,
    ADD COLUMN created_by_account_id UUID REFERENCES accounts(id) ON DELETE SET NULL,
    ADD COLUMN created_by_identity_id UUID REFERENCES identities(id) ON DELETE SET NULL;

UPDATE licenses SET created_by_account_id = account_id WHERE created_by_account_id IS NULL;

ALTER TABLE licenses ALTER COLUMN created_by_account_id SET NOT NULL;

CREATE INDEX idx_licenses_grant ON licenses (grant_id) WHERE grant_id IS NOT NULL;

-- +goose Down
ALTER TABLE licenses
    DROP COLUMN IF EXISTS grant_id,
    DROP COLUMN IF EXISTS created_by_account_id,
    DROP COLUMN IF EXISTS created_by_identity_id;
DROP TABLE IF EXISTS grants;
