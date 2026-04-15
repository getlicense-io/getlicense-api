-- +goose Up
-- Invitations power two flows with one table:
--   kind='membership' → invite an identity to join an account with a role
--   kind='grant'      → invite an account to receive reseller capability
--                       (Phase 7 implements the grant branch; Phase 6 lands
--                       membership and leaves grant_draft untouched by code)
CREATE TABLE invitations (
    id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('membership','grant')),
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,

    -- For kind='membership': target account + role the accepted identity receives
    account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE SET NULL,

    -- For kind='grant': a JSON blob the grant service interprets at accept time
    grant_draft JSONB,

    -- Attribution
    created_by_identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    created_by_account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,

    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT invitations_membership_fields CHECK (
        kind <> 'membership' OR (account_id IS NOT NULL AND role_id IS NOT NULL)
    ),
    CONSTRAINT invitations_grant_fields CHECK (
        kind <> 'grant' OR grant_draft IS NOT NULL
    )
);
CREATE INDEX idx_invitations_email ON invitations (lower(email));
CREATE INDEX idx_invitations_created_by_account ON invitations (created_by_account_id, created_at DESC, id DESC);
CREATE INDEX idx_invitations_token_hash ON invitations (token_hash);

-- RLS: scoped by created_by_account_id so the issuer sees their own
-- invitations. Recipients discover invites via the unauthenticated
-- lookup endpoint using the raw token (which HMACs to token_hash).
-- GetByTokenHash runs without tenant context and relies on the
-- NULLIF escape hatch to bypass the account filter.
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_invitations ON invitations USING (
    NULLIF(current_setting('app.current_account_id', true), '') IS NULL
    OR created_by_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid);

-- +goose Down
DROP TABLE IF EXISTS invitations;
