-- +goose Up

-- Run with the system-context bypass so the backfill UPDATE can see all
-- existing grants through FORCE ROW LEVEL SECURITY, and the role permission
-- seeds can write preset rows regardless of caller tenant. SET LOCAL scopes
-- this to the migration transaction only (safe under goose's default tx-per-migration).
SET LOCAL app.system_context = 'true';

-- Channels v1: a first-class wrapper over grants. A channel is a named
-- partnership between a vendor account and a partner account, with
-- one or more underlying grants ("channel products") under it. Spec:
-- docs/superpowers/specs/2026-04-29-channels-backend-design.md

CREATE TABLE channels (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor_account_id   UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    partner_account_id  UUID NULL REFERENCES accounts(id) ON DELETE RESTRICT,
    name                VARCHAR(100) NOT NULL,
    description         VARCHAR(500) NULL,
    status              TEXT NOT NULL CHECK (status IN ('draft','pending','active','suspended','closed')),
    draft_first_product JSONB NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at           TIMESTAMPTZ NULL,
    CONSTRAINT channels_name_not_blank CHECK (length(trim(name)) >= 1),
    CONSTRAINT channels_closed_at_matches_status CHECK (
        (status = 'closed') = (closed_at IS NOT NULL)
    ),
    CONSTRAINT channels_draft_first_product_only_in_draft CHECK (
        (status = 'draft') OR (draft_first_product IS NULL)
    )
);

CREATE UNIQUE INDEX channels_unique_name
    ON channels (vendor_account_id, partner_account_id, lower(name))
    WHERE status != 'closed';

CREATE INDEX channels_vendor_status_created
    ON channels (vendor_account_id, status, created_at DESC, id DESC);

CREATE INDEX channels_partner_status_created
    ON channels (partner_account_id, status, created_at DESC, id DESC)
    WHERE partner_account_id IS NOT NULL;

ALTER TABLE channels ENABLE ROW LEVEL SECURITY;
CREATE POLICY channels_tenant ON channels
    USING (
        CASE WHEN current_setting('app.system_context', true) = 'true' THEN true
             ELSE vendor_account_id   = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                 '00000000-0000-0000-0000-000000000000')::uuid
                  OR partner_account_id = COALESCE(NULLIF(current_setting('app.current_account_id', true), ''),
                                                   '00000000-0000-0000-0000-000000000000')::uuid
        END
    );

ALTER TABLE grants ADD COLUMN channel_id UUID REFERENCES channels(id) ON DELETE RESTRICT;
CREATE INDEX grants_channel ON grants (channel_id);

ALTER TABLE invitations ADD COLUMN channel_id UUID NULL REFERENCES channels(id) ON DELETE SET NULL;
CREATE INDEX invitations_channel ON invitations (channel_id) WHERE channel_id IS NOT NULL;

-- Auto-promote every existing grant to a single-product channel.
-- Idempotent: re-running is a no-op because of the WHERE channel_id IS NULL
-- filter (after first run there are no unmigrated grants left).

WITH numbered AS (
    SELECT
        g.id AS grant_id,
        g.grantor_account_id,
        g.grantee_account_id,
        g.product_id,
        g.status AS grant_status,
        g.created_at,
        a.name AS partner_name,
        p.name AS product_name,
        ROW_NUMBER() OVER (
            PARTITION BY g.grantor_account_id, g.grantee_account_id, p.name
            ORDER BY g.created_at, g.id
        ) AS dup_rank
    FROM grants g
    JOIN products p ON p.id = g.product_id
    LEFT JOIN accounts a ON a.id = g.grantee_account_id
    WHERE g.channel_id IS NULL
)
INSERT INTO channels (id, vendor_account_id, partner_account_id, name, status, created_at, closed_at)
SELECT
    gen_random_uuid(),
    grantor_account_id,
    -- All existing grants have grantee_account_id populated (even pending ones —
    -- the invitation target is known, just not yet accepted). The channels
    -- constraint requires partner_account_id NOT NULL for any non-draft status,
    -- so we always populate it here. New draft channels created via the API
    -- may have NULL partner_account_id until the invite is sent.
    grantee_account_id,
    CASE
        WHEN dup_rank = 1
            THEN format('%s — %s', COALESCE(partner_name, 'Pending partner'), product_name)
        ELSE format('%s — %s (%s)', COALESCE(partner_name, 'Pending partner'), product_name, dup_rank)
    END,
    CASE
        WHEN grant_status IN ('revoked','left','expired') THEN 'closed'
        WHEN grant_status = 'pending'                     THEN 'pending'
        WHEN grant_status = 'suspended'                   THEN 'suspended'
        ELSE                                                   'active'
    END,
    created_at,
    CASE WHEN grant_status IN ('revoked','left','expired') THEN NOW() ELSE NULL END
FROM numbered;

WITH numbered AS (
    SELECT
        g.id AS grant_id,
        g.grantor_account_id,
        g.grantee_account_id,
        g.product_id,
        g.status AS grant_status,
        g.created_at,
        a.name AS partner_name,
        p.name AS product_name,
        ROW_NUMBER() OVER (
            PARTITION BY g.grantor_account_id, g.grantee_account_id, p.name
            ORDER BY g.created_at, g.id
        ) AS dup_rank
    FROM grants g
    JOIN products p ON p.id = g.product_id
    LEFT JOIN accounts a ON a.id = g.grantee_account_id
    WHERE g.channel_id IS NULL
),
expected_names AS (
    SELECT
        grant_id,
        grantor_account_id,
        grantee_account_id,
        grant_status,
        CASE
            WHEN dup_rank = 1
                THEN format('%s — %s', COALESCE(partner_name, 'Pending partner'), product_name)
            ELSE format('%s — %s (%s)', COALESCE(partner_name, 'Pending partner'), product_name, dup_rank)
        END AS expected_name
    FROM numbered
)
UPDATE grants g
SET channel_id = c.id
FROM expected_names e
JOIN channels c
    ON c.vendor_account_id = e.grantor_account_id
   AND lower(c.name) = lower(e.expected_name)
   AND c.partner_account_id = e.grantee_account_id
WHERE g.id = e.grant_id;

ALTER TABLE grants ALTER COLUMN channel_id SET NOT NULL;

-- Seed channel permissions on preset roles.
-- owner + admin: full channel management
-- operator: create + read (can onboard partners, cannot manage existing channels)
-- developer + read_only: read only

UPDATE roles SET permissions = array_cat(permissions,
    ARRAY['channel:read','channel:create','channel:manage']),
    updated_at = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin');

UPDATE roles SET permissions = array_cat(permissions,
    ARRAY['channel:read','channel:create']),
    updated_at = NOW()
WHERE account_id IS NULL AND slug = 'operator';

UPDATE roles SET permissions = array_cat(permissions,
    ARRAY['channel:read']),
    updated_at = NOW()
WHERE account_id IS NULL AND slug IN ('developer','read_only');

-- Widen the partner constraint: partner is required only for ALIVE channels
-- (active/suspended/closed). Draft and pending may have NULL partner_account_id.
ALTER TABLE channels DROP CONSTRAINT IF EXISTS channels_partner_required_after_draft;
ALTER TABLE channels ADD CONSTRAINT channels_partner_required_when_alive CHECK (
    status IN ('draft', 'pending') OR partner_account_id IS NOT NULL
);

-- +goose Down

-- Same bypass as Up: the role permission removal and the column drops
-- need to see across tenants (preset roles have account_id IS NULL,
-- but the RLS still checks the GUC in some code paths).
SET LOCAL app.system_context = 'true';

ALTER TABLE channels DROP CONSTRAINT IF EXISTS channels_partner_required_when_alive;

UPDATE roles SET permissions = array_remove(permissions, 'channel:manage'), updated_at = NOW() WHERE account_id IS NULL;
UPDATE roles SET permissions = array_remove(permissions, 'channel:create'), updated_at = NOW() WHERE account_id IS NULL;
UPDATE roles SET permissions = array_remove(permissions, 'channel:read'),   updated_at = NOW() WHERE account_id IS NULL;

ALTER TABLE grants ALTER COLUMN channel_id DROP NOT NULL;
ALTER TABLE invitations DROP COLUMN IF EXISTS channel_id;
ALTER TABLE grants DROP COLUMN IF EXISTS channel_id;

DROP TABLE IF EXISTS channels;
