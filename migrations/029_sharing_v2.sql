-- +goose Up

-- Sharing v2: expand grants status to cover three distinct terminal states
-- (revoked = grantor-ended, left = grantee-ended, expired = time-ended),
-- add annotation fields (label + metadata), and seed the grant:update
-- permission on preset roles.
ALTER TABLE grants DROP CONSTRAINT IF EXISTS grants_status_check;
ALTER TABLE grants ADD CONSTRAINT grants_status_check
    CHECK (status IN ('pending','active','suspended','revoked','left','expired'));

ALTER TABLE grants
    ADD COLUMN label TEXT,
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}';

ALTER TABLE grants ADD CONSTRAINT grants_label_length
    CHECK (label IS NULL OR char_length(label) <= 100);

ALTER TABLE grants ADD CONSTRAINT grants_metadata_size
    CHECK (octet_length(metadata::text) <= 8192);

-- Seed grant:update permission on the preset roles that already manage grants.
-- Owner and admin get it. Developer, operator, and read_only do not — the
-- developer preset has no other grant permissions, so grant:update alone
-- would be incoherent.
UPDATE roles
SET permissions = array_cat(permissions, ARRAY['grant:update']),
    updated_at = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin');

-- +goose Down

UPDATE roles
SET permissions = array_remove(permissions, 'grant:update'),
    updated_at = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin');

ALTER TABLE grants DROP CONSTRAINT IF EXISTS grants_metadata_size;
ALTER TABLE grants DROP CONSTRAINT IF EXISTS grants_label_length;
ALTER TABLE grants DROP COLUMN IF EXISTS metadata;
ALTER TABLE grants DROP COLUMN IF EXISTS label;

-- Coerce new terminal states back to 'revoked' before restoring the narrower
-- constraint — otherwise this ADD CONSTRAINT aborts on any production row in
-- 'left'/'expired' status, stranding the DB in a partial-Down state.
UPDATE grants SET status = 'revoked', updated_at = NOW()
WHERE status IN ('left', 'expired');

ALTER TABLE grants DROP CONSTRAINT IF EXISTS grants_status_check;
ALTER TABLE grants ADD CONSTRAINT grants_status_check
    CHECK (status IN ('pending','active','suspended','revoked'));
