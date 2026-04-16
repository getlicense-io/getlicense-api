-- +goose Up

CREATE TABLE domain_events (
    id                 UUID PRIMARY KEY,
    account_id         UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    environment        TEXT NOT NULL DEFAULT '',

    event_type         TEXT NOT NULL,
    resource_type      TEXT NOT NULL,
    resource_id        TEXT,

    acting_account_id  UUID,
    identity_id        UUID,
    actor_label        TEXT NOT NULL DEFAULT '',
    actor_kind         TEXT NOT NULL DEFAULT 'system'
        CHECK (actor_kind IN ('identity','api_key','system','public')),
    api_key_id         UUID,
    grant_id           UUID,

    request_id         TEXT,
    ip_address         INET,
    payload            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_domain_events_cursor
    ON domain_events (account_id, environment, created_at DESC, id DESC);

CREATE INDEX idx_domain_events_resource
    ON domain_events (account_id, resource_type, resource_id, created_at DESC);

CREATE INDEX idx_domain_events_identity
    ON domain_events (account_id, identity_id, created_at DESC)
    WHERE identity_id IS NOT NULL;

CREATE INDEX idx_domain_events_grant
    ON domain_events (account_id, grant_id, created_at DESC)
    WHERE grant_id IS NOT NULL;

ALTER TABLE domain_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE domain_events FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_domain_events ON domain_events
USING (
    (NULLIF(current_setting('app.current_account_id', true), '') IS NULL
     OR account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid)
    AND
    (NULLIF(current_setting('app.current_environment', true), '') IS NULL
     OR environment = current_setting('app.current_environment', true))
);

UPDATE roles
SET permissions = array_cat(permissions, ARRAY['event:read']),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer','operator');

-- +goose Down

UPDATE roles
SET permissions = array_remove(permissions, 'event:read'),
    updated_at  = NOW()
WHERE account_id IS NULL AND slug IN ('owner','admin','developer','operator');

DROP POLICY IF EXISTS tenant_domain_events ON domain_events;
ALTER TABLE domain_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE domain_events DISABLE ROW LEVEL SECURITY;

DROP TABLE IF EXISTS domain_events;
