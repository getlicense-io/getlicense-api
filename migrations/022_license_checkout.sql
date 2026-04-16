-- +goose Up

-- Machines: drop heartbeat last_seen_at, add lease state machine.
ALTER TABLE machines
    DROP COLUMN IF EXISTS last_seen_at,
    ADD COLUMN IF NOT EXISTS lease_issued_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_checkin_at  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS status           text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','stale','dead'));

-- Partial index on alive machines for the expire_leases sweep.
CREATE INDEX IF NOT EXISTS machines_lease_expires_alive
    ON machines (lease_expires_at)
    WHERE status <> 'dead';

CREATE INDEX IF NOT EXISTS machines_license_status
    ON machines (license_id, status);

-- Policies: add checkout_grace_sec for the active → stale → dead grace window.
ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS checkout_grace_sec integer NOT NULL DEFAULT 86400;

-- +goose Down

ALTER TABLE policies
    DROP COLUMN IF EXISTS checkout_grace_sec;

DROP INDEX IF EXISTS machines_license_status;
DROP INDEX IF EXISTS machines_lease_expires_alive;

ALTER TABLE machines
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS last_checkin_at,
    DROP COLUMN IF EXISTS lease_expires_at,
    DROP COLUMN IF EXISTS lease_issued_at,
    ADD COLUMN IF NOT EXISTS last_seen_at timestamptz;
