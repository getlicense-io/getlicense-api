-- +goose Up

CREATE INDEX IF NOT EXISTS idx_licenses_env_status
    ON licenses (account_id, environment, status);

CREATE INDEX IF NOT EXISTS idx_machines_env_status
    ON machines (account_id, environment, status);

-- +goose Down

DROP INDEX IF EXISTS idx_machines_env_status;
DROP INDEX IF EXISTS idx_licenses_env_status;
