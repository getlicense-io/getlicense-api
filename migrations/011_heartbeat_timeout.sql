-- +goose Up
ALTER TABLE products ADD COLUMN heartbeat_timeout INTEGER;

-- +goose Down
ALTER TABLE products DROP COLUMN IF EXISTS heartbeat_timeout;
