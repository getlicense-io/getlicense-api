-- +goose Up
-- Force RLS on all tenant-scoped tables so policies apply even when
-- connected as the table owner (e.g. in development/e2e).
-- Without this, the owner user bypasses all RLS policies.
-- Note: roles and account_memberships get FORCE RLS in migration 016
-- (after their CREATE TABLE statements).
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE products FORCE ROW LEVEL SECURITY;
ALTER TABLE licenses FORCE ROW LEVEL SECURITY;
ALTER TABLE machines FORCE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE webhook_events FORCE ROW LEVEL SECURITY;

-- +goose Down
ALTER TABLE webhook_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE webhook_endpoints NO FORCE ROW LEVEL SECURITY;
ALTER TABLE machines NO FORCE ROW LEVEL SECURITY;
ALTER TABLE licenses NO FORCE ROW LEVEL SECURITY;
ALTER TABLE products NO FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys NO FORCE ROW LEVEL SECURITY;
