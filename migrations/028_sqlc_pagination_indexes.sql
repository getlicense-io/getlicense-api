-- +goose Up

-- Additional composite indexes for paginated list endpoints introduced
-- or confirmed during the sqlc rewrite audit. Every paginated sqlc query
-- sorts by (created_at DESC, id DESC) with a keyset predicate
-- (created_at, id) < (cursor_ts, cursor_id). Without a composite
-- prefixed by the scoping column, Postgres falls back to an index on
-- the scoping column + in-memory sort, which degrades past the first
-- page as row counts grow.
--
-- Migration 015 covered the earliest paginated tables (licenses,
-- api_keys, products, webhook_endpoints). Migrations 016, 017, 019
-- added composites for memberships, invitations, and grants. This
-- migration fills the gaps for the tables added later:
--
--   - customers       -> ListCustomers (account + filter + cursor)
--   - policies        -> ListPoliciesByProduct
--   - entitlements    -> ListEntitlements (account + filter + cursor)
--   - webhook_events  -> ListWebhookEventsByEndpoint
--   - domain_events   -> ListDomainEvents (account via RLS + filter + cursor)
--
-- Additive only; no existing index is modified or dropped.

CREATE INDEX IF NOT EXISTS idx_customers_account_created
    ON customers (account_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_policies_product_created
    ON policies (product_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_entitlements_account_created
    ON entitlements (account_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_webhook_events_endpoint_created
    ON webhook_events (endpoint_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_domain_events_account_created
    ON domain_events (account_id, created_at DESC, id DESC);

-- +goose Down

DROP INDEX IF EXISTS idx_customers_account_created;
DROP INDEX IF EXISTS idx_policies_product_created;
DROP INDEX IF EXISTS idx_entitlements_account_created;
DROP INDEX IF EXISTS idx_webhook_events_endpoint_created;
DROP INDEX IF EXISTS idx_domain_events_account_created;
