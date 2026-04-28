-- name: CreateCustomer :exec
INSERT INTO customers (id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetCustomerByID :one
SELECT id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
FROM customers WHERE id = $1;

-- name: GetCustomerByIDWithCreator :one
-- Single-customer read with LEFT JOIN on the creator account so the
-- response can embed an AccountSummary (name + slug) for partner-sourced
-- customers without an N+1 lookup. Column order for the customer columns
-- matches sqlcgen.Customer; the appended creator_name / creator_slug
-- aliases force sqlc to emit a per-query row struct. The JOIN is LEFT
-- because created_by_account_id is nullable (vendor-created customers
-- have it NULL) — the creator_* columns are then nullable at the result
-- level, and the adapter gates embedding on CreatedByAccountID.
SELECT
    c.id, c.account_id, c.email, c.name, c.metadata,
    c.created_by_account_id, c.created_at, c.updated_at,
    creator.name AS creator_name,
    creator.slug AS creator_slug
FROM customers c
LEFT JOIN accounts creator ON creator.id = c.created_by_account_id
WHERE c.id = sqlc.arg('id')::uuid;

-- name: GetCustomerByEmail :one
-- The account_id filter is redundant under a WithTargetAccount tx
-- (RLS enforces the same) but kept for clarity and to allow callers
-- outside tenant context to query deterministically.
SELECT id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
FROM customers
WHERE account_id = sqlc.arg('account_id')
  AND lower(email) = lower(sqlc.arg('email')::text);

-- name: ListCustomers :many
-- All filters optional; sqlc.narg NULL-guard per field with explicit casts.
SELECT id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
FROM customers
WHERE account_id = sqlc.arg('account_id')
  AND (sqlc.narg('email_prefix')::text IS NULL
       OR lower(email) LIKE lower(sqlc.narg('email_prefix')::text) || '%')
  AND (sqlc.narg('name_prefix')::text IS NULL
       OR lower(COALESCE(name, '')) LIKE lower(sqlc.narg('name_prefix')::text) || '%')
  AND (sqlc.narg('created_by')::uuid IS NULL
       OR created_by_account_id = sqlc.narg('created_by')::uuid)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: ListCustomersWithCreator :many
-- JOIN variant of ListCustomers for list endpoints that need to surface
-- partner attribution in a single round trip. Column order for the
-- customer columns matches sqlcgen.Customer; the trailing creator_name /
-- creator_slug aliases force sqlc to emit a per-query row struct. LEFT
-- JOIN keeps vendor-created customers (NULL created_by_account_id) in
-- the result set — the adapter gates embedding on CreatedByAccountID.
SELECT
    c.id, c.account_id, c.email, c.name, c.metadata,
    c.created_by_account_id, c.created_at, c.updated_at,
    creator.name AS creator_name,
    creator.slug AS creator_slug
FROM customers c
LEFT JOIN accounts creator ON creator.id = c.created_by_account_id
WHERE c.account_id = sqlc.arg('account_id')
  AND (sqlc.narg('email_prefix')::text IS NULL
       OR lower(c.email) LIKE lower(sqlc.narg('email_prefix')::text) || '%')
  AND (sqlc.narg('name_prefix')::text IS NULL
       OR lower(COALESCE(c.name, '')) LIKE lower(sqlc.narg('name_prefix')::text) || '%')
  AND (sqlc.narg('created_by')::uuid IS NULL
       OR c.created_by_account_id = sqlc.narg('created_by')::uuid)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (c.created_at, c.id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY c.created_at DESC, c.id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateCustomer :one
UPDATE customers SET name = $2, metadata = $3, updated_at = NOW()
WHERE id = $1
RETURNING id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at;

-- name: DeleteCustomer :execrows
DELETE FROM customers WHERE id = $1;

-- name: CountLicensesReferencingCustomer :one
SELECT COUNT(*) FROM licenses WHERE customer_id = $1;

-- name: CountCustomers :one
-- Returns the total customer count for the current tenant.
-- RLS scopes by account; customers are environment-agnostic.
SELECT COUNT(*) FROM customers;

-- name: UpsertCustomerByEmail :one
-- INSERT with ON CONFLICT DO NOTHING RETURNING. Empty RETURNING set
-- (i.e. ErrNoRows) means a concurrent insert won and the caller must
-- re-fetch via GetCustomerByEmail.
INSERT INTO customers (id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (account_id, lower(email)) DO NOTHING
RETURNING id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at;
