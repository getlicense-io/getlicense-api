-- name: CreateCustomer :exec
INSERT INTO customers (id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetCustomerByID :one
SELECT id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
FROM customers WHERE id = $1;

-- name: GetCustomerByEmail :one
-- The account_id filter is redundant under a WithTargetAccount tx
-- (RLS enforces the same) but kept for clarity and to allow callers
-- outside tenant context to query deterministically.
SELECT id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
FROM customers
WHERE account_id = $1 AND lower(email) = lower($2);

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

-- name: UpdateCustomer :one
UPDATE customers SET name = $2, metadata = $3, updated_at = NOW()
WHERE id = $1
RETURNING id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at;

-- name: DeleteCustomer :execrows
DELETE FROM customers WHERE id = $1;

-- name: CountLicensesReferencingCustomer :one
SELECT COUNT(*) FROM licenses WHERE customer_id = $1;

-- name: UpsertCustomerByEmail :one
-- INSERT with ON CONFLICT DO NOTHING RETURNING. Empty RETURNING set
-- (i.e. ErrNoRows) means a concurrent insert won and the caller must
-- re-fetch via GetCustomerByEmail.
INSERT INTO customers (id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (account_id, lower(email)) DO NOTHING
RETURNING id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at;
