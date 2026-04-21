-- name: CreateProduct :exec
INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc, metadata, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetProductByID :one
SELECT id, account_id, name, slug, public_key, private_key_enc, metadata, created_at
FROM products WHERE id = $1;

-- name: ListProducts :many
SELECT id, account_id, name, slug, public_key, private_key_enc, metadata, created_at
FROM products
WHERE (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: UpdateProduct :one
-- COALESCE preserves the existing column when the sparse param is NULL.
-- Explicit ::text and ::jsonb casts required so Postgres can pick the right
-- COALESCE branch when both narg args are NULL.
UPDATE products SET
    name     = COALESCE(sqlc.narg('name')::text,      name),
    metadata = COALESCE(sqlc.narg('metadata')::jsonb, metadata)
WHERE id = sqlc.arg('id')
RETURNING id, account_id, name, slug, public_key, private_key_enc, metadata, created_at;

-- name: DeleteProduct :execrows
DELETE FROM products WHERE id = $1;

-- name: SearchProducts :many
-- Case-insensitive prefix match on name OR slug. Explicit sqlc.arg names so
-- the generated params struct has predictable field names.
SELECT id, account_id, name, slug, public_key, private_key_enc, metadata, created_at
FROM products
WHERE LOWER(name) LIKE LOWER(sqlc.arg('query')::text) || '%'
   OR LOWER(slug) LIKE LOWER(sqlc.arg('query')::text) || '%'
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_rows');
