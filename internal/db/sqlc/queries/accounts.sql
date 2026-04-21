-- name: CreateAccount :exec
INSERT INTO accounts (id, name, slug, created_at)
VALUES ($1, $2, $3, $4);

-- name: GetAccountByID :one
SELECT id, name, slug, created_at
FROM accounts
WHERE id = $1;

-- name: GetAccountBySlug :one
SELECT id, name, slug, created_at
FROM accounts
WHERE slug = $1;
