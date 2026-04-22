-- name: CreateEnvironment :exec
INSERT INTO environments (id, account_id, slug, name, description, icon, color, position, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: ListEnvironmentsVisibleToCurrentTenant :many
SELECT id, account_id, slug, name, description, icon, color, position, created_at, updated_at
FROM environments
ORDER BY LOWER(name) ASC, slug ASC;

-- name: GetEnvironmentBySlug :one
SELECT id, account_id, slug, name, description, icon, color, position, created_at, updated_at
FROM environments WHERE slug = $1;

-- name: DeleteEnvironment :execrows
DELETE FROM environments WHERE id = $1;

-- name: CountEnvironmentsVisibleToCurrentTenant :one
SELECT COUNT(*) FROM environments;
