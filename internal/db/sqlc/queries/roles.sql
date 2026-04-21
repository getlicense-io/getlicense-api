-- name: GetRoleByID :one
SELECT id, account_id, slug, name, permissions, created_at, updated_at
FROM roles WHERE id = $1;

-- name: GetPresetRoleBySlug :one
SELECT id, account_id, slug, name, permissions, created_at, updated_at
FROM roles WHERE account_id IS NULL AND slug = $1;

-- name: GetTenantRoleBySlug :one
SELECT id, account_id, slug, name, permissions, created_at, updated_at
FROM roles WHERE account_id = $1 AND slug = $2;

-- name: ListPresetRoles :many
SELECT id, account_id, slug, name, permissions, created_at, updated_at
FROM roles WHERE account_id IS NULL
ORDER BY slug ASC;

-- name: ListRolesVisibleToCurrentTenant :many
-- Returns presets + tenant custom roles via RLS. The roles_tenant_read
-- policy filters rows; we just ORDER.
SELECT id, account_id, slug, name, permissions, created_at, updated_at
FROM roles
ORDER BY account_id NULLS FIRST, slug ASC;
