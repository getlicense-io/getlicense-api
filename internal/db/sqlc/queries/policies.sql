-- name: CreatePolicy :exec
INSERT INTO policies (
    id, account_id, product_id, name, is_default,
    duration_seconds, expiration_strategy, expiration_basis,
    max_machines, max_seats, floating, strict,
    require_checkout, checkout_interval_sec, max_checkout_duration_sec,
    component_matching_strategy, metadata, created_at, updated_at,
    checkout_grace_sec, validation_ttl_sec
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    $9, $10, $11, $12,
    $13, $14, $15,
    $16, $17, $18, $19,
    $20, $21
);

-- name: GetPolicyByID :one
SELECT id, account_id, product_id, name, is_default,
       duration_seconds, expiration_strategy, expiration_basis,
       max_machines, max_seats, floating, strict,
       require_checkout, checkout_interval_sec, max_checkout_duration_sec,
       component_matching_strategy, metadata, created_at, updated_at,
       checkout_grace_sec, validation_ttl_sec
FROM policies WHERE id = $1;

-- name: ListPoliciesByProduct :many
SELECT id, account_id, product_id, name, is_default,
       duration_seconds, expiration_strategy, expiration_basis,
       max_machines, max_seats, floating, strict,
       require_checkout, checkout_interval_sec, max_checkout_duration_sec,
       component_matching_strategy, metadata, created_at, updated_at,
       checkout_grace_sec, validation_ttl_sec
FROM policies
WHERE product_id = sqlc.arg('product_id')
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: GetDefaultPolicyForProduct :one
SELECT id, account_id, product_id, name, is_default,
       duration_seconds, expiration_strategy, expiration_basis,
       max_machines, max_seats, floating, strict,
       require_checkout, checkout_interval_sec, max_checkout_duration_sec,
       component_matching_strategy, metadata, created_at, updated_at,
       checkout_grace_sec, validation_ttl_sec
FROM policies WHERE product_id = $1 AND is_default = true;

-- name: UpdatePolicy :one
UPDATE policies SET
    name = $2,
    duration_seconds = $3, expiration_strategy = $4, expiration_basis = $5,
    max_machines = $6, max_seats = $7, floating = $8, strict = $9,
    require_checkout = $10, checkout_interval_sec = $11,
    max_checkout_duration_sec = $12, checkout_grace_sec = $13,
    component_matching_strategy = $14, metadata = $15,
    validation_ttl_sec = $16,
    updated_at = NOW()
WHERE id = $1
RETURNING id, account_id, product_id, name, is_default,
          duration_seconds, expiration_strategy, expiration_basis,
          max_machines, max_seats, floating, strict,
          require_checkout, checkout_interval_sec, max_checkout_duration_sec,
          component_matching_strategy, metadata, created_at, updated_at,
          checkout_grace_sec, validation_ttl_sec;

-- name: DeletePolicy :execrows
DELETE FROM policies WHERE id = $1;

-- name: ClearDefaultPolicyForProduct :exec
UPDATE policies SET is_default = false, updated_at = NOW()
WHERE product_id = $1 AND is_default = true;

-- name: SetDefaultPolicy :execrows
UPDATE policies SET is_default = true, updated_at = NOW()
WHERE id = $1 AND product_id = $2;

-- name: ReassignLicensesFromPolicy :execrows
-- Named args avoid sqlc's PolicyID / PolicyID_2 naming for two refs to the
-- same column; adapter call sites stay self-documenting.
UPDATE licenses SET policy_id = sqlc.arg('to_policy_id'), updated_at = NOW()
WHERE policy_id = sqlc.arg('from_policy_id');

-- name: CountLicensesReferencingPolicy :one
SELECT COUNT(*) FROM licenses WHERE policy_id = $1;
