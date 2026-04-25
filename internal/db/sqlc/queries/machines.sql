-- Column order below matches the shared sqlcgen.Machine struct in
-- models.go (id, account_id, license_id, fingerprint, hostname, metadata,
-- created_at, environment, lease_issued_at, lease_expires_at,
-- last_checkin_at, status). Matching order lets sqlc reuse the shared
-- Machine type for all :one/:many queries instead of emitting per-query
-- *Row structs.

-- name: GetMachineByID :one
SELECT id, account_id, license_id, fingerprint, hostname, metadata,
       created_at, environment, lease_issued_at, lease_expires_at,
       last_checkin_at, status
FROM machines WHERE id = $1;

-- name: GetMachineByFingerprint :one
SELECT id, account_id, license_id, fingerprint, hostname, metadata,
       created_at, environment, lease_issued_at, lease_expires_at,
       last_checkin_at, status
FROM machines WHERE license_id = $1 AND fingerprint = $2;

-- name: GetMachineByFingerprintForUpdate :one
SELECT id, account_id, license_id, fingerprint, hostname, metadata,
       created_at, environment, lease_issued_at, lease_expires_at,
       last_checkin_at, status
FROM machines WHERE license_id = $1 AND fingerprint = $2
FOR UPDATE;

-- name: CountAliveMachinesByLicense :one
SELECT COUNT(*) FROM machines WHERE license_id = $1 AND status <> 'dead';

-- name: InsertMachine :exec
INSERT INTO machines (
    id, account_id, license_id, fingerprint, hostname, metadata,
    created_at, environment, lease_issued_at, lease_expires_at,
    last_checkin_at, status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: UpdateMachineActivation :exec
-- Resurrect: overwrite hostname/metadata/lease, flip status to 'active'.
UPDATE machines SET
    hostname         = $2,
    metadata         = $3,
    lease_issued_at  = $4,
    lease_expires_at = $5,
    last_checkin_at  = $6,
    status           = 'active'
WHERE id = $1;

-- name: UpdateMachineLease :execrows
-- Renew existing row's lease (caller asserts not dead).
UPDATE machines SET
    lease_issued_at  = $2,
    lease_expires_at = $3,
    last_checkin_at  = $4,
    status           = 'active'
WHERE id = $1;

-- name: DeleteMachineByFingerprint :execrows
DELETE FROM machines WHERE license_id = $1 AND fingerprint = $2;

-- name: SearchMachines :many
-- Case-insensitive prefix match on fingerprint OR hostname. Named args
-- so the generated params struct has predictable field names.
SELECT id, account_id, license_id, fingerprint, hostname, metadata,
       created_at, environment, lease_issued_at, lease_expires_at,
       last_checkin_at, status
FROM machines
WHERE LOWER(fingerprint) LIKE LOWER(sqlc.arg('query')::text) || '%'
   OR LOWER(COALESCE(hostname, '')) LIKE LOWER(sqlc.arg('query')::text) || '%'
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_rows');

-- name: ListMachinesByLicense :many
-- Cursor-paginated machines under one license, optionally narrowed by
-- status (active|stale|dead). RLS scopes by account+env from the tx
-- context. Column list matches sqlcgen.Machine so sqlc reuses the
-- shared type for the row return.
SELECT id, account_id, license_id, fingerprint, hostname, metadata,
       created_at, environment, lease_issued_at, lease_expires_at,
       last_checkin_at, status
FROM machines
WHERE license_id = sqlc.arg('license_id')::uuid
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('cursor_ts')::timestamptz IS NULL
       OR (created_at, id) < (sqlc.narg('cursor_ts')::timestamptz, sqlc.narg('cursor_id')::uuid))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg('limit_plus_one');

-- name: MarkStaleMachines :execrows
-- Active machines past lease expiry with require_checkout=true become stale.
UPDATE machines m SET status = 'stale'
FROM licenses l JOIN policies p ON p.id = l.policy_id
WHERE m.license_id = l.id
  AND m.status = 'active'
  AND p.require_checkout = true
  AND m.lease_expires_at < NOW();

-- name: MarkDeadMachines :execrows
-- Stale machines past grace window become dead.
UPDATE machines m SET status = 'dead'
FROM licenses l JOIN policies p ON p.id = l.policy_id
WHERE m.license_id = l.id
  AND m.status = 'stale'
  AND p.require_checkout = true
  AND m.lease_expires_at + make_interval(secs => p.checkout_grace_sec) < NOW();
