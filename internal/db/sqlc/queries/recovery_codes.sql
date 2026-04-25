-- name: InsertRecoveryCodes :exec
-- Bulk insert per-identity. Row count is bounded (10 codes per
-- ActivateTOTP) so VALUES + UNNEST with a single text[] param is
-- the cheapest shape. ON CONFLICT DO NOTHING makes the insert
-- idempotent: if a previous lazy-migration run inserted the
-- "remaining" rows but crashed before clearing the legacy blob,
-- the next attempt re-inserts the same set without choking on the
-- (identity_id, code_hash) UNIQUE constraint.
INSERT INTO recovery_codes (identity_id, code_hash)
SELECT sqlc.arg('identity_id')::uuid, unnest(sqlc.arg('code_hashes')::text[])
ON CONFLICT (identity_id, code_hash) DO NOTHING;

-- name: ConsumeRecoveryCode :one
-- Atomic single-use. DELETE-RETURNING means concurrent calls for
-- the same code produce ONE winner and N-1 ErrNoRows misses.
-- used_at predicate is belt-and-suspenders (rows are deleted on
-- use, but the nullable column lets us flip to soft-delete later
-- without touching this query's contract).
DELETE FROM recovery_codes
WHERE identity_id = $1 AND code_hash = $2 AND used_at IS NULL
RETURNING id;

-- name: DeleteRecoveryCodesByIdentity :exec
-- Used by DisableTOTP to clear all recovery rows for an identity.
DELETE FROM recovery_codes WHERE identity_id = $1;

-- name: CountRecoveryCodesByIdentity :one
-- Used by tests + lazy-migration housekeeping. Production lookup
-- paths never need a count; ConsumeRecoveryCode does its own miss
-- detection via ErrNoRows.
SELECT COUNT(*) FROM recovery_codes WHERE identity_id = $1;
