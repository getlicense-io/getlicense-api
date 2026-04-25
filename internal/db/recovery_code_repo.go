package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// RecoveryCodeRepo implements domain.RecoveryCodeRepository. Recovery
// codes are global (no RLS) — they hang off identities, which are
// also global. All methods run without tenant context.
type RecoveryCodeRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.RecoveryCodeRepository = (*RecoveryCodeRepo)(nil)

// NewRecoveryCodeRepo creates a new RecoveryCodeRepo.
func NewRecoveryCodeRepo(pool *pgxpool.Pool) *RecoveryCodeRepo {
	return &RecoveryCodeRepo{pool: pool, q: sqlcgen.New()}
}

// Insert writes a batch of code hashes for an identity. The empty-
// slice short-circuit avoids a round-trip when the legacy fallback
// finds nothing remaining to migrate. ON CONFLICT DO NOTHING in the
// underlying query absorbs idempotent re-runs from a crashed
// migration attempt.
func (r *RecoveryCodeRepo) Insert(ctx context.Context, identityID core.IdentityID, codeHashes []string) error {
	if len(codeHashes) == 0 {
		return nil
	}
	return r.q.InsertRecoveryCodes(ctx, conn(ctx, r.pool),
		sqlcgen.InsertRecoveryCodesParams{
			IdentityID: pgUUIDFromID(identityID),
			CodeHashes: codeHashes,
		})
}

// Consume implements the atomic single-use semantics that motivated
// PR-4.5. The DELETE ... RETURNING contract guarantees concurrent
// calls for the same (identity_id, code_hash) tuple produce exactly
// one (true, nil) and N-1 (false, nil) — see
// recovery_codes.sql:ConsumeRecoveryCode for the SQL.
func (r *RecoveryCodeRepo) Consume(ctx context.Context, identityID core.IdentityID, codeHash string) (bool, error) {
	_, err := r.q.ConsumeRecoveryCode(ctx, conn(ctx, r.pool),
		sqlcgen.ConsumeRecoveryCodeParams{
			IdentityID: pgUUIDFromID(identityID),
			CodeHash:   codeHash,
		})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// DeleteAll removes every recovery code row for an identity.
func (r *RecoveryCodeRepo) DeleteAll(ctx context.Context, identityID core.IdentityID) error {
	return r.q.DeleteRecoveryCodesByIdentity(ctx, conn(ctx, r.pool), pgUUIDFromID(identityID))
}

// Count returns the row count for the identity. Returned as int for
// the caller's convenience; the underlying SQL returns int64 but the
// value is bounded by the recovery-code generation step (10).
func (r *RecoveryCodeRepo) Count(ctx context.Context, identityID core.IdentityID) (int, error) {
	n, err := r.q.CountRecoveryCodesByIdentity(ctx, conn(ctx, r.pool), pgUUIDFromID(identityID))
	return int(n), err
}
