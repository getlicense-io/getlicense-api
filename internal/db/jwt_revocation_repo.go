package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// JWTRevocationRepo implements domain.JWTRevocationRepository against
// the revoked_jtis and identity_session_invalidations tables (migration
// 035). Both tables are NOT RLS-scoped — they are checked on every JWT
// verify BEFORE any tenant context is established. Reads/writes go
// straight through the connection pool without WithTargetAccount /
// WithSystemContext wrapping.
type JWTRevocationRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.JWTRevocationRepository = (*JWTRevocationRepo)(nil)

// NewJWTRevocationRepo creates a new JWTRevocationRepo.
func NewJWTRevocationRepo(pool *pgxpool.Pool) *JWTRevocationRepo {
	return &JWTRevocationRepo{pool: pool, q: sqlcgen.New()}
}

// RevokeJTI marks a single jti revoked. Idempotent via ON CONFLICT —
// concurrent logouts of the same JWT collapse to a single row.
func (r *JWTRevocationRepo) RevokeJTI(
	ctx context.Context,
	jti core.JTI,
	identityID core.IdentityID,
	expiresAt time.Time,
	reason string,
) error {
	if reason == "" {
		reason = "logout"
	}
	return r.q.InsertRevokedJTI(ctx, conn(ctx, r.pool), sqlcgen.InsertRevokedJTIParams{
		Jti:        pgUUIDFromID(jti),
		IdentityID: pgUUIDFromID(identityID),
		ExpiresAt:  expiresAt,
		Reason:     reason,
	})
}

// IsJTIRevoked returns true when the jti is present in the revocation
// table AND its expires_at is still in the future.
func (r *JWTRevocationRepo) IsJTIRevoked(ctx context.Context, jti core.JTI) (bool, error) {
	return r.q.IsJTIRevoked(ctx, conn(ctx, r.pool), pgUUIDFromID(jti))
}

// SweepExpired deletes all revoked_jtis rows past their expires_at
// (the JWT is dead anyway — the revocation row is dead weight).
// Returns the count of rows deleted for telemetry.
func (r *JWTRevocationRepo) SweepExpired(ctx context.Context) (int, error) {
	n, err := r.q.SweepExpiredRevokedJTIs(ctx, conn(ctx, r.pool))
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// SetSessionInvalidation upserts the per-identity session-invalidation
// cutoff. The verifier rejects tokens with iat < minIAT.
func (r *JWTRevocationRepo) SetSessionInvalidation(
	ctx context.Context,
	identityID core.IdentityID,
	minIAT time.Time,
) error {
	return r.q.SetIdentitySessionInvalidation(ctx, conn(ctx, r.pool), sqlcgen.SetIdentitySessionInvalidationParams{
		IdentityID: pgUUIDFromID(identityID),
		MinIat:     minIAT,
	})
}

// GetSessionMinIAT returns the per-identity session cutoff, or nil
// when no row exists for the identity. The middleware treats nil as
// "no bulk invalidation has ever been issued" and bypasses the iat
// check entirely (saves one comparison per request when the feature
// is unused).
func (r *JWTRevocationRepo) GetSessionMinIAT(ctx context.Context, identityID core.IdentityID) (*time.Time, error) {
	row, err := r.q.GetIdentitySessionMinIAT(ctx, conn(ctx, r.pool), pgUUIDFromID(identityID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}
