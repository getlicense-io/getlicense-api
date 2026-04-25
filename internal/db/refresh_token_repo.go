package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshTokenRepo implements domain.RefreshTokenRepository. Refresh
// tokens are global and not tenant-scoped — they identify an identity,
// and the acting account is chosen at switch time.
type RefreshTokenRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.RefreshTokenRepository = (*RefreshTokenRepo)(nil)

// NewRefreshTokenRepo creates a new RefreshTokenRepo.
func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{pool: pool, q: sqlcgen.New()}
}

// refreshTokenFromRow translates a sqlcgen.RefreshToken to the domain struct.
// The domain ID is string-typed (opaque to callers); the DB stores UUID —
// we stringify here. CreatedAt is on the row but not on the domain struct;
// ignore it.
func refreshTokenFromRow(row sqlcgen.RefreshToken) domain.RefreshToken {
	return domain.RefreshToken{
		ID:         uuid.UUID(row.ID.Bytes).String(),
		IdentityID: idFromPgUUID[core.IdentityID](row.IdentityID),
		TokenHash:  row.TokenHash,
		ExpiresAt:  row.ExpiresAt,
	}
}

// Create inserts a new refresh token. token.ID is a string holding a UUID;
// parse it before writing so the column type matches. A token_hash unique
// collision is a catastrophic crypto event (HMAC collision on a random
// input) — pass the raw error through rather than classifying a typed
// error; we do not want to leak "collision" as a user-facing message.
func (r *RefreshTokenRepo) Create(ctx context.Context, token *domain.RefreshToken) error {
	id, err := uuid.Parse(token.ID)
	if err != nil {
		return err
	}
	return r.q.CreateRefreshToken(ctx, conn(ctx, r.pool), sqlcgen.CreateRefreshTokenParams{
		ID:         pgtype.UUID{Bytes: id, Valid: true},
		IdentityID: pgUUIDFromID(token.IdentityID),
		TokenHash:  token.TokenHash,
		ExpiresAt:  token.ExpiresAt,
	})
}

// GetByHash returns the refresh token with the given hash, or nil if not found.
func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	row, err := r.q.GetRefreshTokenByHash(ctx, conn(ctx, r.pool), tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rt := refreshTokenFromRow(row)
	return &rt, nil
}

// DeleteByHash removes a single refresh token by its hash. A missing row is
// not an error — callers (logout, refresh-rotate) treat "no-op" and "deleted"
// the same.
func (r *RefreshTokenRepo) DeleteByHash(ctx context.Context, tokenHash string) error {
	return r.q.DeleteRefreshTokenByHash(ctx, conn(ctx, r.pool), tokenHash)
}

// DeleteByIdentityID removes every refresh token for an identity (global logout).
func (r *RefreshTokenRepo) DeleteByIdentityID(ctx context.Context, identityID core.IdentityID) error {
	return r.q.DeleteRefreshTokensByIdentity(ctx, conn(ctx, r.pool), pgUUIDFromID(identityID))
}

// Consume implements domain.RefreshTokenRepository.Consume. Atomic
// DELETE + RETURNING — see the sqlc query header for race rationale.
// Returns (zero ID, nil) when the token was already consumed, expired,
// or never existed.
func (r *RefreshTokenRepo) Consume(ctx context.Context, tokenHash string) (core.IdentityID, error) {
	rawID, err := r.q.ConsumeRefreshToken(ctx, conn(ctx, r.pool), tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.IdentityID{}, nil
	}
	if err != nil {
		return core.IdentityID{}, err
	}
	return idFromPgUUID[core.IdentityID](rawID), nil
}
