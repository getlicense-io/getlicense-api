package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scanRefreshToken scans a refresh token row from a scannable (pgx.Row or pgx.Rows).
func scanRefreshToken(s scannable) (domain.RefreshToken, error) {
	var rt domain.RefreshToken
	var rawID, rawUserID, rawAccountID uuid.UUID
	err := s.Scan(&rawID, &rawUserID, &rawAccountID, &rt.TokenHash, &rt.ExpiresAt)
	if err != nil {
		return rt, err
	}
	rt.ID = rawID.String()
	rt.UserID = core.UserID(rawUserID)
	rt.AccountID = core.AccountID(rawAccountID)
	return rt, nil
}

// RefreshTokenRepo implements domain.RefreshTokenRepository using PostgreSQL.
type RefreshTokenRepo struct {
	pool *pgxpool.Pool
}

var _ domain.RefreshTokenRepository = (*RefreshTokenRepo)(nil)

// NewRefreshTokenRepo creates a new RefreshTokenRepo.
func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{pool: pool}
}

// Create inserts a new refresh token into the database.
// domain.RefreshToken.ID is a string containing a UUID value.
func (r *RefreshTokenRepo) Create(ctx context.Context, token *domain.RefreshToken) error {
	q := conn(ctx, r.pool)
	// Parse the string ID to uuid.UUID for storage.
	id, err := uuid.Parse(token.ID)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx,
		`INSERT INTO refresh_tokens (id, user_id, account_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, uuid.UUID(token.UserID), uuid.UUID(token.AccountID),
		token.TokenHash, token.ExpiresAt,
	)
	return err
}

// GetByHash returns the refresh token matching the given hash, or nil if not found.
func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	q := conn(ctx, r.pool)
	rt, err := scanRefreshToken(q.QueryRow(ctx,
		`SELECT id, user_id, account_id, token_hash, expires_at
		 FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &rt, nil
}

// DeleteByHash removes the refresh token with the given hash.
func (r *RefreshTokenRepo) DeleteByHash(ctx context.Context, tokenHash string) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteByUserID removes all refresh tokens for the given user.
func (r *RefreshTokenRepo) DeleteByUserID(ctx context.Context, userID core.UserID) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, uuid.UUID(userID))
	return err
}
