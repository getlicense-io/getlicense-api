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
	var rawID, rawUserID, rawAccountID uuid.UUID
	var t domain.RefreshToken
	err := q.QueryRow(ctx,
		`SELECT id, user_id, account_id, token_hash, expires_at
		 FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&rawID, &rawUserID, &rawAccountID, &t.TokenHash, &t.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.ID = rawID.String()
	t.UserID = core.UserID(rawUserID)
	t.AccountID = core.AccountID(rawAccountID)
	return &t, nil
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
