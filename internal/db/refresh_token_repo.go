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

func scanRefreshToken(s scannable) (domain.RefreshToken, error) {
	var rt domain.RefreshToken
	var rawID, rawIdentityID uuid.UUID
	err := s.Scan(&rawID, &rawIdentityID, &rt.TokenHash, &rt.ExpiresAt)
	if err != nil {
		return rt, err
	}
	rt.ID = rawID.String()
	rt.IdentityID = core.IdentityID(rawIdentityID)
	return rt, nil
}

// RefreshTokenRepo implements domain.RefreshTokenRepository. Refresh
// tokens are global and not tenant-scoped — they identify an identity,
// and the acting account is chosen at switch time.
type RefreshTokenRepo struct {
	pool *pgxpool.Pool
}

var _ domain.RefreshTokenRepository = (*RefreshTokenRepo)(nil)

func NewRefreshTokenRepo(pool *pgxpool.Pool) *RefreshTokenRepo {
	return &RefreshTokenRepo{pool: pool}
}

func (r *RefreshTokenRepo) Create(ctx context.Context, token *domain.RefreshToken) error {
	q := conn(ctx, r.pool)
	id, err := uuid.Parse(token.ID)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx,
		`INSERT INTO refresh_tokens (id, identity_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		id, uuid.UUID(token.IdentityID), token.TokenHash, token.ExpiresAt,
	)
	return err
}

func (r *RefreshTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	q := conn(ctx, r.pool)
	rt, err := scanRefreshToken(q.QueryRow(ctx,
		`SELECT id, identity_id, token_hash, expires_at
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

func (r *RefreshTokenRepo) DeleteByHash(ctx context.Context, tokenHash string) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, tokenHash)
	return err
}

func (r *RefreshTokenRepo) DeleteByIdentityID(ctx context.Context, identityID core.IdentityID) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM refresh_tokens WHERE identity_id = $1`, uuid.UUID(identityID))
	return err
}
