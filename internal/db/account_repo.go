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

// AccountRepo implements domain.AccountRepository using PostgreSQL.
type AccountRepo struct {
	pool *pgxpool.Pool
}

var _ domain.AccountRepository = (*AccountRepo)(nil)

// NewAccountRepo creates a new AccountRepo.
func NewAccountRepo(pool *pgxpool.Pool) *AccountRepo {
	return &AccountRepo{pool: pool}
}

// Create inserts a new account into the database.
func (r *AccountRepo) Create(ctx context.Context, account *domain.Account) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO accounts (id, name, slug, created_at) VALUES ($1, $2, $3, $4)`,
		uuid.UUID(account.ID), account.Name, account.Slug, account.CreatedAt,
	)
	return err
}

// GetByID returns the account with the given ID, or nil if not found.
func (r *AccountRepo) GetByID(ctx context.Context, id core.AccountID) (*domain.Account, error) {
	q := conn(ctx, r.pool)
	var rawID uuid.UUID
	var a domain.Account
	err := q.QueryRow(ctx,
		`SELECT id, name, slug, created_at FROM accounts WHERE id = $1`,
		uuid.UUID(id),
	).Scan(&rawID, &a.Name, &a.Slug, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	a.ID = core.AccountID(rawID)
	return &a, nil
}

// GetBySlug returns the account with the given slug, or nil if not found.
func (r *AccountRepo) GetBySlug(ctx context.Context, slug string) (*domain.Account, error) {
	q := conn(ctx, r.pool)
	var rawID uuid.UUID
	var a domain.Account
	err := q.QueryRow(ctx,
		`SELECT id, name, slug, created_at FROM accounts WHERE slug = $1`,
		slug,
	).Scan(&rawID, &a.Name, &a.Slug, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	a.ID = core.AccountID(rawID)
	return &a, nil
}
