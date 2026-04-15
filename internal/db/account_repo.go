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

// scanAccount scans an account row from a scannable (pgx.Row or pgx.Rows).
func scanAccount(s scannable) (domain.Account, error) {
	var a domain.Account
	var rawID uuid.UUID
	err := s.Scan(&rawID, &a.Name, &a.Slug, &a.CreatedAt)
	if err != nil {
		return a, err
	}
	a.ID = core.AccountID(rawID)
	return a, nil
}

const accountColumns = `id, name, slug, created_at`

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
		`INSERT INTO accounts (`+accountColumns+`) VALUES ($1, $2, $3, $4)`,
		uuid.UUID(account.ID), account.Name, account.Slug, account.CreatedAt,
	)
	if err != nil {
		if IsUniqueViolation(err, "accounts_slug_key") {
			return core.NewAppError(core.ErrAccountAlreadyExists, "An account with that name already exists")
		}
		return err
	}
	return nil
}

// GetByID returns the account with the given ID, or nil if not found.
func (r *AccountRepo) GetByID(ctx context.Context, id core.AccountID) (*domain.Account, error) {
	q := conn(ctx, r.pool)
	a, err := scanAccount(q.QueryRow(ctx,
		`SELECT `+accountColumns+` FROM accounts WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// GetBySlug returns the account with the given slug, or nil if not found.
func (r *AccountRepo) GetBySlug(ctx context.Context, slug string) (*domain.Account, error) {
	q := conn(ctx, r.pool)
	a, err := scanAccount(q.QueryRow(ctx,
		`SELECT `+accountColumns+` FROM accounts WHERE slug = $1`,
		slug,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}
