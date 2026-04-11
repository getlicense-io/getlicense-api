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

// UserRepo implements domain.UserRepository using PostgreSQL.
type UserRepo struct {
	pool *pgxpool.Pool
}

var _ domain.UserRepository = (*UserRepo)(nil)

// NewUserRepo creates a new UserRepo.
func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

// Create inserts a new user into the database.
func (r *UserRepo) Create(ctx context.Context, user *domain.User) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO users (id, account_id, email, password_hash, role, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.UUID(user.ID), uuid.UUID(user.AccountID), user.Email,
		user.PasswordHash, string(user.Role), user.CreatedAt,
	)
	return err
}

// GetByID returns the user with the given ID, or nil if not found.
func (r *UserRepo) GetByID(ctx context.Context, id core.UserID) (*domain.User, error) {
	q := conn(ctx, r.pool)
	var rawID, rawAccountID uuid.UUID
	var u domain.User
	var role string
	err := q.QueryRow(ctx,
		`SELECT id, account_id, email, password_hash, role, created_at FROM users WHERE id = $1`,
		uuid.UUID(id),
	).Scan(&rawID, &rawAccountID, &u.Email, &u.PasswordHash, &role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.ID = core.UserID(rawID)
	u.AccountID = core.AccountID(rawAccountID)
	u.Role = core.UserRole(role)
	return &u, nil
}

// GetByEmail returns the user with the given email, or nil if not found.
// This is a global query used for login (bypasses tenant scope).
func (r *UserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	q := conn(ctx, r.pool)
	var rawID, rawAccountID uuid.UUID
	var u domain.User
	var role string
	err := q.QueryRow(ctx,
		`SELECT id, account_id, email, password_hash, role, created_at FROM users WHERE email = $1`,
		email,
	).Scan(&rawID, &rawAccountID, &u.Email, &u.PasswordHash, &role, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	u.ID = core.UserID(rawID)
	u.AccountID = core.AccountID(rawAccountID)
	u.Role = core.UserRole(role)
	return &u, nil
}
