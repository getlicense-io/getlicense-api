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

// scanEnvironment scans an environment row from a scannable.
func scanEnvironment(s scannable) (domain.Environment, error) {
	var e domain.Environment
	var rawID, rawAccountID uuid.UUID
	var slug string
	err := s.Scan(
		&rawID, &rawAccountID, &slug, &e.Name, &e.Description,
		&e.Icon, &e.Color, &e.Position, &e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return e, err
	}
	e.ID = core.EnvironmentID(rawID)
	e.AccountID = core.AccountID(rawAccountID)
	e.Slug = core.Environment(slug)
	return e, nil
}

const environmentColumns = `id, account_id, slug, name, description, icon, color, position, created_at, updated_at`

// EnvironmentRepo implements domain.EnvironmentRepository using PostgreSQL.
type EnvironmentRepo struct {
	pool *pgxpool.Pool
}

var _ domain.EnvironmentRepository = (*EnvironmentRepo)(nil)

// NewEnvironmentRepo creates a new EnvironmentRepo.
func NewEnvironmentRepo(pool *pgxpool.Pool) *EnvironmentRepo {
	return &EnvironmentRepo{pool: pool}
}

// Create inserts a new environment. The caller must be inside a tenant
// transaction — RLS will reject inserts where `account_id` does not
// match `app.current_account_id`.
func (r *EnvironmentRepo) Create(ctx context.Context, env *domain.Environment) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO environments (`+environmentColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		uuid.UUID(env.ID), uuid.UUID(env.AccountID), string(env.Slug),
		env.Name, env.Description, env.Icon, env.Color, env.Position,
		env.CreatedAt, env.UpdatedAt,
	)
	return err
}

// ListByAccount returns all environments for the current tenant,
// ordered by position then created_at.
func (r *EnvironmentRepo) ListByAccount(ctx context.Context) ([]domain.Environment, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT `+environmentColumns+` FROM environments
		 ORDER BY position ASC, created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	envs := make([]domain.Environment, 0, 2)
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		envs = append(envs, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return envs, nil
}

// GetBySlug returns the environment for the current tenant account
// with the given slug, or nil if not found.
func (r *EnvironmentRepo) GetBySlug(ctx context.Context, slug core.Environment) (*domain.Environment, error) {
	q := conn(ctx, r.pool)
	e, err := scanEnvironment(q.QueryRow(ctx,
		`SELECT `+environmentColumns+` FROM environments WHERE slug = $1`,
		string(slug),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &e, nil
}

// Delete removes an environment by ID. The service layer is
// responsible for preventing deletion of the last environment and
// for blocking deletes while tenant-scoped rows still reference the
// slug.
func (r *EnvironmentRepo) Delete(ctx context.Context, id core.EnvironmentID) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx, `DELETE FROM environments WHERE id = $1`, uuid.UUID(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrEnvironmentNotFound, "Environment not found")
	}
	return nil
}

// CountByAccount returns the number of environments for the current
// tenant account. Used to enforce the max-environments-per-account
// limit in the service layer.
func (r *EnvironmentRepo) CountByAccount(ctx context.Context) (int, error) {
	q := conn(ctx, r.pool)
	var count int
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM environments`).Scan(&count)
	return count, err
}
