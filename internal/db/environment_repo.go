package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnvironmentRepo implements domain.EnvironmentRepository against
// sqlc-generated queries. Environments are account-scoped via RLS; all
// reads except GetBySlug rely on the tenant session variable being set.
type EnvironmentRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.EnvironmentRepository = (*EnvironmentRepo)(nil)

// NewEnvironmentRepo creates a new EnvironmentRepo.
func NewEnvironmentRepo(pool *pgxpool.Pool) *EnvironmentRepo {
	return &EnvironmentRepo{pool: pool, q: sqlcgen.New()}
}

// environmentFromRow translates a sqlcgen.Environment to the domain
// struct. Position is int32 in Postgres / sqlcgen; the domain exposes
// plain int, so we coerce at the seam.
func environmentFromRow(row sqlcgen.Environment) domain.Environment {
	return domain.Environment{
		ID:          idFromPgUUID[core.EnvironmentID](row.ID),
		AccountID:   idFromPgUUID[core.AccountID](row.AccountID),
		Slug:        core.Environment(row.Slug),
		Name:        row.Name,
		Description: row.Description,
		Icon:        row.Icon,
		Color:       row.Color,
		Position:    int(row.Position),
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

// Create inserts a new environment row. A UNIQUE violation on
// (account_id, slug) is translated to core.ErrEnvironmentAlreadyExists.
func (r *EnvironmentRepo) Create(ctx context.Context, env *domain.Environment) error {
	err := r.q.CreateEnvironment(ctx, conn(ctx, r.pool), sqlcgen.CreateEnvironmentParams{
		ID:          pgUUIDFromID(env.ID),
		AccountID:   pgUUIDFromID(env.AccountID),
		Slug:        string(env.Slug),
		Name:        env.Name,
		Description: env.Description,
		Icon:        env.Icon,
		Color:       env.Color,
		Position:    int32(env.Position),
		CreatedAt:   env.CreatedAt,
		UpdatedAt:   env.UpdatedAt,
	})
	if IsUniqueViolation(err, ConstraintEnvironmentSlugUnique) {
		return core.NewAppError(
			core.ErrEnvironmentAlreadyExists,
			"An environment with this slug already exists",
		)
	}
	return err
}

// ListByAccount returns all environments visible to the current RLS
// tenant, ordered by display name then slug so the UI can render them
// alphabetically without a client-side sort.
func (r *EnvironmentRepo) ListByAccount(ctx context.Context) ([]domain.Environment, error) {
	rows, err := r.q.ListEnvironmentsVisibleToCurrentTenant(ctx, conn(ctx, r.pool))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Environment, 0, len(rows))
	for _, row := range rows {
		out = append(out, environmentFromRow(row))
	}
	return out, nil
}

// GetBySlug returns the environment with the given slug visible to the
// current RLS tenant, or nil if not found.
func (r *EnvironmentRepo) GetBySlug(ctx context.Context, slug core.Environment) (*domain.Environment, error) {
	row, err := r.q.GetEnvironmentBySlug(ctx, conn(ctx, r.pool), string(slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	env := environmentFromRow(row)
	return &env, nil
}

// Delete removes the environment with the given id. Returns
// core.ErrEnvironmentNotFound when no row was affected (either the id
// does not exist or RLS filtered it out).
func (r *EnvironmentRepo) Delete(ctx context.Context, id core.EnvironmentID) error {
	n, err := r.q.DeleteEnvironment(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrEnvironmentNotFound, "Environment not found")
	}
	return nil
}

// CountByAccount returns the number of environments visible to the
// current RLS tenant. Used to enforce the per-account environment cap.
func (r *EnvironmentRepo) CountByAccount(ctx context.Context) (int, error) {
	n, err := r.q.CountEnvironmentsVisibleToCurrentTenant(ctx, conn(ctx, r.pool))
	return int(n), err
}
