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

// RoleRepo implements domain.RoleRepository. Preset rows (account_id NULL)
// are exposed by RLS to every tenant; custom rows are tenant-scoped.
type RoleRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.RoleRepository = (*RoleRepo)(nil)

// NewRoleRepo creates a new RoleRepo.
func NewRoleRepo(pool *pgxpool.Pool) *RoleRepo {
	return &RoleRepo{pool: pool, q: sqlcgen.New()}
}

// roleFromRow translates a sqlcgen.Role to the domain struct. No fallible
// decoding — permissions is a plain text[] and account_id is handled via
// nullableIDFromPgUUID (NULL for presets).
func roleFromRow(row sqlcgen.Role) domain.Role {
	return domain.Role{
		ID:          idFromPgUUID[core.RoleID](row.ID),
		AccountID:   nullableIDFromPgUUID[core.AccountID](row.AccountID),
		Slug:        row.Slug,
		Name:        row.Name,
		Permissions: row.Permissions,
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

// GetByID returns the role with the given ID, or nil if not found.
func (r *RoleRepo) GetByID(ctx context.Context, id core.RoleID) (*domain.Role, error) {
	row, err := r.q.GetRoleByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	role := roleFromRow(row)
	return &role, nil
}

// GetBySlug returns a preset role when accountID is nil, or a tenant-scoped
// custom role when accountID is set. Returns nil if not found.
func (r *RoleRepo) GetBySlug(ctx context.Context, accountID *core.AccountID, slug string) (*domain.Role, error) {
	db := conn(ctx, r.pool)
	var row sqlcgen.Role
	var err error
	if accountID == nil {
		row, err = r.q.GetPresetRoleBySlug(ctx, db, slug)
	} else {
		row, err = r.q.GetTenantRoleBySlug(ctx, db, sqlcgen.GetTenantRoleBySlugParams{
			AccountID: pgUUIDFromID(*accountID),
			Slug:      slug,
		})
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	role := roleFromRow(row)
	return &role, nil
}

// ListPresets returns all preset roles (account_id IS NULL).
func (r *RoleRepo) ListPresets(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.q.ListPresetRoles(ctx, conn(ctx, r.pool))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for _, row := range rows {
		out = append(out, roleFromRow(row))
	}
	return out, nil
}

// ListByAccount returns presets + custom roles visible to the current
// RLS tenant. The roles RLS policy exposes preset rows with NULL
// account_id to every tenant, so a plain SELECT returns both sets.
func (r *RoleRepo) ListByAccount(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.q.ListRolesVisibleToCurrentTenant(ctx, conn(ctx, r.pool))
	if err != nil {
		return nil, err
	}
	out := make([]domain.Role, 0, len(rows))
	for _, row := range rows {
		out = append(out, roleFromRow(row))
	}
	return out, nil
}
