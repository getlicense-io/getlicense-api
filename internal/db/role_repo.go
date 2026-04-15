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

// scanRole scans a role row. Column order must match roleColumns.
func scanRole(s scannable) (domain.Role, error) {
	var r domain.Role
	var rawID uuid.UUID
	var rawAccountID *uuid.UUID
	err := s.Scan(&rawID, &rawAccountID, &r.Slug, &r.Name, &r.Permissions, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	r.ID = core.RoleID(rawID)
	if rawAccountID != nil {
		aid := core.AccountID(*rawAccountID)
		r.AccountID = &aid
	}
	return r, nil
}

const roleColumns = `id, account_id, slug, name, permissions, created_at, updated_at`

// RoleRepo implements domain.RoleRepository using PostgreSQL. Preset
// rows (account_id NULL) are exposed by RLS to every tenant; custom
// rows are tenant-scoped via the standard RLS predicate.
type RoleRepo struct {
	pool *pgxpool.Pool
}

var _ domain.RoleRepository = (*RoleRepo)(nil)

func NewRoleRepo(pool *pgxpool.Pool) *RoleRepo {
	return &RoleRepo{pool: pool}
}

func (r *RoleRepo) GetByID(ctx context.Context, id core.RoleID) (*domain.Role, error) {
	q := conn(ctx, r.pool)
	role, err := scanRole(q.QueryRow(ctx,
		`SELECT `+roleColumns+` FROM roles WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

// GetBySlug returns a preset role when accountID is nil, or a custom
// role for the given account when accountID is set.
func (r *RoleRepo) GetBySlug(ctx context.Context, accountID *core.AccountID, slug string) (*domain.Role, error) {
	q := conn(ctx, r.pool)
	var row pgx.Row
	if accountID == nil {
		row = q.QueryRow(ctx,
			`SELECT `+roleColumns+` FROM roles WHERE account_id IS NULL AND slug = $1`,
			slug,
		)
	} else {
		row = q.QueryRow(ctx,
			`SELECT `+roleColumns+` FROM roles WHERE account_id = $1 AND slug = $2`,
			uuid.UUID(*accountID), slug,
		)
	}
	role, err := scanRole(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &role, nil
}

func (r *RoleRepo) ListPresets(ctx context.Context) ([]domain.Role, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT `+roleColumns+` FROM roles WHERE account_id IS NULL ORDER BY slug`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

// ListByAccount returns presets + custom roles visible to the current
// RLS tenant. The roles RLS policy exposes preset rows with NULL
// account_id to every tenant, so a plain SELECT returns both sets.
func (r *RoleRepo) ListByAccount(ctx context.Context) ([]domain.Role, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT `+roleColumns+` FROM roles ORDER BY account_id NULLS FIRST, slug`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}
