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

// scanMembership scans an account_memberships row. Column order must
// match membershipColumns.
func scanMembership(s scannable) (domain.AccountMembership, error) {
	var m domain.AccountMembership
	var rawID, rawAccountID, rawIdentityID, rawRoleID uuid.UUID
	var rawInvitedBy *uuid.UUID
	var status string
	err := s.Scan(
		&rawID, &rawAccountID, &rawIdentityID, &rawRoleID,
		&status, &rawInvitedBy, &m.JoinedAt, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		return m, err
	}
	m.ID = core.MembershipID(rawID)
	m.AccountID = core.AccountID(rawAccountID)
	m.IdentityID = core.IdentityID(rawIdentityID)
	m.RoleID = core.RoleID(rawRoleID)
	m.Status = domain.MembershipStatus(status)
	if rawInvitedBy != nil {
		iid := core.IdentityID(*rawInvitedBy)
		m.InvitedByIdentityID = &iid
	}
	return m, nil
}

const membershipColumns = `id, account_id, identity_id, role_id, status, invited_by_identity_id, joined_at, created_at, updated_at`

// MembershipRepo implements domain.AccountMembershipRepository using
// PostgreSQL. Most methods are RLS-scoped through the account_id
// predicate. ListByIdentity and CountOwners intentionally run as
// cross-tenant queries — ListByIdentity backs the login flow, which
// needs every membership for the authenticating identity; CountOwners
// enforces the last-owner guard before any membership is removed.
type MembershipRepo struct {
	pool *pgxpool.Pool
}

var _ domain.AccountMembershipRepository = (*MembershipRepo)(nil)

func NewMembershipRepo(pool *pgxpool.Pool) *MembershipRepo {
	return &MembershipRepo{pool: pool}
}

func (r *MembershipRepo) Create(ctx context.Context, m *domain.AccountMembership) error {
	q := conn(ctx, r.pool)
	var invitedBy *uuid.UUID
	if m.InvitedByIdentityID != nil {
		u := uuid.UUID(*m.InvitedByIdentityID)
		invitedBy = &u
	}
	_, err := q.Exec(ctx,
		`INSERT INTO account_memberships (`+membershipColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.UUID(m.ID), uuid.UUID(m.AccountID), uuid.UUID(m.IdentityID),
		uuid.UUID(m.RoleID), string(m.Status), invitedBy,
		m.JoinedAt, m.CreatedAt, m.UpdatedAt,
	)
	return err
}

func (r *MembershipRepo) GetByID(ctx context.Context, id core.MembershipID) (*domain.AccountMembership, error) {
	q := conn(ctx, r.pool)
	m, err := scanMembership(q.QueryRow(ctx,
		`SELECT `+membershipColumns+` FROM account_memberships WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// GetByIDWithRole fetches a membership and its role in a single query
// to keep auth middleware hot-path latency low.
func (r *MembershipRepo) GetByIDWithRole(ctx context.Context, id core.MembershipID) (*domain.AccountMembership, *domain.Role, error) {
	q := conn(ctx, r.pool)
	row := q.QueryRow(ctx, `
		SELECT `+membershipColumns+`,
		       r.id, r.account_id, r.slug, r.name, r.permissions, r.created_at, r.updated_at
		FROM account_memberships m
		JOIN roles r ON r.id = m.role_id
		WHERE m.id = $1`,
		uuid.UUID(id),
	)

	var m domain.AccountMembership
	var rawMID, rawAccountID, rawIdentityID, rawRoleID uuid.UUID
	var rawInvitedBy *uuid.UUID
	var mStatus string

	var role domain.Role
	var rawRID uuid.UUID
	var rawRoleAccountID *uuid.UUID

	err := row.Scan(
		// membership columns (9)
		&rawMID, &rawAccountID, &rawIdentityID, &rawRoleID,
		&mStatus, &rawInvitedBy, &m.JoinedAt, &m.CreatedAt, &m.UpdatedAt,
		// role columns (7)
		&rawRID, &rawRoleAccountID, &role.Slug, &role.Name, &role.Permissions, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	m.ID = core.MembershipID(rawMID)
	m.AccountID = core.AccountID(rawAccountID)
	m.IdentityID = core.IdentityID(rawIdentityID)
	m.RoleID = core.RoleID(rawRoleID)
	m.Status = domain.MembershipStatus(mStatus)
	if rawInvitedBy != nil {
		iid := core.IdentityID(*rawInvitedBy)
		m.InvitedByIdentityID = &iid
	}

	role.ID = core.RoleID(rawRID)
	if rawRoleAccountID != nil {
		aid := core.AccountID(*rawRoleAccountID)
		role.AccountID = &aid
	}

	return &m, &role, nil
}

func (r *MembershipRepo) GetByIdentityAndAccount(ctx context.Context, identityID core.IdentityID, accountID core.AccountID) (*domain.AccountMembership, error) {
	q := conn(ctx, r.pool)
	m, err := scanMembership(q.QueryRow(ctx,
		`SELECT `+membershipColumns+` FROM account_memberships
		 WHERE identity_id = $1 AND account_id = $2`,
		uuid.UUID(identityID), uuid.UUID(accountID),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// ListByIdentity is a cross-tenant query — it MUST run without a
// WithTargetAccount wrapper so the RLS predicate matches every row for
// the identity. Used by the login flow to build the list of available
// accounts for the identity.
func (r *MembershipRepo) ListByIdentity(ctx context.Context, identityID core.IdentityID) ([]domain.AccountMembership, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT `+membershipColumns+` FROM account_memberships
		 WHERE identity_id = $1 AND status = $2
		 ORDER BY created_at ASC`,
		uuid.UUID(identityID), string(domain.MembershipStatusActive),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.AccountMembership
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListByAccount returns one cursor page of memberships for the current
// RLS-scoped account. The returned bool is hasMore.
func (r *MembershipRepo) ListByAccount(ctx context.Context, cursor core.Cursor, limit int) ([]domain.AccountMembership, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+membershipColumns+` FROM account_memberships
			 ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+membershipColumns+` FROM account_memberships
			 WHERE (created_at, id) < ($1, $2)
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.AccountMembership, 0, limit+1)
	for rows.Next() {
		m, err := scanMembership(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (r *MembershipRepo) UpdateRole(ctx context.Context, id core.MembershipID, roleID core.RoleID) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE account_memberships SET role_id = $2, updated_at = NOW() WHERE id = $1`,
		uuid.UUID(id), uuid.UUID(roleID),
	)
	return err
}

func (r *MembershipRepo) UpdateStatus(ctx context.Context, id core.MembershipID, status domain.MembershipStatus) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE account_memberships SET status = $2, updated_at = NOW() WHERE id = $1`,
		uuid.UUID(id), string(status),
	)
	return err
}

func (r *MembershipRepo) Delete(ctx context.Context, id core.MembershipID) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM account_memberships WHERE id = $1`, uuid.UUID(id))
	return err
}

// CountOwners returns the number of active members holding the owner
// role for the given account. Runs as a cross-tenant query to enforce
// the last-owner guard from any acting account context. It matches
// ONLY the preset owner role (account_id IS NULL), so a custom tenant
// role that happens to share the slug 'owner' does not count.
func (r *MembershipRepo) CountOwners(ctx context.Context, accountID core.AccountID) (int, error) {
	q := conn(ctx, r.pool)
	var n int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM account_memberships m
		 JOIN roles r ON r.id = m.role_id
		 WHERE m.account_id = $1 AND m.status = 'active' AND r.slug = 'owner' AND r.account_id IS NULL`,
		uuid.UUID(accountID),
	).Scan(&n)
	return n, err
}
