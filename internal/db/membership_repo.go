package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MembershipRepo implements domain.AccountMembershipRepository against
// sqlc-generated queries. Most methods are RLS-scoped via the
// account_id predicate on the underlying rows. ListByIdentity and
// CountOwners intentionally run as cross-tenant queries —
// ListByIdentity backs the login flow (needs every membership for the
// authenticating identity); CountOwners enforces the last-owner guard
// from any acting-account context.
//
// Update* and Delete return nil even when no row was affected. That
// "silent success on no-row" is intentional: the service layer
// pre-checks ownership and RLS hides rows that shouldn't be touched,
// so a missing row here indicates the caller already validated.
type MembershipRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.AccountMembershipRepository = (*MembershipRepo)(nil)

// NewMembershipRepo creates a new MembershipRepo.
func NewMembershipRepo(pool *pgxpool.Pool) *MembershipRepo {
	return &MembershipRepo{pool: pool, q: sqlcgen.New()}
}

// membershipFromRow is the single translation seam for
// account_membership rows. Every Get / List path that produces a
// sqlcgen.AccountMembership converts through here.
func membershipFromRow(row sqlcgen.AccountMembership) domain.AccountMembership {
	return domain.AccountMembership{
		ID:                  idFromPgUUID[core.MembershipID](row.ID),
		AccountID:           idFromPgUUID[core.AccountID](row.AccountID),
		IdentityID:          idFromPgUUID[core.IdentityID](row.IdentityID),
		RoleID:              idFromPgUUID[core.RoleID](row.RoleID),
		Status:              domain.MembershipStatus(row.Status),
		InvitedByIdentityID: nullableIDFromPgUUID[core.IdentityID](row.InvitedByIdentityID),
		JoinedAt:            row.JoinedAt,
		CreatedAt:           row.CreatedAt,
		UpdatedAt:           row.UpdatedAt,
	}
}

// Create inserts a new account membership. No unique-violation
// classification — the current membership service pre-checks for
// existing rows and the (identity_id, account_id) unique constraint
// is a belt-and-braces guard rather than a user-facing surface.
func (r *MembershipRepo) Create(ctx context.Context, m *domain.AccountMembership) error {
	return r.q.CreateAccountMembership(ctx, conn(ctx, r.pool), sqlcgen.CreateAccountMembershipParams{
		ID:                  pgUUIDFromID(m.ID),
		AccountID:           pgUUIDFromID(m.AccountID),
		IdentityID:          pgUUIDFromID(m.IdentityID),
		RoleID:              pgUUIDFromID(m.RoleID),
		Status:              string(m.Status),
		InvitedByIdentityID: pgUUIDFromIDPtr(m.InvitedByIdentityID),
		JoinedAt:            m.JoinedAt,
		CreatedAt:           m.CreatedAt,
		UpdatedAt:           m.UpdatedAt,
	})
}

// GetByID returns the membership with the given id, or nil if not
// found (or filtered by RLS).
func (r *MembershipRepo) GetByID(ctx context.Context, id core.MembershipID) (*domain.AccountMembership, error) {
	row, err := r.q.GetAccountMembershipByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m := membershipFromRow(row)
	return &m, nil
}

// GetByIDWithRole fetches a membership and its role in a single JOIN
// query to keep the auth middleware hot path fast. The join-row
// struct sqlc emits has aliased field names (Membership*, Role*) so
// the overlapping id/account_id/created_at/updated_at columns stay
// legible.
func (r *MembershipRepo) GetByIDWithRole(ctx context.Context, id core.MembershipID) (*domain.AccountMembership, *domain.Role, error) {
	row, err := r.q.GetAccountMembershipByIDWithRole(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	m := domain.AccountMembership{
		ID:                  idFromPgUUID[core.MembershipID](row.MembershipID),
		AccountID:           idFromPgUUID[core.AccountID](row.MembershipAccountID),
		IdentityID:          idFromPgUUID[core.IdentityID](row.MembershipIdentityID),
		RoleID:              idFromPgUUID[core.RoleID](row.MembershipRoleID),
		Status:              domain.MembershipStatus(row.MembershipStatus),
		InvitedByIdentityID: nullableIDFromPgUUID[core.IdentityID](row.MembershipInvitedByIdentityID),
		JoinedAt:            row.MembershipJoinedAt,
		CreatedAt:           row.MembershipCreatedAt,
		UpdatedAt:           row.MembershipUpdatedAt,
	}
	role := domain.Role{
		ID:          idFromPgUUID[core.RoleID](row.RoleIDFull),
		AccountID:   nullableIDFromPgUUID[core.AccountID](row.RoleAccountID),
		Slug:        row.RoleSlug,
		Name:        row.RoleName,
		Permissions: row.RolePermissions,
		CreatedAt:   row.RoleCreatedAt,
		UpdatedAt:   row.RoleUpdatedAt,
	}
	return &m, &role, nil
}

// GetByIdentityAndAccount returns the membership matching the given
// (identity, account) pair, or nil if not found.
func (r *MembershipRepo) GetByIdentityAndAccount(ctx context.Context, identityID core.IdentityID, accountID core.AccountID) (*domain.AccountMembership, error) {
	row, err := r.q.GetAccountMembershipByIdentityAndAccount(ctx, conn(ctx, r.pool),
		sqlcgen.GetAccountMembershipByIdentityAndAccountParams{
			IdentityID: pgUUIDFromID(identityID),
			AccountID:  pgUUIDFromID(accountID),
		})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m := membershipFromRow(row)
	return &m, nil
}

// ListByIdentity is a cross-tenant query: it MUST run without a
// WithTargetAccount wrapper so every active membership for the
// identity is returned. Used by the login flow to build the list of
// accounts the identity can switch to.
func (r *MembershipRepo) ListByIdentity(ctx context.Context, identityID core.IdentityID) ([]domain.AccountMembership, error) {
	rows, err := r.q.ListAccountMembershipsByIdentity(ctx, conn(ctx, r.pool), pgUUIDFromID(identityID))
	if err != nil {
		return nil, err
	}
	out := make([]domain.AccountMembership, 0, len(rows))
	for _, row := range rows {
		out = append(out, membershipFromRow(row))
	}
	return out, nil
}

// ListByAccount returns one cursor page of memberships for the
// current RLS-scoped account. The returned bool is has_more.
func (r *MembershipRepo) ListByAccount(ctx context.Context, cursor core.Cursor, limit int) ([]domain.AccountMembership, bool, error) {
	ts, id := cursorParams(cursor)

	// sqlc infers CursorID as pgtype.UUID (non-pointer) for the row
	// comparison; the cursor_ts IS NULL guard fires first, so a
	// zero-value pgtype.UUID on the unset-cursor branch is never read.
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}

	rows, err := r.q.ListAccountMembershipsByAccount(ctx, conn(ctx, r.pool),
		sqlcgen.ListAccountMembershipsByAccountParams{
			CursorTs:     ts,
			CursorID:     cursorID,
			LimitPlusOne: int32(limit + 1),
		})
	if err != nil {
		return nil, false, err
	}

	out := make([]domain.AccountMembership, 0, len(rows))
	for _, row := range rows {
		out = append(out, membershipFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// UpdateRole changes the role of an existing membership. No row
// count check — see package doc on "silent success".
func (r *MembershipRepo) UpdateRole(ctx context.Context, id core.MembershipID, roleID core.RoleID) error {
	return r.q.UpdateAccountMembershipRole(ctx, conn(ctx, r.pool),
		sqlcgen.UpdateAccountMembershipRoleParams{
			ID:     pgUUIDFromID(id),
			RoleID: pgUUIDFromID(roleID),
		})
}

// UpdateStatus changes the status of an existing membership. No row
// count check — see package doc on "silent success".
func (r *MembershipRepo) UpdateStatus(ctx context.Context, id core.MembershipID, status domain.MembershipStatus) error {
	return r.q.UpdateAccountMembershipStatus(ctx, conn(ctx, r.pool),
		sqlcgen.UpdateAccountMembershipStatusParams{
			ID:     pgUUIDFromID(id),
			Status: string(status),
		})
}

// Delete removes the given membership. No row count check — see
// package doc on "silent success".
func (r *MembershipRepo) Delete(ctx context.Context, id core.MembershipID) error {
	return r.q.DeleteAccountMembership(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
}

// CountOwners returns the number of active members holding the
// preset owner role for the given account. Runs as a cross-tenant
// query so the last-owner guard works from any acting-account
// context. Matches ONLY the preset owner role (r.account_id IS NULL)
// so a custom tenant role that happens to share the slug 'owner'
// does not count.
func (r *MembershipRepo) CountOwners(ctx context.Context, accountID core.AccountID) (int, error) {
	n, err := r.q.CountAccountOwners(ctx, conn(ctx, r.pool), pgUUIDFromID(accountID))
	return int(n), err
}

// ListAccountWithDetails implements
// domain.AccountMembershipRepository.ListAccountWithDetails. RLS scopes
// the underlying query to app.current_account_id. Identities are
// global so the JOIN doesn't hit RLS.
func (r *MembershipRepo) ListAccountWithDetails(
	ctx context.Context,
	cursor core.Cursor,
	limit int,
) ([]domain.MembershipDetail, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}

	rows, err := r.q.ListAccountMembershipsByAccountWithDetails(ctx, conn(ctx, r.pool),
		sqlcgen.ListAccountMembershipsByAccountWithDetailsParams{
			CursorTs:     ts,
			CursorID:     cursorID,
			LimitPlusOne: int32(limit + 1),
		})
	if err != nil {
		return nil, false, err
	}

	out := make([]domain.MembershipDetail, 0, len(rows))
	for _, row := range rows {
		out = append(out, membershipDetailFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// membershipDetailFromRow is the translation seam for the
// ListAccountMembershipsByAccountWithDetails sqlc row. Mirrors the
// non-fallible xFromRow seam pattern used elsewhere in this repo.
func membershipDetailFromRow(row sqlcgen.ListAccountMembershipsByAccountWithDetailsRow) domain.MembershipDetail {
	return domain.MembershipDetail{
		MembershipID: idFromPgUUID[core.MembershipID](row.MembershipID),
		Identity: domain.MembershipIdentity{
			ID:    idFromPgUUID[core.IdentityID](row.IdentityIDFull),
			Email: row.IdentityEmail,
		},
		Role: domain.MembershipRole{
			ID:   idFromPgUUID[core.RoleID](row.RoleIDFull),
			Slug: row.RoleSlug,
			Name: row.RoleName,
		},
		JoinedAt:            row.MembershipJoinedAt,
		InvitedByIdentityID: nullableIDFromPgUUID[core.IdentityID](row.MembershipInvitedByIdentityID),
		CreatedAt:           row.MembershipCreatedAt,
	}
}
