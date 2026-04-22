package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GrantRepo implements domain.GrantRepository against sqlc-generated queries.
// The grants table has a dual-branch RLS policy that lets both the grantor
// and the grantee read a row — the list methods narrow explicitly via
// grantor_account_id / grantee_account_id using the current RLS account id
// read from the session GUC via currentAccountID().
type GrantRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.GrantRepository = (*GrantRepo)(nil)

// NewGrantRepo creates a new GrantRepo.
func NewGrantRepo(pool *pgxpool.Pool) *GrantRepo {
	return &GrantRepo{pool: pool, q: sqlcgen.New()}
}

// grantFromRow is the single translation seam for grant rows.
func grantFromRow(row sqlcgen.Grant) domain.Grant {
	caps := make([]domain.GrantCapability, len(row.Capabilities))
	for i, c := range row.Capabilities {
		caps[i] = domain.GrantCapability(c)
	}
	var constraints json.RawMessage
	if row.Constraints != nil {
		constraints = json.RawMessage(row.Constraints)
	}
	return domain.Grant{
		ID:               idFromPgUUID[core.GrantID](row.ID),
		GrantorAccountID: idFromPgUUID[core.AccountID](row.GrantorAccountID),
		GranteeAccountID: idFromPgUUID[core.AccountID](row.GranteeAccountID),
		ProductID:        idFromPgUUID[core.ProductID](row.ProductID),
		Status:           domain.GrantStatus(row.Status),
		Capabilities:     caps,
		Constraints:      constraints,
		InvitationID:     nullableIDFromPgUUID[core.InvitationID](row.InvitationID),
		ExpiresAt:        row.ExpiresAt,
		AcceptedAt:       row.AcceptedAt,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}
}

// Create inserts a new grant row. Must be called inside a
// WithTargetAccount context scoped to the grantor account. A unique
// violation on idx_grants_invitation_unique (partial unique on
// invitation_id WHERE NOT NULL) is classified into
// core.ErrInvitationAlreadyUsed so the service layer can surface a
// clean 409 on repeat accept attempts.
func (r *GrantRepo) Create(ctx context.Context, g *domain.Grant) error {
	caps := make([]string, len(g.Capabilities))
	for i, c := range g.Capabilities {
		caps[i] = string(c)
	}
	constraints := g.Constraints
	if constraints == nil {
		constraints = json.RawMessage(`{}`)
	}
	err := r.q.CreateGrant(ctx, conn(ctx, r.pool), sqlcgen.CreateGrantParams{
		ID:               pgUUIDFromID(g.ID),
		GrantorAccountID: pgUUIDFromID(g.GrantorAccountID),
		GranteeAccountID: pgUUIDFromID(g.GranteeAccountID),
		Status:           string(g.Status),
		ProductID:        pgUUIDFromID(g.ProductID),
		Capabilities:     caps,
		Constraints:      constraints,
		InvitationID:     pgUUIDFromIDPtr(g.InvitationID),
		ExpiresAt:        g.ExpiresAt,
		AcceptedAt:       g.AcceptedAt,
		CreatedAt:        g.CreatedAt,
		UpdatedAt:        g.UpdatedAt,
	})
	if IsUniqueViolation(err, ConstraintGrantInvitationUnique) {
		return core.NewAppError(core.ErrInvitationAlreadyUsed, "Grant already issued from this invitation")
	}
	return err
}

// GetByID returns the grant with the given id, or nil if not found
// (or filtered by RLS). The dual-branch RLS policy lets both grantor
// and grantee read the row.
func (r *GrantRepo) GetByID(ctx context.Context, id core.GrantID) (*domain.Grant, error) {
	row, err := r.q.GetGrantByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g := grantFromRow(row)
	return &g, nil
}

// ListByGrantor returns cursor-paginated grants where the current
// RLS-scoped account is the grantor. The account id is read from the
// app.current_account_id session GUC via currentAccountID().
func (r *GrantRepo) ListByGrantor(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
	db := conn(ctx, r.pool)
	aid, err := currentAccountID(ctx, db)
	if err != nil {
		return nil, false, err
	}
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListGrantsByGrantor(ctx, db, sqlcgen.ListGrantsByGrantorParams{
		GrantorAccountID: pgUUIDFromID(aid),
		CursorTs:         ts,
		CursorID:         cursorID,
		LimitPlusOne:     int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		out = append(out, grantFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// ListByGrantee returns cursor-paginated grants where the current
// RLS-scoped account is the grantee. The account id is read from the
// app.current_account_id session GUC via currentAccountID().
func (r *GrantRepo) ListByGrantee(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
	db := conn(ctx, r.pool)
	aid, err := currentAccountID(ctx, db)
	if err != nil {
		return nil, false, err
	}
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListGrantsByGrantee(ctx, db, sqlcgen.ListGrantsByGranteeParams{
		GranteeAccountID: pgUUIDFromID(aid),
		CursorTs:         ts,
		CursorID:         cursorID,
		LimitPlusOne:     int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		out = append(out, grantFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// UpdateStatus updates the grant status and bumps updated_at. Silent
// success on zero rows — the grant service pre-checks existence via
// GetByID, so a missing-row UPDATE here is a no-op we do not flag.
func (r *GrantRepo) UpdateStatus(ctx context.Context, id core.GrantID, status domain.GrantStatus) error {
	return r.q.UpdateGrantStatus(ctx, conn(ctx, r.pool), sqlcgen.UpdateGrantStatusParams{
		ID:     pgUUIDFromID(id),
		Status: string(status),
	})
}

// MarkAccepted atomically sets status=active, accepted_at, and
// updated_at in one statement. Silent success on zero rows — same
// contract as UpdateStatus. Used by Service.Accept.
func (r *GrantRepo) MarkAccepted(ctx context.Context, id core.GrantID, acceptedAt time.Time) error {
	return r.q.MarkGrantAccepted(ctx, conn(ctx, r.pool), sqlcgen.MarkGrantAcceptedParams{
		ID:         pgUUIDFromID(id),
		AcceptedAt: &acceptedAt,
	})
}

// CountLicensesInPeriod counts licenses attributed to the grant and
// created on or after `since`. A zero `since` (time.Time{}) matches
// all licenses because created_at >= 0001-01-01 is always true.
func (r *GrantRepo) CountLicensesInPeriod(ctx context.Context, grantID core.GrantID, since time.Time) (int, error) {
	n, err := r.q.CountLicensesByGrantInPeriod(ctx, conn(ctx, r.pool),
		sqlcgen.CountLicensesByGrantInPeriodParams{
			GrantID:   pgUUIDFromID(grantID),
			CreatedAt: since,
		})
	return int(n), err
}
