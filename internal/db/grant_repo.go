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

// grantFromRow is the single translation seam for plain grant rows
// (no JOIN). Used by non-JOIN query paths like ListExpirable.
func grantFromRow(row sqlcgen.Grant) domain.Grant {
	caps := make([]domain.GrantCapability, len(row.Capabilities))
	for i, c := range row.Capabilities {
		caps[i] = domain.GrantCapability(c)
	}
	var constraints json.RawMessage
	if row.Constraints != nil {
		constraints = json.RawMessage(row.Constraints)
	}
	var metadata json.RawMessage
	if row.Metadata != nil {
		metadata = json.RawMessage(row.Metadata)
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
		Label:            row.Label,
		Metadata:         metadata,
	}
}

// grantJoinFields is the shared projection of the JOIN-generated row
// types. The three sqlc row structs (GetGrantByIDWithAccountsRow,
// ListGrantsByGrantorFilteredRow, ListGrantsByGranteeFilteredRow) are
// structurally identical but nominally distinct, so each helper below
// copies the fields onto this internal shape before running the shared
// translation logic. Keeps the translation seam in one place.
type grantJoinFields struct {
	ID               pgtype.UUID
	GrantorAccountID pgtype.UUID
	GranteeAccountID pgtype.UUID
	Status           string
	ProductID        pgtype.UUID
	Capabilities     []string
	Constraints      []byte
	InvitationID     pgtype.UUID
	ExpiresAt        *time.Time
	AcceptedAt       *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Label            *string
	Metadata         []byte
	GrantorName      string
	GrantorSlug      string
	GranteeName      string
	GranteeSlug      string
}

// grantFromJoinFields is the shared post-projection translator used by
// all three JOIN-row variants.
func grantFromJoinFields(f grantJoinFields) domain.Grant {
	caps := make([]domain.GrantCapability, len(f.Capabilities))
	for i, c := range f.Capabilities {
		caps[i] = domain.GrantCapability(c)
	}
	var constraints json.RawMessage
	if f.Constraints != nil {
		constraints = json.RawMessage(f.Constraints)
	}
	var metadata json.RawMessage
	if f.Metadata != nil {
		metadata = json.RawMessage(f.Metadata)
	}
	grantorID := idFromPgUUID[core.AccountID](f.GrantorAccountID)
	granteeID := idFromPgUUID[core.AccountID](f.GranteeAccountID)
	g := domain.Grant{
		ID:               idFromPgUUID[core.GrantID](f.ID),
		GrantorAccountID: grantorID,
		GranteeAccountID: granteeID,
		ProductID:        idFromPgUUID[core.ProductID](f.ProductID),
		Status:           domain.GrantStatus(f.Status),
		Capabilities:     caps,
		Constraints:      constraints,
		InvitationID:     nullableIDFromPgUUID[core.InvitationID](f.InvitationID),
		ExpiresAt:        f.ExpiresAt,
		AcceptedAt:       f.AcceptedAt,
		CreatedAt:        f.CreatedAt,
		UpdatedAt:        f.UpdatedAt,
		Label:            f.Label,
		Metadata:         metadata,
		GrantorAccount: &domain.AccountSummary{
			ID:   grantorID,
			Name: f.GrantorName,
			Slug: f.GrantorSlug,
		},
		GranteeAccount: &domain.AccountSummary{
			ID:   granteeID,
			Name: f.GranteeName,
			Slug: f.GranteeSlug,
		},
	}
	return g
}

func grantFromGetByIDWithAccountsRow(row sqlcgen.GetGrantByIDWithAccountsRow) domain.Grant {
	return grantFromJoinFields(grantJoinFields{
		ID:               row.ID,
		GrantorAccountID: row.GrantorAccountID,
		GranteeAccountID: row.GranteeAccountID,
		Status:           row.Status,
		ProductID:        row.ProductID,
		Capabilities:     row.Capabilities,
		Constraints:      row.Constraints,
		InvitationID:     row.InvitationID,
		ExpiresAt:        row.ExpiresAt,
		AcceptedAt:       row.AcceptedAt,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
		Label:            row.Label,
		Metadata:         row.Metadata,
		GrantorName:      row.GrantorName,
		GrantorSlug:      row.GrantorSlug,
		GranteeName:      row.GranteeName,
		GranteeSlug:      row.GranteeSlug,
	})
}

func grantFromGrantorFilteredRow(row sqlcgen.ListGrantsByGrantorFilteredRow) domain.Grant {
	return grantFromJoinFields(grantJoinFields{
		ID:               row.ID,
		GrantorAccountID: row.GrantorAccountID,
		GranteeAccountID: row.GranteeAccountID,
		Status:           row.Status,
		ProductID:        row.ProductID,
		Capabilities:     row.Capabilities,
		Constraints:      row.Constraints,
		InvitationID:     row.InvitationID,
		ExpiresAt:        row.ExpiresAt,
		AcceptedAt:       row.AcceptedAt,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
		Label:            row.Label,
		Metadata:         row.Metadata,
		GrantorName:      row.GrantorName,
		GrantorSlug:      row.GrantorSlug,
		GranteeName:      row.GranteeName,
		GranteeSlug:      row.GranteeSlug,
	})
}

func grantFromGranteeFilteredRow(row sqlcgen.ListGrantsByGranteeFilteredRow) domain.Grant {
	return grantFromJoinFields(grantJoinFields{
		ID:               row.ID,
		GrantorAccountID: row.GrantorAccountID,
		GranteeAccountID: row.GranteeAccountID,
		Status:           row.Status,
		ProductID:        row.ProductID,
		Capabilities:     row.Capabilities,
		Constraints:      row.Constraints,
		InvitationID:     row.InvitationID,
		ExpiresAt:        row.ExpiresAt,
		AcceptedAt:       row.AcceptedAt,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
		Label:            row.Label,
		Metadata:         row.Metadata,
		GrantorName:      row.GrantorName,
		GrantorSlug:      row.GrantorSlug,
		GranteeName:      row.GranteeName,
		GranteeSlug:      row.GranteeSlug,
	})
}

// capabilitiesToStringSlice converts a typed capability slice to the
// plain string slice expected by the sqlc-generated text[] parameter.
func capabilitiesToStringSlice(caps []domain.GrantCapability) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = string(c)
	}
	return out
}

// statusesToStringSlice converts a typed status slice to the plain
// string slice expected by the sqlc-generated text[] parameter.
// Returns nil for an empty input so the ($N::text[] IS NULL) branch
// in the query acts as "no filter."
func statusesToStringSlice(statuses []domain.GrantStatus) []string {
	if len(statuses) == 0 {
		return nil
	}
	out := make([]string, len(statuses))
	for i, s := range statuses {
		out[i] = string(s)
	}
	return out
}

// boolPtr returns a pointer to the given bool. Used to wire the
// `_set` discriminators on partial-update params.
func boolPtr(b bool) *bool { return &b }

// Create inserts a new grant row. Must be called inside a
// WithTargetAccount context scoped to the grantor account. A unique
// violation on idx_grants_invitation_unique (partial unique on
// invitation_id WHERE NOT NULL) is classified into
// core.ErrInvitationAlreadyUsed so the service layer can surface a
// clean 409 on repeat accept attempts.
func (r *GrantRepo) Create(ctx context.Context, g *domain.Grant) error {
	caps := capabilitiesToStringSlice(g.Capabilities)
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

// GetByID returns the grant with the given id (with grantor + grantee
// AccountSummary populated via JOIN), or nil if not found (or filtered
// by RLS). The dual-branch RLS policy lets both grantor and grantee
// read the row.
func (r *GrantRepo) GetByID(ctx context.Context, id core.GrantID) (*domain.Grant, error) {
	row, err := r.q.GetGrantByIDWithAccounts(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	g := grantFromGetByIDWithAccountsRow(row)
	return &g, nil
}

// ListByGrantor returns cursor-paginated grants where the current
// RLS-scoped account is the grantor, with optional filters projected
// onto the sqlc params. The account id is read from the
// app.current_account_id session GUC via currentAccountID().
func (r *GrantRepo) ListByGrantor(ctx context.Context, filter domain.GrantListFilter, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
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
	rows, err := r.q.ListGrantsByGrantorFiltered(ctx, db, sqlcgen.ListGrantsByGrantorFilteredParams{
		GrantorAccountID: pgUUIDFromID(aid),
		ProductID:        pgUUIDFromIDPtr(filter.ProductID),
		GranteeAccountID: pgUUIDFromIDPtr(filter.GranteeAccountID),
		Statuses:         statusesToStringSlice(filter.Statuses),
		IncludeTerminal:  filter.IncludeTerminal,
		CursorTs:         ts,
		CursorID:         cursorID,
		LimitPlusOne:     int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		out = append(out, grantFromGrantorFilteredRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// ListByGrantee returns cursor-paginated grants where the current
// RLS-scoped account is the grantee, with optional filters projected
// onto the sqlc params. The account id is read from the
// app.current_account_id session GUC via currentAccountID().
func (r *GrantRepo) ListByGrantee(ctx context.Context, filter domain.GrantListFilter, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
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
	rows, err := r.q.ListGrantsByGranteeFiltered(ctx, db, sqlcgen.ListGrantsByGranteeFilteredParams{
		GranteeAccountID: pgUUIDFromID(aid),
		ProductID:        pgUUIDFromIDPtr(filter.ProductID),
		GrantorAccountID: pgUUIDFromIDPtr(filter.GrantorAccountID),
		Statuses:         statusesToStringSlice(filter.Statuses),
		IncludeTerminal:  filter.IncludeTerminal,
		CursorTs:         ts,
		CursorID:         cursorID,
		LimitPlusOne:     int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		out = append(out, grantFromGranteeFilteredRow(row))
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

// Update applies the partial-update semantics of domain.UpdateGrantParams
// to the sqlc UpdateGrant query. Field-by-field translation:
//
//   - Capabilities / Constraints / Metadata use COALESCE on the query
//     side — nil on the generated struct means "leave alone", non-nil
//     replaces. These columns are NOT NULL at the schema level, so there
//     is no "clear to NULL" case to distinguish.
//   - ExpiresAt and Label are nullable; the query pairs each value
//     column with a `_set` boolean. Outer nil on the domain pointer maps
//     to `_set = nil` (leave alone); inner nil maps to
//     `_set = true, value = nil` (clear to NULL); inner non-nil maps to
//     `_set = true, value = *ptr` (set to value).
//
// Callers are expected to pre-validate (empty capabilities, oversized
// label/metadata) at the service layer.
func (r *GrantRepo) Update(ctx context.Context, id core.GrantID, params domain.UpdateGrantParams) error {
	args := sqlcgen.UpdateGrantParams{
		ID: pgUUIDFromID(id),
	}
	if params.Capabilities != nil {
		args.Capabilities = capabilitiesToStringSlice(*params.Capabilities)
	}
	if params.Constraints != nil {
		args.Constraints = []byte(*params.Constraints)
	}
	if params.Metadata != nil {
		args.Metadata = []byte(*params.Metadata)
	}
	if params.ExpiresAt != nil {
		args.ExpiresAtSet = boolPtr(true)
		args.ExpiresAt = *params.ExpiresAt
	}
	if params.Label != nil {
		args.LabelSet = boolPtr(true)
		args.Label = *params.Label
	}
	return r.q.UpdateGrant(ctx, conn(ctx, r.pool), args)
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

// CountLicensesTotal returns the all-time license count for the grant.
// Delegates to the sqlc CountLicensesByGrant query.
func (r *GrantRepo) CountLicensesTotal(ctx context.Context, grantID core.GrantID) (int, error) {
	n, err := r.q.CountLicensesByGrant(ctx, conn(ctx, r.pool), pgUUIDFromID(grantID))
	return int(n), err
}

// CountDistinctCustomers returns the number of distinct customers
// referenced by licenses issued under the grant.
func (r *GrantRepo) CountDistinctCustomers(ctx context.Context, grantID core.GrantID) (int, error) {
	n, err := r.q.CountDistinctCustomersByGrant(ctx, conn(ctx, r.pool), pgUUIDFromID(grantID))
	return int(n), err
}

// ListExpirable returns grants whose expires_at has passed and whose
// status is still non-terminal. Runs without tenant context — passes
// through the NULLIF escape hatch in the tenant_grants RLS policy.
// Used by the background expire_grants job.
func (r *GrantRepo) ListExpirable(ctx context.Context, now time.Time, limit int) ([]domain.Grant, error) {
	rows, err := r.q.ListExpirableGrants(ctx, conn(ctx, r.pool), sqlcgen.ListExpirableGrantsParams{
		Now:       now,
		LimitRows: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, row := range rows {
		out = append(out, grantFromRow(row))
	}
	return out, nil
}
