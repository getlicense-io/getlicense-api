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

// InvitationRepo implements domain.InvitationRepository against
// sqlc-generated queries. Most methods are RLS-scoped;
// GetByTokenHash runs outside tenant context for the public
// invitation preview endpoint and relies on the raw token acting as
// its own access token (caller must possess the 32-byte random the
// HMAC was computed from).
type InvitationRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.InvitationRepository = (*InvitationRepo)(nil)

// NewInvitationRepo creates a new InvitationRepo.
func NewInvitationRepo(pool *pgxpool.Pool) *InvitationRepo {
	return &InvitationRepo{pool: pool, q: sqlcgen.New()}
}

// invitationFromRow is the single translation seam between the sqlc
// row and the domain struct. grant_draft jsonb is optional: NULL in
// the DB becomes nil json.RawMessage in domain (preserving the
// "nullable-as-empty" convention the service layer expects).
func invitationFromRow(row sqlcgen.Invitation) domain.Invitation {
	var draft json.RawMessage
	if row.GrantDraft != nil {
		draft = json.RawMessage(row.GrantDraft)
	}
	return domain.Invitation{
		ID:                  idFromPgUUID[core.InvitationID](row.ID),
		Kind:                domain.InvitationKind(row.Kind),
		Email:               row.Email,
		TokenHash:           row.TokenHash,
		AccountID:           nullableIDFromPgUUID[core.AccountID](row.AccountID),
		RoleID:              nullableIDFromPgUUID[core.RoleID](row.RoleID),
		GrantDraft:          draft,
		CreatedByIdentityID: idFromPgUUID[core.IdentityID](row.CreatedByIdentityID),
		CreatedByAccountID:  idFromPgUUID[core.AccountID](row.CreatedByAccountID),
		ExpiresAt:           row.ExpiresAt,
		AcceptedAt:          row.AcceptedAt,
		CreatedAt:           row.CreatedAt,
	}
}

// Create inserts a new invitation row. A nil GrantDraft is written
// through as []byte(nil), which Postgres stores as NULL in the jsonb
// column. No unique-violation classification — the invitation token
// is a 32-byte random, so collisions are statistically impossible.
func (r *InvitationRepo) Create(ctx context.Context, inv *domain.Invitation) error {
	return r.q.CreateInvitation(ctx, conn(ctx, r.pool), sqlcgen.CreateInvitationParams{
		ID:                  pgUUIDFromID(inv.ID),
		Kind:                string(inv.Kind),
		Email:               inv.Email,
		TokenHash:           inv.TokenHash,
		AccountID:           pgUUIDFromIDPtr(inv.AccountID),
		RoleID:              pgUUIDFromIDPtr(inv.RoleID),
		GrantDraft:          []byte(inv.GrantDraft),
		CreatedByIdentityID: pgUUIDFromID(inv.CreatedByIdentityID),
		CreatedByAccountID:  pgUUIDFromID(inv.CreatedByAccountID),
		ExpiresAt:           inv.ExpiresAt,
		AcceptedAt:          inv.AcceptedAt,
		CreatedAt:           inv.CreatedAt,
	})
}

// GetByID returns the invitation with the given id, or nil if not
// found (or filtered by RLS).
func (r *InvitationRepo) GetByID(ctx context.Context, id core.InvitationID) (*domain.Invitation, error) {
	row, err := r.q.GetInvitationByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	inv := invitationFromRow(row)
	return &inv, nil
}

// GetByTokenHash is the cross-tenant lookup used by the public
// invitation preview endpoint. conn(ctx, pool) returns the pool
// directly when ctx has no tx, so the query runs without tenant
// context and the RLS policy's NULL-escape branch matches regardless
// of which account created the invitation.
func (r *InvitationRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Invitation, error) {
	row, err := r.q.GetInvitationByTokenHash(ctx, conn(ctx, r.pool), tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	inv := invitationFromRow(row)
	return &inv, nil
}

// ListByAccount returns cursor-paginated invitations for the current
// RLS-scoped account. The WHERE clause filters by the tenant context
// GUC via the standard RLS policy — no explicit account_id filter is
// needed here.
func (r *InvitationRepo) ListByAccount(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Invitation, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListInvitationsByAccount(ctx, conn(ctx, r.pool), sqlcgen.ListInvitationsByAccountParams{
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Invitation, 0, len(rows))
	for _, row := range rows {
		out = append(out, invitationFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// MarkAccepted stamps accepted_at on the invitation row. Silent
// success on zero rows — the invitation service pre-checks existence
// via GetByTokenHash, so a missing-row UPDATE here is a no-op.
func (r *InvitationRepo) MarkAccepted(ctx context.Context, id core.InvitationID, acceptedAt time.Time) error {
	return r.q.MarkInvitationAccepted(ctx, conn(ctx, r.pool), sqlcgen.MarkInvitationAcceptedParams{
		ID:         pgUUIDFromID(id),
		AcceptedAt: &acceptedAt,
	})
}

// Delete removes the invitation. Silent success on zero rows — same
// contract as MarkAccepted.
func (r *InvitationRepo) Delete(ctx context.Context, id core.InvitationID) error {
	return r.q.DeleteInvitation(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
}
