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

// invitationJoinFields captures every column read by the JOIN-variant
// queries so the three row types (GetInvitationByIDWithCreatorRow,
// ListInvitationsByAccountFilteredRow, and any future JOIN query) can
// funnel through one translation seam. sqlc emits per-query row structs
// whose fields differ only in name, so this intermediate struct keeps
// the mapping DRY.
type invitationJoinFields struct {
	ID                  pgtype.UUID
	Kind                string
	Email               string
	TokenHash           string
	AccountID           pgtype.UUID
	RoleID              pgtype.UUID
	GrantDraft          []byte
	CreatedByIdentityID pgtype.UUID
	CreatedByAccountID  pgtype.UUID
	ExpiresAt           time.Time
	AcceptedAt          *time.Time
	CreatedAt           time.Time
	CreatorName         string
	CreatorSlug         string
}

// invitationFromJoinFields is the single translation seam for JOIN
// reads. Populates Invitation.CreatedByAccount from creator_name /
// creator_slug and computes Status via domain.ComputeInvitationStatus.
// NULL grant_draft jsonb is preserved as nil json.RawMessage (not an
// empty slice) so the service-layer "nullable-as-empty" convention
// keeps working.
func invitationFromJoinFields(f invitationJoinFields, now time.Time) domain.Invitation {
	var draft json.RawMessage
	if f.GrantDraft != nil {
		draft = json.RawMessage(f.GrantDraft)
	}
	createdByAccountID := idFromPgUUID[core.AccountID](f.CreatedByAccountID)
	inv := domain.Invitation{
		ID:                  idFromPgUUID[core.InvitationID](f.ID),
		Kind:                domain.InvitationKind(f.Kind),
		Email:               f.Email,
		TokenHash:           f.TokenHash,
		AccountID:           nullableIDFromPgUUID[core.AccountID](f.AccountID),
		RoleID:              nullableIDFromPgUUID[core.RoleID](f.RoleID),
		GrantDraft:          draft,
		CreatedByIdentityID: idFromPgUUID[core.IdentityID](f.CreatedByIdentityID),
		CreatedByAccountID:  createdByAccountID,
		ExpiresAt:           f.ExpiresAt,
		AcceptedAt:          f.AcceptedAt,
		CreatedAt:           f.CreatedAt,
	}
	inv.Status = domain.ComputeInvitationStatus(inv.AcceptedAt, inv.ExpiresAt, now)
	inv.CreatedByAccount = &domain.AccountSummary{
		ID:   createdByAccountID,
		Name: f.CreatorName,
		Slug: f.CreatorSlug,
	}
	return inv
}

// invitationFromRow translates the plain sqlcgen.Invitation (no JOIN)
// used by GetByTokenHash — the public preview endpoint has no tenant
// context to resolve the creator account against, so
// CreatedByAccount stays nil and is surfaced lazily downstream. Status
// is still populated so callers don't see a blank string.
func invitationFromRow(row sqlcgen.Invitation, now time.Time) domain.Invitation {
	var draft json.RawMessage
	if row.GrantDraft != nil {
		draft = json.RawMessage(row.GrantDraft)
	}
	inv := domain.Invitation{
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
	inv.Status = domain.ComputeInvitationStatus(inv.AcceptedAt, inv.ExpiresAt, now)
	return inv
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
// found (or filtered by RLS). The JOIN variant populates
// CreatedByAccount so callers get creator name/slug in a single round
// trip.
func (r *InvitationRepo) GetByID(ctx context.Context, id core.InvitationID) (*domain.Invitation, error) {
	row, err := r.q.GetInvitationByIDWithCreator(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	inv := invitationFromJoinFields(invitationJoinFields{
		ID:                  row.ID,
		Kind:                row.Kind,
		Email:               row.Email,
		TokenHash:           row.TokenHash,
		AccountID:           row.AccountID,
		RoleID:              row.RoleID,
		GrantDraft:          row.GrantDraft,
		CreatedByIdentityID: row.CreatedByIdentityID,
		CreatedByAccountID:  row.CreatedByAccountID,
		ExpiresAt:           row.ExpiresAt,
		AcceptedAt:          row.AcceptedAt,
		CreatedAt:           row.CreatedAt,
		CreatorName:         row.CreatorName,
		CreatorSlug:         row.CreatorSlug,
	}, time.Now().UTC())
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
	inv := invitationFromRow(row, time.Now().UTC())
	return &inv, nil
}

// ListByAccount returns cursor-paginated invitations for the current
// RLS-scoped account, optionally filtered by kind and computed
// status. The WHERE clause relies on RLS for the tenant filter — no
// explicit account_id is passed. Status is derived at query time via
// the accepted_at/expires_at/now tuple.
func (r *InvitationRepo) ListByAccount(ctx context.Context, filter domain.InvitationListFilter, cursor core.Cursor, limit int) ([]domain.Invitation, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	var kindParam *string
	if filter.Kind != nil {
		k := string(*filter.Kind)
		kindParam = &k
	}
	var statuses []string
	if len(filter.Status) > 0 {
		statuses = filter.Status
	}
	now := time.Now().UTC()
	rows, err := r.q.ListInvitationsByAccountFiltered(ctx, conn(ctx, r.pool), sqlcgen.ListInvitationsByAccountFilteredParams{
		Kind:         kindParam,
		Statuses:     statuses,
		Now:          now,
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Invitation, 0, len(rows))
	for _, row := range rows {
		out = append(out, invitationFromJoinFields(invitationJoinFields{
			ID:                  row.ID,
			Kind:                row.Kind,
			Email:               row.Email,
			TokenHash:           row.TokenHash,
			AccountID:           row.AccountID,
			RoleID:              row.RoleID,
			GrantDraft:          row.GrantDraft,
			CreatedByIdentityID: row.CreatedByIdentityID,
			CreatedByAccountID:  row.CreatedByAccountID,
			ExpiresAt:           row.ExpiresAt,
			AcceptedAt:          row.AcceptedAt,
			CreatedAt:           row.CreatedAt,
			CreatorName:         row.CreatorName,
			CreatorSlug:         row.CreatorSlug,
		}, now))
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

// UpdateTokenHash rotates the token hash on an existing invitation.
// Used by POST /v1/invitations/:id/resend to invalidate the prior
// token. Silent success on zero rows mirrors MarkAccepted — the
// service layer pre-checks existence via GetByID.
func (r *InvitationRepo) UpdateTokenHash(ctx context.Context, id core.InvitationID, tokenHash string) error {
	return r.q.UpdateInvitationTokenHash(ctx, conn(ctx, r.pool), sqlcgen.UpdateInvitationTokenHashParams{
		ID:        pgUUIDFromID(id),
		TokenHash: tokenHash,
	})
}

// Delete removes the invitation. Silent success on zero rows — same
// contract as MarkAccepted.
func (r *InvitationRepo) Delete(ctx context.Context, id core.InvitationID) error {
	return r.q.DeleteInvitation(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
}
