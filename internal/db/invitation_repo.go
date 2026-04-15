package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func scanInvitation(s scannable) (domain.Invitation, error) {
	var inv domain.Invitation
	var rawID uuid.UUID
	var rawAccountID, rawRoleID *uuid.UUID
	var rawCreatedByIdentity, rawCreatedByAccount uuid.UUID
	var kind string
	var grantDraft []byte
	err := s.Scan(
		&rawID,
		&kind,
		&inv.Email,
		&inv.TokenHash,
		&rawAccountID,
		&rawRoleID,
		&grantDraft,
		&rawCreatedByIdentity,
		&rawCreatedByAccount,
		&inv.ExpiresAt,
		&inv.AcceptedAt,
		&inv.CreatedAt,
	)
	if err != nil {
		return inv, err
	}
	inv.ID = core.InvitationID(rawID)
	inv.Kind = domain.InvitationKind(kind)
	if rawAccountID != nil {
		aid := core.AccountID(*rawAccountID)
		inv.AccountID = &aid
	}
	if rawRoleID != nil {
		rid := core.RoleID(*rawRoleID)
		inv.RoleID = &rid
	}
	inv.CreatedByIdentityID = core.IdentityID(rawCreatedByIdentity)
	inv.CreatedByAccountID = core.AccountID(rawCreatedByAccount)
	if grantDraft != nil {
		inv.GrantDraft = json.RawMessage(grantDraft)
	}
	return inv, nil
}

const invitationColumns = `id, kind, email, token_hash, account_id, role_id, grant_draft, created_by_identity_id, created_by_account_id, expires_at, accepted_at, created_at`

// InvitationRepo implements domain.InvitationRepository. Most methods
// are RLS-scoped; GetByTokenHash runs outside tenant context for the
// public lookup path and relies on the raw token acting as its own
// access token (caller must possess the 32-byte random the HMAC was
// computed from).
type InvitationRepo struct {
	pool *pgxpool.Pool
}

var _ domain.InvitationRepository = (*InvitationRepo)(nil)

func NewInvitationRepo(pool *pgxpool.Pool) *InvitationRepo {
	return &InvitationRepo{pool: pool}
}

func (r *InvitationRepo) Create(ctx context.Context, inv *domain.Invitation) error {
	q := conn(ctx, r.pool)
	var rawAccountID, rawRoleID *uuid.UUID
	if inv.AccountID != nil {
		u := uuid.UUID(*inv.AccountID)
		rawAccountID = &u
	}
	if inv.RoleID != nil {
		u := uuid.UUID(*inv.RoleID)
		rawRoleID = &u
	}
	_, err := q.Exec(ctx,
		`INSERT INTO invitations (`+invitationColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		uuid.UUID(inv.ID),
		string(inv.Kind),
		inv.Email,
		inv.TokenHash,
		rawAccountID,
		rawRoleID,
		[]byte(inv.GrantDraft),
		uuid.UUID(inv.CreatedByIdentityID),
		uuid.UUID(inv.CreatedByAccountID),
		inv.ExpiresAt,
		inv.AcceptedAt,
		inv.CreatedAt,
	)
	return err
}

func (r *InvitationRepo) GetByID(ctx context.Context, id core.InvitationID) (*domain.Invitation, error) {
	q := conn(ctx, r.pool)
	inv, err := scanInvitation(q.QueryRow(ctx,
		`SELECT `+invitationColumns+` FROM invitations WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &inv, nil
}

// GetByTokenHash is the cross-tenant lookup used by the public
// invitation preview endpoint. Because it runs without tenant
// context, the RLS policy's NULL-escape branch matches and the
// query returns the row regardless of which account created it.
func (r *InvitationRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Invitation, error) {
	q := conn(ctx, r.pool)
	inv, err := scanInvitation(q.QueryRow(ctx,
		`SELECT `+invitationColumns+` FROM invitations WHERE token_hash = $1`,
		tokenHash,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &inv, nil
}

func (r *InvitationRepo) ListByAccount(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Invitation, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+invitationColumns+` FROM invitations
			 ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+invitationColumns+` FROM invitations
			 WHERE (created_at, id) < ($1, $2)
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Invitation, 0, limit+1)
	for rows.Next() {
		inv, err := scanInvitation(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, inv)
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

func (r *InvitationRepo) MarkAccepted(ctx context.Context, id core.InvitationID, acceptedAt time.Time) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE invitations SET accepted_at = $2 WHERE id = $1`,
		uuid.UUID(id), acceptedAt,
	)
	return err
}

func (r *InvitationRepo) Delete(ctx context.Context, id core.InvitationID) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx, `DELETE FROM invitations WHERE id = $1`, uuid.UUID(id))
	return err
}
