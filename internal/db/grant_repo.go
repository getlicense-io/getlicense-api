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

// scanGrant scans a grants row. Column order must match grantColumns.
func scanGrant(s scannable) (domain.Grant, error) {
	var g domain.Grant
	var rawID, rawGrantor, rawGrantee, rawProduct uuid.UUID
	var rawInvitationID *uuid.UUID
	var status string
	var caps []string
	var constraints []byte
	err := s.Scan(
		&rawID,
		&rawGrantor,
		&rawGrantee,
		&status,
		&rawProduct,
		&caps,
		&constraints,
		&rawInvitationID,
		&g.ExpiresAt,
		&g.AcceptedAt,
		&g.CreatedAt,
		&g.UpdatedAt,
	)
	if err != nil {
		return g, err
	}
	g.ID = core.GrantID(rawID)
	g.GrantorAccountID = core.AccountID(rawGrantor)
	g.GranteeAccountID = core.AccountID(rawGrantee)
	g.ProductID = core.ProductID(rawProduct)
	g.Status = domain.GrantStatus(status)

	// Convert []string → []GrantCapability.
	g.Capabilities = make([]domain.GrantCapability, len(caps))
	for i, c := range caps {
		g.Capabilities[i] = domain.GrantCapability(c)
	}

	if constraints != nil {
		g.Constraints = json.RawMessage(constraints)
	}
	if rawInvitationID != nil {
		iid := core.InvitationID(*rawInvitationID)
		g.InvitationID = &iid
	}
	return g, nil
}

const grantColumns = `id, grantor_account_id, grantee_account_id, status, product_id, capabilities, constraints, invitation_id, expires_at, accepted_at, created_at, updated_at`

// GrantRepo implements domain.GrantRepository using PostgreSQL.
type GrantRepo struct {
	pool *pgxpool.Pool
}

var _ domain.GrantRepository = (*GrantRepo)(nil)

// NewGrantRepo creates a new GrantRepo.
func NewGrantRepo(pool *pgxpool.Pool) *GrantRepo {
	return &GrantRepo{pool: pool}
}

// Create inserts a new grant row. Must be called inside a
// WithTargetAccount context scoped to the grantor account.
func (r *GrantRepo) Create(ctx context.Context, grant *domain.Grant) error {
	q := conn(ctx, r.pool)

	caps := make([]string, len(grant.Capabilities))
	for i, c := range grant.Capabilities {
		caps[i] = string(c)
	}

	var rawInvitationID *uuid.UUID
	if grant.InvitationID != nil {
		u := uuid.UUID(*grant.InvitationID)
		rawInvitationID = &u
	}

	constraints := grant.Constraints
	if constraints == nil {
		constraints = json.RawMessage(`{}`)
	}

	_, err := q.Exec(ctx,
		`INSERT INTO grants (`+grantColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		uuid.UUID(grant.ID),
		uuid.UUID(grant.GrantorAccountID),
		uuid.UUID(grant.GranteeAccountID),
		string(grant.Status),
		uuid.UUID(grant.ProductID),
		caps,
		[]byte(constraints),
		rawInvitationID,
		grant.ExpiresAt,
		grant.AcceptedAt,
		grant.CreatedAt,
		grant.UpdatedAt,
	)
	return err
}

// GetByID returns the grant with the given ID, or nil if not found.
// The RLS dual-branch policy ensures this is readable by both the
// grantor and the grantee.
func (r *GrantRepo) GetByID(ctx context.Context, id core.GrantID) (*domain.Grant, error) {
	q := conn(ctx, r.pool)
	g, err := scanGrant(q.QueryRow(ctx,
		`SELECT `+grantColumns+` FROM grants WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &g, nil
}

// ListByGrantor returns cursor-paginated grants where the current
// RLS-scoped account is the grantor. The account filter is read from
// the GUC set by WithTargetAccount — no extra parameter needed.
func (r *GrantRepo) ListByGrantor(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+grantColumns+` FROM grants
			 WHERE grantor_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
			 ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+grantColumns+` FROM grants
			 WHERE grantor_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
			   AND (created_at, id) < ($1, $2)
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Grant, 0, limit+1)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, g)
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

// ListByGrantee returns cursor-paginated grants where the current
// RLS-scoped account is the grantee. The account filter is read from
// the GUC set by WithTargetAccount — no extra parameter needed.
func (r *GrantRepo) ListByGrantee(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+grantColumns+` FROM grants
			 WHERE grantee_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
			 ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+grantColumns+` FROM grants
			 WHERE grantee_account_id = NULLIF(current_setting('app.current_account_id', true), '')::uuid
			   AND (created_at, id) < ($1, $2)
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Grant, 0, limit+1)
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, g)
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

// UpdateStatus updates the grant status and bumps updated_at.
func (r *GrantRepo) UpdateStatus(ctx context.Context, id core.GrantID, status domain.GrantStatus) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE grants SET status = $2, updated_at = NOW() WHERE id = $1`,
		uuid.UUID(id), string(status),
	)
	return err
}

// MarkAccepted atomically sets status=active, accepted_at, and
// updated_at in one statement. Used by Service.Accept.
func (r *GrantRepo) MarkAccepted(ctx context.Context, id core.GrantID, acceptedAt time.Time) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE grants SET status = 'active', accepted_at = $2, updated_at = NOW() WHERE id = $1`,
		uuid.UUID(id), acceptedAt,
	)
	return err
}

// CountLicensesInPeriod counts licenses attributed to the grant
// created on or after `since`. Pass time.Time{} for an all-time count.
func (r *GrantRepo) CountLicensesInPeriod(ctx context.Context, grantID core.GrantID, since time.Time) (int, error) {
	q := conn(ctx, r.pool)
	var n int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM licenses WHERE grant_id = $1 AND created_at >= $2`,
		uuid.UUID(grantID), since,
	).Scan(&n)
	return n, err
}
