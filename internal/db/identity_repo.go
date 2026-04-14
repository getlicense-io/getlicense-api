package db

import (
	"context"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scanIdentity scans an identity row. Column order must match identityColumns.
func scanIdentity(s scannable) (domain.Identity, error) {
	var i domain.Identity
	var rawID uuid.UUID
	err := s.Scan(
		&rawID,
		&i.Email,
		&i.PasswordHash,
		&i.TOTPSecretEnc,
		&i.TOTPEnabledAt,
		&i.RecoveryCodesEnc,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	if err != nil {
		return i, err
	}
	i.ID = core.IdentityID(rawID)
	return i, nil
}

const identityColumns = `id, email, password_hash, totp_secret_enc, totp_enabled_at, recovery_codes_enc, created_at, updated_at`

// IdentityRepo implements domain.IdentityRepository using PostgreSQL.
// Identities are global — queries run without RLS context and are
// guarded at the service layer.
type IdentityRepo struct {
	pool *pgxpool.Pool
}

var _ domain.IdentityRepository = (*IdentityRepo)(nil)

func NewIdentityRepo(pool *pgxpool.Pool) *IdentityRepo {
	return &IdentityRepo{pool: pool}
}

func (r *IdentityRepo) Create(ctx context.Context, i *domain.Identity) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO identities (`+identityColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.UUID(i.ID), i.Email, i.PasswordHash,
		i.TOTPSecretEnc, i.TOTPEnabledAt, i.RecoveryCodesEnc,
		i.CreatedAt, i.UpdatedAt,
	)
	return err
}

func (r *IdentityRepo) GetByID(ctx context.Context, id core.IdentityID) (*domain.Identity, error) {
	q := conn(ctx, r.pool)
	i, err := scanIdentity(q.QueryRow(ctx,
		`SELECT `+identityColumns+` FROM identities WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

// GetByEmail uses lower(email) matching to align with the case-insensitive
// UNIQUE INDEX on identities.
func (r *IdentityRepo) GetByEmail(ctx context.Context, email string) (*domain.Identity, error) {
	q := conn(ctx, r.pool)
	i, err := scanIdentity(q.QueryRow(ctx,
		`SELECT `+identityColumns+` FROM identities WHERE lower(email) = lower($1)`,
		email,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &i, nil
}

func (r *IdentityRepo) Update(ctx context.Context, i *domain.Identity) error {
	q := conn(ctx, r.pool)
	var updatedAt time.Time
	err := q.QueryRow(ctx,
		`UPDATE identities
		 SET email = $2, password_hash = $3, totp_secret_enc = $4,
		     totp_enabled_at = $5, recovery_codes_enc = $6, updated_at = NOW()
		 WHERE id = $1
		 RETURNING updated_at`,
		uuid.UUID(i.ID), i.Email, i.PasswordHash,
		i.TOTPSecretEnc, i.TOTPEnabledAt, i.RecoveryCodesEnc,
	).Scan(&updatedAt)
	if err != nil {
		return err
	}
	i.UpdatedAt = updatedAt
	return nil
}

func (r *IdentityRepo) UpdatePassword(ctx context.Context, id core.IdentityID, hash string) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE identities SET password_hash = $2, updated_at = NOW() WHERE id = $1`,
		uuid.UUID(id), hash,
	)
	return err
}

// UpdateTOTP writes the TOTP state on an identity. The three call
// sites in internal/identity.Service pass different combinations:
//   - EnrollTOTP:   secretEnc = encrypted secret, enabledAt = nil, recoveryEnc = nil
//                   (secret stored, not yet activated)
//   - ActivateTOTP: secretEnc unchanged from enrollment, enabledAt = now,
//                   recoveryEnc = encrypted recovery codes
//   - DisableTOTP:  all three nil — writes NULLs, clearing all TOTP state
//
// Passing nil for any parameter writes NULL to the corresponding column.
func (r *IdentityRepo) UpdateTOTP(ctx context.Context, id core.IdentityID, secretEnc []byte, enabledAt *time.Time, recoveryEnc []byte) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`UPDATE identities
		 SET totp_secret_enc = $2, totp_enabled_at = $3, recovery_codes_enc = $4, updated_at = NOW()
		 WHERE id = $1`,
		uuid.UUID(id), secretEnc, enabledAt, recoveryEnc,
	)
	return err
}
