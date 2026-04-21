package db

import (
	"context"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// IdentityRepo implements domain.IdentityRepository. Identities are
// global (no RLS) — all methods run without tenant context.
type IdentityRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.IdentityRepository = (*IdentityRepo)(nil)

// NewIdentityRepo creates a new IdentityRepo.
func NewIdentityRepo(pool *pgxpool.Pool) *IdentityRepo {
	return &IdentityRepo{pool: pool, q: sqlcgen.New()}
}

// identityFromRow translates a sqlcgen.Identity to the domain struct.
// No fallible decoding — pure field coercion.
func identityFromRow(row sqlcgen.Identity) domain.Identity {
	return domain.Identity{
		ID:               idFromPgUUID[core.IdentityID](row.ID),
		Email:            row.Email,
		PasswordHash:     row.PasswordHash,
		TOTPSecretEnc:    row.TotpSecretEnc,
		TOTPEnabledAt:    row.TotpEnabledAt,
		RecoveryCodesEnc: row.RecoveryCodesEnc,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
	}
}

// Create inserts a new identity into the database.
func (r *IdentityRepo) Create(ctx context.Context, i *domain.Identity) error {
	err := r.q.CreateIdentity(ctx, conn(ctx, r.pool), sqlcgen.CreateIdentityParams{
		ID:               pgUUIDFromID(i.ID),
		Email:            i.Email,
		PasswordHash:     i.PasswordHash,
		TotpSecretEnc:    i.TOTPSecretEnc,
		TotpEnabledAt:    i.TOTPEnabledAt,
		RecoveryCodesEnc: i.RecoveryCodesEnc,
		CreatedAt:        i.CreatedAt,
		UpdatedAt:        i.UpdatedAt,
	})
	if IsUniqueViolation(err, ConstraintIdentityEmailUnique) {
		return core.NewAppError(core.ErrEmailAlreadyExists, "An identity with that email already exists")
	}
	return err
}

// GetByID returns the identity with the given ID, or nil if not found.
func (r *IdentityRepo) GetByID(ctx context.Context, id core.IdentityID) (*domain.Identity, error) {
	row, err := r.q.GetIdentityByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	i := identityFromRow(row)
	return &i, nil
}

// GetByEmail uses lower(email) matching to align with the case-insensitive
// UNIQUE INDEX on identities.
func (r *IdentityRepo) GetByEmail(ctx context.Context, email string) (*domain.Identity, error) {
	row, err := r.q.GetIdentityByEmail(ctx, conn(ctx, r.pool), email)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	i := identityFromRow(row)
	return &i, nil
}

// Update writes all mutable identity fields and refreshes i.UpdatedAt from
// the DB (via RETURNING updated_at).
func (r *IdentityRepo) Update(ctx context.Context, i *domain.Identity) error {
	updatedAt, err := r.q.UpdateIdentity(ctx, conn(ctx, r.pool), sqlcgen.UpdateIdentityParams{
		ID:               pgUUIDFromID(i.ID),
		Email:            i.Email,
		PasswordHash:     i.PasswordHash,
		TotpSecretEnc:    i.TOTPSecretEnc,
		TotpEnabledAt:    i.TOTPEnabledAt,
		RecoveryCodesEnc: i.RecoveryCodesEnc,
	})
	if err != nil {
		return err
	}
	i.UpdatedAt = updatedAt
	return nil
}

// UpdatePassword writes only the password_hash (used on password change).
func (r *IdentityRepo) UpdatePassword(ctx context.Context, id core.IdentityID, hash string) error {
	return r.q.UpdateIdentityPassword(ctx, conn(ctx, r.pool), sqlcgen.UpdateIdentityPasswordParams{
		ID:           pgUUIDFromID(id),
		PasswordHash: hash,
	})
}

// UpdateTOTP writes the TOTP state on an identity. The three call
// sites in internal/identity.Service pass different combinations:
//   - EnrollTOTP:   secretEnc = encrypted secret, enabledAt = nil, recoveryEnc = nil
//     (secret stored, not yet activated)
//   - ActivateTOTP: secretEnc unchanged from enrollment, enabledAt = now,
//     recoveryEnc = encrypted recovery codes
//   - DisableTOTP:  all three nil — writes NULLs, clearing all TOTP state
//
// Passing nil for any parameter writes NULL to the corresponding column.
func (r *IdentityRepo) UpdateTOTP(ctx context.Context, id core.IdentityID, secretEnc []byte, enabledAt *time.Time, recoveryEnc []byte) error {
	return r.q.UpdateIdentityTOTP(ctx, conn(ctx, r.pool), sqlcgen.UpdateIdentityTOTPParams{
		ID:               pgUUIDFromID(id),
		TotpSecretEnc:    secretEnc,
		TotpEnabledAt:    enabledAt,
		RecoveryCodesEnc: recoveryEnc,
	})
}
