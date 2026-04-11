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

// MachineRepo implements domain.MachineRepository using PostgreSQL.
type MachineRepo struct {
	pool *pgxpool.Pool
}

var _ domain.MachineRepository = (*MachineRepo)(nil)

// NewMachineRepo creates a new MachineRepo.
func NewMachineRepo(pool *pgxpool.Pool) *MachineRepo {
	return &MachineRepo{pool: pool}
}

const machineColumns = `id, account_id, license_id, fingerprint, hostname, metadata, last_seen_at, created_at`

// Create inserts a new machine activation record into the database.
func (r *MachineRepo) Create(ctx context.Context, machine *domain.Machine) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO machines (id, account_id, license_id, fingerprint, hostname, metadata, last_seen_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.UUID(machine.ID), uuid.UUID(machine.AccountID), uuid.UUID(machine.LicenseID),
		machine.Fingerprint, machine.Hostname, machine.Metadata, machine.LastSeenAt, machine.CreatedAt,
	)
	return err
}

// GetByFingerprint returns the machine for the given license and fingerprint, or nil if not found.
func (r *MachineRepo) GetByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	q := conn(ctx, r.pool)
	var rawID, rawAccountID, rawLicenseID uuid.UUID
	var m domain.Machine
	err := q.QueryRow(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE license_id = $1 AND fingerprint = $2`,
		uuid.UUID(licenseID), fingerprint,
	).Scan(
		&rawID, &rawAccountID, &rawLicenseID,
		&m.Fingerprint, &m.Hostname, &m.Metadata, &m.LastSeenAt, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	m.ID = core.MachineID(rawID)
	m.AccountID = core.AccountID(rawAccountID)
	m.LicenseID = core.LicenseID(rawLicenseID)
	return &m, nil
}

// CountByLicense returns the number of machines activated for the given license.
func (r *MachineRepo) CountByLicense(ctx context.Context, licenseID core.LicenseID) (int, error) {
	q := conn(ctx, r.pool)
	var count int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM machines WHERE license_id = $1`,
		uuid.UUID(licenseID),
	).Scan(&count)
	return count, err
}

// DeleteByFingerprint removes a machine activation by license and fingerprint.
// Returns ErrMachineNotFound if no matching record exists.
func (r *MachineRepo) DeleteByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx,
		`DELETE FROM machines WHERE license_id = $1 AND fingerprint = $2`,
		uuid.UUID(licenseID), fingerprint,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrMachineNotFound, "machine not found")
	}
	return nil
}

// UpdateHeartbeat sets last_seen_at = NOW() for the machine and returns the updated record.
func (r *MachineRepo) UpdateHeartbeat(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	q := conn(ctx, r.pool)
	var rawID, rawAccountID, rawLicenseID uuid.UUID
	var m domain.Machine
	err := q.QueryRow(ctx,
		`UPDATE machines SET last_seen_at = NOW()
		 WHERE license_id = $1 AND fingerprint = $2
		 RETURNING `+machineColumns,
		uuid.UUID(licenseID), fingerprint,
	).Scan(
		&rawID, &rawAccountID, &rawLicenseID,
		&m.Fingerprint, &m.Hostname, &m.Metadata, &m.LastSeenAt, &m.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.NewAppError(core.ErrMachineNotFound, "machine not found")
		}
		return nil, err
	}
	m.ID = core.MachineID(rawID)
	m.AccountID = core.AccountID(rawAccountID)
	m.LicenseID = core.LicenseID(rawLicenseID)
	return &m, nil
}
