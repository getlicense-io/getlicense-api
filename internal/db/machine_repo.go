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

const machineColumns = `id, account_id, license_id, fingerprint, hostname, metadata, lease_issued_at, lease_expires_at, last_checkin_at, status, environment, created_at`

// scanMachine scans a machine row from a scannable (pgx.Row or pgx.Rows).
func scanMachine(s scannable) (domain.Machine, error) {
	var m domain.Machine
	var rawID, rawAccountID, rawLicenseID uuid.UUID
	var envStr, statusStr string
	err := s.Scan(
		&rawID, &rawAccountID, &rawLicenseID,
		&m.Fingerprint, &m.Hostname, &m.Metadata,
		&m.LeaseIssuedAt, &m.LeaseExpiresAt, &m.LastCheckinAt, &statusStr,
		&envStr, &m.CreatedAt,
	)
	if err != nil {
		return m, err
	}
	m.ID = core.MachineID(rawID)
	m.AccountID = core.AccountID(rawAccountID)
	m.LicenseID = core.LicenseID(rawLicenseID)
	m.Status = core.MachineStatus(statusStr)
	m.Environment = core.Environment(envStr)
	return m, nil
}

// MachineRepo implements domain.MachineRepository using PostgreSQL.
type MachineRepo struct {
	pool *pgxpool.Pool
}

var _ domain.MachineRepository = (*MachineRepo)(nil)

// NewMachineRepo creates a new MachineRepo.
func NewMachineRepo(pool *pgxpool.Pool) *MachineRepo {
	return &MachineRepo{pool: pool}
}

// GetByID returns the machine with the given id, or nil if not found.
func (r *MachineRepo) GetByID(ctx context.Context, id core.MachineID) (*domain.Machine, error) {
	q := conn(ctx, r.pool)
	m, err := scanMachine(q.QueryRow(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// GetByFingerprint returns the machine for the given license and fingerprint, or nil if not found.
func (r *MachineRepo) GetByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	q := conn(ctx, r.pool)
	m, err := scanMachine(q.QueryRow(ctx,
		`SELECT `+machineColumns+` FROM machines WHERE license_id = $1 AND fingerprint = $2`,
		uuid.UUID(licenseID), fingerprint,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// getByFingerprintForUpdate is an internal helper that locks the row.
func (r *MachineRepo) getByFingerprintForUpdate(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	q := conn(ctx, r.pool)
	m, err := scanMachine(q.QueryRow(ctx,
		`SELECT `+machineColumns+` FROM machines
		 WHERE license_id = $1 AND fingerprint = $2
		 FOR UPDATE`,
		uuid.UUID(licenseID), fingerprint,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// CountAliveByLicense returns the number of machines that count against
// the license's max_machines cap. Active and stale count; dead does not.
func (r *MachineRepo) CountAliveByLicense(ctx context.Context, licenseID core.LicenseID) (int, error) {
	q := conn(ctx, r.pool)
	var count int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM machines WHERE license_id = $1 AND status <> 'dead'`,
		uuid.UUID(licenseID),
	).Scan(&count)
	return count, err
}

// UpsertActivation inserts a new machine row OR resurrects a dead row
// (matching by license_id + fingerprint). Both paths reset the lease
// fields and set status to 'active'. Hostname / metadata from the
// incoming activation overwrite any prior values.
func (r *MachineRepo) UpsertActivation(ctx context.Context, m *domain.Machine) error {
	q := conn(ctx, r.pool)
	existing, err := r.getByFingerprintForUpdate(ctx, m.LicenseID, m.Fingerprint)
	if err != nil {
		return err
	}
	if existing == nil {
		// Insert new row.
		if len(m.Metadata) == 0 {
			m.Metadata = []byte("{}")
		}
		_, err := q.Exec(ctx,
			`INSERT INTO machines (`+machineColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			uuid.UUID(m.ID), uuid.UUID(m.AccountID), uuid.UUID(m.LicenseID),
			m.Fingerprint, m.Hostname, m.Metadata,
			m.LeaseIssuedAt, m.LeaseExpiresAt, m.LastCheckinAt, string(m.Status),
			string(m.Environment), m.CreatedAt,
		)
		return err
	}
	// Resurrect: keep the existing ID, overwrite hostname / metadata /
	// lease state. Status flips to 'active' regardless of prior state.
	if len(m.Metadata) == 0 {
		m.Metadata = []byte("{}")
	}
	_, err = q.Exec(ctx,
		`UPDATE machines SET
			hostname         = $2,
			metadata         = $3,
			lease_issued_at  = $4,
			lease_expires_at = $5,
			last_checkin_at  = $6,
			status           = 'active'
		 WHERE id = $1`,
		uuid.UUID(existing.ID),
		m.Hostname, m.Metadata,
		m.LeaseIssuedAt, m.LeaseExpiresAt, m.LastCheckinAt,
	)
	if err != nil {
		return err
	}
	// Mutate the caller's struct so they see the resurrected ID.
	m.ID = existing.ID
	m.CreatedAt = existing.CreatedAt
	m.Status = core.MachineStatusActive
	return nil
}

// RenewLease updates the lease state for an existing machine row. Used
// by the Checkin path. Caller must have already SELECTed FOR UPDATE
// and verified the machine is not dead.
func (r *MachineRepo) RenewLease(ctx context.Context, m *domain.Machine) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx,
		`UPDATE machines SET
			lease_issued_at  = $2,
			lease_expires_at = $3,
			last_checkin_at  = $4,
			status           = 'active'
		 WHERE id = $1`,
		uuid.UUID(m.ID),
		m.LeaseIssuedAt, m.LeaseExpiresAt, m.LastCheckinAt,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrMachineNotFound, "machine not found")
	}
	return nil
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

// Search returns machines whose fingerprint or hostname prefix-matches
// the query (case-insensitive), ordered by created_at DESC.
func (r *MachineRepo) Search(ctx context.Context, query string, limit int) ([]domain.Machine, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT `+machineColumns+` FROM machines
		 WHERE LOWER(fingerprint) LIKE LOWER($1) || '%'
		    OR LOWER(COALESCE(hostname, '')) LIKE LOWER($1) || '%'
		 ORDER BY created_at DESC, id DESC LIMIT $2`,
		query, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]domain.Machine, 0, limit)
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MarkStaleExpired transitions active machines whose lease has expired
// to 'stale', restricted to policies with require_checkout=true.
// Returns the number of rows transitioned.
func (r *MachineRepo) MarkStaleExpired(ctx context.Context) (int, error) {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx,
		`UPDATE machines m
		 SET status = 'stale'
		 FROM licenses l JOIN policies p ON p.id = l.policy_id
		 WHERE m.license_id = l.id
		   AND m.status = 'active'
		   AND p.require_checkout = true
		   AND m.lease_expires_at < now()`,
	)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// MarkDeadExpired transitions stale machines past their grace window
// to 'dead'. Grace window is per-policy via checkout_grace_sec.
func (r *MachineRepo) MarkDeadExpired(ctx context.Context) (int, error) {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx,
		`UPDATE machines m
		 SET status = 'dead'
		 FROM licenses l JOIN policies p ON p.id = l.policy_id
		 WHERE m.license_id = l.id
		   AND m.status = 'stale'
		   AND p.require_checkout = true
		   AND m.lease_expires_at + make_interval(secs => p.checkout_grace_sec) < now()`,
	)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
