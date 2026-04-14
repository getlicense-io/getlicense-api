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

// scanLicense scans a license row from a scannable (pgx.Row or pgx.Rows).
func scanLicense(s scannable) (domain.License, error) {
	var l domain.License
	var rawID, rawAccountID, rawProductID uuid.UUID
	var licenseType, status, envStr string
	err := s.Scan(
		&rawID, &rawAccountID, &rawProductID,
		&l.KeyPrefix, &l.KeyHash, &l.Token,
		&licenseType, &status,
		&l.MaxMachines, &l.MaxSeats, &l.Entitlements,
		&l.LicenseeName, &l.LicenseeEmail, &l.ExpiresAt,
		&envStr, &l.CreatedAt, &l.UpdatedAt,
	)
	if err != nil {
		return l, err
	}
	l.ID = core.LicenseID(rawID)
	l.AccountID = core.AccountID(rawAccountID)
	l.ProductID = core.ProductID(rawProductID)
	l.LicenseType = core.LicenseType(licenseType)
	l.Status = core.LicenseStatus(status)
	l.Environment = core.Environment(envStr)
	return l, nil
}

const licenseColumns = `id, account_id, product_id, key_prefix, key_hash, token, license_type, status, max_machines, max_seats, entitlements, licensee_name, licensee_email, expires_at, environment, created_at, updated_at`

// LicenseRepo implements domain.LicenseRepository using PostgreSQL.
type LicenseRepo struct {
	pool *pgxpool.Pool
}

var _ domain.LicenseRepository = (*LicenseRepo)(nil)

// NewLicenseRepo creates a new LicenseRepo.
func NewLicenseRepo(pool *pgxpool.Pool) *LicenseRepo {
	return &LicenseRepo{pool: pool}
}

// Create inserts a new license into the database.
func (r *LicenseRepo) Create(ctx context.Context, license *domain.License) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO licenses (`+licenseColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		uuid.UUID(license.ID), uuid.UUID(license.AccountID), uuid.UUID(license.ProductID),
		license.KeyPrefix, license.KeyHash, license.Token,
		string(license.LicenseType), string(license.Status),
		license.MaxMachines, license.MaxSeats, license.Entitlements,
		license.LicenseeName, license.LicenseeEmail, license.ExpiresAt,
		string(license.Environment), license.CreatedAt, license.UpdatedAt,
	)
	return err
}

// BulkCreate inserts multiple licenses into the database within the current transaction.
func (r *LicenseRepo) BulkCreate(ctx context.Context, licenses []*domain.License) error {
	for _, l := range licenses {
		if err := r.Create(ctx, l); err != nil {
			return err
		}
	}
	return nil
}

// GetByID returns the license with the given ID, or nil if not found.
func (r *LicenseRepo) GetByID(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	q := conn(ctx, r.pool)
	l, err := scanLicense(q.QueryRow(ctx,
		`SELECT `+licenseColumns+` FROM licenses WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &l, nil
}

// GetByIDForUpdate returns the license with the given ID using SELECT ... FOR UPDATE,
// locking the row for the duration of the current transaction.
func (r *LicenseRepo) GetByIDForUpdate(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	q := conn(ctx, r.pool)
	l, err := scanLicense(q.QueryRow(ctx,
		`SELECT `+licenseColumns+` FROM licenses WHERE id = $1 FOR UPDATE`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &l, nil
}

// GetByKeyHash returns the license with the given key hash, or nil if not found.
// This is a global query used for public license validation.
func (r *LicenseRepo) GetByKeyHash(ctx context.Context, keyHash string) (*domain.License, error) {
	q := conn(ctx, r.pool)
	l, err := scanLicense(q.QueryRow(ctx,
		`SELECT `+licenseColumns+` FROM licenses WHERE key_hash = $1`,
		keyHash,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &l, nil
}

// List returns a paginated list of licenses and the total count.
func (r *LicenseRepo) List(ctx context.Context, limit, offset int) ([]domain.License, int, error) {
	q := conn(ctx, r.pool)

	var total int
	if err := q.QueryRow(ctx, `SELECT COUNT(*) FROM licenses`).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx,
		`SELECT `+licenseColumns+` FROM licenses ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	licenses := make([]domain.License, 0, limit)
	for rows.Next() {
		l, err := scanLicense(rows)
		if err != nil {
			return nil, 0, err
		}
		licenses = append(licenses, l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return licenses, total, nil
}

// CountByProduct returns the number of active or suspended licenses for the given product.
// Revoked and expired licenses do not block product deletion.
func (r *LicenseRepo) CountByProduct(ctx context.Context, productID core.ProductID) (int, error) {
	q := conn(ctx, r.pool)
	var count int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM licenses WHERE product_id = $1 AND status IN ($2, $3)`,
		uuid.UUID(productID),
		string(core.LicenseStatusActive),
		string(core.LicenseStatusSuspended),
	).Scan(&count)
	return count, err
}

// CountsByProductStatus returns a per-status breakdown of every license
// belonging to the given product in the current RLS env. Used by the
// dashboard's product-detail page to render an accurate blocking count
// without paging through all license rows.
func (r *LicenseRepo) CountsByProductStatus(ctx context.Context, productID core.ProductID) (domain.LicenseStatusCounts, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`SELECT status, COUNT(*) FROM licenses WHERE product_id = $1 GROUP BY status`,
		uuid.UUID(productID),
	)
	if err != nil {
		return domain.LicenseStatusCounts{}, err
	}
	defer rows.Close()

	var counts domain.LicenseStatusCounts
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return domain.LicenseStatusCounts{}, err
		}
		switch core.LicenseStatus(status) {
		case core.LicenseStatusActive:
			counts.Active = n
		case core.LicenseStatusSuspended:
			counts.Suspended = n
		case core.LicenseStatusRevoked:
			counts.Revoked = n
		case core.LicenseStatusExpired:
			counts.Expired = n
		case core.LicenseStatusInactive:
			counts.Inactive = n
		}
		counts.Total += n
	}
	return counts, rows.Err()
}

// BulkRevokeByProduct atomically revokes every active or suspended
// license for the given product in the current RLS env. Returns the
// number of rows affected. Used by the dashboard to unblock product
// deletion when there are too many licenses to revoke individually
// through the bulk-action toolbar.
func (r *LicenseRepo) BulkRevokeByProduct(ctx context.Context, productID core.ProductID) (int, error) {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx,
		`UPDATE licenses
		   SET status = $1, updated_at = NOW()
		 WHERE product_id = $2
		   AND status IN ($3, $4)`,
		string(core.LicenseStatusRevoked),
		uuid.UUID(productID),
		string(core.LicenseStatusActive),
		string(core.LicenseStatusSuspended),
	)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// HasBlocking reports whether any active or suspended license exists
// in the current RLS tenant+environment context. Stops at the first
// match (LIMIT 1) — cheaper than a full COUNT on large tables.
func (r *LicenseRepo) HasBlocking(ctx context.Context) (bool, error) {
	q := conn(ctx, r.pool)
	var one int
	err := q.QueryRow(ctx,
		`SELECT 1 FROM licenses WHERE status IN ($1, $2) LIMIT 1`,
		string(core.LicenseStatusActive),
		string(core.LicenseStatusSuspended),
	).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// UpdateStatus atomically updates the license status from an expected value.
// Returns the DB-authoritative updated_at timestamp.
// If the license is not found or its current status does not match from, an error is returned.
func (r *LicenseRepo) UpdateStatus(ctx context.Context, id core.LicenseID, from, to core.LicenseStatus) (time.Time, error) {
	q := conn(ctx, r.pool)
	var updatedAt time.Time
	err := q.QueryRow(ctx,
		`UPDATE licenses SET status = $2, updated_at = NOW()
		 WHERE id = $1 AND status = $3
		 RETURNING updated_at`,
		uuid.UUID(id), string(to), string(from),
	).Scan(&updatedAt)
	if err != nil {
		return time.Time{}, classifyLicenseStatusUpdateError(ctx, q, id, err)
	}
	return updatedAt, nil
}

func classifyLicenseStatusUpdateError(ctx context.Context, q querier, id core.LicenseID, err error) error {
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	var exists bool
	if existsErr := q.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM licenses WHERE id = $1)`,
		uuid.UUID(id),
	).Scan(&exists); existsErr != nil {
		return existsErr
	}

	if exists {
		return core.NewAppError(core.ErrValidationError, "License status changed")
	}
	return core.NewAppError(core.ErrLicenseNotFound, "License not found")
}

// ExpireActive sets status = 'expired' on all active licenses past their expiry time
// and returns the affected licenses.
func (r *LicenseRepo) ExpireActive(ctx context.Context) ([]domain.License, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`UPDATE licenses SET status = $1, updated_at = NOW()
		 WHERE status = $2 AND expires_at IS NOT NULL AND expires_at < NOW()
		 RETURNING `+licenseColumns,
		string(core.LicenseStatusExpired), string(core.LicenseStatusActive),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	licenses := make([]domain.License, 0)
	for rows.Next() {
		l, err := scanLicense(rows)
		if err != nil {
			return nil, err
		}
		licenses = append(licenses, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return licenses, nil
}
