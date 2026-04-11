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
		`INSERT INTO licenses (id, account_id, product_id, key_prefix, key_hash, token,
		 license_type, status, max_machines, max_seats, entitlements,
		 licensee_name, licensee_email, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		uuid.UUID(license.ID), uuid.UUID(license.AccountID), uuid.UUID(license.ProductID),
		license.KeyPrefix, license.KeyHash, license.Token,
		string(license.LicenseType), string(license.Status),
		license.MaxMachines, license.MaxSeats, license.Entitlements,
		license.LicenseeName, license.LicenseeEmail, license.ExpiresAt,
		license.CreatedAt, license.UpdatedAt,
	)
	return err
}

// GetByID returns the license with the given ID, or nil if not found.
func (r *LicenseRepo) GetByID(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	q := conn(ctx, r.pool)
	var rawID, rawAccountID, rawProductID uuid.UUID
	var l domain.License
	var licenseType, status string
	err := q.QueryRow(ctx,
		`SELECT id, account_id, product_id, key_prefix, key_hash, token,
		 license_type, status, max_machines, max_seats, entitlements,
		 licensee_name, licensee_email, expires_at, created_at, updated_at
		 FROM licenses WHERE id = $1`,
		uuid.UUID(id),
	).Scan(
		&rawID, &rawAccountID, &rawProductID,
		&l.KeyPrefix, &l.KeyHash, &l.Token,
		&licenseType, &status,
		&l.MaxMachines, &l.MaxSeats, &l.Entitlements,
		&l.LicenseeName, &l.LicenseeEmail, &l.ExpiresAt,
		&l.CreatedAt, &l.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	l.ID = core.LicenseID(rawID)
	l.AccountID = core.AccountID(rawAccountID)
	l.ProductID = core.ProductID(rawProductID)
	l.LicenseType = core.LicenseType(licenseType)
	l.Status = core.LicenseStatus(status)
	return &l, nil
}

// GetByKeyHash returns the license with the given key hash, or nil if not found.
// This is a global query used for public license validation.
func (r *LicenseRepo) GetByKeyHash(ctx context.Context, keyHash string) (*domain.License, error) {
	q := conn(ctx, r.pool)
	var rawID, rawAccountID, rawProductID uuid.UUID
	var l domain.License
	var licenseType, status string
	err := q.QueryRow(ctx,
		`SELECT id, account_id, product_id, key_prefix, key_hash, token,
		 license_type, status, max_machines, max_seats, entitlements,
		 licensee_name, licensee_email, expires_at, created_at, updated_at
		 FROM licenses WHERE key_hash = $1`,
		keyHash,
	).Scan(
		&rawID, &rawAccountID, &rawProductID,
		&l.KeyPrefix, &l.KeyHash, &l.Token,
		&licenseType, &status,
		&l.MaxMachines, &l.MaxSeats, &l.Entitlements,
		&l.LicenseeName, &l.LicenseeEmail, &l.ExpiresAt,
		&l.CreatedAt, &l.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	l.ID = core.LicenseID(rawID)
	l.AccountID = core.AccountID(rawAccountID)
	l.ProductID = core.ProductID(rawProductID)
	l.LicenseType = core.LicenseType(licenseType)
	l.Status = core.LicenseStatus(status)
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
		`SELECT id, account_id, product_id, key_prefix, key_hash, token,
		 license_type, status, max_machines, max_seats, entitlements,
		 licensee_name, licensee_email, expires_at, created_at, updated_at
		 FROM licenses ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var licenses []domain.License
	for rows.Next() {
		var rawID, rawAccountID, rawProductID uuid.UUID
		var l domain.License
		var licenseType, status string
		if err := rows.Scan(
			&rawID, &rawAccountID, &rawProductID,
			&l.KeyPrefix, &l.KeyHash, &l.Token,
			&licenseType, &status,
			&l.MaxMachines, &l.MaxSeats, &l.Entitlements,
			&l.LicenseeName, &l.LicenseeEmail, &l.ExpiresAt,
			&l.CreatedAt, &l.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		l.ID = core.LicenseID(rawID)
		l.AccountID = core.AccountID(rawAccountID)
		l.ProductID = core.ProductID(rawProductID)
		l.LicenseType = core.LicenseType(licenseType)
		l.Status = core.LicenseStatus(status)
		licenses = append(licenses, l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return licenses, total, nil
}

// UpdateStatus updates the status of the license and sets updated_at to now.
func (r *LicenseRepo) UpdateStatus(ctx context.Context, id core.LicenseID, status core.LicenseStatus) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx,
		`UPDATE licenses SET status = $2, updated_at = NOW() WHERE id = $1`,
		uuid.UUID(id), string(status),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrLicenseNotFound, "license not found")
	}
	return nil
}

// ExpireActive sets status = 'expired' on all active licenses past their expiry time
// and returns the affected licenses.
func (r *LicenseRepo) ExpireActive(ctx context.Context) ([]domain.License, error) {
	q := conn(ctx, r.pool)
	rows, err := q.Query(ctx,
		`UPDATE licenses
		 SET status = 'expired', updated_at = NOW()
		 WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW()
		 RETURNING id, account_id, product_id, key_prefix, key_hash, token,
		           license_type, status, max_machines, max_seats, entitlements,
		           licensee_name, licensee_email, expires_at, created_at, updated_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var licenses []domain.License
	for rows.Next() {
		var rawID, rawAccountID, rawProductID uuid.UUID
		var l domain.License
		var licenseType, status string
		if err := rows.Scan(
			&rawID, &rawAccountID, &rawProductID,
			&l.KeyPrefix, &l.KeyHash, &l.Token,
			&licenseType, &status,
			&l.MaxMachines, &l.MaxSeats, &l.Entitlements,
			&l.LicenseeName, &l.LicenseeEmail, &l.ExpiresAt,
			&l.CreatedAt, &l.UpdatedAt,
		); err != nil {
			return nil, err
		}
		l.ID = core.LicenseID(rawID)
		l.AccountID = core.AccountID(rawAccountID)
		l.ProductID = core.ProductID(rawProductID)
		l.LicenseType = core.LicenseType(licenseType)
		l.Status = core.LicenseStatus(status)
		licenses = append(licenses, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return licenses, nil
}
