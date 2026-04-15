package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// buildLicenseFilterClause returns a fragment that can be appended
// after an existing WHERE clause (leading " AND ", empty when no
// filter is active) plus the matching args. argStart lets callers
// compose after their own placeholders — e.g. ListByProduct reserves
// $1 for product_id and passes argStart=2.
func buildLicenseFilterClause(filters domain.LicenseListFilters, argStart int) (string, []any) {
	var clauses []string
	var args []any
	next := argStart
	if filters.Status != "" {
		clauses = append(clauses, fmt.Sprintf("status = $%d", next))
		args = append(args, string(filters.Status))
		next++
	}
	if filters.Q != "" {
		// Match key_prefix directly, plus the referenced customer's
		// name/email via an EXISTS subquery. The subquery runs under the
		// same RLS context as the outer licenses query; customers and
		// licenses share the account scope so visibility matches.
		clauses = append(clauses, fmt.Sprintf(
			"(LOWER(key_prefix) LIKE LOWER($%d) OR EXISTS (SELECT 1 FROM customers c WHERE c.id = licenses.customer_id AND (LOWER(COALESCE(c.name, '')) LIKE LOWER($%d) OR LOWER(c.email) LIKE LOWER($%d))))",
			next, next, next,
		))
		args = append(args, "%"+filters.Q+"%")
		next++
	}
	if filters.CustomerID != nil {
		clauses = append(clauses, fmt.Sprintf("customer_id = $%d", next))
		args = append(args, uuid.UUID(*filters.CustomerID))
		next++
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(clauses, " AND "), args
}

// scanLicense scans a license row from a scannable (pgx.Row or pgx.Rows).
func scanLicense(s scannable) (domain.License, error) {
	var l domain.License
	var rawID, rawAccountID, rawProductID, rawPolicyID, rawCustomerID uuid.UUID
	var status, envStr string
	var overridesRaw []byte
	var rawGrantID *uuid.UUID
	var rawCreatedByAccount uuid.UUID
	var rawCreatedByIdentity *uuid.UUID
	err := s.Scan(
		&rawID, &rawAccountID, &rawProductID, &rawPolicyID,
		&overridesRaw,
		&l.KeyPrefix, &l.KeyHash, &l.Token,
		&status,
		&rawCustomerID,
		&l.ExpiresAt, &l.FirstActivatedAt,
		&envStr, &l.CreatedAt, &l.UpdatedAt,
		&rawGrantID, &rawCreatedByAccount, &rawCreatedByIdentity,
	)
	if err != nil {
		return l, err
	}
	l.ID = core.LicenseID(rawID)
	l.AccountID = core.AccountID(rawAccountID)
	l.ProductID = core.ProductID(rawProductID)
	l.PolicyID = core.PolicyID(rawPolicyID)
	l.CustomerID = core.CustomerID(rawCustomerID)
	if len(overridesRaw) > 0 {
		if err := json.Unmarshal(overridesRaw, &l.Overrides); err != nil {
			return l, fmt.Errorf("license_repo: decode overrides: %w", err)
		}
	}
	l.Status = core.LicenseStatus(status)
	l.Environment = core.Environment(envStr)
	l.CreatedByAccountID = core.AccountID(rawCreatedByAccount)
	if rawGrantID != nil {
		gid := core.GrantID(*rawGrantID)
		l.GrantID = &gid
	}
	if rawCreatedByIdentity != nil {
		iid := core.IdentityID(*rawCreatedByIdentity)
		l.CreatedByIdentityID = &iid
	}
	return l, nil
}

const licenseColumns = `id, account_id, product_id, policy_id, overrides, key_prefix, key_hash, token, status, customer_id, expires_at, first_activated_at, environment, created_at, updated_at, grant_id, created_by_account_id, created_by_identity_id`

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

	var rawGrantID *uuid.UUID
	if license.GrantID != nil {
		u := uuid.UUID(*license.GrantID)
		rawGrantID = &u
	}
	var rawCreatedByIdentity *uuid.UUID
	if license.CreatedByIdentityID != nil {
		u := uuid.UUID(*license.CreatedByIdentityID)
		rawCreatedByIdentity = &u
	}

	overridesJSON, err := json.Marshal(license.Overrides)
	if err != nil {
		return fmt.Errorf("license_repo: encode overrides: %w", err)
	}

	_, err = q.Exec(ctx,
		`INSERT INTO licenses (`+licenseColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		uuid.UUID(license.ID), uuid.UUID(license.AccountID), uuid.UUID(license.ProductID), uuid.UUID(license.PolicyID),
		overridesJSON,
		license.KeyPrefix, license.KeyHash, license.Token,
		string(license.Status),
		uuid.UUID(license.CustomerID),
		license.ExpiresAt, license.FirstActivatedAt,
		string(license.Environment), license.CreatedAt, license.UpdatedAt,
		rawGrantID, uuid.UUID(license.CreatedByAccountID), rawCreatedByIdentity,
	)
	return err
}

// Update persists mutable license fields. Status transitions go through
// UpdateStatus to keep the from/to check; this method covers the policy,
// override, customer, and expiry surfaces that Freeze / AttachPolicy /
// Activate (first-activation stamping) / Update need.
func (r *LicenseRepo) Update(ctx context.Context, license *domain.License) error {
	q := conn(ctx, r.pool)

	overridesJSON, err := json.Marshal(license.Overrides)
	if err != nil {
		return fmt.Errorf("license_repo: encode overrides: %w", err)
	}

	var updatedAt time.Time
	err = q.QueryRow(ctx,
		`UPDATE licenses SET
		   policy_id          = $2,
		   overrides          = $3,
		   customer_id        = $4,
		   expires_at         = $5,
		   first_activated_at = $6,
		   updated_at         = NOW()
		 WHERE id = $1
		 RETURNING updated_at`,
		uuid.UUID(license.ID),
		uuid.UUID(license.PolicyID),
		overridesJSON,
		uuid.UUID(license.CustomerID),
		license.ExpiresAt, license.FirstActivatedAt,
	).Scan(&updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.NewAppError(core.ErrLicenseNotFound, "License not found")
		}
		return err
	}
	license.UpdatedAt = updatedAt
	return nil
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

func (r *LicenseRepo) List(ctx context.Context, filters domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	return r.listPage(ctx, "1=1", nil, filters, cursor, limit)
}

func (r *LicenseRepo) ListByProduct(ctx context.Context, productID core.ProductID, filters domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	return r.listPage(ctx, "product_id = $1", []any{uuid.UUID(productID)}, filters, cursor, limit)
}

// listPage drives both keyset-paginated list variants. seedWhere and
// seedArgs carry any caller-supplied predicates (e.g. product_id = $1)
// and occupy the first argument slots.
func (r *LicenseRepo) listPage(ctx context.Context, seedWhere string, seedArgs []any, filters domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	filterClause, filterArgs := buildLicenseFilterClause(filters, len(seedArgs)+1)
	args := append([]any{}, seedArgs...)
	args = append(args, filterArgs...)

	where := seedWhere + filterClause
	if !cursor.IsZero() {
		where += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d)", len(args)+1, len(args)+2)
		args = append(args, cursor.CreatedAt, cursor.ID)
	}

	args = append(args, limit+1)
	query := `SELECT ` + licenseColumns + ` FROM licenses WHERE ` + where +
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args))

	rows, err := conn(ctx, r.pool).Query(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.License, 0, limit+1)
	for rows.Next() {
		l, err := scanLicense(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, l)
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

// ExpireActive sets status = 'expired' on active licenses past their
// expiry time whose policy opts into REVOKE_ACCESS, and returns the
// affected licenses. Licenses attached to policies with RESTRICT or
// MAINTAIN strategies are left in the active state — their effective
// expired-ness is computed at validate time via policy.EvaluateExpiration.
func (r *LicenseRepo) ExpireActive(ctx context.Context) ([]domain.License, error) {
	q := conn(ctx, r.pool)
	// Column list is spelled out with the `l.` alias so the JOIN against
	// `policies` (which shares id/account_id/created_at/updated_at) does
	// not emit ambiguous-column errors. Keep this list in sync with the
	// `licenseColumns` constant and the `scanLicense` reader order.
	const licenseColumnsAliased = `l.id, l.account_id, l.product_id, l.policy_id, l.overrides, l.key_prefix, l.key_hash, l.token, l.status, l.customer_id, l.expires_at, l.first_activated_at, l.environment, l.created_at, l.updated_at, l.grant_id, l.created_by_account_id, l.created_by_identity_id`
	rows, err := q.Query(ctx,
		`UPDATE licenses l SET status = $1, updated_at = NOW()
		 FROM policies p
		 WHERE l.policy_id = p.id
		   AND l.status = $2
		   AND l.expires_at IS NOT NULL
		   AND l.expires_at < NOW()
		   AND p.expiration_strategy = $3
		 RETURNING `+licenseColumnsAliased,
		string(core.LicenseStatusExpired),
		string(core.LicenseStatusActive),
		string(core.ExpirationStrategyRevokeAccess),
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
