package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LicenseRepo implements domain.LicenseRepository using sqlc-generated
// queries. The dynamic list filter (buildLicenseFilterClause) from the
// hand-written adapter is collapsed into the single ListLicenses query
// via sqlc.narg NULL-guards; List and ListByProduct both dispatch to
// the same generated method with product_id as an optional narg.
type LicenseRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.LicenseRepository = (*LicenseRepo)(nil)

// NewLicenseRepo creates a new LicenseRepo.
func NewLicenseRepo(pool *pgxpool.Pool) *LicenseRepo {
	return &LicenseRepo{pool: pool, q: sqlcgen.New()}
}

// licenseFromRow translates a sqlcgen.License to domain.License.
//
// This is the FIRST fallible xFromRow in the sqlc port: the jsonb
// `overrides` column unmarshals into the typed domain.LicenseOverrides
// struct, and that unmarshal can fail if the DB contains malformed
// json (would indicate corruption, but we surface the error rather
// than silently returning an empty Overrides value).
func licenseFromRow(row sqlcgen.License) (domain.License, error) {
	var overrides domain.LicenseOverrides
	if len(row.Overrides) > 0 {
		if err := json.Unmarshal(row.Overrides, &overrides); err != nil {
			return domain.License{}, fmt.Errorf("license_repo: decode overrides: %w", err)
		}
	}
	return domain.License{
		ID:                  idFromPgUUID[core.LicenseID](row.ID),
		AccountID:           idFromPgUUID[core.AccountID](row.AccountID),
		ProductID:           idFromPgUUID[core.ProductID](row.ProductID),
		PolicyID:            idFromPgUUID[core.PolicyID](row.PolicyID),
		CustomerID:          idFromPgUUID[core.CustomerID](row.CustomerID),
		Overrides:           overrides,
		KeyPrefix:           row.KeyPrefix,
		KeyHash:             row.KeyHash,
		Token:               row.Token,
		Status:              core.LicenseStatus(row.Status),
		ExpiresAt:           row.ExpiresAt,
		FirstActivatedAt:    row.FirstActivatedAt,
		CreatedAt:           row.CreatedAt,
		UpdatedAt:           row.UpdatedAt,
		Environment:         core.Environment(row.Environment),
		GrantID:             nullableIDFromPgUUID[core.GrantID](row.GrantID),
		CreatedByAccountID:  idFromPgUUID[core.AccountID](row.CreatedByAccountID),
		CreatedByIdentityID: nullableIDFromPgUUID[core.IdentityID](row.CreatedByIdentityID),
	}, nil
}

// Create inserts a new license. Caller supplies the full row.
func (r *LicenseRepo) Create(ctx context.Context, l *domain.License) error {
	overridesJSON, err := json.Marshal(l.Overrides)
	if err != nil {
		return fmt.Errorf("license_repo: encode overrides: %w", err)
	}
	return r.q.CreateLicense(ctx, conn(ctx, r.pool), sqlcgen.CreateLicenseParams{
		ID:                  pgUUIDFromID(l.ID),
		AccountID:           pgUUIDFromID(l.AccountID),
		ProductID:           pgUUIDFromID(l.ProductID),
		KeyPrefix:           l.KeyPrefix,
		KeyHash:             l.KeyHash,
		Token:               l.Token,
		Status:              string(l.Status),
		ExpiresAt:           l.ExpiresAt,
		CreatedAt:           l.CreatedAt,
		UpdatedAt:           l.UpdatedAt,
		Environment:         string(l.Environment),
		GrantID:             pgUUIDFromIDPtr(l.GrantID),
		CreatedByAccountID:  pgUUIDFromID(l.CreatedByAccountID),
		CreatedByIdentityID: pgUUIDFromIDPtr(l.CreatedByIdentityID),
		PolicyID:            pgUUIDFromID(l.PolicyID),
		Overrides:           overridesJSON,
		FirstActivatedAt:    l.FirstActivatedAt,
		CustomerID:          pgUUIDFromID(l.CustomerID),
	})
}

// BulkCreate inserts multiple licenses within the caller's transaction.
// No batching optimization here — each row goes through Create so the
// overrides jsonb encoding path runs identically per row.
func (r *LicenseRepo) BulkCreate(ctx context.Context, licenses []*domain.License) error {
	for _, l := range licenses {
		if err := r.Create(ctx, l); err != nil {
			return err
		}
	}
	return nil
}

// getOne factors the ErrNoRows + licenseFromRow boilerplate used by
// GetByID / GetByIDForUpdate / GetByKeyHash. Fetch returns the raw
// sqlcgen.License row; getOne handles translation and the nil-on-missing
// contract.
func (r *LicenseRepo) getOne(ctx context.Context, fetch func(context.Context, sqlcgen.DBTX) (sqlcgen.License, error)) (*domain.License, error) {
	row, err := fetch(ctx, conn(ctx, r.pool))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	l, err := licenseFromRow(row)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// GetByID returns the license or nil if not found.
func (r *LicenseRepo) GetByID(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	return r.getOne(ctx, func(ctx context.Context, db sqlcgen.DBTX) (sqlcgen.License, error) {
		return r.q.GetLicenseByID(ctx, db, pgUUIDFromID(id))
	})
}

// GetByIDForUpdate is GetByID with SELECT ... FOR UPDATE; the row lock
// is held for the duration of the caller's transaction.
func (r *LicenseRepo) GetByIDForUpdate(ctx context.Context, id core.LicenseID) (*domain.License, error) {
	return r.getOne(ctx, func(ctx context.Context, db sqlcgen.DBTX) (sqlcgen.License, error) {
		return r.q.GetLicenseByIDForUpdate(ctx, db, pgUUIDFromID(id))
	})
}

// GetByKeyHash looks up a license by its HMAC key hash. Global query
// used by the public validate path; RLS policies include the NULL
// escape hatch so this works outside a tenant-scoped tx.
func (r *LicenseRepo) GetByKeyHash(ctx context.Context, hash string) (*domain.License, error) {
	return r.getOne(ctx, func(ctx context.Context, db sqlcgen.DBTX) (sqlcgen.License, error) {
		return r.q.GetLicenseByKeyHash(ctx, db, hash)
	})
}

// List returns one cursor page of licenses. Filters are all optional
// (empty → sqlc.narg NULL-guard disables the predicate).
func (r *LicenseRepo) List(ctx context.Context, f domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	return r.list(ctx, nil, f, cursor, limit)
}

// ListByProduct scopes List to a single product.
func (r *LicenseRepo) ListByProduct(ctx context.Context, pid core.ProductID, f domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	return r.list(ctx, &pid, f, cursor, limit)
}

// list is the single driver for both List and ListByProduct. The
// generated ListLicenses query has a narg product_id filter that goes
// NULL when productID is nil, so one query services both entry points.
func (r *LicenseRepo) list(ctx context.Context, productID *core.ProductID, f domain.LicenseListFilters, cursor core.Cursor, limit int) ([]domain.License, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	var pid pgtype.UUID
	if productID != nil {
		pid = pgtype.UUID{Bytes: [16]byte(*productID), Valid: true}
	}
	var cid pgtype.UUID
	if f.CustomerID != nil {
		cid = pgtype.UUID{Bytes: [16]byte(*f.CustomerID), Valid: true}
	}
	rows, err := r.q.ListLicenses(ctx, conn(ctx, r.pool), sqlcgen.ListLicensesParams{
		ProductID:    pid,
		Status:       nilIfEmpty(string(f.Status)),
		CustomerID:   cid,
		Q:            nilIfEmpty(f.Q),
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.License, 0, len(rows))
	for _, row := range rows {
		l, err := licenseFromRow(row)
		if err != nil {
			return nil, false, err
		}
		out = append(out, l)
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// Update persists mutable license fields (policy, overrides, customer,
// expiry timestamps). Status transitions go through UpdateStatus so the
// from→to invariant holds; this method handles everything else.
func (r *LicenseRepo) Update(ctx context.Context, l *domain.License) error {
	overridesJSON, err := json.Marshal(l.Overrides)
	if err != nil {
		return fmt.Errorf("license_repo: encode overrides: %w", err)
	}
	row, err := r.q.UpdateLicense(ctx, conn(ctx, r.pool), sqlcgen.UpdateLicenseParams{
		ID:               pgUUIDFromID(l.ID),
		PolicyID:         pgUUIDFromID(l.PolicyID),
		Overrides:        overridesJSON,
		CustomerID:       pgUUIDFromID(l.CustomerID),
		ExpiresAt:        l.ExpiresAt,
		FirstActivatedAt: l.FirstActivatedAt,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NewAppError(core.ErrLicenseNotFound, "license not found")
	}
	if err != nil {
		return err
	}
	updated, err := licenseFromRow(row)
	if err != nil {
		return err
	}
	*l = updated
	return nil
}

// UpdateStatus atomically transitions from an expected status to a new
// one. Returns the DB-authoritative updated_at timestamp.
//
// The `WHERE id=$1 AND status=$expected` predicate is the atomicity
// lever: ErrNoRows means EITHER the id is gone OR the row is still
// there but its status no longer matches. We disambiguate with a
// follow-up LicenseExists call (same tx, so the answer reflects the
// same snapshot) and return the typed error accordingly.
func (r *LicenseRepo) UpdateStatus(ctx context.Context, id core.LicenseID, from, to core.LicenseStatus) (time.Time, error) {
	db := conn(ctx, r.pool)
	updatedAt, err := r.q.UpdateLicenseStatusFromTo(ctx, db, sqlcgen.UpdateLicenseStatusFromToParams{
		ID:             pgUUIDFromID(id),
		NewStatus:      string(to),
		ExpectedStatus: string(from),
	})
	if err == nil {
		return updatedAt, nil
	}
	return time.Time{}, r.classifyStatusUpdateErr(ctx, db, id, err)
}

// classifyStatusUpdateErr is the ErrNoRows → typed error seam shared
// by UpdateStatus. Extracted so unit tests can hit the 2-query
// classification path without round-tripping to Postgres.
func (r *LicenseRepo) classifyStatusUpdateErr(ctx context.Context, db sqlcgen.DBTX, id core.LicenseID, err error) error {
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	exists, existsErr := r.q.LicenseExists(ctx, db, pgUUIDFromID(id))
	if existsErr != nil {
		return existsErr
	}
	if exists {
		return core.NewAppError(core.ErrValidationError, "License status changed")
	}
	return core.NewAppError(core.ErrLicenseNotFound, "License not found")
}

// CountByProduct returns the number of active or suspended licenses
// attached to the given product. Revoked and expired licenses don't
// block product deletion and are not counted.
func (r *LicenseRepo) CountByProduct(ctx context.Context, pid core.ProductID) (int, error) {
	n, err := r.q.CountBlockingLicensesByProduct(ctx, conn(ctx, r.pool), pgUUIDFromID(pid))
	return int(n), err
}

// CountsByProductStatus returns the per-status breakdown for a product
// in the current RLS env. Used by the dashboard product-detail page to
// render accurate blocking counters without paging through every row.
func (r *LicenseRepo) CountsByProductStatus(ctx context.Context, pid core.ProductID) (domain.LicenseStatusCounts, error) {
	rows, err := r.q.CountsByProductStatus(ctx, conn(ctx, r.pool), pgUUIDFromID(pid))
	if err != nil {
		return domain.LicenseStatusCounts{}, err
	}
	var counts domain.LicenseStatusCounts
	for _, row := range rows {
		n := int(row.Count)
		switch core.LicenseStatus(row.Status) {
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
	return counts, nil
}

// BulkRevokeByProduct atomically revokes every active or suspended
// license for the given product in the current RLS env. Returns the
// number of rows affected.
func (r *LicenseRepo) BulkRevokeByProduct(ctx context.Context, pid core.ProductID) (int, error) {
	n, err := r.q.BulkRevokeLicensesByProduct(ctx, conn(ctx, r.pool), pgUUIDFromID(pid))
	return int(n), err
}

// HasBlocking reports whether any active or suspended license exists
// in the current RLS tenant+environment. Stops at the first match —
// cheaper than COUNT on large tables.
func (r *LicenseRepo) HasBlocking(ctx context.Context) (bool, error) {
	return r.q.HasBlockingLicenses(ctx, conn(ctx, r.pool))
}

// ExpireActive flips active-and-past-expiry licenses to 'expired' for
// policies that opt into REVOKE_ACCESS, returning the affected rows so
// the background job can emit domain events per license.
//
// Licenses on RESTRICT / MAINTAIN policies are not touched — their
// effective expired-ness is computed at validate time via
// policy.EvaluateExpiration and the on-disk status stays 'active'.
func (r *LicenseRepo) ExpireActive(ctx context.Context) ([]domain.License, error) {
	rows, err := r.q.ExpireActiveLicenses(ctx, conn(ctx, r.pool))
	if err != nil {
		return nil, err
	}
	out := make([]domain.License, 0, len(rows))
	for _, row := range rows {
		l, err := licenseFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}
