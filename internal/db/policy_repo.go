package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PolicyRepo implements domain.PolicyRepository against sqlc-generated
// queries. All reads are RLS-scoped. Create does NOT classify the partial
// `policies_default_per_product` unique index — callers (product auto-default
// creation, SetDefault) ensure at most one is_default=true per product by
// construction, so a conflict is a programmer error we surface raw.
type PolicyRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.PolicyRepository = (*PolicyRepo)(nil)

// NewPolicyRepo creates a new PolicyRepo.
func NewPolicyRepo(pool *pgxpool.Pool) *PolicyRepo {
	return &PolicyRepo{pool: pool, q: sqlcgen.New()}
}

// policyFromRow is the single translation seam for policy rows. Handles:
//   - pgtype.UUID → typed core.*ID
//   - sqlc string → typed core.Expiration*/ComponentMatchingStrategy
//   - *int32 ↔ *int for nullable int columns
//   - int32 → int for non-nullable int columns
//   - []byte → json.RawMessage for metadata (no copy, same backing bytes)
func policyFromRow(row sqlcgen.Policy) domain.Policy {
	return domain.Policy{
		ID:                        idFromPgUUID[core.PolicyID](row.ID),
		AccountID:                 idFromPgUUID[core.AccountID](row.AccountID),
		ProductID:                 idFromPgUUID[core.ProductID](row.ProductID),
		Name:                      row.Name,
		IsDefault:                 row.IsDefault,
		DurationSeconds:           int32PtrToIntPtr(row.DurationSeconds),
		ExpirationStrategy:        core.ExpirationStrategy(row.ExpirationStrategy),
		ExpirationBasis:           core.ExpirationBasis(row.ExpirationBasis),
		ValidationTTLSec:          int32PtrToIntPtr(row.ValidationTtlSec),
		MaxMachines:               int32PtrToIntPtr(row.MaxMachines),
		MaxSeats:                  int32PtrToIntPtr(row.MaxSeats),
		Floating:                  row.Floating,
		Strict:                    row.Strict,
		RequireCheckout:           row.RequireCheckout,
		CheckoutIntervalSec:       int(row.CheckoutIntervalSec),
		MaxCheckoutDurationSec:    int(row.MaxCheckoutDurationSec),
		CheckoutGraceSec:          int(row.CheckoutGraceSec),
		ComponentMatchingStrategy: core.ComponentMatchingStrategy(row.ComponentMatchingStrategy),
		Metadata:                  json.RawMessage(row.Metadata),
		CreatedAt:                 row.CreatedAt,
		UpdatedAt:                 row.UpdatedAt,
	}
}

// Create inserts a new policy row. Empty Metadata is coerced to `{}` so
// the NOT NULL jsonb column is satisfied.
func (r *PolicyRepo) Create(ctx context.Context, p *domain.Policy) error {
	if len(p.Metadata) == 0 {
		p.Metadata = json.RawMessage("{}")
	}
	return r.q.CreatePolicy(ctx, conn(ctx, r.pool), sqlcgen.CreatePolicyParams{
		ID:                        pgUUIDFromID(p.ID),
		AccountID:                 pgUUIDFromID(p.AccountID),
		ProductID:                 pgUUIDFromID(p.ProductID),
		Name:                      p.Name,
		IsDefault:                 p.IsDefault,
		DurationSeconds:           intPtrToInt32Ptr(p.DurationSeconds),
		ExpirationStrategy:        string(p.ExpirationStrategy),
		ExpirationBasis:           string(p.ExpirationBasis),
		MaxMachines:               intPtrToInt32Ptr(p.MaxMachines),
		MaxSeats:                  intPtrToInt32Ptr(p.MaxSeats),
		Floating:                  p.Floating,
		Strict:                    p.Strict,
		RequireCheckout:           p.RequireCheckout,
		CheckoutIntervalSec:       int32(p.CheckoutIntervalSec),
		MaxCheckoutDurationSec:    int32(p.MaxCheckoutDurationSec),
		CheckoutGraceSec:          int32(p.CheckoutGraceSec),
		ComponentMatchingStrategy: string(p.ComponentMatchingStrategy),
		Metadata:                  p.Metadata,
		CreatedAt:                 p.CreatedAt,
		UpdatedAt:                 p.UpdatedAt,
		ValidationTtlSec:          intPtrToInt32Ptr(p.ValidationTTLSec),
	})
}

// Get returns the policy with the given id, or nil if not found
// (or filtered by RLS).
func (r *PolicyRepo) Get(ctx context.Context, id core.PolicyID) (*domain.Policy, error) {
	row, err := r.q.GetPolicyByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := policyFromRow(row)
	return &p, nil
}

// GetByProduct returns one cursor page of policies for a product,
// ordered (created_at DESC, id DESC) with an id-tiebreaker for
// microsecond-collision safety. limit+1 probe detects has_more.
func (r *PolicyRepo) GetByProduct(ctx context.Context, productID core.ProductID, cursor core.Cursor, limit int) ([]domain.Policy, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListPoliciesByProduct(ctx, conn(ctx, r.pool), sqlcgen.ListPoliciesByProductParams{
		ProductID:    pgUUIDFromID(productID),
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Policy, 0, len(rows))
	for _, row := range rows {
		out = append(out, policyFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// GetDefaultForProduct returns the default policy for a product, or
// nil if none exists (or is filtered by RLS).
func (r *PolicyRepo) GetDefaultForProduct(ctx context.Context, productID core.ProductID) (*domain.Policy, error) {
	row, err := r.q.GetDefaultPolicyForProduct(ctx, conn(ctx, r.pool), pgUUIDFromID(productID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := policyFromRow(row)
	return &p, nil
}

// Update applies mutations to overridable/policy-only fields and
// rewrites updated_at. Returns core.ErrPolicyNotFound when no row
// matches the id.
func (r *PolicyRepo) Update(ctx context.Context, p *domain.Policy) error {
	if len(p.Metadata) == 0 {
		p.Metadata = json.RawMessage("{}")
	}
	row, err := r.q.UpdatePolicy(ctx, conn(ctx, r.pool), sqlcgen.UpdatePolicyParams{
		ID:                        pgUUIDFromID(p.ID),
		Name:                      p.Name,
		DurationSeconds:           intPtrToInt32Ptr(p.DurationSeconds),
		ExpirationStrategy:        string(p.ExpirationStrategy),
		ExpirationBasis:           string(p.ExpirationBasis),
		MaxMachines:               intPtrToInt32Ptr(p.MaxMachines),
		MaxSeats:                  intPtrToInt32Ptr(p.MaxSeats),
		Floating:                  p.Floating,
		Strict:                    p.Strict,
		RequireCheckout:           p.RequireCheckout,
		CheckoutIntervalSec:       int32(p.CheckoutIntervalSec),
		MaxCheckoutDurationSec:    int32(p.MaxCheckoutDurationSec),
		CheckoutGraceSec:          int32(p.CheckoutGraceSec),
		ComponentMatchingStrategy: string(p.ComponentMatchingStrategy),
		Metadata:                  p.Metadata,
		ValidationTtlSec:          intPtrToInt32Ptr(p.ValidationTTLSec),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	if err != nil {
		return err
	}
	*p = policyFromRow(row)
	return nil
}

// Delete removes the policy with the given id. Returns
// core.ErrPolicyNotFound when no row was affected.
func (r *PolicyRepo) Delete(ctx context.Context, id core.PolicyID) error {
	n, err := r.q.DeletePolicy(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	return nil
}

// SetDefault clears the old default policy for the product, then marks
// policyID as the new default. The two statements must run inside the
// same tx; callers are expected to have opened WithTargetAccount / WithTx
// before calling. When the target policy does not belong to the product
// (second UPDATE affects 0 rows) we return core.ErrPolicyProductMismatch.
func (r *PolicyRepo) SetDefault(ctx context.Context, productID core.ProductID, policyID core.PolicyID) error {
	db := conn(ctx, r.pool)
	if err := r.q.ClearDefaultPolicyForProduct(ctx, db, pgUUIDFromID(productID)); err != nil {
		return err
	}
	n, err := r.q.SetDefaultPolicy(ctx, db, sqlcgen.SetDefaultPolicyParams{
		ID:        pgUUIDFromID(policyID),
		ProductID: pgUUIDFromID(productID),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrPolicyProductMismatch, "policy does not belong to product")
	}
	return nil
}

// ReassignLicensesFromPolicy moves every license pointing at fromPolicyID
// to toPolicyID in one UPDATE, returning the number of rows touched. Used
// by the `?force=true` delete path to reassign referencing licenses to
// the product's default before deleting the old policy.
func (r *PolicyRepo) ReassignLicensesFromPolicy(ctx context.Context, fromPolicyID, toPolicyID core.PolicyID) (int, error) {
	n, err := r.q.ReassignLicensesFromPolicy(ctx, conn(ctx, r.pool), sqlcgen.ReassignLicensesFromPolicyParams{
		FromPolicyID: pgUUIDFromID(fromPolicyID),
		ToPolicyID:   pgUUIDFromID(toPolicyID),
	})
	return int(n), err
}

// CountReferencingLicenses returns the number of license rows that
// reference this policy (any status). Used by the service layer to
// block deletion of in-use policies unless ?force=true is set.
func (r *PolicyRepo) CountReferencingLicenses(ctx context.Context, id core.PolicyID) (int, error) {
	n, err := r.q.CountLicensesReferencingPolicy(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	return int(n), err
}
