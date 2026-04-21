package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EntitlementRepo implements domain.EntitlementRepository against sqlc-generated
// queries. All reads are RLS-scoped. Create does NOT classify the unique
// violation on entitlements_account_code_ci — the entitlement service
// pre-checks via GetByCodes, so a Create-time conflict is a programmer
// error we surface raw (mirrors CustomerRepo.Create).
type EntitlementRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.EntitlementRepository = (*EntitlementRepo)(nil)

// NewEntitlementRepo creates a new EntitlementRepo.
func NewEntitlementRepo(pool *pgxpool.Pool) *EntitlementRepo {
	return &EntitlementRepo{pool: pool, q: sqlcgen.New()}
}

// entitlementFromRow is the single translation seam for entitlement rows.
func entitlementFromRow(row sqlcgen.Entitlement) domain.Entitlement {
	return domain.Entitlement{
		ID:        idFromPgUUID[core.EntitlementID](row.ID),
		AccountID: idFromPgUUID[core.AccountID](row.AccountID),
		Code:      row.Code,
		Name:      row.Name,
		Metadata:  json.RawMessage(row.Metadata),
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// entitlementIDsToPgUUIDs converts a typed ID slice to []pgtype.UUID so
// it can be passed as `entitlement_id = ANY($2::uuid[])`. sqlc emits
// []pgtype.UUID for `::uuid[]` with pgx/v5.
func entitlementIDsToPgUUIDs(ids []core.EntitlementID) []pgtype.UUID {
	out := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		out[i] = pgtype.UUID{Bytes: [16]byte(id), Valid: true}
	}
	return out
}

// ---------------------------------------------------------------------------
// Registry CRUD
// ---------------------------------------------------------------------------

// Create inserts a new entitlement row. Empty Metadata is coerced to `{}`
// so the NOT NULL jsonb column is satisfied. Unique-violation translation
// is intentionally omitted — the service pre-checks via GetByCodes, and
// a Create-time conflict is a programmer error we surface as the raw
// pg error for visibility (matches CustomerRepo.Create).
func (r *EntitlementRepo) Create(ctx context.Context, e *domain.Entitlement) error {
	if len(e.Metadata) == 0 {
		e.Metadata = json.RawMessage("{}")
	}
	return r.q.CreateEntitlement(ctx, conn(ctx, r.pool), sqlcgen.CreateEntitlementParams{
		ID:        pgUUIDFromID(e.ID),
		AccountID: pgUUIDFromID(e.AccountID),
		Code:      e.Code,
		Name:      e.Name,
		Metadata:  e.Metadata,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	})
}

// Get returns the entitlement with the given id, or nil if not found
// (or filtered by RLS).
func (r *EntitlementRepo) Get(ctx context.Context, id core.EntitlementID) (*domain.Entitlement, error) {
	row, err := r.q.GetEntitlementByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e := entitlementFromRow(row)
	return &e, nil
}

// GetByCodes returns entitlements matching any of the given codes
// (case-insensitive) scoped to the account. Returns nil on empty input.
func (r *EntitlementRepo) GetByCodes(ctx context.Context, accountID core.AccountID, codes []string) ([]domain.Entitlement, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	lower := make([]string, len(codes))
	for i, c := range codes {
		lower[i] = strings.ToLower(c)
	}
	rows, err := r.q.GetEntitlementsByCodes(ctx, conn(ctx, r.pool), sqlcgen.GetEntitlementsByCodesParams{
		AccountID: pgUUIDFromID(accountID),
		Codes:     lower,
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Entitlement, 0, len(rows))
	for _, row := range rows {
		out = append(out, entitlementFromRow(row))
	}
	return out, nil
}

// List returns one cursor page of entitlements for the account, optionally
// filtered by a case-insensitive code prefix. Orders (created_at DESC, id DESC)
// with the id tiebreaker for microsecond-collision safety; a limit+1 probe
// detects has_more.
func (r *EntitlementRepo) List(ctx context.Context, accountID core.AccountID, codePrefix string, cursor core.Cursor, limit int) ([]domain.Entitlement, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}
	rows, err := r.q.ListEntitlements(ctx, conn(ctx, r.pool), sqlcgen.ListEntitlementsParams{
		AccountID:    pgUUIDFromID(accountID),
		CodePrefix:   nilIfEmpty(codePrefix),
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Entitlement, 0, len(rows))
	for _, row := range rows {
		out = append(out, entitlementFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// Update applies mutations to name and metadata, and rewrites updated_at.
// Code is immutable by design (enforced at the service layer); this method
// does not touch it. Returns core.ErrEntitlementNotFound when no row matches.
func (r *EntitlementRepo) Update(ctx context.Context, e *domain.Entitlement) error {
	if len(e.Metadata) == 0 {
		e.Metadata = json.RawMessage("{}")
	}
	row, err := r.q.UpdateEntitlement(ctx, conn(ctx, r.pool), sqlcgen.UpdateEntitlementParams{
		ID:       pgUUIDFromID(e.ID),
		Name:     e.Name,
		Metadata: e.Metadata,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NewAppError(core.ErrEntitlementNotFound, "entitlement not found")
	}
	if err != nil {
		return err
	}
	*e = entitlementFromRow(row)
	return nil
}

// Delete removes the entitlement with the given id. Returns
// core.ErrEntitlementNotFound when no row was affected. FK violations
// from policy_entitlements / license_entitlements (ON DELETE RESTRICT)
// are surfaced raw for the service layer to classify into ErrEntitlementInUse.
func (r *EntitlementRepo) Delete(ctx context.Context, id core.EntitlementID) error {
	n, err := r.q.DeleteEntitlement(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrEntitlementNotFound, "entitlement not found")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Policy attachments
// ---------------------------------------------------------------------------

// AttachToPolicy idempotently attaches each entitlement to the policy via
// INSERT ... ON CONFLICT DO NOTHING. Loops per-row — typical batch sizes
// are small and the explicit loop keeps the error surface obvious.
func (r *EntitlementRepo) AttachToPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	db := conn(ctx, r.pool)
	policyPgID := pgUUIDFromID(policyID)
	for _, eid := range entitlementIDs {
		if err := r.q.AttachEntitlementToPolicy(ctx, db, sqlcgen.AttachEntitlementToPolicyParams{
			PolicyID:      policyPgID,
			EntitlementID: pgUUIDFromID(eid),
		}); err != nil {
			return err
		}
	}
	return nil
}

// DetachFromPolicy removes the join rows for the given entitlement ids in
// a single DELETE via ANY($2::uuid[]).
func (r *EntitlementRepo) DetachFromPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	return r.q.DetachEntitlementsFromPolicy(ctx, conn(ctx, r.pool), sqlcgen.DetachEntitlementsFromPolicyParams{
		PolicyID:       pgUUIDFromID(policyID),
		EntitlementIds: entitlementIDsToPgUUIDs(entitlementIDs),
	})
}

// ReplacePolicyAttachments replaces the full attachment set for the policy:
// DELETE ALL then Attach the new set. Caller is expected to have opened
// WithTargetAccount / WithTx so the two statements run in the same tx.
func (r *EntitlementRepo) ReplacePolicyAttachments(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	db := conn(ctx, r.pool)
	policyPgID := pgUUIDFromID(policyID)
	if err := r.q.DeleteAllPolicyEntitlements(ctx, db, policyPgID); err != nil {
		return err
	}
	for _, eid := range entitlementIDs {
		if err := r.q.AttachEntitlementToPolicy(ctx, db, sqlcgen.AttachEntitlementToPolicyParams{
			PolicyID:      policyPgID,
			EntitlementID: pgUUIDFromID(eid),
		}); err != nil {
			return err
		}
	}
	return nil
}

// ListPolicyCodes returns the attached entitlement codes for the policy,
// sorted ASC.
func (r *EntitlementRepo) ListPolicyCodes(ctx context.Context, policyID core.PolicyID) ([]string, error) {
	return r.q.ListPolicyEntitlementCodes(ctx, conn(ctx, r.pool), pgUUIDFromID(policyID))
}

// ---------------------------------------------------------------------------
// License attachments
// ---------------------------------------------------------------------------

// AttachToLicense idempotently attaches each entitlement to the license.
func (r *EntitlementRepo) AttachToLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	db := conn(ctx, r.pool)
	licensePgID := pgUUIDFromID(licenseID)
	for _, eid := range entitlementIDs {
		if err := r.q.AttachEntitlementToLicense(ctx, db, sqlcgen.AttachEntitlementToLicenseParams{
			LicenseID:     licensePgID,
			EntitlementID: pgUUIDFromID(eid),
		}); err != nil {
			return err
		}
	}
	return nil
}

// DetachFromLicense removes the join rows for the given entitlement ids in
// a single DELETE via ANY($2::uuid[]).
func (r *EntitlementRepo) DetachFromLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	return r.q.DetachEntitlementsFromLicense(ctx, conn(ctx, r.pool), sqlcgen.DetachEntitlementsFromLicenseParams{
		LicenseID:      pgUUIDFromID(licenseID),
		EntitlementIds: entitlementIDsToPgUUIDs(entitlementIDs),
	})
}

// ReplaceLicenseAttachments replaces the full attachment set for the license.
// Caller is expected to have opened WithTargetAccount / WithTx.
func (r *EntitlementRepo) ReplaceLicenseAttachments(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	db := conn(ctx, r.pool)
	licensePgID := pgUUIDFromID(licenseID)
	if err := r.q.DeleteAllLicenseEntitlements(ctx, db, licensePgID); err != nil {
		return err
	}
	for _, eid := range entitlementIDs {
		if err := r.q.AttachEntitlementToLicense(ctx, db, sqlcgen.AttachEntitlementToLicenseParams{
			LicenseID:     licensePgID,
			EntitlementID: pgUUIDFromID(eid),
		}); err != nil {
			return err
		}
	}
	return nil
}

// ListLicenseCodes returns the attached entitlement codes for the license,
// sorted ASC.
func (r *EntitlementRepo) ListLicenseCodes(ctx context.Context, licenseID core.LicenseID) ([]string, error) {
	return r.q.ListLicenseEntitlementCodes(ctx, conn(ctx, r.pool), pgUUIDFromID(licenseID))
}

// ---------------------------------------------------------------------------
// Effective entitlements
// ---------------------------------------------------------------------------

// ResolveEffective returns the sorted UNION of entitlement codes inherited
// from the license's policy plus directly-attached license entitlements.
func (r *EntitlementRepo) ResolveEffective(ctx context.Context, licenseID core.LicenseID) ([]string, error) {
	return r.q.ResolveEffectiveEntitlements(ctx, conn(ctx, r.pool), pgUUIDFromID(licenseID))
}
