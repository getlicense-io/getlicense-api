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

// MachineRepo implements domain.MachineRepository using sqlc-generated queries.
//
// UpsertActivation preserves the SELECT FOR UPDATE → INSERT-or-resurrect
// contract from the hand-written repo: callers wrap the call in a
// transaction (via WithTargetAccount), which holds the row lock for the
// duration of the activation.
type MachineRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.MachineRepository = (*MachineRepo)(nil)

// NewMachineRepo creates a new MachineRepo.
func NewMachineRepo(pool *pgxpool.Pool) *MachineRepo {
	return &MachineRepo{pool: pool, q: sqlcgen.New()}
}

// machineFromRow is the single translation seam between the sqlc row
// and the domain struct. Status/Environment are typed enums in domain;
// Hostname is a *string passed through unchanged.
func machineFromRow(row sqlcgen.Machine) domain.Machine {
	return domain.Machine{
		ID:             idFromPgUUID[core.MachineID](row.ID),
		AccountID:      idFromPgUUID[core.AccountID](row.AccountID),
		LicenseID:      idFromPgUUID[core.LicenseID](row.LicenseID),
		Fingerprint:    row.Fingerprint,
		Hostname:       row.Hostname,
		Metadata:       json.RawMessage(row.Metadata),
		LeaseIssuedAt:  row.LeaseIssuedAt,
		LeaseExpiresAt: row.LeaseExpiresAt,
		LastCheckinAt:  row.LastCheckinAt,
		Status:         core.MachineStatus(row.Status),
		Environment:    core.Environment(row.Environment),
		CreatedAt:      row.CreatedAt,
	}
}

// GetByID returns the machine with the given id, or nil if not found.
func (r *MachineRepo) GetByID(ctx context.Context, id core.MachineID) (*domain.Machine, error) {
	row, err := r.q.GetMachineByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m := machineFromRow(row)
	return &m, nil
}

// GetByFingerprint returns the machine for the given license and
// fingerprint, or nil if not found.
func (r *MachineRepo) GetByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	row, err := r.q.GetMachineByFingerprint(ctx, conn(ctx, r.pool), sqlcgen.GetMachineByFingerprintParams{
		LicenseID:   pgUUIDFromID(licenseID),
		Fingerprint: fingerprint,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m := machineFromRow(row)
	return &m, nil
}

// CountAliveByLicense returns the number of machines that count against
// the license's max_machines cap. Active and stale count; dead does not.
func (r *MachineRepo) CountAliveByLicense(ctx context.Context, licenseID core.LicenseID) (int, error) {
	n, err := r.q.CountAliveMachinesByLicense(ctx, conn(ctx, r.pool), pgUUIDFromID(licenseID))
	return int(n), err
}

// UpsertActivation inserts a new machine row OR resurrects an existing
// row (matching by license_id + fingerprint). The SELECT FOR UPDATE
// locks any existing row so concurrent activations for the same
// fingerprint serialize. Caller wraps this in a tx (via
// WithTargetAccount) so the lock holds for the lifetime of the
// insert/update.
//
// On resurrection the caller's *domain.Machine is mutated so the
// caller observes the preserved ID and CreatedAt.
func (r *MachineRepo) UpsertActivation(ctx context.Context, m *domain.Machine) error {
	db := conn(ctx, r.pool)
	if len(m.Metadata) == 0 {
		m.Metadata = []byte("{}")
	}

	existing, err := r.q.GetMachineByFingerprintForUpdate(ctx, db, sqlcgen.GetMachineByFingerprintForUpdateParams{
		LicenseID:   pgUUIDFromID(m.LicenseID),
		Fingerprint: m.Fingerprint,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	if errors.Is(err, pgx.ErrNoRows) {
		// Fresh insert.
		return r.q.InsertMachine(ctx, db, sqlcgen.InsertMachineParams{
			ID:             pgUUIDFromID(m.ID),
			AccountID:      pgUUIDFromID(m.AccountID),
			LicenseID:      pgUUIDFromID(m.LicenseID),
			Fingerprint:    m.Fingerprint,
			Hostname:       m.Hostname,
			Metadata:       m.Metadata,
			CreatedAt:      m.CreatedAt,
			Environment:    string(m.Environment),
			LeaseIssuedAt:  m.LeaseIssuedAt,
			LeaseExpiresAt: m.LeaseExpiresAt,
			LastCheckinAt:  m.LastCheckinAt,
			Status:         string(m.Status),
		})
	}

	// Resurrect existing row: reuse its ID & CreatedAt; overwrite
	// hostname/metadata/lease; flip status to 'active' regardless of
	// prior state.
	if err := r.q.UpdateMachineActivation(ctx, db, sqlcgen.UpdateMachineActivationParams{
		ID:             existing.ID,
		Hostname:       m.Hostname,
		Metadata:       m.Metadata,
		LeaseIssuedAt:  m.LeaseIssuedAt,
		LeaseExpiresAt: m.LeaseExpiresAt,
		LastCheckinAt:  m.LastCheckinAt,
	}); err != nil {
		return err
	}
	// Mutate caller's struct to reflect the resurrected identity.
	m.ID = idFromPgUUID[core.MachineID](existing.ID)
	m.CreatedAt = existing.CreatedAt
	m.Status = core.MachineStatusActive
	return nil
}

// RenewLease updates the lease state for an existing machine row. Used
// by the Checkin path. Returns ErrMachineNotFound if no row matches.
func (r *MachineRepo) RenewLease(ctx context.Context, m *domain.Machine) error {
	n, err := r.q.UpdateMachineLease(ctx, conn(ctx, r.pool), sqlcgen.UpdateMachineLeaseParams{
		ID:             pgUUIDFromID(m.ID),
		LeaseIssuedAt:  m.LeaseIssuedAt,
		LeaseExpiresAt: m.LeaseExpiresAt,
		LastCheckinAt:  m.LastCheckinAt,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrMachineNotFound, "machine not found")
	}
	return nil
}

// DeleteByFingerprint removes a machine activation by license and
// fingerprint. Returns ErrMachineNotFound if no matching record exists.
func (r *MachineRepo) DeleteByFingerprint(ctx context.Context, licenseID core.LicenseID, fingerprint string) error {
	n, err := r.q.DeleteMachineByFingerprint(ctx, conn(ctx, r.pool), sqlcgen.DeleteMachineByFingerprintParams{
		LicenseID:   pgUUIDFromID(licenseID),
		Fingerprint: fingerprint,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrMachineNotFound, "machine not found")
	}
	return nil
}

// MarkStaleExpired transitions active machines whose lease has expired
// to 'stale', restricted to policies with require_checkout=true.
// Returns the number of rows transitioned.
func (r *MachineRepo) MarkStaleExpired(ctx context.Context) (int, error) {
	n, err := r.q.MarkStaleMachines(ctx, conn(ctx, r.pool))
	return int(n), err
}

// MarkDeadExpired transitions stale machines past their grace window
// to 'dead'. Grace window is per-policy via checkout_grace_sec.
func (r *MachineRepo) MarkDeadExpired(ctx context.Context) (int, error) {
	n, err := r.q.MarkDeadMachines(ctx, conn(ctx, r.pool))
	return int(n), err
}

// Search returns machines whose fingerprint or hostname prefix-matches
// the query (case-insensitive), ordered by created_at DESC.
func (r *MachineRepo) Search(ctx context.Context, query string, limit int) ([]domain.Machine, error) {
	rows, err := r.q.SearchMachines(ctx, conn(ctx, r.pool), sqlcgen.SearchMachinesParams{
		Query:     query,
		LimitRows: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Machine, 0, len(rows))
	for _, row := range rows {
		out = append(out, machineFromRow(row))
	}
	return out, nil
}

// ListByLicense implements domain.MachineRepository.ListByLicense.
// RLS scopes the query to the current account+environment via the
// tx context (caller wraps with WithTargetAccount).
func (r *MachineRepo) ListByLicense(
	ctx context.Context,
	licenseID core.LicenseID,
	statusFilter string,
	cursor core.Cursor,
	limit int,
) ([]domain.Machine, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}

	rows, err := r.q.ListMachinesByLicense(ctx, conn(ctx, r.pool),
		sqlcgen.ListMachinesByLicenseParams{
			LicenseID:    pgUUIDFromID(licenseID),
			Status:       nilIfEmpty(statusFilter),
			CursorTs:     ts,
			CursorID:     cursorID,
			LimitPlusOne: int32(limit + 1),
		})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Machine, 0, len(rows))
	for _, row := range rows {
		out = append(out, machineFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}
