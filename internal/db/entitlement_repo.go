package db

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// entitlementColumns is the canonical select list for single-table
// entitlement queries. DO NOT reuse inside JOINs — use fully qualified
// aliases in join queries (see CLAUDE.md Gotchas).
const entitlementColumns = `
	id, account_id, code, name, metadata, created_at, updated_at
`

type EntitlementRepo struct {
	pool *pgxpool.Pool
}

var _ domain.EntitlementRepository = (*EntitlementRepo)(nil)

func NewEntitlementRepo(pool *pgxpool.Pool) *EntitlementRepo {
	return &EntitlementRepo{pool: pool}
}

func scanEntitlement(s scannable) (*domain.Entitlement, error) {
	e := &domain.Entitlement{}
	err := s.Scan(
		&e.ID, &e.AccountID, &e.Code, &e.Name, &e.Metadata,
		&e.CreatedAt, &e.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// entitlementIDsToUUIDs converts a typed ID slice to a plain uuid.UUID slice
// so pgx can encode it as a Postgres UUID array for ANY($n) clauses.
func entitlementIDsToUUIDs(ids []core.EntitlementID) []uuid.UUID {
	out := make([]uuid.UUID, len(ids))
	for i, id := range ids {
		out[i] = uuid.UUID(id)
	}
	return out
}

// ---------------------------------------------------------------------------
// Registry CRUD
// ---------------------------------------------------------------------------

func (r *EntitlementRepo) Create(ctx context.Context, e *domain.Entitlement) error {
	if len(e.Metadata) == 0 {
		e.Metadata = json.RawMessage("{}")
	}
	q := `INSERT INTO entitlements (
		id, account_id, code, name, metadata, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := conn(ctx, r.pool).Exec(ctx, q,
		e.ID, e.AccountID, e.Code, e.Name, e.Metadata,
		e.CreatedAt, e.UpdatedAt,
	)
	return err
}

func (r *EntitlementRepo) Get(ctx context.Context, id core.EntitlementID) (*domain.Entitlement, error) {
	q := `SELECT ` + entitlementColumns + ` FROM entitlements WHERE id = $1`
	row := conn(ctx, r.pool).QueryRow(ctx, q, id)
	e, err := scanEntitlement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return e, nil
}

func (r *EntitlementRepo) GetByCodes(ctx context.Context, accountID core.AccountID, codes []string) ([]domain.Entitlement, error) {
	if len(codes) == 0 {
		return nil, nil
	}
	// Lowercase all codes for case-insensitive matching against the
	// lower(code) index.
	lower := make([]string, len(codes))
	for i, c := range codes {
		lower[i] = strings.ToLower(c)
	}
	q := `SELECT ` + entitlementColumns + ` FROM entitlements
	      WHERE account_id = $1 AND lower(code) = ANY($2)`
	rows, err := conn(ctx, r.pool).Query(ctx, q, accountID, lower)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Entitlement
	for rows.Next() {
		e, err := scanEntitlement(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (r *EntitlementRepo) List(ctx context.Context, accountID core.AccountID, codePrefix string, cursor core.Cursor, limit int) ([]domain.Entitlement, bool, error) {
	args := []any{accountID}
	where := "account_id = $1"
	next := 2

	if codePrefix != "" {
		where += " AND lower(code) LIKE lower($" + strconv.Itoa(next) + ") || '%'"
		args = append(args, codePrefix)
		next++
	}

	var q string
	if cursor.IsZero() {
		q = `SELECT ` + entitlementColumns + ` FROM entitlements WHERE ` + where +
			` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(next)
		args = append(args, limit+1)
	} else {
		q = `SELECT ` + entitlementColumns + ` FROM entitlements WHERE ` + where +
			` AND (created_at, id) < ($` + strconv.Itoa(next) + `, $` + strconv.Itoa(next+1) + `)` +
			` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(next+2)
		args = append(args, cursor.CreatedAt, cursor.ID, limit+1)
	}

	rows, err := conn(ctx, r.pool).Query(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Entitlement, 0, limit+1)
	for rows.Next() {
		e, err := scanEntitlement(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, *e)
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

func (r *EntitlementRepo) Update(ctx context.Context, e *domain.Entitlement) error {
	if len(e.Metadata) == 0 {
		e.Metadata = json.RawMessage("{}")
	}
	q := `UPDATE entitlements SET
		name       = $2,
		metadata   = $3,
		updated_at = NOW()
	WHERE id = $1
	RETURNING ` + entitlementColumns
	row := conn(ctx, r.pool).QueryRow(ctx, q, e.ID, e.Name, e.Metadata)
	got, err := scanEntitlement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.NewAppError(core.ErrEntitlementNotFound, "entitlement not found")
		}
		return err
	}
	*e = *got
	return nil
}

func (r *EntitlementRepo) Delete(ctx context.Context, id core.EntitlementID) error {
	tag, err := conn(ctx, r.pool).Exec(ctx, `DELETE FROM entitlements WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrEntitlementNotFound, "entitlement not found")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Policy attachments
// ---------------------------------------------------------------------------

func (r *EntitlementRepo) AttachToPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	for _, eid := range entitlementIDs {
		_, err := conn(ctx, r.pool).Exec(ctx,
			`INSERT INTO policy_entitlements (policy_id, entitlement_id)
			 VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`,
			policyID, eid,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *EntitlementRepo) DetachFromPolicy(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	_, err := conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM policy_entitlements
		 WHERE policy_id = $1 AND entitlement_id = ANY($2)`,
		policyID, entitlementIDsToUUIDs(entitlementIDs),
	)
	return err
}

func (r *EntitlementRepo) ReplacePolicyAttachments(ctx context.Context, policyID core.PolicyID, entitlementIDs []core.EntitlementID) error {
	_, err := conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM policy_entitlements WHERE policy_id = $1`, policyID)
	if err != nil {
		return err
	}
	if len(entitlementIDs) == 0 {
		return nil
	}
	for _, eid := range entitlementIDs {
		_, err := conn(ctx, r.pool).Exec(ctx,
			`INSERT INTO policy_entitlements (policy_id, entitlement_id)
			 VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`,
			policyID, eid,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *EntitlementRepo) ListPolicyCodes(ctx context.Context, policyID core.PolicyID) ([]string, error) {
	q := `SELECT e.code FROM entitlements e
	      JOIN policy_entitlements pe ON pe.entitlement_id = e.id
	      WHERE pe.policy_id = $1
	      ORDER BY e.code ASC`
	rows, err := conn(ctx, r.pool).Query(ctx, q, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, rows.Err()
}

// ---------------------------------------------------------------------------
// License attachments
// ---------------------------------------------------------------------------

func (r *EntitlementRepo) AttachToLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	for _, eid := range entitlementIDs {
		_, err := conn(ctx, r.pool).Exec(ctx,
			`INSERT INTO license_entitlements (license_id, entitlement_id)
			 VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`,
			licenseID, eid,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *EntitlementRepo) DetachFromLicense(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	if len(entitlementIDs) == 0 {
		return nil
	}
	_, err := conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM license_entitlements
		 WHERE license_id = $1 AND entitlement_id = ANY($2)`,
		licenseID, entitlementIDsToUUIDs(entitlementIDs),
	)
	return err
}

func (r *EntitlementRepo) ReplaceLicenseAttachments(ctx context.Context, licenseID core.LicenseID, entitlementIDs []core.EntitlementID) error {
	_, err := conn(ctx, r.pool).Exec(ctx,
		`DELETE FROM license_entitlements WHERE license_id = $1`, licenseID)
	if err != nil {
		return err
	}
	if len(entitlementIDs) == 0 {
		return nil
	}
	for _, eid := range entitlementIDs {
		_, err := conn(ctx, r.pool).Exec(ctx,
			`INSERT INTO license_entitlements (license_id, entitlement_id)
			 VALUES ($1, $2)
			 ON CONFLICT DO NOTHING`,
			licenseID, eid,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *EntitlementRepo) ListLicenseCodes(ctx context.Context, licenseID core.LicenseID) ([]string, error) {
	q := `SELECT e.code FROM entitlements e
	      JOIN license_entitlements le ON le.entitlement_id = e.id
	      WHERE le.license_id = $1
	      ORDER BY e.code ASC`
	rows, err := conn(ctx, r.pool).Query(ctx, q, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, rows.Err()
}

// ---------------------------------------------------------------------------
// Effective entitlements
// ---------------------------------------------------------------------------

func (r *EntitlementRepo) ResolveEffective(ctx context.Context, licenseID core.LicenseID) ([]string, error) {
	q := `SELECT DISTINCT e.code FROM entitlements e
	      WHERE e.id IN (
	          SELECT pe.entitlement_id FROM policy_entitlements pe
	          JOIN licenses l ON l.policy_id = pe.policy_id
	          WHERE l.id = $1
	          UNION
	          SELECT le.entitlement_id FROM license_entitlements le
	          WHERE le.license_id = $1
	      )
	      ORDER BY e.code ASC`
	rows, err := conn(ctx, r.pool).Query(ctx, q, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, rows.Err()
}
