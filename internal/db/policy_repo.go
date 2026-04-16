package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// policyColumns is the canonical select list for single-table policy
// queries. DO NOT reuse inside JOINs — use fully qualified aliases in
// join queries to avoid ambiguous column errors (see CLAUDE.md Gotchas).
const policyColumns = `
	id, account_id, product_id, name, is_default,
	duration_seconds, expiration_strategy, expiration_basis,
	max_machines, max_seats, floating, strict,
	require_checkout, checkout_interval_sec, max_checkout_duration_sec, checkout_grace_sec,
	component_matching_strategy, metadata, created_at, updated_at
`

type PolicyRepo struct {
	pool *pgxpool.Pool
}

var _ domain.PolicyRepository = (*PolicyRepo)(nil)

func NewPolicyRepo(pool *pgxpool.Pool) *PolicyRepo { return &PolicyRepo{pool: pool} }

func scanPolicy(s scannable) (*domain.Policy, error) {
	p := &domain.Policy{}
	err := s.Scan(
		&p.ID, &p.AccountID, &p.ProductID, &p.Name, &p.IsDefault,
		&p.DurationSeconds, &p.ExpirationStrategy, &p.ExpirationBasis,
		&p.MaxMachines, &p.MaxSeats, &p.Floating, &p.Strict,
		&p.RequireCheckout, &p.CheckoutIntervalSec, &p.MaxCheckoutDurationSec, &p.CheckoutGraceSec,
		&p.ComponentMatchingStrategy, &p.Metadata, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *PolicyRepo) Create(ctx context.Context, p *domain.Policy) error {
	q := `INSERT INTO policies (
		id, account_id, product_id, name, is_default,
		duration_seconds, expiration_strategy, expiration_basis,
		max_machines, max_seats, floating, strict,
		require_checkout, checkout_interval_sec, max_checkout_duration_sec, checkout_grace_sec,
		component_matching_strategy, metadata, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8,
		$9, $10, $11, $12,
		$13, $14, $15, $16,
		$17, $18, $19, $20
	)`
	// metadata is NOT NULL in the schema; the column default only fires
	// when the column is omitted from the INSERT column list, not when
	// we pass an explicit nil. Coerce to an empty JSON object so callers
	// who don't care about metadata (e.g. product auto-default policy)
	// get the intended {} instead of a NOT NULL violation.
	if len(p.Metadata) == 0 {
		p.Metadata = []byte("{}")
	}
	_, err := conn(ctx, r.pool).Exec(ctx, q,
		p.ID, p.AccountID, p.ProductID, p.Name, p.IsDefault,
		p.DurationSeconds, p.ExpirationStrategy, p.ExpirationBasis,
		p.MaxMachines, p.MaxSeats, p.Floating, p.Strict,
		p.RequireCheckout, p.CheckoutIntervalSec, p.MaxCheckoutDurationSec, p.CheckoutGraceSec,
		p.ComponentMatchingStrategy, p.Metadata, p.CreatedAt, p.UpdatedAt,
	)
	return err
}

func (r *PolicyRepo) Get(ctx context.Context, id core.PolicyID) (*domain.Policy, error) {
	q := `SELECT ` + policyColumns + ` FROM policies WHERE id = $1`
	row := conn(ctx, r.pool).QueryRow(ctx, q, id)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

func (r *PolicyRepo) GetByProduct(ctx context.Context, productID core.ProductID, cursor core.Cursor, limit int) ([]domain.Policy, bool, error) {
	// Cursor pagination matching Release 1 pattern: (created_at DESC, id DESC).
	// Fetch limit+1 to detect has_more.
	q := conn(ctx, r.pool)
	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+policyColumns+` FROM policies
			 WHERE product_id = $1
			 ORDER BY created_at DESC, id DESC LIMIT $2`,
			productID, limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+policyColumns+` FROM policies
			 WHERE product_id = $1 AND (created_at, id) < ($2, $3)
			 ORDER BY created_at DESC, id DESC LIMIT $4`,
			productID, cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Policy, 0, limit+1)
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, *p)
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

func (r *PolicyRepo) GetDefaultForProduct(ctx context.Context, productID core.ProductID) (*domain.Policy, error) {
	q := `SELECT ` + policyColumns + ` FROM policies WHERE product_id = $1 AND is_default = true`
	row := conn(ctx, r.pool).QueryRow(ctx, q, productID)
	p, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return p, nil
}

func (r *PolicyRepo) Update(ctx context.Context, p *domain.Policy) error {
	q := `UPDATE policies SET
		name = $2,
		duration_seconds = $3,
		expiration_strategy = $4,
		expiration_basis = $5,
		max_machines = $6,
		max_seats = $7,
		floating = $8,
		strict = $9,
		require_checkout = $10,
		checkout_interval_sec = $11,
		max_checkout_duration_sec = $12,
		checkout_grace_sec = $13,
		component_matching_strategy = $14,
		metadata = $15,
		updated_at = NOW()
	WHERE id = $1
	RETURNING ` + policyColumns
	if len(p.Metadata) == 0 {
		p.Metadata = []byte("{}")
	}
	row := conn(ctx, r.pool).QueryRow(ctx, q,
		p.ID, p.Name, p.DurationSeconds, p.ExpirationStrategy, p.ExpirationBasis,
		p.MaxMachines, p.MaxSeats, p.Floating, p.Strict,
		p.RequireCheckout, p.CheckoutIntervalSec, p.MaxCheckoutDurationSec, p.CheckoutGraceSec,
		p.ComponentMatchingStrategy, p.Metadata,
	)
	result, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		return err
	}
	*p = *result
	return nil
}

func (r *PolicyRepo) Delete(ctx context.Context, id core.PolicyID) error {
	tag, err := conn(ctx, r.pool).Exec(ctx, `DELETE FROM policies WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
	}
	return nil
}

func (r *PolicyRepo) SetDefault(ctx context.Context, productID core.ProductID, policyID core.PolicyID) error {
	// Clear old default then set new, inside the ambient tx (caller
	// must ensure WithTargetAccount / WithTx wraps this call).
	if _, err := conn(ctx, r.pool).Exec(ctx,
		`UPDATE policies SET is_default = false, updated_at = NOW()
		 WHERE product_id = $1 AND is_default = true`, productID); err != nil {
		return err
	}
	tag, err := conn(ctx, r.pool).Exec(ctx,
		`UPDATE policies SET is_default = true, updated_at = NOW()
		 WHERE id = $1 AND product_id = $2`, policyID, productID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrPolicyProductMismatch, "policy does not belong to product")
	}
	return nil
}

func (r *PolicyRepo) ReassignLicensesFromPolicy(ctx context.Context, fromPolicyID, toPolicyID core.PolicyID) (int, error) {
	tag, err := conn(ctx, r.pool).Exec(ctx,
		`UPDATE licenses SET policy_id = $2, updated_at = NOW() WHERE policy_id = $1`,
		fromPolicyID, toPolicyID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (r *PolicyRepo) CountReferencingLicenses(ctx context.Context, id core.PolicyID) (int, error) {
	var n int
	err := conn(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM licenses WHERE policy_id = $1`, id).Scan(&n)
	return n, err
}
