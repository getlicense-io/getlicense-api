package db

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// customerColumns is the canonical select list for single-table
// customer queries. DO NOT reuse inside JOINs — use fully qualified
// aliases in join queries (see CLAUDE.md Gotchas).
const customerColumns = `
	id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
`

type CustomerRepo struct {
	pool *pgxpool.Pool
}

var _ domain.CustomerRepository = (*CustomerRepo)(nil)

func NewCustomerRepo(pool *pgxpool.Pool) *CustomerRepo { return &CustomerRepo{pool: pool} }

func scanCustomer(s scannable) (*domain.Customer, error) {
	c := &domain.Customer{}
	err := s.Scan(
		&c.ID, &c.AccountID, &c.Email, &c.Name, &c.Metadata,
		&c.CreatedByAccountID, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (r *CustomerRepo) Create(ctx context.Context, c *domain.Customer) error {
	// metadata is NOT NULL in the schema; the column default only fires
	// when the column is omitted from the INSERT column list, not when
	// we pass an explicit nil. Coerce to '{}' to avoid a NOT NULL
	// violation on callers that don't populate metadata. (Same pattern
	// as policy_repo.Create.)
	if len(c.Metadata) == 0 {
		c.Metadata = json.RawMessage("{}")
	}
	q := `INSERT INTO customers (
		id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := conn(ctx, r.pool).Exec(ctx, q,
		c.ID, c.AccountID, c.Email, c.Name, c.Metadata,
		c.CreatedByAccountID, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (r *CustomerRepo) Get(ctx context.Context, id core.CustomerID) (*domain.Customer, error) {
	q := `SELECT ` + customerColumns + ` FROM customers WHERE id = $1`
	row := conn(ctx, r.pool).QueryRow(ctx, q, id)
	c, err := scanCustomer(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return c, nil
}

func (r *CustomerRepo) GetByEmail(ctx context.Context, accountID core.AccountID, email string) (*domain.Customer, error) {
	// The account_id filter is redundant under a WithTargetAccount tx
	// (RLS enforces the same), but we keep it for clarity and to allow
	// callers outside a tenant context (e.g. background jobs) to query
	// deterministically. The unique index on (account_id, lower(email))
	// makes this query cheap.
	q := `SELECT ` + customerColumns + `
	      FROM customers
	      WHERE account_id = $1 AND lower(email) = lower($2)`
	row := conn(ctx, r.pool).QueryRow(ctx, q, accountID, email)
	c, err := scanCustomer(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return c, nil
}

func (r *CustomerRepo) List(ctx context.Context, accountID core.AccountID, filter domain.CustomerListFilter, cursor core.Cursor, limit int) ([]domain.Customer, bool, error) {
	args := []any{accountID}
	where := "account_id = $1"
	next := 2
	if filter.Email != "" {
		where += " AND lower(email) LIKE lower($" + strconv.Itoa(next) + ") || '%'"
		args = append(args, filter.Email)
		next++
	}
	if filter.CreatedByAccountID != nil {
		where += " AND created_by_account_id = $" + strconv.Itoa(next)
		args = append(args, *filter.CreatedByAccountID)
		next++
	}
	var q string
	if cursor.IsZero() {
		q = `SELECT ` + customerColumns + ` FROM customers WHERE ` + where +
			` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(next)
		args = append(args, limit+1)
	} else {
		q = `SELECT ` + customerColumns + ` FROM customers WHERE ` + where +
			` AND (created_at, id) < ($` + strconv.Itoa(next) + `, $` + strconv.Itoa(next+1) + `)` +
			` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(next+2)
		args = append(args, cursor.CreatedAt, cursor.ID, limit+1)
	}
	rows, err := conn(ctx, r.pool).Query(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Customer, 0, limit+1)
	for rows.Next() {
		c, err := scanCustomer(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, *c)
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

func (r *CustomerRepo) Update(ctx context.Context, c *domain.Customer) error {
	if len(c.Metadata) == 0 {
		c.Metadata = json.RawMessage("{}")
	}
	q := `UPDATE customers SET
		name       = $2,
		metadata   = $3,
		updated_at = NOW()
	WHERE id = $1
	RETURNING ` + customerColumns
	row := conn(ctx, r.pool).QueryRow(ctx, q, c.ID, c.Name, c.Metadata)
	got, err := scanCustomer(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
		}
		return err
	}
	*c = *got
	return nil
}

func (r *CustomerRepo) Delete(ctx context.Context, id core.CustomerID) error {
	tag, err := conn(ctx, r.pool).Exec(ctx, `DELETE FROM customers WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	return nil
}

func (r *CustomerRepo) CountReferencingLicenses(ctx context.Context, id core.CustomerID) (int, error) {
	var n int
	err := conn(ctx, r.pool).QueryRow(ctx,
		`SELECT count(*) FROM licenses WHERE customer_id = $1`, id).Scan(&n)
	return n, err
}

func (r *CustomerRepo) UpsertByEmail(
	ctx context.Context,
	accountID core.AccountID,
	email string,
	name *string,
	metadata json.RawMessage,
	createdByAccountID *core.AccountID,
) (*domain.Customer, bool, error) {
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}
	// Try fetch first — cheaper than INSERT+ON CONFLICT when the
	// customer already exists.
	existing, err := r.GetByEmail(ctx, accountID, email)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		return existing, false, nil
	}
	now := timeNow()
	c := &domain.Customer{
		ID:                 core.NewCustomerID(),
		AccountID:          accountID,
		Email:              email,
		Name:               name,
		Metadata:           metadata,
		CreatedByAccountID: createdByAccountID,
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	// ON CONFLICT handles the race where two concurrent license
	// creates insert the same new email. The conflict target is the
	// unique index on (account_id, lower(email)).
	q := `INSERT INTO customers (
		id, account_id, email, name, metadata, created_by_account_id, created_at, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	ON CONFLICT (account_id, lower(email)) DO NOTHING
	RETURNING ` + customerColumns
	row := conn(ctx, r.pool).QueryRow(ctx, q,
		c.ID, c.AccountID, c.Email, c.Name, c.Metadata,
		c.CreatedByAccountID, c.CreatedAt, c.UpdatedAt,
	)
	inserted, scanErr := scanCustomer(row)
	if scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Conflict — another concurrent tx inserted first. Re-fetch.
			existing, err := r.GetByEmail(ctx, accountID, email)
			if err != nil {
				return nil, false, err
			}
			if existing == nil {
				return nil, false, errors.New("customer_repo: upsert conflict without matching row")
			}
			return existing, false, nil
		}
		return nil, false, scanErr
	}
	return inserted, true, nil
}

// timeNow is a package-level shim so tests can stub it if needed.
var timeNow = func() time.Time { return time.Now().UTC() }
