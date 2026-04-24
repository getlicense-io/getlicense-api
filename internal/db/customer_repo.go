package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CustomerRepo implements domain.CustomerRepository against sqlc-generated
// queries. Account-scoped, environment-agnostic. Email uniqueness is
// enforced by the partial unique index customers_account_email_ci on
// (account_id, lower(email)). Create does NOT classify unique violations
// — callers funnel duplicate handling through UpsertByEmail instead.
type CustomerRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.CustomerRepository = (*CustomerRepo)(nil)

// NewCustomerRepo creates a new CustomerRepo.
func NewCustomerRepo(pool *pgxpool.Pool) *CustomerRepo {
	return &CustomerRepo{pool: pool, q: sqlcgen.New()}
}

// timeNow is a package-level shim so tests can stub it if needed.
var timeNow = func() time.Time { return time.Now().UTC() }

// customerFromRow is the single translation seam for plain customer
// rows (no JOIN). Used by GetByEmail, Update, and UpsertByEmail.
// CreatedByAccount stays nil on this path — callers that need
// creator-attribution embedding go through the JOIN variants.
func customerFromRow(row sqlcgen.Customer) domain.Customer {
	return domain.Customer{
		ID:                 idFromPgUUID[core.CustomerID](row.ID),
		AccountID:          idFromPgUUID[core.AccountID](row.AccountID),
		Email:              row.Email,
		Name:               row.Name,
		Metadata:           json.RawMessage(row.Metadata),
		CreatedByAccountID: nullableIDFromPgUUID[core.AccountID](row.CreatedByAccountID),
		CreatedAt:          row.CreatedAt,
		UpdatedAt:          row.UpdatedAt,
	}
}

// customerJoinFields captures every column read by the JOIN-variant
// queries so the two per-query row structs (GetCustomerByIDWithCreatorRow,
// ListCustomersWithCreatorRow) funnel through one translation seam.
// CreatorName and CreatorSlug are *string because the LEFT JOIN returns
// NULL for vendor-created customers (created_by_account_id is nil) —
// the adapter gates embedding on CreatedByAccountID, not on the
// creator_* columns, so the pointer check here is defense in depth.
type customerJoinFields struct {
	ID                 pgtype.UUID
	AccountID          pgtype.UUID
	Email              string
	Name               *string
	Metadata           []byte
	CreatedByAccountID pgtype.UUID
	CreatedAt          time.Time
	UpdatedAt          time.Time
	CreatorName        *string
	CreatorSlug        *string
}

// customerFromJoinFields is the single translation seam for JOIN reads.
// Populates Customer.CreatedByAccount from creator_name / creator_slug
// only when created_by_account_id is non-nil; vendor-created customers
// leave CreatedByAccount == nil.
func customerFromJoinFields(f customerJoinFields) domain.Customer {
	out := domain.Customer{
		ID:                 idFromPgUUID[core.CustomerID](f.ID),
		AccountID:          idFromPgUUID[core.AccountID](f.AccountID),
		Email:              f.Email,
		Name:               f.Name,
		Metadata:           json.RawMessage(f.Metadata),
		CreatedByAccountID: nullableIDFromPgUUID[core.AccountID](f.CreatedByAccountID),
		CreatedAt:          f.CreatedAt,
		UpdatedAt:          f.UpdatedAt,
	}
	if out.CreatedByAccountID != nil && f.CreatorName != nil && f.CreatorSlug != nil {
		out.CreatedByAccount = &domain.AccountSummary{
			ID:   *out.CreatedByAccountID,
			Name: *f.CreatorName,
			Slug: *f.CreatorSlug,
		}
	}
	return out
}

// Create inserts a new customer row. Empty metadata is coerced to `{}`
// so the NOT NULL jsonb column is satisfied. Unique-violation on the
// case-insensitive (account_id, email) index is translated to
// core.ErrCustomerAlreadyExists → 409 so the direct vendor-side POST
// /v1/customers path does not leak 500s when a client re-POSTs the
// same email. Grant-scoped and licensing callers funnel through
// UpsertByEmail and never trip this path.
func (r *CustomerRepo) Create(ctx context.Context, c *domain.Customer) error {
	if len(c.Metadata) == 0 {
		c.Metadata = json.RawMessage("{}")
	}
	err := r.q.CreateCustomer(ctx, conn(ctx, r.pool), sqlcgen.CreateCustomerParams{
		ID:                 pgUUIDFromID(c.ID),
		AccountID:          pgUUIDFromID(c.AccountID),
		Email:              c.Email,
		Name:               c.Name,
		Metadata:           c.Metadata,
		CreatedByAccountID: pgUUIDFromIDPtr(c.CreatedByAccountID),
		CreatedAt:          c.CreatedAt,
		UpdatedAt:          c.UpdatedAt,
	})
	if IsUniqueViolation(err, ConstraintCustomerEmailUnique) {
		return core.NewAppError(core.ErrCustomerAlreadyExists, "A customer with that email already exists")
	}
	return err
}

// Get returns the customer with the given id, or nil if not found
// (or filtered by RLS). The JOIN variant populates CreatedByAccount
// so API responses surface partner attribution in a single round trip.
func (r *CustomerRepo) Get(ctx context.Context, id core.CustomerID) (*domain.Customer, error) {
	row, err := r.q.GetCustomerByIDWithCreator(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c := customerFromJoinFields(customerJoinFields{
		ID:                 row.ID,
		AccountID:          row.AccountID,
		Email:              row.Email,
		Name:               row.Name,
		Metadata:           row.Metadata,
		CreatedByAccountID: row.CreatedByAccountID,
		CreatedAt:          row.CreatedAt,
		UpdatedAt:          row.UpdatedAt,
		CreatorName:        row.CreatorName,
		CreatorSlug:        row.CreatorSlug,
	})
	return &c, nil
}

// GetByEmail looks up a customer by (accountID, email) case-insensitively.
// Returns nil when no row exists.
func (r *CustomerRepo) GetByEmail(ctx context.Context, accountID core.AccountID, email string) (*domain.Customer, error) {
	row, err := r.q.GetCustomerByEmail(ctx, conn(ctx, r.pool), sqlcgen.GetCustomerByEmailParams{
		AccountID: pgUUIDFromID(accountID),
		Email:     email,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c := customerFromRow(row)
	return &c, nil
}

// List returns one cursor page of customers for the given account. The
// filter fields are all optional — empty string / nil disables the
// corresponding predicate via the sqlc.narg NULL-guard pattern.
func (r *CustomerRepo) List(ctx context.Context, accountID core.AccountID, filter domain.CustomerListFilter, cursor core.Cursor, limit int) ([]domain.Customer, bool, error) {
	ts, id := cursorParams(cursor)
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}

	// CreatedBy narg emits as pgtype.UUID because the SQL uses a `::uuid`
	// cast on the narg. nil filter → Valid=false → NULL narg → predicate
	// short-circuited.
	var createdBy pgtype.UUID
	if filter.CreatedByAccountID != nil {
		createdBy = pgtype.UUID{Bytes: [16]byte(*filter.CreatedByAccountID), Valid: true}
	}

	rows, err := r.q.ListCustomersWithCreator(ctx, conn(ctx, r.pool), sqlcgen.ListCustomersWithCreatorParams{
		AccountID:    pgUUIDFromID(accountID),
		EmailPrefix:  nilIfEmpty(filter.Email),
		NamePrefix:   nilIfEmpty(filter.Name),
		CreatedBy:    createdBy,
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Customer, 0, len(rows))
	for _, row := range rows {
		out = append(out, customerFromJoinFields(customerJoinFields{
			ID:                 row.ID,
			AccountID:          row.AccountID,
			Email:              row.Email,
			Name:               row.Name,
			Metadata:           row.Metadata,
			CreatedByAccountID: row.CreatedByAccountID,
			CreatedAt:          row.CreatedAt,
			UpdatedAt:          row.UpdatedAt,
			CreatorName:        row.CreatorName,
			CreatorSlug:        row.CreatorSlug,
		}))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// Update applies name + metadata mutations and rewrites updated_at.
// Returns core.ErrCustomerNotFound when no row matches the id.
func (r *CustomerRepo) Update(ctx context.Context, c *domain.Customer) error {
	if len(c.Metadata) == 0 {
		c.Metadata = json.RawMessage("{}")
	}
	row, err := r.q.UpdateCustomer(ctx, conn(ctx, r.pool), sqlcgen.UpdateCustomerParams{
		ID:       pgUUIDFromID(c.ID),
		Name:     c.Name,
		Metadata: c.Metadata,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	if err != nil {
		return err
	}
	*c = customerFromRow(row)
	return nil
}

// Delete removes the customer with the given id. Returns
// core.ErrCustomerNotFound when no row was affected.
func (r *CustomerRepo) Delete(ctx context.Context, id core.CustomerID) error {
	n, err := r.q.DeleteCustomer(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrCustomerNotFound, "customer not found")
	}
	return nil
}

// CountReferencingLicenses returns the number of license rows that
// reference this customer (any status). Used by the service layer to
// block deletion of in-use customers.
func (r *CustomerRepo) CountReferencingLicenses(ctx context.Context, id core.CustomerID) (int, error) {
	n, err := r.q.CountLicensesReferencingCustomer(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	return int(n), err
}

// UpsertByEmail inserts a new customer row or returns the existing one
// keyed on (account_id, lower(email)). The flow is:
//
//  1. GET first — cheap for the common hit-case (existing customer).
//  2. INSERT ... ON CONFLICT DO NOTHING RETURNING — loses the race
//     cleanly on concurrent inserts (empty RETURNING → ErrNoRows).
//  3. On ErrNoRows, re-fetch to return the winning row.
//
// Returns (customer, inserted, err). On conflict the returned row is the
// pre-existing customer UNCHANGED — name and metadata from this call are
// discarded (first-write-wins per spec §Upsert semantics).
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
	db := conn(ctx, r.pool)

	// 1) Try fetch first.
	existing, err := r.GetByEmail(ctx, accountID, email)
	if err != nil {
		return nil, false, err
	}
	if existing != nil {
		return existing, false, nil
	}

	// 2) Try insert with DO NOTHING.
	now := timeNow()
	row, err := r.q.UpsertCustomerByEmail(ctx, db, sqlcgen.UpsertCustomerByEmailParams{
		ID:                 pgUUIDFromID(core.NewCustomerID()),
		AccountID:          pgUUIDFromID(accountID),
		Email:              email,
		Name:               name,
		Metadata:           metadata,
		CreatedByAccountID: pgUUIDFromIDPtr(createdByAccountID),
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err == nil {
		c := customerFromRow(row)
		return &c, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}

	// 3) Conflict — another tx won. Refetch.
	existing, err = r.GetByEmail(ctx, accountID, email)
	if err != nil {
		return nil, false, err
	}
	if existing == nil {
		return nil, false, errors.New("customer_repo: upsert conflict without matching row")
	}
	return existing, false, nil
}
