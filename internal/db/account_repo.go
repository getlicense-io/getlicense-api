package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	sqlcgen "github.com/getlicense-io/getlicense-api/internal/db/sqlc/gen"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AccountRepo implements domain.AccountRepository against sqlc-generated
// queries. It holds no per-call state; the DBTX (tx or pool) is extracted
// from request context via conn() on each call. Translation between
// sqlcgen.Account and domain.Account happens at the adapter boundary
// through accountFromRow.
type AccountRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.AccountRepository = (*AccountRepo)(nil)

// NewAccountRepo creates a new AccountRepo.
func NewAccountRepo(pool *pgxpool.Pool) *AccountRepo {
	return &AccountRepo{pool: pool, q: sqlcgen.New()}
}

// accountFromRow is the single translation seam for account rows. Every
// Get / List / RETURNING path that produces a sqlcgen.Account converts
// through here, keeping sqlcgen quirks (pgtype.UUID) out of the domain.
func accountFromRow(row sqlcgen.Account) domain.Account {
	return domain.Account{
		ID:        idFromPgUUID[core.AccountID](row.ID),
		Name:      row.Name,
		Slug:      row.Slug,
		CreatedAt: row.CreatedAt,
	}
}

// Create inserts a new account into the database.
func (r *AccountRepo) Create(ctx context.Context, account *domain.Account) error {
	err := r.q.CreateAccount(ctx, conn(ctx, r.pool), sqlcgen.CreateAccountParams{
		ID:        pgUUIDFromID(account.ID),
		Name:      account.Name,
		Slug:      account.Slug,
		CreatedAt: account.CreatedAt,
	})
	if IsUniqueViolation(err, ConstraintAccountSlugUnique) {
		return core.NewAppError(core.ErrAccountAlreadyExists, "An account with that name already exists")
	}
	return err
}

// GetByID returns the account with the given ID, or nil if not found.
func (r *AccountRepo) GetByID(ctx context.Context, id core.AccountID) (*domain.Account, error) {
	row, err := r.q.GetAccountByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := accountFromRow(row)
	return &a, nil
}

// GetBySlug returns the account with the given slug, or nil if not found.
func (r *AccountRepo) GetBySlug(ctx context.Context, slug string) (*domain.Account, error) {
	row, err := r.q.GetAccountBySlug(ctx, conn(ctx, r.pool), slug)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := accountFromRow(row)
	return &a, nil
}

// GetIfAccessible returns the target account only if the caller has a
// visibility relationship with it: (a) a membership in the target
// account under the caller's identity, or (b) a non-terminal grant
// (pending/active/suspended) between the caller and target in either
// direction. Otherwise returns (nil, nil). Runs outside tenant RLS —
// the access predicate is explicit, and the query must be able to read
// rows in either tenant, so callers MUST NOT pin app.current_account_id
// before invoking.
func (r *AccountRepo) GetIfAccessible(
	ctx context.Context,
	targetID core.AccountID,
	callerAccountID core.AccountID,
	callerIdentityID core.IdentityID,
) (*domain.Account, error) {
	row, err := r.q.GetAccountIfAccessible(ctx, conn(ctx, r.pool), sqlcgen.GetAccountIfAccessibleParams{
		TargetID:         pgUUIDFromID(targetID),
		CallerIdentityID: pgUUIDFromID(callerIdentityID),
		CallerAccountID:  pgUUIDFromID(callerAccountID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a := accountFromRow(row)
	return &a, nil
}
