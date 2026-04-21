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

// ProductRepo implements domain.ProductRepository against sqlc-generated
// queries. All reads are RLS-scoped; Create classifies a unique-violation
// on (account_id, slug) as core.ErrProductAlreadyExists.
type ProductRepo struct {
	pool *pgxpool.Pool
	q    *sqlcgen.Queries
}

var _ domain.ProductRepository = (*ProductRepo)(nil)

// NewProductRepo creates a new ProductRepo.
func NewProductRepo(pool *pgxpool.Pool) *ProductRepo {
	return &ProductRepo{pool: pool, q: sqlcgen.New()}
}

// productFromRow is the single translation seam for product rows. The
// jsonb metadata column comes back as []byte; we hand it to the domain
// struct as json.RawMessage with no copy (same underlying bytes).
func productFromRow(row sqlcgen.Product) domain.Product {
	return domain.Product{
		ID:            idFromPgUUID[core.ProductID](row.ID),
		AccountID:     idFromPgUUID[core.AccountID](row.AccountID),
		Name:          row.Name,
		Slug:          row.Slug,
		PublicKey:     row.PublicKey,
		PrivateKeyEnc: row.PrivateKeyEnc,
		Metadata:      json.RawMessage(row.Metadata),
		CreatedAt:     row.CreatedAt,
	}
}

// Create inserts a new product row. Empty Metadata is coerced to `{}`
// so the NOT NULL jsonb column is satisfied. A unique-violation on
// (account_id, slug) is translated to core.ErrProductAlreadyExists.
func (r *ProductRepo) Create(ctx context.Context, p *domain.Product) error {
	if len(p.Metadata) == 0 {
		p.Metadata = json.RawMessage("{}")
	}
	err := r.q.CreateProduct(ctx, conn(ctx, r.pool), sqlcgen.CreateProductParams{
		ID:            pgUUIDFromID(p.ID),
		AccountID:     pgUUIDFromID(p.AccountID),
		Name:          p.Name,
		Slug:          p.Slug,
		PublicKey:     p.PublicKey,
		PrivateKeyEnc: p.PrivateKeyEnc,
		Metadata:      p.Metadata,
		CreatedAt:     p.CreatedAt,
	})
	if IsUniqueViolation(err, ConstraintProductSlugUnique) {
		return core.NewAppError(
			core.ErrProductAlreadyExists,
			"A product with this name already exists",
		)
	}
	return err
}

// GetByID returns the product with the given id, or nil if not found
// (or filtered by RLS).
func (r *ProductRepo) GetByID(ctx context.Context, id core.ProductID) (*domain.Product, error) {
	row, err := r.q.GetProductByID(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p := productFromRow(row)
	return &p, nil
}

// List returns one cursor page of products for the current RLS-scoped
// tenant. The returned bool is has_more.
func (r *ProductRepo) List(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Product, bool, error) {
	ts, id := cursorParams(cursor)

	// sqlc emits CursorID as pgtype.UUID (non-pointer) for the row
	// comparison; the cursor_ts IS NULL guard fires first, so a
	// zero-value pgtype.UUID on the unset-cursor branch is never read.
	var cursorID pgtype.UUID
	if id != nil {
		cursorID = pgtype.UUID{Bytes: *id, Valid: true}
	}

	rows, err := r.q.ListProducts(ctx, conn(ctx, r.pool), sqlcgen.ListProductsParams{
		CursorTs:     ts,
		CursorID:     cursorID,
		LimitPlusOne: int32(limit + 1),
	})
	if err != nil {
		return nil, false, err
	}
	out := make([]domain.Product, 0, len(rows))
	for _, row := range rows {
		out = append(out, productFromRow(row))
	}
	out, hasMore := sliceHasMore(out, limit)
	return out, hasMore, nil
}

// Update applies the non-nil sparse params to the product and returns
// the updated row. Nil fields are preserved via COALESCE in SQL. An
// empty-but-non-nil Metadata is coerced to `{}` to preserve the
// existing behaviour (domain callers sometimes pass an empty
// json.RawMessage meaning "set to empty object").
func (r *ProductRepo) Update(ctx context.Context, id core.ProductID, params domain.UpdateProductParams) (*domain.Product, error) {
	// metaArg == nil → narg is NULL → COALESCE preserves the existing column.
	// metaArg == []byte("{}") → COALESCE resolves to the new value.
	var metaArg []byte
	if params.Metadata != nil {
		m := *params.Metadata
		if len(m) == 0 {
			m = json.RawMessage("{}")
		}
		metaArg = m
	}

	row, err := r.q.UpdateProduct(ctx, conn(ctx, r.pool), sqlcgen.UpdateProductParams{
		Name:     params.Name,
		Metadata: metaArg,
		ID:       pgUUIDFromID(id),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.NewAppError(core.ErrProductNotFound, "product not found")
	}
	if err != nil {
		return nil, err
	}
	p := productFromRow(row)
	return &p, nil
}

// Delete removes the product with the given id. Returns
// core.ErrProductNotFound when no row was affected.
func (r *ProductRepo) Delete(ctx context.Context, id core.ProductID) error {
	n, err := r.q.DeleteProduct(ctx, conn(ctx, r.pool), pgUUIDFromID(id))
	if err != nil {
		return err
	}
	if n == 0 {
		return core.NewAppError(core.ErrProductNotFound, "product not found")
	}
	return nil
}

// Search returns products whose name or slug prefix-matches the query
// (case-insensitive). Used by the global search endpoint.
func (r *ProductRepo) Search(ctx context.Context, query string, limit int) ([]domain.Product, error) {
	rows, err := r.q.SearchProducts(ctx, conn(ctx, r.pool), sqlcgen.SearchProductsParams{
		Query:     query,
		LimitRows: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Product, 0, len(rows))
	for _, row := range rows {
		out = append(out, productFromRow(row))
	}
	return out, nil
}
