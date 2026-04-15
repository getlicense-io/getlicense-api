package db

import (
	"context"
	"errors"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// scanProduct scans a product row from a scannable (pgx.Row or pgx.Rows).
func scanProduct(s scannable) (domain.Product, error) {
	var p domain.Product
	var rawID, rawAccountID uuid.UUID
	err := s.Scan(
		&rawID, &rawAccountID, &p.Name, &p.Slug, &p.PublicKey, &p.PrivateKeyEnc,
		&p.Metadata, &p.CreatedAt,
	)
	if err != nil {
		return p, err
	}
	p.ID = core.ProductID(rawID)
	p.AccountID = core.AccountID(rawAccountID)
	return p, nil
}

const productColumns = `id, account_id, name, slug, public_key, private_key_enc, metadata, created_at`

// ProductRepo implements domain.ProductRepository using PostgreSQL.
type ProductRepo struct {
	pool *pgxpool.Pool
}

var _ domain.ProductRepository = (*ProductRepo)(nil)

// NewProductRepo creates a new ProductRepo.
func NewProductRepo(pool *pgxpool.Pool) *ProductRepo {
	return &ProductRepo{pool: pool}
}

func (r *ProductRepo) Create(ctx context.Context, product *domain.Product) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO products (`+productColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		uuid.UUID(product.ID), uuid.UUID(product.AccountID),
		product.Name, product.Slug, product.PublicKey, product.PrivateKeyEnc,
		product.Metadata, product.CreatedAt,
	)
	if IsUniqueViolation(err, "products_account_id_slug_key") {
		return core.NewAppError(
			core.ErrProductAlreadyExists,
			"A product with this name already exists",
		)
	}
	return err
}

// GetByID returns the product with the given ID, or nil if not found.
func (r *ProductRepo) GetByID(ctx context.Context, id core.ProductID) (*domain.Product, error) {
	q := conn(ctx, r.pool)
	p, err := scanProduct(q.QueryRow(ctx,
		`SELECT `+productColumns+` FROM products WHERE id = $1`,
		uuid.UUID(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (r *ProductRepo) List(ctx context.Context, cursor core.Cursor, limit int) ([]domain.Product, bool, error) {
	q := conn(ctx, r.pool)

	var rows pgx.Rows
	var err error
	if cursor.IsZero() {
		rows, err = q.Query(ctx,
			`SELECT `+productColumns+` FROM products
			 ORDER BY created_at DESC, id DESC LIMIT $1`,
			limit+1,
		)
	} else {
		rows, err = q.Query(ctx,
			`SELECT `+productColumns+` FROM products
			 WHERE (created_at, id) < ($1, $2)
			 ORDER BY created_at DESC, id DESC LIMIT $3`,
			cursor.CreatedAt, cursor.ID, limit+1,
		)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	out := make([]domain.Product, 0, limit+1)
	for rows.Next() {
		p, err := scanProduct(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, p)
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

// Update applies optional fields from params to the product and returns the updated record.
func (r *ProductRepo) Update(ctx context.Context, id core.ProductID, params domain.UpdateProductParams) (*domain.Product, error) {
	q := conn(ctx, r.pool)

	var metadataArg interface{}
	if params.Metadata != nil {
		metadataArg = *params.Metadata
	}

	p, err := scanProduct(q.QueryRow(ctx,
		`UPDATE products SET
		   name     = COALESCE($2, name),
		   metadata = COALESCE($3, metadata)
		 WHERE id = $1
		 RETURNING `+productColumns,
		uuid.UUID(id),
		params.Name,
		metadataArg,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.NewAppError(core.ErrProductNotFound, "product not found")
		}
		return nil, err
	}
	return &p, nil
}

// Delete removes the product with the given ID.
// Returns ErrProductNotFound if the product does not exist.
func (r *ProductRepo) Delete(ctx context.Context, id core.ProductID) error {
	q := conn(ctx, r.pool)
	tag, err := q.Exec(ctx, `DELETE FROM products WHERE id = $1`, uuid.UUID(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.NewAppError(core.ErrProductNotFound, "product not found")
	}
	return nil
}
