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
		&p.ValidationTTL, &p.GracePeriod, &p.Metadata, &p.CreatedAt,
	)
	if err != nil {
		return p, err
	}
	p.ID = core.ProductID(rawID)
	p.AccountID = core.AccountID(rawAccountID)
	return p, nil
}

// ProductRepo implements domain.ProductRepository using PostgreSQL.
type ProductRepo struct {
	pool *pgxpool.Pool
}

var _ domain.ProductRepository = (*ProductRepo)(nil)

// NewProductRepo creates a new ProductRepo.
func NewProductRepo(pool *pgxpool.Pool) *ProductRepo {
	return &ProductRepo{pool: pool}
}

// Create inserts a new product into the database.
func (r *ProductRepo) Create(ctx context.Context, product *domain.Product) error {
	q := conn(ctx, r.pool)
	_, err := q.Exec(ctx,
		`INSERT INTO products (id, account_id, name, slug, public_key, private_key_enc,
		 validation_ttl, grace_period, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		uuid.UUID(product.ID), uuid.UUID(product.AccountID),
		product.Name, product.Slug, product.PublicKey, product.PrivateKeyEnc,
		product.ValidationTTL, product.GracePeriod, product.Metadata, product.CreatedAt,
	)
	return err
}

// GetByID returns the product with the given ID, or nil if not found.
func (r *ProductRepo) GetByID(ctx context.Context, id core.ProductID) (*domain.Product, error) {
	q := conn(ctx, r.pool)
	p, err := scanProduct(q.QueryRow(ctx,
		`SELECT id, account_id, name, slug, public_key, private_key_enc,
		 validation_ttl, grace_period, metadata, created_at
		 FROM products WHERE id = $1`,
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

// List returns a paginated list of products and the total count.
func (r *ProductRepo) List(ctx context.Context, limit, offset int) ([]domain.Product, int, error) {
	q := conn(ctx, r.pool)

	var total int
	err := q.QueryRow(ctx, `SELECT COUNT(*) FROM products`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := q.Query(ctx,
		`SELECT id, account_id, name, slug, public_key, private_key_enc,
		 validation_ttl, grace_period, metadata, created_at
		 FROM products ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var products []domain.Product
	for rows.Next() {
		p, err := scanProduct(rows)
		if err != nil {
			return nil, 0, err
		}
		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return products, total, nil
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
		   name           = COALESCE($2, name),
		   validation_ttl = COALESCE($3, validation_ttl),
		   grace_period   = COALESCE($4, grace_period),
		   metadata       = COALESCE($5, metadata)
		 WHERE id = $1
		 RETURNING id, account_id, name, slug, public_key, private_key_enc,
		           validation_ttl, grace_period, metadata, created_at`,
		uuid.UUID(id),
		params.Name,
		params.ValidationTTL,
		params.GracePeriod,
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
