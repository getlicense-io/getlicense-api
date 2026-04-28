package testfakes

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// ProductRepo is an in-memory domain.ProductRepository fake.
type ProductRepo struct {
	byID map[core.ProductID]*domain.Product
}

func NewProductRepo() *ProductRepo {
	return &ProductRepo{byID: make(map[core.ProductID]*domain.Product)}
}

// Compile-time check.
var _ domain.ProductRepository = (*ProductRepo)(nil)

// Seed inserts a product directly without going through Create.
// Returns the same pointer for chaining/inspection.
func (r *ProductRepo) Seed(p *domain.Product) *domain.Product {
	r.byID[p.ID] = p
	return p
}

func (r *ProductRepo) Create(_ context.Context, p *domain.Product) error {
	r.byID[p.ID] = p
	return nil
}

func (r *ProductRepo) GetByID(_ context.Context, id core.ProductID) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (r *ProductRepo) List(_ context.Context, _ core.Cursor, _ int) ([]domain.Product, bool, error) {
	return nil, false, nil
}

func (r *ProductRepo) Update(_ context.Context, id core.ProductID, params domain.UpdateProductParams) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	if params.Name != nil {
		p.Name = *params.Name
	}
	cp := *p
	return &cp, nil
}

func (r *ProductRepo) Delete(_ context.Context, id core.ProductID) error {
	delete(r.byID, id)
	return nil
}

func (r *ProductRepo) GetSummariesByIDs(_ context.Context, ids []core.ProductID) ([]domain.ProductSummary, error) {
	out := make([]domain.ProductSummary, 0, len(ids))
	for _, id := range ids {
		if p, ok := r.byID[id]; ok {
			out = append(out, domain.ProductSummary{
				ID:   p.ID,
				Name: p.Name,
				Slug: p.Slug,
			})
		}
	}
	return out, nil
}

func (r *ProductRepo) Search(_ context.Context, _ string, _ int) ([]domain.Product, error) {
	return nil, nil
}
