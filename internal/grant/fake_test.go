package grant

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- fake TxManager (passthrough) ---

type fakeTxManager struct{}

func (f *fakeTxManager) WithTargetAccount(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
	return fn(context.Background())
}

func (f *fakeTxManager) WithTx(_ context.Context, fn func(context.Context) error) error {
	return fn(context.Background())
}

// --- fake GrantRepository ---

type fakeGrantRepo struct {
	byID            map[core.GrantID]*domain.Grant
	licenseCounts   map[core.GrantID]int
}

func newFakeGrantRepo() *fakeGrantRepo {
	return &fakeGrantRepo{
		byID:          make(map[core.GrantID]*domain.Grant),
		licenseCounts: make(map[core.GrantID]int),
	}
}

var _ domain.GrantRepository = (*fakeGrantRepo)(nil)

func (r *fakeGrantRepo) Create(_ context.Context, g *domain.Grant) error {
	r.byID[g.ID] = g
	return nil
}

func (r *fakeGrantRepo) GetByID(_ context.Context, id core.GrantID) (*domain.Grant, error) {
	g, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	// Return a copy so callers can't mutate the stored pointer.
	cp := *g
	return &cp, nil
}

func (r *fakeGrantRepo) ListByGrantor(_ context.Context, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
	var out []domain.Grant
	for _, g := range r.byID {
		out = append(out, *g)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (r *fakeGrantRepo) ListByGrantee(_ context.Context, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
	var out []domain.Grant
	for _, g := range r.byID {
		out = append(out, *g)
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (r *fakeGrantRepo) UpdateStatus(_ context.Context, id core.GrantID, status domain.GrantStatus) error {
	g, ok := r.byID[id]
	if !ok {
		return nil
	}
	g.Status = status
	g.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *fakeGrantRepo) MarkAccepted(_ context.Context, id core.GrantID, acceptedAt time.Time) error {
	g, ok := r.byID[id]
	if !ok {
		return nil
	}
	g.Status = domain.GrantStatusActive
	g.AcceptedAt = &acceptedAt
	g.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *fakeGrantRepo) CountLicensesInPeriod(_ context.Context, grantID core.GrantID, _ time.Time) (int, error) {
	return r.licenseCounts[grantID], nil
}

// --- fake ProductRepository ---

type fakeProductRepo struct {
	byID map[core.ProductID]*domain.Product
}

func newFakeProductRepo() *fakeProductRepo {
	return &fakeProductRepo{byID: make(map[core.ProductID]*domain.Product)}
}

var _ domain.ProductRepository = (*fakeProductRepo)(nil)

func (r *fakeProductRepo) Create(_ context.Context, p *domain.Product) error {
	r.byID[p.ID] = p
	return nil
}

func (r *fakeProductRepo) GetByID(_ context.Context, id core.ProductID) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (r *fakeProductRepo) List(_ context.Context, _ core.Cursor, _ int) ([]domain.Product, bool, error) {
	return nil, false, nil
}

func (r *fakeProductRepo) Update(_ context.Context, id core.ProductID, params domain.UpdateProductParams) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (r *fakeProductRepo) Delete(_ context.Context, id core.ProductID) error {
	delete(r.byID, id)
	return nil
}
