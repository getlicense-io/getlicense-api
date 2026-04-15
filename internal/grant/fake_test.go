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
	byID map[core.GrantID]*domain.Grant
}

func newFakeGrantRepo() *fakeGrantRepo {
	return &fakeGrantRepo{byID: make(map[core.GrantID]*domain.Grant)}
}

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

func (r *fakeGrantRepo) UpdateStatus(_ context.Context, id core.GrantID, status domain.GrantStatus, ts time.Time) error {
	g, ok := r.byID[id]
	if !ok {
		return nil
	}
	g.Status = status
	g.UpdatedAt = ts
	switch status {
	case domain.GrantStatusActive:
		g.AcceptedAt = &ts
	case domain.GrantStatusSuspended:
		g.SuspendedAt = &ts
	case domain.GrantStatusRevoked:
		g.RevokedAt = &ts
	}
	return nil
}
