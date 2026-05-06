package grant

import (
	"context"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- fake AccountRepository ---

type fakeAccountRepo struct {
	byID map[core.AccountID]*domain.Account
}

func newFakeAccountRepo() *fakeAccountRepo {
	return &fakeAccountRepo{byID: make(map[core.AccountID]*domain.Account)}
}

var _ domain.AccountRepository = (*fakeAccountRepo)(nil)

func (r *fakeAccountRepo) Create(_ context.Context, a *domain.Account) error {
	r.byID[a.ID] = a
	return nil
}

func (r *fakeAccountRepo) GetByID(_ context.Context, id core.AccountID) (*domain.Account, error) {
	if a, ok := r.byID[id]; ok {
		cp := *a
		return &cp, nil
	}
	// Unknown accounts return a placeholder so Issue's grantee-lookup doesn't
	// 404 in unit tests that don't pre-seed the account.
	return &domain.Account{ID: id, Name: "Test Account", Slug: "test-account"}, nil
}

func (r *fakeAccountRepo) GetBySlug(_ context.Context, _ string) (*domain.Account, error) {
	return nil, nil
}

func (r *fakeAccountRepo) GetIfAccessible(_ context.Context, _ core.AccountID, _ core.AccountID, _ core.IdentityID) (*domain.Account, error) {
	return nil, nil
}

// --- fake ChannelRepository ---

type fakeChannelRepo struct {
	channels []*domain.Channel
}

func newFakeChannelRepo() *fakeChannelRepo {
	return &fakeChannelRepo{}
}

var _ domain.ChannelRepository = (*fakeChannelRepo)(nil)

func (r *fakeChannelRepo) Create(_ context.Context, c *domain.Channel) error {
	r.channels = append(r.channels, c)
	return nil
}

func (r *fakeChannelRepo) Get(_ context.Context, _ core.ChannelID) (*domain.Channel, error) {
	return nil, nil
}

func (r *fakeChannelRepo) ListByVendor(_ context.Context, _ core.AccountID, _ domain.ChannelListFilter, _ core.Cursor, _ int) ([]domain.Channel, bool, error) {
	out := make([]domain.Channel, 0, len(r.channels))
	for _, c := range r.channels {
		out = append(out, *c)
	}
	return out, false, nil
}

func (r *fakeChannelRepo) ListByPartner(_ context.Context, _ core.AccountID, _ domain.ChannelListFilter, _ core.Cursor, _ int) ([]domain.Channel, bool, error) {
	return nil, false, nil
}

func (r *fakeChannelRepo) ListProducts(_ context.Context, _ core.ChannelID, _ core.Cursor, _ int) ([]domain.ChannelProduct, bool, error) {
	return nil, false, nil
}

func (r *fakeChannelRepo) GetStats(_ context.Context, _ core.ChannelID, _ core.AccountID, _ bool, _ time.Time) (*domain.ChannelStats, error) {
	return nil, nil
}

func (r *fakeChannelRepo) Update(_ context.Context, _ core.ChannelID, _ domain.UpdateChannelParams) error {
	return nil
}

func (r *fakeChannelRepo) UpdateStatus(_ context.Context, _ core.ChannelID, _ domain.ChannelStatus, _ *time.Time) error {
	return nil
}

func (r *fakeChannelRepo) SetPartnerAndActivate(_ context.Context, _ core.ChannelID, _ core.AccountID) error {
	return nil
}

func (r *fakeChannelRepo) ClearDraftFirstProduct(_ context.Context, _ core.ChannelID) error {
	return nil
}

// --- fake GrantRepository ---

type fakeGrantRepo struct {
	byID          map[core.GrantID]*domain.Grant
	licenseCounts map[core.GrantID]int
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

func (r *fakeGrantRepo) ListByGrantor(_ context.Context, _ domain.GrantListFilter, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
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

func (r *fakeGrantRepo) ListByGrantee(_ context.Context, _ domain.GrantListFilter, cursor core.Cursor, limit int) ([]domain.Grant, bool, error) {
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

func (r *fakeGrantRepo) Update(_ context.Context, id core.GrantID, params domain.UpdateGrantParams) error {
	g, ok := r.byID[id]
	if !ok {
		return nil
	}
	if params.Capabilities != nil {
		g.Capabilities = *params.Capabilities
	}
	if params.Constraints != nil {
		g.Constraints = *params.Constraints
	}
	if params.Metadata != nil {
		g.Metadata = *params.Metadata
	}
	if params.ExpiresAt != nil {
		g.ExpiresAt = *params.ExpiresAt
	}
	if params.Label != nil {
		g.Label = *params.Label
	}
	g.UpdatedAt = time.Now().UTC()
	return nil
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

func (r *fakeGrantRepo) GetUsage(_ context.Context, grantID core.GrantID, _ time.Time) (domain.GrantUsage, error) {
	return domain.GrantUsage{
		LicensesTotal:     r.licenseCounts[grantID],
		LicensesThisMonth: r.licenseCounts[grantID],
		CustomersTotal:    0,
	}, nil
}

func (r *fakeGrantRepo) ListExpirable(_ context.Context, _ time.Time, _ int) ([]domain.Grant, error) {
	return nil, nil
}

// HasActiveGrantForProductEmail is stubbed to always return false.
// The duplicate-guard tests live in internal/invitation/ and use a
// purpose-built fake; no grant-package tests exercise this path today.
func (r *fakeGrantRepo) HasActiveGrantForProductEmail(_ context.Context, _ core.AccountID, _ string, _ core.ProductID) (bool, error) {
	return false, nil
}

func (r *fakeGrantRepo) CountActiveByGrantor(_ context.Context, _ core.AccountID) (int, error) {
	return 0, nil
}
