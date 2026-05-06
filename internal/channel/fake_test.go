package channel

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

type fakeChannelRepo struct {
	mu       sync.Mutex
	channels map[core.ChannelID]domain.Channel
	products map[core.ChannelID][]domain.ChannelProduct // returned by ListProducts
	stats    *domain.ChannelStats                       // returned by GetStats; nil → zero value
}

func newFakeChannelRepo() *fakeChannelRepo {
	return &fakeChannelRepo{
		channels: map[core.ChannelID]domain.Channel{},
		products: map[core.ChannelID][]domain.ChannelProduct{},
	}
}

var _ domain.ChannelRepository = (*fakeChannelRepo)(nil)

func (f *fakeChannelRepo) Get(ctx context.Context, id core.ChannelID) (*domain.Channel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.channels[id]; ok {
		cp := c
		return &cp, nil
	}
	return nil, nil
}

func (f *fakeChannelRepo) ListByVendor(
	ctx context.Context, vendorAccountID core.AccountID,
	filter domain.ChannelListFilter, cursor core.Cursor, limit int,
) ([]domain.Channel, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []domain.Channel{}
	for _, c := range f.channels {
		if c.VendorAccountID != vendorAccountID {
			continue
		}
		if filter.Status != nil && c.Status != *filter.Status {
			continue
		}
		if filter.PartnerAccountID != nil &&
			(c.PartnerAccountID == nil || *c.PartnerAccountID != *filter.PartnerAccountID) {
			continue
		}
		out = append(out, c)
	}
	return out, false, nil
}

func (f *fakeChannelRepo) ListByPartner(
	ctx context.Context, partnerAccountID core.AccountID,
	filter domain.ChannelListFilter, cursor core.Cursor, limit int,
) ([]domain.Channel, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []domain.Channel{}
	for _, c := range f.channels {
		if c.PartnerAccountID == nil || *c.PartnerAccountID != partnerAccountID {
			continue
		}
		if filter.Status != nil && c.Status != *filter.Status {
			continue
		}
		out = append(out, c)
	}
	return out, false, nil
}

func (f *fakeChannelRepo) ListProducts(
	ctx context.Context, channelID core.ChannelID,
	cursor core.Cursor, limit int,
) ([]domain.ChannelProduct, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]domain.ChannelProduct(nil), f.products[channelID]...), false, nil
}

func (f *fakeChannelRepo) GetStats(
	ctx context.Context, channelID core.ChannelID,
	callerAccountID core.AccountID, isPartner bool, since time.Time,
) (*domain.ChannelStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stats != nil {
		cp := *f.stats
		return &cp, nil
	}
	return &domain.ChannelStats{}, nil
}
func (f *fakeChannelRepo) Create(ctx context.Context, c *domain.Channel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.channels[c.ID] = *c
	return nil
}
func (f *fakeChannelRepo) Update(context.Context, core.ChannelID, domain.UpdateChannelParams) error {
	return errors.New("fake: Update not implemented")
}
func (f *fakeChannelRepo) UpdateStatus(context.Context, core.ChannelID, domain.ChannelStatus, *time.Time) error {
	return errors.New("fake: UpdateStatus not implemented")
}
func (f *fakeChannelRepo) SetPartnerAndActivate(context.Context, core.ChannelID, core.AccountID) error {
	return errors.New("fake: SetPartnerAndActivate not implemented")
}
func (f *fakeChannelRepo) ClearDraftFirstProduct(context.Context, core.ChannelID) error {
	return errors.New("fake: ClearDraftFirstProduct not implemented")
}
