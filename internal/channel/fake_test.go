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
}

func newFakeChannelRepo() *fakeChannelRepo {
	return &fakeChannelRepo{channels: map[core.ChannelID]domain.Channel{}}
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

func (f *fakeChannelRepo) ListByPartner(context.Context, core.AccountID, domain.ChannelListFilter, core.Cursor, int) ([]domain.Channel, bool, error) {
	return nil, false, errors.New("fake: ListByPartner not implemented")
}
func (f *fakeChannelRepo) ListProducts(context.Context, core.ChannelID, core.Cursor, int) ([]domain.ChannelProduct, bool, error) {
	return nil, false, errors.New("fake: ListProducts not implemented")
}
func (f *fakeChannelRepo) GetStats(context.Context, core.ChannelID, core.AccountID, bool, time.Time) (*domain.ChannelStats, error) {
	return nil, errors.New("fake: GetStats not implemented")
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
