package channel

import (
	"context"
	"testing"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/testfakes"
	"github.com/stretchr/testify/require"
)

func newServiceForTest() (*Service, *fakeChannelRepo) {
	repo := newFakeChannelRepo()
	s := NewService(testfakes.TxManager{}, repo, nil)
	return s, repo
}

func TestService_Get_VendorReadsOwnChannel(t *testing.T) {
	s, repo := newServiceForTest()
	vendor := core.NewAccountID()
	partner := core.NewAccountID()
	cid := core.NewChannelID()
	repo.channels[cid] = domain.Channel{
		ID:               cid,
		VendorAccountID:  vendor,
		PartnerAccountID: &partner,
		Name:             "Acme EMEA",
		Status:           domain.ChannelStatusActive,
	}
	got, err := s.Get(context.Background(), vendor, cid)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, "Acme EMEA", got.Name)
}

func TestService_Get_PartnerReadsChannel(t *testing.T) {
	s, repo := newServiceForTest()
	vendor := core.NewAccountID()
	partner := core.NewAccountID()
	cid := core.NewChannelID()
	repo.channels[cid] = domain.Channel{
		ID:               cid,
		VendorAccountID:  vendor,
		PartnerAccountID: &partner,
		Name:             "Acme EMEA",
		Status:           domain.ChannelStatusActive,
	}
	got, err := s.Get(context.Background(), partner, cid)
	require.NoError(t, err)
	require.NotNil(t, got)
}

func TestService_Get_UnrelatedAccount_Returns404(t *testing.T) {
	s, repo := newServiceForTest()
	vendor := core.NewAccountID()
	partner := core.NewAccountID()
	other := core.NewAccountID()
	cid := core.NewChannelID()
	repo.channels[cid] = domain.Channel{
		ID:               cid,
		VendorAccountID:  vendor,
		PartnerAccountID: &partner,
		Status:           domain.ChannelStatusActive,
	}
	_, err := s.Get(context.Background(), other, cid)
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, core.ErrChannelNotFound, appErr.Code)
}

func TestService_Get_NotFound_Returns404(t *testing.T) {
	s, _ := newServiceForTest()
	_, err := s.Get(context.Background(), core.NewAccountID(), core.NewChannelID())
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, core.ErrChannelNotFound, appErr.Code)
}

func TestService_ListByVendor_FiltersByStatus(t *testing.T) {
	s, repo := newServiceForTest()
	vendor := core.NewAccountID()
	partner := core.NewAccountID()
	active := core.NewChannelID()
	closed := core.NewChannelID()
	repo.channels[active] = domain.Channel{
		ID: active, VendorAccountID: vendor, PartnerAccountID: &partner,
		Name: "active-ch", Status: domain.ChannelStatusActive,
	}
	repo.channels[closed] = domain.Channel{
		ID: closed, VendorAccountID: vendor, PartnerAccountID: &partner,
		Name: "closed-ch", Status: domain.ChannelStatusClosed,
	}
	statusActive := domain.ChannelStatusActive
	rows, _, err := s.ListByVendor(context.Background(), vendor, domain.ChannelListFilter{Status: &statusActive}, core.Cursor{}, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "active-ch", rows[0].Name)
}

func TestService_ListByVendor_FiltersByPartner(t *testing.T) {
	s, repo := newServiceForTest()
	vendor := core.NewAccountID()
	partnerA := core.NewAccountID()
	partnerB := core.NewAccountID()
	repo.channels[core.NewChannelID()] = domain.Channel{
		VendorAccountID: vendor, PartnerAccountID: &partnerA,
		Status: domain.ChannelStatusActive, Name: "to-A",
	}
	repo.channels[core.NewChannelID()] = domain.Channel{
		VendorAccountID: vendor, PartnerAccountID: &partnerB,
		Status: domain.ChannelStatusActive, Name: "to-B",
	}
	rows, _, err := s.ListByVendor(context.Background(), vendor, domain.ChannelListFilter{PartnerAccountID: &partnerA}, core.Cursor{}, 50)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "to-A", rows[0].Name)
}
