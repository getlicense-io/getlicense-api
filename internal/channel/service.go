package channel

import (
	"context"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// Service is the channels orchestrator. P0 is read-only — Get and
// ListByVendor open a tenant-scoped tx and delegate to ChannelRepository.
// Write paths (Create, Update, Invite, Suspend, ...) land in P2.
type Service struct {
	txManager domain.TxManager
	channels  domain.ChannelRepository
	audit     *audit.Writer
}

// NewService creates a new channel Service.
func NewService(
	txManager domain.TxManager,
	channels domain.ChannelRepository,
	auditWriter *audit.Writer,
) *Service {
	return &Service{
		txManager: txManager,
		channels:  channels,
		audit:     auditWriter,
	}
}

// Get returns a single channel by id. Either the vendor or the partner
// may read; the dual-branch RLS policy on channels enforces that. Stats
// are NOT populated in P0 — they land in P1.
//
// Existence-leak prevention: if the caller is neither vendor nor
// partner, returns ErrChannelNotFound (404), not a 403.
func (s *Service) Get(
	ctx context.Context,
	callerAccountID core.AccountID,
	channelID core.ChannelID,
) (*domain.Channel, error) {
	var ch *domain.Channel
	err := s.txManager.WithTargetAccount(ctx, callerAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		ch, err = s.channels.Get(ctx, channelID)
		if err != nil {
			return err
		}
		if ch == nil {
			return core.NewAppError(core.ErrChannelNotFound, "Channel not found")
		}
		if ch.VendorAccountID != callerAccountID &&
			(ch.PartnerAccountID == nil || *ch.PartnerAccountID != callerAccountID) {
			return core.NewAppError(core.ErrChannelNotFound, "Channel not found")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ch, nil
}

// ListByVendor returns cursor-paginated channels owned by vendorAccountID.
// Filter supports status and partner_account_id (per contract).
func (s *Service) ListByVendor(
	ctx context.Context,
	vendorAccountID core.AccountID,
	filter domain.ChannelListFilter,
	cursor core.Cursor,
	limit int,
) ([]domain.Channel, bool, error) {
	var rows []domain.Channel
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, vendorAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		rows, hasMore, err = s.channels.ListByVendor(ctx, vendorAccountID, filter, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return rows, hasMore, nil
}
