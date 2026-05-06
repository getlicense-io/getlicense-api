package channel

import (
	"context"
	"time"

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

// Get returns a single channel by id, populated with stats. Either the
// vendor or the partner may read.
//
// Existence-leak prevention: if the caller is neither vendor nor
// partner, returns ErrChannelNotFound (404), not a 403.
//
// Partner-side scoping limitation: stats run in the partner's tenant
// tx. RLS on licenses/customers filters by license.account_id = vendor,
// so partner reads see zero counts for licenses_total / licenses_this_month /
// customers_total in v1. ProductsTotal / ProductsActive are unaffected
// (grants RLS is dual-branch). Mirrors the existing Grant.Usage gotcha;
// the vendor-tx workaround is deferred to a follow-up.
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
		isPartner := ch.PartnerAccountID != nil && *ch.PartnerAccountID == callerAccountID
		if ch.VendorAccountID != callerAccountID && !isPartner {
			return core.NewAppError(core.ErrChannelNotFound, "Channel not found")
		}
		// Stats: single repo call (it runs three count queries serially).
		// Could parallelize via errgroup but the simpler shape ships
		// first; revisit if EXPLAIN shows latency issues at scale.
		since := time.Now().UTC().AddDate(0, 0, -30)
		stats, serr := s.channels.GetStats(ctx, channelID, callerAccountID, isPartner, since)
		if serr != nil {
			return serr
		}
		ch.Stats = stats
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

// ListByPartner returns cursor-paginated channels where the caller is
// the partner. Used by GET /v1/channels/received.
func (s *Service) ListByPartner(
	ctx context.Context,
	partnerAccountID core.AccountID,
	filter domain.ChannelListFilter,
	cursor core.Cursor,
	limit int,
) ([]domain.Channel, bool, error) {
	var rows []domain.Channel
	var hasMore bool
	err := s.txManager.WithTargetAccount(ctx, partnerAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		rows, hasMore, err = s.channels.ListByPartner(ctx, partnerAccountID, filter, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return rows, hasMore, nil
}

// ListProducts returns the channel-products under a channel. Caller must
// be either the vendor or the partner; unrelated callers get
// ErrChannelNotFound (existence-leak prevention).
//
// Two-tx pattern: the existence check runs under the caller's tenant so
// the 404-not-403 invariant is preserved. The actual list runs under the
// vendor's tenant so the products JOIN in ListChannelProducts sees vendor-
// owned product rows (products RLS is single-tenant; a partner-context tx
// would filter them out, returning an empty list).
func (s *Service) ListProducts(
	ctx context.Context,
	callerAccountID core.AccountID,
	channelID core.ChannelID,
	cursor core.Cursor,
	limit int,
) ([]domain.ChannelProduct, bool, error) {
	// Step 1: existence + authorization check under caller's tenant.
	var vendorAccountID core.AccountID
	err := s.txManager.WithTargetAccount(ctx, callerAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		ch, err := s.channels.Get(ctx, channelID)
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
		vendorAccountID = ch.VendorAccountID
		return nil
	})
	if err != nil {
		return nil, false, err
	}

	// Step 2: list query runs under vendor's tenant so the JOIN on products
	// (which has single-tenant RLS) resolves correctly for both vendor and
	// partner callers.
	var rows []domain.ChannelProduct
	var hasMore bool
	err = s.txManager.WithTargetAccount(ctx, vendorAccountID, core.EnvironmentLive, func(ctx context.Context) error {
		var err error
		rows, hasMore, err = s.channels.ListProducts(ctx, channelID, cursor, limit)
		return err
	})
	if err != nil {
		return nil, false, err
	}
	return rows, hasMore, nil
}
