package handler

import (
	"github.com/getlicense-io/getlicense-api/internal/channel"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
)

// ChannelHandler handles the /v1/channels and /v1/accounts/:id/channels
// route groups. P0 surface is read-only (list + get); writes land in P2.
type ChannelHandler struct {
	svc *channel.Service
}

// NewChannelHandler creates a new ChannelHandler.
func NewChannelHandler(svc *channel.Service) *ChannelHandler {
	return &ChannelHandler{svc: svc}
}

// channelCursor is the single cursor projection for channel list endpoints.
func channelCursor(ch domain.Channel) core.Cursor {
	return core.Cursor{CreatedAt: ch.CreatedAt, ID: uuid.UUID(ch.ID)}
}

// channelProductCursor is the cursor projection for channel product list endpoints.
func channelProductCursor(cp domain.ChannelProduct) core.Cursor {
	return core.Cursor{CreatedAt: cp.CreatedAt, ID: uuid.UUID(cp.ID)}
}

// ListByVendor handles GET /v1/accounts/:account_id/channels.
// Filters: status, partner_account_id. Cursor-paginated.
func (h *ChannelHandler) ListByVendor(c fiber.Ctx) error {
	auth, err := authz(c, rbac.ChannelRead)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	filter := domain.ChannelListFilter{}
	if s := c.Query("status"); s != "" {
		st := domain.ChannelStatus(s)
		filter.Status = &st
	}
	if pa := c.Query("partner_account_id"); pa != "" {
		partnerID, perr := core.ParseAccountID(pa)
		if perr != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid partner_account_id")
		}
		filter.PartnerAccountID = &partnerID
	}
	rows, hasMore, err := h.svc.ListByVendor(c.Context(), auth.TargetAccountID, filter, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, channelCursor))
}

// GetByVendor handles GET /v1/accounts/:account_id/channels/:channel_id.
func (h *ChannelHandler) GetByVendor(c fiber.Ctx) error {
	auth, err := authz(c, rbac.ChannelRead)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	channelID, err := core.ParseChannelID(c.Params("channel_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid channel ID")
	}
	ch, err := h.svc.Get(c.Context(), auth.TargetAccountID, channelID)
	if err != nil {
		return err
	}
	return c.JSON(ch)
}

// GetByCaller handles GET /v1/channels/:channel_id (caller-scoped — works
// for both vendor and partner; the service does the existence-leak check).
func (h *ChannelHandler) GetByCaller(c fiber.Ctx) error {
	auth, err := authz(c, rbac.ChannelRead)
	if err != nil {
		return err
	}
	channelID, err := core.ParseChannelID(c.Params("channel_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid channel ID")
	}
	ch, err := h.svc.Get(c.Context(), auth.ActingAccountID, channelID)
	if err != nil {
		return err
	}
	return c.JSON(ch)
}

// ListReceived handles GET /v1/channels/received — partner's "Channels
// I sell through" list. Caller-scoped (uses ActingAccountID).
func (h *ChannelHandler) ListReceived(c fiber.Ctx) error {
	auth, err := authz(c, rbac.ChannelRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	filter := domain.ChannelListFilter{}
	if s := c.Query("status"); s != "" {
		st := domain.ChannelStatus(s)
		filter.Status = &st
	}
	rows, hasMore, err := h.svc.ListByPartner(c.Context(), auth.ActingAccountID, filter, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, channelCursor))
}

// ListProductsByVendor handles GET /v1/accounts/:account_id/channels/:channel_id/products.
func (h *ChannelHandler) ListProductsByVendor(c fiber.Ctx) error {
	auth, err := authz(c, rbac.ChannelRead)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	channelID, err := core.ParseChannelID(c.Params("channel_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid channel ID")
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	rows, hasMore, err := h.svc.ListProducts(c.Context(), auth.TargetAccountID, channelID, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, channelProductCursor))
}

// ListProductsByCaller handles GET /v1/channels/:channel_id/products
// (caller-scoped — works for both vendor and partner).
func (h *ChannelHandler) ListProductsByCaller(c fiber.Ctx) error {
	auth, err := authz(c, rbac.ChannelRead)
	if err != nil {
		return err
	}
	channelID, err := core.ParseChannelID(c.Params("channel_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid channel ID")
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	rows, hasMore, err := h.svc.ListProducts(c.Context(), auth.ActingAccountID, channelID, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, channelProductCursor))
}
