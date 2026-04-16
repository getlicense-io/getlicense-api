package handler

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// ListDeliveries returns a cursor-paginated list of webhook deliveries for an endpoint.
func (h *WebhookHandler) ListDeliveries(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}

	a, err := authz(c, rbac.WebhookRead)
	if err != nil {
		return err
	}

	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}

	filter := domain.WebhookDeliveryFilter{
		EventType: core.EventType(c.Query("event_type")),
		Status:    core.DeliveryStatus(c.Query("status")),
	}

	events, hasMore, err := h.svc.ListDeliveries(c.Context(), a.TargetAccountID, a.Environment, endpointID, filter, cursor, limit)
	if err != nil {
		return err
	}

	return c.JSON(pageFromCursor(events, hasMore, func(ev domain.WebhookEvent) core.Cursor {
		return core.Cursor{CreatedAt: ev.CreatedAt, ID: uuid.UUID(ev.ID)}
	}))
}

// GetDelivery returns a single webhook delivery by ID.
func (h *WebhookHandler) GetDelivery(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}

	deliveryID, err := core.ParseWebhookEventID(c.Params("delivery_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid delivery ID")
	}

	a, err := authz(c, rbac.WebhookRead)
	if err != nil {
		return err
	}

	event, err := h.svc.GetDelivery(c.Context(), a.TargetAccountID, a.Environment, endpointID, deliveryID)
	if err != nil {
		return err
	}

	return c.JSON(event)
}

// Redeliver re-dispatches the domain event linked to a webhook delivery.
func (h *WebhookHandler) Redeliver(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}

	deliveryID, err := core.ParseWebhookEventID(c.Params("delivery_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid delivery ID")
	}

	a, err := authz(c, rbac.WebhookUpdate)
	if err != nil {
		return err
	}

	event, err := h.svc.Redeliver(c.Context(), a.TargetAccountID, a.Environment, endpointID, deliveryID)
	if err != nil {
		return err
	}

	return c.Status(fiber.StatusCreated).JSON(event)
}
