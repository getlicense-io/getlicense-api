package handler

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/webhook"
)

// WebhookHandler handles webhook endpoint management.
type WebhookHandler struct {
	svc *webhook.Service
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(svc *webhook.Service) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

// Create registers a new webhook endpoint.
func (h *WebhookHandler) Create(c fiber.Ctx) error {
	var req webhook.CreateEndpointRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	a, err := authz(c, rbac.WebhookCreate)
	if err != nil {
		return err
	}
	result, err := h.svc.CreateEndpoint(c.Context(), a.TargetAccountID, a.Environment, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a cursor-paginated list of webhook endpoints.
func (h *WebhookHandler) List(c fiber.Ctx) error {
	a, err := authz(c, rbac.WebhookRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	endpoints, hasMore, err := h.svc.ListPageEndpoints(c.Context(), a.TargetAccountID, a.Environment, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(endpoints, hasMore, func(ep domain.WebhookEndpoint) core.Cursor {
		return core.Cursor{CreatedAt: ep.CreatedAt, ID: uuid.UUID(ep.ID)}
	}))
}

// Delete removes a webhook endpoint by ID.
func (h *WebhookHandler) Delete(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}

	a, err := authz(c, rbac.WebhookDelete)
	if err != nil {
		return err
	}
	if err := h.svc.DeleteEndpoint(c.Context(), a.TargetAccountID, a.Environment, endpointID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
