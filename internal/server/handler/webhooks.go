package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
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

	a := middleware.FromContext(c)
	result, err := h.svc.CreateEndpoint(c.Context(), a.AccountID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a paginated list of webhook endpoints.
func (h *WebhookHandler) List(c fiber.Ctx) error {
	limit, offset := paginationParams(c)
	a := middleware.FromContext(c)

	endpoints, total, err := h.svc.ListEndpoints(c.Context(), a.AccountID, limit, offset)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(domain.ListResponse[domain.WebhookEndpoint]{
		Data: endpoints,
		Pagination: domain.Pagination{
			Limit:  limit,
			Offset: offset,
			Total:  total,
		},
	})
}

// Delete removes a webhook endpoint by ID.
func (h *WebhookHandler) Delete(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}

	a := middleware.FromContext(c)
	if err := h.svc.DeleteEndpoint(c.Context(), a.AccountID, endpointID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
