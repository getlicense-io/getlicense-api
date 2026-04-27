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
	if err := bindStrict(c, &req); err != nil {
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
	endpoints, hasMore, err := h.svc.ListEndpoints(c.Context(), a.TargetAccountID, a.Environment, cursor, limit)
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

// RotateSigningSecret mints a fresh current HMAC signing secret for
// the endpoint and returns it ONCE in the response. The previous
// secret remains in the previous slot for a short verification grace
// window so receivers can deploy current/previous verification safely.
//
// Permission: webhook:update.
// Route:      POST /v1/webhooks/:id/rotate-signing-secret
func (h *WebhookHandler) RotateSigningSecret(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}
	a, err := authz(c, rbac.WebhookUpdate)
	if err != nil {
		return err
	}
	result, err := h.svc.RotateSigningSecret(c.Context(), a.TargetAccountID, a.Environment, endpointID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

func (h *WebhookHandler) FinishSigningSecretRotation(c fiber.Ctx) error {
	endpointID, err := core.ParseWebhookEndpointID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid webhook endpoint ID")
	}
	a, err := authz(c, rbac.WebhookUpdate)
	if err != nil {
		return err
	}
	ep, err := h.svc.FinishSigningSecretRotation(c.Context(), a.TargetAccountID, a.Environment, endpointID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"endpoint": ep})
}
