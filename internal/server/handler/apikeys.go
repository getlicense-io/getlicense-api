package handler

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// APIKeyHandler handles API key management endpoints.
type APIKeyHandler struct {
	svc *auth.Service
}

// NewAPIKeyHandler creates a new APIKeyHandler.
func NewAPIKeyHandler(svc *auth.Service) *APIKeyHandler {
	return &APIKeyHandler{svc: svc}
}

// Create creates a new API key.
func (h *APIKeyHandler) Create(c fiber.Ctx) error {
	var req auth.CreateAPIKeyRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	a, err := authz(c, rbac.APIKeyCreate)
	if err != nil {
		return err
	}
	result, err := h.svc.CreateAPIKey(c.Context(), a.TargetAccountID, a.Environment, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a cursor-paginated list of API keys.
func (h *APIKeyHandler) List(c fiber.Ctx) error {
	a, err := authz(c, rbac.APIKeyRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	keys, hasMore, err := h.svc.ListAPIKeysPage(c.Context(), a.TargetAccountID, a.Environment, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(keys, hasMore, func(k domain.APIKey) core.Cursor {
		return core.Cursor{CreatedAt: k.CreatedAt, ID: uuid.UUID(k.ID)}
	}))
}

// Delete removes an API key by ID.
func (h *APIKeyHandler) Delete(c fiber.Ctx) error {
	apiKeyID, err := core.ParseAPIKeyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid API key ID")
	}

	a, err := authz(c, rbac.APIKeyRevoke)
	if err != nil {
		return err
	}
	if err := h.svc.DeleteAPIKey(c.Context(), a.TargetAccountID, a.Environment, apiKeyID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
