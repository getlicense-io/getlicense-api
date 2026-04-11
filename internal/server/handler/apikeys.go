package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
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

	a := middleware.FromContext(c)
	result, err := h.svc.CreateAPIKey(c.Context(), a.AccountID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a paginated list of API keys.
func (h *APIKeyHandler) List(c fiber.Ctx) error {
	limit, offset := paginationParams(c)
	a := middleware.FromContext(c)

	keys, total, err := h.svc.ListAPIKeys(c.Context(), a.AccountID, limit, offset)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(domain.ListResponse[domain.APIKey]{
		Data: keys,
		Pagination: domain.Pagination{
			Limit:  limit,
			Offset: offset,
			Total:  total,
		},
	})
}

// Delete removes an API key by ID.
func (h *APIKeyHandler) Delete(c fiber.Ctx) error {
	apiKeyID, err := core.ParseAPIKeyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid API key ID")
	}

	a := middleware.FromContext(c)
	if err := h.svc.DeleteAPIKey(c.Context(), a.AccountID, apiKeyID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
