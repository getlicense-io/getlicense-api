package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/search"
)

// SearchHandler handles the global search endpoint.
type SearchHandler struct {
	svc *search.Service
}

// NewSearchHandler creates a new SearchHandler.
func NewSearchHandler(svc *search.Service) *SearchHandler {
	return &SearchHandler{svc: svc}
}

// Search handles GET /v1/search?q=<query>&types=license,machine,customer,product.
// Any authenticated caller can search — RLS scopes results to their tenant.
func (h *SearchHandler) Search(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}

	q := c.Query("q")
	if q == "" {
		return core.NewAppError(core.ErrValidationError, "q parameter is required")
	}

	types, err := search.ValidateTypes(c.Query("types"))
	if err != nil {
		return err
	}

	result, err := h.svc.Search(c.Context(), auth.TargetAccountID, auth.Environment, auth.Role, q, types, 10)
	if err != nil {
		return err
	}

	return c.JSON(result)
}
