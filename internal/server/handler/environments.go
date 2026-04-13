package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// EnvironmentHandler serves the per-account environment metadata
// endpoints used by the dashboard account switcher.
type EnvironmentHandler struct {
	svc *environment.Service
}

// NewEnvironmentHandler creates a new EnvironmentHandler.
func NewEnvironmentHandler(svc *environment.Service) *EnvironmentHandler {
	return &EnvironmentHandler{svc: svc}
}

// List returns every environment defined for the authenticated
// account, ordered by position. Unlike most resources this is not
// paginated — there are at most MaxEnvironmentsPerAccount rows and
// the dashboard wants all of them at once to render the switcher.
func (h *EnvironmentHandler) List(c fiber.Ctx) error {
	a := middleware.FromContext(c)
	envs, err := h.svc.List(c.Context(), a.AccountID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"data": envs})
}

// Create adds a new environment. Enforces the per-account cap and
// the unique-slug constraint in the service layer.
func (h *EnvironmentHandler) Create(c fiber.Ctx) error {
	var req environment.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	a := middleware.FromContext(c)
	env, err := h.svc.Create(c.Context(), a.AccountID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(env)
}

// Delete removes an environment. Fails with 422 when the environment
// is the last one for the account or still has active/suspended
// licenses.
func (h *EnvironmentHandler) Delete(c fiber.Ctx) error {
	envID, err := core.ParseEnvironmentID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid environment ID")
	}
	a := middleware.FromContext(c)
	if err := h.svc.Delete(c.Context(), a.AccountID, envID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
