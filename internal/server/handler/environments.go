package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

type EnvironmentHandler struct {
	svc *environment.Service
}

func NewEnvironmentHandler(svc *environment.Service) *EnvironmentHandler {
	return &EnvironmentHandler{svc: svc}
}

// List returns every environment for the account. Environments are
// capped at environment.MaxEnvironmentsPerAccount so the response
// shape includes has_more for API consistency but hasMore is always
// false and next_cursor is never set.
func (h *EnvironmentHandler) List(c fiber.Ctx) error {
	a, err := authz(c, rbac.EnvironmentRead)
	if err != nil {
		return err
	}
	envs, err := h.svc.List(c.Context(), a.TargetAccountID)
	if err != nil {
		return err
	}
	return c.JSON(core.Page[domain.Environment]{Data: envs, HasMore: false})
}

func (h *EnvironmentHandler) Create(c fiber.Ctx) error {
	var req environment.CreateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	a, err := authz(c, rbac.EnvironmentCreate)
	if err != nil {
		return err
	}
	env, err := h.svc.Create(c.Context(), a.TargetAccountID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(env)
}

func (h *EnvironmentHandler) Delete(c fiber.Ctx) error {
	envID, err := core.ParseEnvironmentID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid environment ID")
	}
	a, err := authz(c, rbac.EnvironmentDelete)
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.Context(), a.TargetAccountID, envID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
