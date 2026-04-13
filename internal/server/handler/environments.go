package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/environment"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

type EnvironmentHandler struct {
	svc *environment.Service
}

func NewEnvironmentHandler(svc *environment.Service) *EnvironmentHandler {
	return &EnvironmentHandler{svc: svc}
}

func (h *EnvironmentHandler) List(c fiber.Ctx) error {
	a := middleware.FromContext(c)
	envs, err := h.svc.List(c.Context(), a.AccountID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"data": envs})
}

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
