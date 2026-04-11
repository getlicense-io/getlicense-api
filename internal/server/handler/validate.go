package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/licensing"
)

// ValidateHandler handles public license validation.
type ValidateHandler struct {
	svc *licensing.Service
}

// NewValidateHandler creates a new ValidateHandler.
func NewValidateHandler(svc *licensing.Service) *ValidateHandler {
	return &ValidateHandler{svc: svc}
}

// validateRequest holds the body for the validate endpoint.
type validateRequest struct {
	LicenseKey string `json:"license_key" validate:"required"`
}

// Validate checks a license key and returns its status.
func (h *ValidateHandler) Validate(c fiber.Ctx) error {
	var req validateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	result, err := h.svc.Validate(c.Context(), req.LicenseKey)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}
