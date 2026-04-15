package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/identity"
)

// IdentityHandler manages identity-level endpoints that aren't part
// of the auth flow itself: TOTP enrollment, activation, and disable.
type IdentityHandler struct {
	svc *identity.Service
}

func NewIdentityHandler(svc *identity.Service) *IdentityHandler {
	return &IdentityHandler{svc: svc}
}

type totpCodeRequest struct {
	Code string `json:"code" validate:"required"`
}

// EnrollTOTP generates a new TOTP secret and returns it alongside the
// provisioning URL for QR-code rendering. Requires identity auth —
// API keys cannot enroll TOTP since they have no identity.
func (h *IdentityHandler) EnrollTOTP(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	if auth.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "Identity authentication required")
	}
	secret, url, err := h.svc.EnrollTOTP(c.Context(), *auth.IdentityID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"secret": secret, "otpauth_url": url})
}

// ActivateTOTP verifies the first code and activates two-factor auth.
// On success, returns the one-time-displayable recovery codes.
func (h *IdentityHandler) ActivateTOTP(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	if auth.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "Identity authentication required")
	}
	var req totpCodeRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	codes, err := h.svc.ActivateTOTP(c.Context(), *auth.IdentityID, req.Code)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

// DisableTOTP clears TOTP state after verifying the current code.
func (h *IdentityHandler) DisableTOTP(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	if auth.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "Identity authentication required")
	}
	var req totpCodeRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	if err := h.svc.DisableTOTP(c.Context(), *auth.IdentityID, req.Code); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
