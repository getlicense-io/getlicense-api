package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// AuthHandler handles authentication and token management endpoints.
type AuthHandler struct {
	svc *auth.Service
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(svc *auth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// Signup creates a new account, owner user, and initial API key.
func (h *AuthHandler) Signup(c fiber.Ctx) error {
	var req auth.SignupRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	result, err := h.svc.Signup(c.Context(), req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// Login authenticates a user and returns tokens.
func (h *AuthHandler) Login(c fiber.Ctx) error {
	var req auth.LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	result, err := h.svc.Login(c.Context(), req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// refreshRequest holds the body for refresh and logout endpoints.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// Refresh exchanges a refresh token for a new token pair.
func (h *AuthHandler) Refresh(c fiber.Ctx) error {
	var req refreshRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	result, err := h.svc.Refresh(c.Context(), req.RefreshToken)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Logout invalidates a refresh token.
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	var req refreshRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	if err := h.svc.Logout(c.Context(), req.RefreshToken); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Me returns the authenticated account and user.
func (h *AuthHandler) Me(c fiber.Ctx) error {
	a := middleware.FromContext(c)

	result, err := h.svc.GetMe(c.Context(), a.AccountID, a.UserID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}
