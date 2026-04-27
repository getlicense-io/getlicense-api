package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/auth"
	"github.com/getlicense-io/getlicense-api/internal/core"
)

type AuthHandler struct {
	svc *auth.Service
}

func NewAuthHandler(svc *auth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

func (h *AuthHandler) Signup(c fiber.Ctx) error {
	var req auth.SignupRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	result, err := h.svc.Signup(c.Context(), req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

func (h *AuthHandler) Login(c fiber.Ctx) error {
	var req auth.LoginRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	result, err := h.svc.Login(c.Context(), req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *AuthHandler) Refresh(c fiber.Ctx) error {
	var req refreshRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	result, err := h.svc.Refresh(c.Context(), req.RefreshToken)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Logout revokes the access JWT (per-jti) and deletes the matching
// refresh token. Requires identity auth — the access token's jti and
// expiry come from the auth context. API-key callers cannot logout
// (they have no JWT to revoke).
func (h *AuthHandler) Logout(c fiber.Ctx) error {
	authCtx, err := mustAuth(c)
	if err != nil {
		return err
	}
	if authCtx.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "This endpoint requires identity authentication, not an API key")
	}
	var req refreshRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	if err := h.svc.Logout(
		c.Context(),
		req.RefreshToken,
		authCtx.JTI,
		*authCtx.IdentityID,
		authCtx.JWTExpiresAt,
	); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// LogoutAll bulk-revokes every active session for the calling
// identity. Sets the session-invalidation cutoff to now (rejects every
// JWT issued before this instant) and deletes every refresh token.
// Requires identity auth — API keys are unaffected by this endpoint
// (they have no concept of "all my sessions").
func (h *AuthHandler) LogoutAll(c fiber.Ctx) error {
	authCtx, err := mustAuth(c)
	if err != nil {
		return err
	}
	if authCtx.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "This endpoint requires identity authentication, not an API key")
	}
	if err := h.svc.LogoutAll(c.Context(), *authCtx.IdentityID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Me returns the authenticated identity with all memberships and the
// current acting account + role. Requires identity auth — API keys
// cannot call this endpoint because they have no concept of "me".
func (h *AuthHandler) Me(c fiber.Ctx) error {
	authCtx, err := mustAuth(c)
	if err != nil {
		return err
	}
	if authCtx.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "This endpoint requires identity authentication, not an API key")
	}
	result, err := h.svc.GetMe(c.Context(), *authCtx.IdentityID, authCtx.ActingAccountID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// LoginTOTP is the second step of a two-step login. The client sends
// the pending token from the first Login response along with a fresh
// TOTP code; on success, returns the full token pair.
func (h *AuthHandler) LoginTOTP(c fiber.Ctx) error {
	var req auth.LoginStep2Request
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	result, err := h.svc.LoginStep2(c.Context(), req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Switch reissues a JWT pair with a different acting account. Requires
// identity auth. Target account must be one the identity already has
// an active membership in.
func (h *AuthHandler) Switch(c fiber.Ctx) error {
	authCtx, err := mustAuth(c)
	if err != nil {
		return err
	}
	if authCtx.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "This endpoint requires identity authentication, not an API key")
	}
	var req auth.SwitchRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	result, err := h.svc.Switch(c.Context(), *authCtx.IdentityID, req.MembershipID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}
