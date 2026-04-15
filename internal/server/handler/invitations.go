package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// InvitationHandler wires the three invitation routes: issue (auth'd),
// lookup (public), and accept (auth'd).
type InvitationHandler struct {
	svc *invitation.Service
}

func NewInvitationHandler(svc *invitation.Service) *InvitationHandler {
	return &InvitationHandler{svc: svc}
}

// CreateMembership issues a membership-kind invitation for the caller's
// current account. Requires user:invite permission.
func (h *InvitationHandler) CreateMembership(c fiber.Ctx) error {
	auth, err := authz(c, rbac.UserInvite)
	if err != nil {
		return err
	}
	if auth.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "Identity auth required to issue invitations")
	}

	pathAccountID, err := core.ParseAccountID(c.Params("account_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid account_id in path")
	}
	if pathAccountID != auth.TargetAccountID {
		return core.NewAppError(core.ErrValidationError, "account_id in path does not match authenticated account")
	}

	var req invitation.CreateMembershipRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	result, err := h.svc.CreateMembership(c.Context(), auth.TargetAccountID, auth.Environment, *auth.IdentityID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// Lookup is the unauthenticated invitation preview. The raw token
// from the URL IS the access token for this one call — the server
// only reveals non-sensitive preview fields.
func (h *InvitationHandler) Lookup(c fiber.Ctx) error {
	token := c.Params("token")
	if token == "" {
		return core.NewAppError(core.ErrValidationError, "Missing token")
	}
	result, err := h.svc.Lookup(c.Context(), token)
	if err != nil {
		return err
	}
	return c.JSON(result)
}

// Accept consumes the token and creates the resource the invitation
// promises. Requires identity auth — the JWT identity becomes the new
// member. API keys cannot accept invitations since they have no
// identity of their own.
func (h *InvitationHandler) Accept(c fiber.Ctx) error {
	auth, err := requireIdentityAuth(c)
	if err != nil {
		return err
	}
	token := c.Params("token")
	if token == "" {
		return core.NewAppError(core.ErrValidationError, "Missing token")
	}
	result, err := h.svc.Accept(c.Context(), token, *auth.IdentityID)
	if err != nil {
		return err
	}
	return c.JSON(result)
}
