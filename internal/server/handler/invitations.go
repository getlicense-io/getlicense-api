package handler

import (
	"bytes"

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

// Create issues a membership- or grant-kind invitation for the caller's
// current account. The body shape selects the kind — presence of
// role_slug triggers membership, presence of grant_draft triggers grant.
// Clients may include a `kind` hint field; it is ignored (field presence
// is the canonical discriminator per the OpenAPI spec).
//
// Membership-kind requires user:invite. Grant-kind additionally requires
// grant:issue, since accepting the invitation mints an active grant —
// the permission bar must match direct POST /v1/accounts/:id/grants.
func (h *InvitationHandler) Create(c fiber.Ctx) error {
	auth, err := authz(c, rbac.UserInvite)
	if err != nil {
		return err
	}
	if auth.IsAPIKey() {
		return core.NewAppError(core.ErrAuthenticationRequired, "Identity auth required to issue invitations")
	}

	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}

	var req invitation.CreateInvitationRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	hasRole := req.RoleSlug != ""
	hasGrant := len(req.GrantDraft) > 0 && !bytes.Equal(bytes.TrimSpace(req.GrantDraft), []byte("null"))
	if hasRole && hasGrant {
		return core.NewAppError(core.ErrValidationError, "Provide exactly one of role_slug or grant_draft")
	}
	if !hasRole && !hasGrant {
		return core.NewAppError(core.ErrValidationError, "Provide role_slug (membership) or grant_draft (grant)")
	}

	var result *invitation.CreateResult
	attr := attributionFromAuth(auth)
	if hasRole {
		result, err = h.svc.CreateMembership(
			c.Context(),
			auth.TargetAccountID,
			auth.Environment,
			*auth.IdentityID,
			invitation.CreateMembershipRequest{Email: req.Email, RoleSlug: req.RoleSlug},
			attr,
		)
	} else {
		if _, err := authz(c, rbac.GrantIssue); err != nil {
			return err
		}
		result, err = h.svc.CreateGrant(
			c.Context(),
			auth.TargetAccountID,
			auth.Environment,
			*auth.IdentityID,
			req.Email,
			req.GrantDraft,
			attr,
		)
	}
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
	result, err := h.svc.Accept(c.Context(), token, *auth.IdentityID, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.JSON(result)
}
