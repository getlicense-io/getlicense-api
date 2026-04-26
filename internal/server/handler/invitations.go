package handler

import (
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/invitation"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// invitationCursor is the cursor projection for invitation list endpoints.
// Mirrors grantCursor / licenseCursor etc.: created_at DESC, id DESC.
func invitationCursor(inv domain.Invitation) core.Cursor {
	return core.Cursor{CreatedAt: inv.CreatedAt, ID: uuid.UUID(inv.ID)}
}

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
	if err := bindStrict(c, &req); err != nil {
		return err
	}

	hasRole := req.RoleSlug != ""
	hasGrant := len(req.GrantDraft) > 0 && !bytesEqualNull(req.GrantDraft)
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

// List returns cursor-paginated invitations issued by the caller's
// target account, gated by the caller's permissions per invitation
// kind. Membership-kind invitations contain role assignments and email
// addresses; grant-kind invitations carry capability lists, expected
// emails, and product metadata. Both leak vendor-internal context to
// any member of the account if listed indiscriminately.
//
// The visibility matrix:
//
//	membership kind  →  full visibility iff caller has user:invite OR user:list
//	grant      kind  →  full visibility iff caller has grant:issue OR grant:use
//
// For kinds the caller doesn't have permission for, only invitations
// the caller themselves created (created_by_identity_id == auth.IdentityID)
// are returned. API-key callers (no IdentityID) have no own-invitations
// and get an empty result for kinds they can't see.
//
// Route: GET /v1/accounts/:account_id/invitations
//
// Query parameters:
//   - kind=membership|grant — optional, restricts to one kind
//   - status=pending[,accepted[,expired]] — optional, comma-separated
//     subset of computed statuses
//   - cursor + limit — standard pagination
func (h *InvitationHandler) List(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}

	filter := domain.InvitationListFilter{}
	if k := c.Query("kind"); k != "" {
		if k != string(domain.InvitationKindMembership) && k != string(domain.InvitationKindGrant) {
			return core.NewAppError(core.ErrValidationError, "Invalid kind; must be 'membership' or 'grant'")
		}
		kind := domain.InvitationKind(k)
		filter.Kind = &kind
	}
	if s := c.Query("status"); s != "" {
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if p != "pending" && p != "accepted" && p != "expired" {
				return core.NewAppError(core.ErrValidationError, "Invalid status: "+p)
			}
			filter.Status = append(filter.Status, p)
		}
	}

	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}

	// Permission gating: full visibility on a kind requires the
	// kind-specific permission set. Callers without permission for a
	// kind see ONLY the invitations they themselves created.
	if returnEmpty := applyInvitationListPermissions(&filter, auth.Role, auth.IdentityID); returnEmpty {
		// API-key caller (no IdentityID) with no kind it can see in full.
		return c.JSON(pageFromCursor[domain.Invitation](nil, false, invitationCursor))
	}

	rows, hasMore, err := h.svc.List(c.Context(), auth.TargetAccountID, filter, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, invitationCursor))
}

// applyInvitationListPermissions encodes the gating policy for
// GET /v1/accounts/:account_id/invitations. It mutates filter in place
// to honor what the caller is allowed to see and returns returnEmpty=true
// when the caller would be restricted to own-only but has no IdentityID
// (API-key caller). In that case the handler MUST short-circuit with an
// empty page rather than dispatching to the service — passing the unset
// CreatedByIdentityID downstream would otherwise behave as un-gated.
//
// Logic:
//
//	membership kind  →  full visibility iff caller has user:invite OR user:list
//	grant      kind  →  full visibility iff caller has grant:issue OR grant:use
//
// When the caller asked for a specific kind and lacks the kind-specific
// permission, restrict to own. When the caller asked for both kinds (no
// kind filter), restrict to own only if BOTH kinds lack permission;
// otherwise narrow to the single kind they can see in full to avoid
// returning unscrubbed rows for the kind they can't see.
//
// Pure (no fiber dependency) so the gating matrix can be unit-tested
// without spinning up a Fiber context. role==nil and identityID==nil
// are both supported and behave conservatively (deny full visibility).
func applyInvitationListPermissions(filter *domain.InvitationListFilter, role *domain.Role, identityID *core.IdentityID) (returnEmpty bool) {
	checker := rbac.NewChecker(role)
	canSeeAllMembership := checker.Can(rbac.UserInvite) || checker.Can(rbac.UserList)
	canSeeAllGrant := checker.Can(rbac.GrantIssue) || checker.Can(rbac.GrantUse)

	var gated bool
	if filter.Kind != nil {
		switch *filter.Kind {
		case domain.InvitationKindMembership:
			gated = !canSeeAllMembership
		case domain.InvitationKindGrant:
			gated = !canSeeAllGrant
		}
	} else {
		// No explicit kind filter: gate to own only if caller can't see
		// ALL of either kind. Otherwise the mixed-case narrowing below
		// will restrict by kind to the side the caller is permitted on.
		gated = !canSeeAllMembership && !canSeeAllGrant
	}

	if gated {
		if identityID == nil {
			// API-key caller: no own-invitations possible.
			return true
		}
		id := *identityID
		filter.CreatedByIdentityID = &id
	}

	// Mixed case: caller has full visibility for ONE kind but not the
	// other and didn't filter by kind. Narrow to the permitted kind so
	// the repo doesn't return un-scrubbed rows for the kind the caller
	// can't see.
	if filter.Kind == nil {
		switch {
		case canSeeAllMembership && !canSeeAllGrant:
			k := domain.InvitationKindMembership
			filter.Kind = &k
		case !canSeeAllMembership && canSeeAllGrant:
			k := domain.InvitationKindGrant
			filter.Kind = &k
		}
		// Both true: no narrowing — returns everything.
		// Both false: gated branch already restricted to own.
	}
	return false
}

// Get returns a single invitation by id. RLS scopes the lookup to the
// caller's target account (created_by_account_id), so a caller asking
// for an id they did not create sees 404 — no existence leak, no
// explicit auth check needed beyond mustAuth.
//
// Route: GET /v1/invitations/:invitation_id
func (h *InvitationHandler) Get(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	id, err := core.ParseInvitationID(c.Params("invitation_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid invitation_id")
	}
	inv, err := h.svc.Get(c.Context(), auth.TargetAccountID, id)
	if err != nil {
		return err
	}
	return c.JSON(inv)
}

// Resend regenerates the invitation's raw token and emails a new accept
// URL to the recipient. The old URL is invalidated the moment the token
// hash is rotated. Allowed for the creator identity (always) or any
// caller holding the kind-appropriate permission (user:invite for
// membership, grant:issue for grant) on the target account — mirrors
// the bar required to issue the invitation in the first place.
//
// Route: POST /v1/invitations/:invitation_id/resend
func (h *InvitationHandler) Resend(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	id, err := core.ParseInvitationID(c.Params("invitation_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid invitation_id")
	}
	// Resolve the invitation first so we can pick the right permission
	// gate based on its kind (and confirm it belongs to the caller's
	// tenant — RLS on the Get handles that).
	inv, err := h.svc.Get(c.Context(), auth.TargetAccountID, id)
	if err != nil {
		return err
	}
	if err := requireInvitationManage(c, auth, inv); err != nil {
		return err
	}

	result, err := h.svc.Resend(c.Context(), auth.TargetAccountID, id, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.JSON(result)
}

// Delete hard-deletes an unaccepted invitation. Same auth bar as
// Resend — creator OR kind-appropriate permission. Revoking an
// accepted invitation is rejected by the service (the side-effect
// membership/grant is separately revocable).
//
// Route: DELETE /v1/invitations/:invitation_id
func (h *InvitationHandler) Delete(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	id, err := core.ParseInvitationID(c.Params("invitation_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid invitation_id")
	}
	inv, err := h.svc.Get(c.Context(), auth.TargetAccountID, id)
	if err != nil {
		return err
	}
	if err := requireInvitationManage(c, auth, inv); err != nil {
		return err
	}

	if err := h.svc.Revoke(c.Context(), auth.TargetAccountID, id, attributionFromAuth(auth)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// requireInvitationManage gates Resend/Delete. Creator identity passes
// unconditionally; any other caller must hold the permission matching
// the invitation's kind (grant:issue for grant invitations, user:invite
// for membership). API-key callers (nil IdentityID) can never match the
// creator fast-path and always fall through to the permission check.
func requireInvitationManage(c fiber.Ctx, auth *middleware.AuthContext, inv *domain.Invitation) error {
	if auth.IdentityID != nil && inv.CreatedByIdentityID == *auth.IdentityID {
		return nil
	}
	perm := rbac.UserInvite
	if inv.Kind == domain.InvitationKindGrant {
		perm = rbac.GrantIssue
	}
	checker := rbac.NewChecker(auth.Role)
	return checker.Require(perm)
}
