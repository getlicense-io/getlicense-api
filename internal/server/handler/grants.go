package handler

import (
	"context"

	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/grant"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// GrantHandler handles grant lifecycle and grant-scoped license creation.
type GrantHandler struct {
	svc        *grant.Service
	licenseSvc *licensing.Service
	txManager  domain.TxManager
}

// NewGrantHandler creates a new GrantHandler.
func NewGrantHandler(svc *grant.Service, licenseSvc *licensing.Service, txManager domain.TxManager) *GrantHandler {
	return &GrantHandler{svc: svc, licenseSvc: licenseSvc, txManager: txManager}
}

// Issue creates a new pending grant from the caller's account (the
// grantor) to another account (the grantee). Requires grant:issue.
// Route: POST /v1/accounts/:account_id/grants
func (h *GrantHandler) Issue(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantIssue)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}

	var req grant.IssueRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	result, err := h.svc.Issue(c.Context(), auth.TargetAccountID, auth.Environment, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// Accept transitions a pending grant to active. Called by the grantee.
// Requires grant:accept. Does NOT use ResolveGrant — the grantee's
// TargetAccountID equals ActingAccountID on this route.
// Route: POST /v1/grants/:grant_id/accept
func (h *GrantHandler) Accept(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantAccept)
	if err != nil {
		return err
	}
	grantID, err := core.ParseGrantID(c.Params("grant_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid grant ID")
	}
	// Accept(ctx, granteeAccountID, env, grantID) — service verifies
	// internally that the acting account is the grantee.
	result, err := h.svc.Accept(c.Context(), auth.ActingAccountID, auth.Environment, grantID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Suspend temporarily suspends an active grant. Called by the grantor.
// Requires grant:revoke. Account match validates the grantor is the caller.
// Route: POST /v1/accounts/:account_id/grants/:grant_id/suspend
func (h *GrantHandler) Suspend(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantRevoke)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	grantID, err := core.ParseGrantID(c.Params("grant_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid grant ID")
	}
	result, err := h.svc.Suspend(c.Context(), auth.TargetAccountID, auth.Environment, grantID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Revoke permanently revokes a grant. Called by the grantor.
// Requires grant:revoke. Account match validates the grantor is the caller.
// Route: POST /v1/accounts/:account_id/grants/:grant_id/revoke
func (h *GrantHandler) Revoke(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantRevoke)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	grantID, err := core.ParseGrantID(c.Params("grant_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid grant ID")
	}
	result, err := h.svc.Revoke(c.Context(), auth.TargetAccountID, auth.Environment, grantID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// CreateLicense creates a license on behalf of the grantor via a
// capability grant. The ResolveGrant middleware has already loaded and
// validated the grant, flipped AuthContext.TargetAccountID to the
// grantor, and stored the grant on locals before this handler runs.
//
// This handler:
//  1. Requires grant:use on the grantee
//  2. Requires the LICENSE_CREATE grant capability
//  3. Runs CheckLicenseCreateConstraints scoped to the grantor's tenant
//  4. Creates the license via licensing.Service.Create with full
//     attribution (grant_id + grantee account + identity)
//
// Route: POST /v1/grants/:grant_id/licenses (with ResolveGrant middleware)
func (h *GrantHandler) CreateLicense(c fiber.Ctx) error {
	// ResolveGrant has already switched TargetAccountID to the grantor.
	// ActingAccountID is still the grantee.
	auth, err := authz(c, rbac.GrantUse)
	if err != nil {
		return err
	}
	g := middleware.GrantFromContext(c)
	if g == nil {
		return core.NewAppError(core.ErrInternalError, "Grant context missing from request")
	}
	if err := h.svc.RequireCapability(g, domain.GrantCapLicenseCreate); err != nil {
		return err
	}

	var req licensing.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	// Constraint check runs in a short read-only tx scoped to the
	// grantor so license counts are RLS-filtered to the right tenant.
	// CustomerEmailPattern is no longer enforced here — the check
	// moved to licensing.Service.Create where the resolved customer
	// email is available. We still project it into CreateOptions below.
	if err := h.txManager.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		return h.svc.CheckLicenseCreateConstraints(ctx, g)
	}); err != nil {
		return err
	}

	// Decode the typed constraints again to project AllowedPolicyIDs
	// and CustomerEmailPattern onto CreateOptions. The policy allowlist
	// check runs inside licensing.Service.Create after policy resolution
	// so an omitted req.PolicyID that resolves to the product default is
	// enforced against the same list.
	constraints, err := h.svc.DecodeConstraints(g)
	if err != nil {
		return err
	}
	allowedPolicyIDs, err := parseAllowedPolicyIDs(constraints.AllowedPolicyIDs)
	if err != nil {
		return err
	}

	opts := licensing.CreateOptions{
		GrantID:              &g.ID,
		CreatedByAccountID:   auth.ActingAccountID,
		CreatedByIdentityID:  auth.IdentityID,
		AllowedPolicyIDs:     allowedPolicyIDs,
		CustomerEmailPattern: constraints.CustomerEmailPattern,
	}
	// licensing.Service.Create is called with TargetAccountID (grantor)
	// so the license is inserted under the grantor's RLS scope.
	result, err := h.licenseSvc.Create(c.Context(), auth.TargetAccountID, auth.Environment, g.ProductID, req, opts)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// parseAllowedPolicyIDs converts the stringy allowlist from
// GrantConstraints into typed PolicyIDs. An empty / nil input yields
// a nil slice (meaning "no constraint"). Invalid UUIDs surface as
// ErrValidationError — they indicate a malformed grant record.
func parseAllowedPolicyIDs(raw []string) ([]core.PolicyID, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]core.PolicyID, 0, len(raw))
	for _, s := range raw {
		id, err := core.ParsePolicyID(s)
		if err != nil {
			return nil, core.NewAppError(core.ErrValidationError, "Grant constraints contain invalid policy id")
		}
		out = append(out, id)
	}
	return out, nil
}
