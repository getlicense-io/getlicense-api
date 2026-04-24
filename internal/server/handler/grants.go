package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/grant"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// GrantHandler handles grant lifecycle and grant-scoped license creation.
type GrantHandler struct {
	svc         *grant.Service
	licenseSvc  *licensing.Service
	customerSvc *customer.Service
	txManager   domain.TxManager
}

// NewGrantHandler creates a new GrantHandler.
func NewGrantHandler(svc *grant.Service, licenseSvc *licensing.Service, customerSvc *customer.Service, txManager domain.TxManager) *GrantHandler {
	return &GrantHandler{svc: svc, licenseSvc: licenseSvc, customerSvc: customerSvc, txManager: txManager}
}

// grantCursor is the single cursor projection for grant list endpoints.
func grantCursor(g domain.Grant) core.Cursor {
	return core.Cursor{CreatedAt: g.CreatedAt, ID: uuid.UUID(g.ID)}
}

// ListByGrantor returns cursor-paginated grants issued by the target
// account. The caller must hold grant:issue on the path account.
// Route: GET /v1/accounts/:account_id/grants
func (h *GrantHandler) ListByGrantor(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantIssue)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	filter, err := parseGrantListFilter(c, grantorSide)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	grants, hasMore, err := h.svc.ListByGrantor(c.Context(), auth.TargetAccountID, auth.Environment, filter, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(scrubGrantsForReader(grants, auth.ActingAccountID), hasMore, grantCursor))
}

// ListByGrantee returns cursor-paginated grants received by the caller's
// account. Requires grant:use (held by owner, admin, and operator presets).
// Uses the acting account — path-less because grants cross account
// boundaries and there is no grantor account in the URL.
// Route: GET /v1/grants/received
func (h *GrantHandler) ListByGrantee(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantUse)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	grants, hasMore, err := h.svc.ListByGrantee(c.Context(), auth.ActingAccountID, auth.Environment, domain.GrantListFilter{}, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(scrubGrantsForReader(grants, auth.ActingAccountID), hasMore, grantCursor))
}

// ListReceived returns cursor-paginated grants received by the target
// account (grantee-side list with filters). Requires grant:use on the
// path account. Mirror of ListByGrantor from the grantee perspective.
// Route: GET /v1/accounts/:account_id/received-grants
func (h *GrantHandler) ListReceived(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantUse)
	if err != nil {
		return err
	}
	if err := requirePathAccountMatch(c, auth); err != nil {
		return err
	}
	filter, err := parseGrantListFilter(c, granteeSide)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	grants, hasMore, err := h.svc.ListByGrantee(c.Context(), auth.TargetAccountID, auth.Environment, filter, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(scrubGrantsForReader(grants, auth.ActingAccountID), hasMore, grantCursor))
}

// Get returns a single grant by ID. Accessible to either the grantor
// or the grantee — the service verifies the acting account is a party
// to the grant and returns 404 otherwise (no existence leak).
// Requires grant:use, which owner/admin (grantor-capable) and operator
// (grantee-capable) all hold.
// Route: GET /v1/grants/:grant_id
func (h *GrantHandler) Get(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantUse)
	if err != nil {
		return err
	}
	grantID, err := core.ParseGrantID(c.Params("grant_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid grant ID")
	}
	g, err := h.svc.Get(c.Context(), auth.ActingAccountID, auth.Environment, grantID)
	if err != nil {
		return err
	}
	return c.JSON(scrubGrantForReader(g, auth.ActingAccountID))
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
	result, err := h.svc.Issue(c.Context(), auth.TargetAccountID, auth.Environment, req, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(scrubGrantForReader(result, auth.ActingAccountID))
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
	result, err := h.svc.Accept(c.Context(), auth.ActingAccountID, auth.Environment, grantID, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(scrubGrantForReader(result, auth.ActingAccountID))
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
	result, err := h.svc.Suspend(c.Context(), auth.TargetAccountID, auth.Environment, grantID, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(scrubGrantForReader(result, auth.ActingAccountID))
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
	result, err := h.svc.Revoke(c.Context(), auth.TargetAccountID, auth.Environment, grantID, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(scrubGrantForReader(result, auth.ActingAccountID))
}

// Reinstate flips a suspended grant back to active. Called by the grantor.
// Requires grant:revoke (same bundle as Suspend — anyone who can suspend
// can reinstate). Account match validates the grantor is the caller.
// Route: POST /v1/accounts/:account_id/grants/:grant_id/reinstate
func (h *GrantHandler) Reinstate(c fiber.Ctx) error {
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
	result, err := h.svc.Reinstate(c.Context(), auth.TargetAccountID, auth.Environment, grantID, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(scrubGrantForReader(result, auth.ActingAccountID))
}

// Leave transitions a grant to the 'left' terminal state. Called by
// the grantee to end their own access without grantor involvement.
// Authenticated but no RBAC check — any authenticated grantee can
// walk away from a grant they hold.
// Route: POST /v1/grants/:grant_id/leave
func (h *GrantHandler) Leave(c fiber.Ctx) error {
	auth, err := mustAuth(c)
	if err != nil {
		return err
	}
	grantID, err := core.ParseGrantID(c.Params("grant_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid grant ID")
	}
	result, err := h.svc.Leave(c.Context(), auth.ActingAccountID, auth.Environment, grantID, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.JSON(scrubGrantForReader(result, auth.ActingAccountID))
}

// Update applies a partial update to a grant. Called by the grantor.
// Requires grant:update. Account match validates the grantor is the caller.
// Body is parsed with a map[string]json.RawMessage intermediate so
// "field absent" is distinguishable from "field: null" for expires_at
// and label (the only two fields with clear-to-null semantics).
// Route: PATCH /v1/accounts/:account_id/grants/:grant_id
func (h *GrantHandler) Update(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantUpdate)
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

	var req grant.UpdateRequest
	if err := parseGrantUpdateRequest(c.Body(), &req); err != nil {
		return err
	}

	result, err := h.svc.Update(c.Context(), auth.TargetAccountID, auth.Environment, grantID, req, attributionFromAuth(auth))
	if err != nil {
		return err
	}
	return c.JSON(scrubGrantForReader(result, auth.ActingAccountID))
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

	// L4: discriminate the customer path so CheckLicenseCreateConstraints
	// can require the right capability. An inline `customer` block
	// requires CUSTOMER_CREATE; a bare `customer_id` requires
	// CUSTOMER_READ. licensing.Service.Create separately enforces that
	// exactly one of the two is provided.
	inlineCustomer := req.Customer != nil

	// Constraint check runs in a short read-only tx scoped to the
	// grantor so license counts are RLS-filtered to the right tenant.
	// CustomerEmailPattern is no longer enforced here — the check
	// moved to licensing.Service.Create where the resolved customer
	// email is available. We still project it into CreateOptions below.
	if err := h.txManager.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		return h.svc.CheckLicenseCreateConstraints(ctx, g, inlineCustomer)
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

	attr := attributionFromAuth(auth)
	opts := licensing.CreateOptions{
		GrantID:                 &g.ID,
		CreatedByAccountID:      auth.ActingAccountID,
		CreatedByIdentityID:     auth.IdentityID,
		AllowedPolicyIDs:        allowedPolicyIDs,
		CustomerEmailPattern:    constraints.CustomerEmailPattern,
		AllowedEntitlementCodes: constraints.AllowedEntitlementCodes,
		Attribution:             attr,
	}
	// licensing.Service.Create is called with TargetAccountID (grantor)
	// so the license is inserted under the grantor's RLS scope.
	result, err := h.licenseSvc.Create(c.Context(), auth.TargetAccountID, auth.Environment, g.ProductID, req, opts)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// ListCustomers returns customers this grantee created under this
// grant's scope. The ResolveGrant middleware has already flipped
// AuthContext.TargetAccountID to the grantor, so the RLS scope covers
// customers owned by the grantor. We additionally filter by
// created_by_account_id = acting (grantee) so a grantee only sees
// customers they themselves created under this grant — not customers
// the vendor created directly, nor customers created by other grantees
// of the same vendor.
//
// Requires grant:use on the grantee role AND the CUSTOMER_READ grant
// capability. Route is registered in Batch 5.
//
// Route: GET /v1/grants/:grant_id/customers (with ResolveGrant middleware)
func (h *GrantHandler) ListCustomers(c fiber.Ctx) error {
	auth, err := authz(c, rbac.GrantUse)
	if err != nil {
		return err
	}
	g := middleware.GrantFromContext(c)
	if g == nil {
		return core.NewAppError(core.ErrInternalError, "Grant context missing from request")
	}
	if err := h.svc.RequireActive(g); err != nil {
		return err
	}
	if !slices.Contains(g.Capabilities, domain.GrantCapCustomerRead) {
		return core.NewAppError(core.ErrGrantCapabilityMissing, "grant lacks CUSTOMER_READ capability")
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	acting := auth.ActingAccountID
	filter := domain.CustomerListFilter{CreatedByAccountID: &acting}
	var page core.Page[domain.Customer]
	err = h.txManager.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		items, hasMore, err := h.customerSvc.List(ctx, auth.TargetAccountID, filter, cursor, limit)
		if err != nil {
			return err
		}
		page = pageFromCursor(items, hasMore, func(cu domain.Customer) core.Cursor {
			return core.Cursor{CreatedAt: cu.CreatedAt, ID: uuid.UUID(cu.ID)}
		})
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(page)
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

// grantListSide selects which counterparty account_id query param
// parseGrantListFilter reads. Grantor-side lists filter by grantee;
// grantee-side lists filter by grantor.
type grantListSide int

const (
	grantorSide grantListSide = iota // reads `grantee_account_id`
	granteeSide                      // reads `grantor_account_id`
)

// parseGrantListFilter parses query params into a GrantListFilter.
// Accepts `product_id`, counterparty `*_account_id` (grantee or grantor
// per `side`), `status` (comma-separated), and `include_terminal=true`.
func parseGrantListFilter(c fiber.Ctx, side grantListSide) (domain.GrantListFilter, error) {
	var f domain.GrantListFilter
	if raw := c.Query("product_id"); raw != "" {
		pid, err := core.ParseProductID(raw)
		if err != nil {
			return f, core.NewAppError(core.ErrValidationError, "Invalid product_id")
		}
		f.ProductID = &pid
	}
	counterpartyKey := "grantee_account_id"
	if side == granteeSide {
		counterpartyKey = "grantor_account_id"
	}
	if raw := c.Query(counterpartyKey); raw != "" {
		aid, err := core.ParseAccountID(raw)
		if err != nil {
			return f, core.NewAppError(core.ErrValidationError, "Invalid "+counterpartyKey)
		}
		if side == grantorSide {
			f.GranteeAccountID = &aid
		} else {
			f.GrantorAccountID = &aid
		}
	}
	statuses, err := parseGrantStatusList(c.Query("status"))
	if err != nil {
		return f, err
	}
	f.Statuses = statuses
	if c.Query("include_terminal") == "true" {
		f.IncludeTerminal = true
	}
	return f, nil
}

// parseGrantStatusList splits a comma-separated status query parameter
// into typed GrantStatus values. Empty input returns a nil slice; any
// unknown status rejects with ErrValidationError.
func parseGrantStatusList(raw string) ([]domain.GrantStatus, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]domain.GrantStatus, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		s := domain.GrantStatus(p)
		if !domain.IsValidGrantStatus(s) {
			return nil, core.NewAppError(core.ErrValidationError, "Invalid status: "+p)
		}
		out = append(out, s)
	}
	return out, nil
}

// parseGrantUpdateRequest parses a PATCH grant JSON body into an
// UpdateRequest while preserving the key-absent vs. explicit-null
// distinction for expires_at and label. This is required so the
// service layer can implement clear-to-null semantics via the
// double-pointer shape on UpdateGrantParams.
func parseGrantUpdateRequest(raw []byte, dst *grant.UpdateRequest) error {
	if len(raw) == 0 {
		return nil
	}
	var presence map[string]json.RawMessage
	if err := json.Unmarshal(raw, &presence); err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid JSON body")
	}

	if v, ok := presence["capabilities"]; ok {
		var caps []domain.GrantCapability
		if err := json.Unmarshal(v, &caps); err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid capabilities")
		}
		dst.Capabilities = &caps
	}
	if v, ok := presence["constraints"]; ok {
		rm := json.RawMessage(v)
		dst.Constraints = &rm
	}
	if v, ok := presence["metadata"]; ok {
		rm := json.RawMessage(v)
		dst.Metadata = &rm
	}
	if v, ok := presence["expires_at"]; ok {
		var t *time.Time
		if !bytesEqualNull(v) {
			var parsed time.Time
			if err := json.Unmarshal(v, &parsed); err != nil {
				return core.NewAppError(core.ErrValidationError, "Invalid expires_at")
			}
			t = &parsed
		}
		dst.ExpiresAt = &t
	}
	if v, ok := presence["label"]; ok {
		var s *string
		if !bytesEqualNull(v) {
			var parsed string
			if err := json.Unmarshal(v, &parsed); err != nil {
				return core.NewAppError(core.ErrValidationError, "Invalid label")
			}
			s = &parsed
		}
		dst.Label = &s
	}
	return nil
}

// bytesEqualNull reports whether raw is the JSON literal `null` after
// stripping whitespace. Used by parseGrantUpdateRequest to detect the
// explicit-null case on fields that support clear-to-null semantics.
func bytesEqualNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}
