package handler

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// parseLicenseListFilters pulls `status`, `q`, and `product_id` from the
// request query string and validates them. Invalid values return 422 so
// the dashboard can surface the problem instead of silently ignoring it.
// The `type` filter that existed in L0 was removed alongside the
// license_type column; type-shaped narrowing now goes through policies.
func parseLicenseListFilters(c fiber.Ctx) (domain.LicenseListFilters, error) {
	var f domain.LicenseListFilters

	if s := c.Query("status"); s != "" {
		status, err := core.ParseLicenseStatus(s)
		if err != nil {
			return f, core.NewAppError(core.ErrValidationError, "Invalid status filter")
		}
		f.Status = status
	}

	f.Q = c.Query("q")

	if pid := c.Query("product_id"); pid != "" {
		parsed, err := core.ParseProductID(pid)
		if err != nil {
			return f, core.NewAppError(core.ErrValidationError, "Invalid product_id filter")
		}
		f.ProductID = &parsed
	}

	return f, nil
}

// applyAPIKeyProductScope enforces the product-scope contract on the
// flat GET /v1/licenses list handler. If the caller is NOT a
// product-scoped API key, this is a no-op. If they are:
//   - filters.ProductID is injected from auth.APIKeyProductID when
//     not already explicitly set via `?product_id=`.
//   - If filters.ProductID is already set and differs from
//     auth.APIKeyProductID, return 403 api_key_scope_mismatch.
//
// Identity callers and account-wide API keys pass through unchanged.
// The GET /v1/products/:id/licenses path goes through its own
// licensing.Service.ListByProduct, which hits middleware.EnforceProductScope
// on the productID path arg (Task 12), so this helper only fires on the
// flat list route.
func applyAPIKeyProductScope(c fiber.Ctx, filters *domain.LicenseListFilters) error {
	auth := middleware.AuthFromContext(c)
	if auth == nil {
		return nil
	}
	if auth.ActorKind != middleware.ActorKindAPIKey {
		return nil
	}
	if auth.APIKeyScope != core.APIKeyScopeProduct {
		return nil
	}
	if auth.APIKeyProductID == nil {
		return core.NewAppError(core.ErrAPIKeyScopeMismatch,
			"API key is product-scoped but has no product binding")
	}
	if filters.ProductID != nil && *filters.ProductID != *auth.APIKeyProductID {
		return core.NewAppError(core.ErrAPIKeyScopeMismatch,
			"product_id filter does not match this API key's bound product")
	}
	pid := *auth.APIKeyProductID
	filters.ProductID = &pid
	return nil
}

// LicenseHandler handles license lifecycle and machine endpoints.
type LicenseHandler struct {
	svc *licensing.Service
}

// NewLicenseHandler creates a new LicenseHandler.
func NewLicenseHandler(svc *licensing.Service) *LicenseHandler {
	return &LicenseHandler{svc: svc}
}

// Create creates a new license under a product.
// The product ID comes from the URL parameter :id.
func (h *LicenseHandler) Create(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	var req licensing.CreateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseCreate)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	opts := licensing.CreateOptions{
		CreatedByAccountID:  auth.ActingAccountID,
		CreatedByIdentityID: auth.IdentityID,
		Attribution:         attr,
	}
	result, err := h.svc.Create(c.Context(), auth.TargetAccountID, auth.Environment, productID, req, opts)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// BulkCreate creates up to 100 licenses under a product in a single transaction.
func (h *LicenseHandler) BulkCreate(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	var req licensing.BulkCreateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseCreate)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	opts := licensing.CreateOptions{
		CreatedByAccountID:  auth.ActingAccountID,
		CreatedByIdentityID: auth.IdentityID,
		Attribution:         attr,
	}
	result, err := h.svc.BulkCreate(c.Context(), auth.TargetAccountID, auth.Environment, productID, req, opts)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a cursor-paginated list of licenses, optionally narrowed by
// `?status=` and `?q=` query params. The dashboard drives these from the
// URL so filters survive pagination.
func (h *LicenseHandler) List(c fiber.Ctx) error {
	filters, err := parseLicenseListFilters(c)
	if err != nil {
		return err
	}
	auth, err := authz(c, rbac.LicenseRead)
	if err != nil {
		return err
	}
	if err := applyAPIKeyProductScope(c, &filters); err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	licenses, hasMore, err := h.svc.List(c.Context(), auth.TargetAccountID, auth.Environment, filters, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(licenses, hasMore, func(l domain.License) core.Cursor {
		return core.Cursor{CreatedAt: l.CreatedAt, ID: uuid.UUID(l.ID)}
	}))
}

// ListByProduct returns a cursor-paginated list of licenses scoped to a
// single product, optionally narrowed by `?status=` and `?q=` query
// params. Routed as GET /v1/products/:id/licenses to match the existing
// POST and DELETE on the same collection.
func (h *LicenseHandler) ListByProduct(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	filters, err := parseLicenseListFilters(c)
	if err != nil {
		return err
	}
	auth, err := authz(c, rbac.LicenseRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	licenses, hasMore, err := h.svc.ListByProduct(c.Context(), auth.TargetAccountID, auth.Environment, productID, filters, cursor, limit)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(licenses, hasMore, func(l domain.License) core.Cursor {
		return core.Cursor{CreatedAt: l.CreatedAt, ID: uuid.UUID(l.ID)}
	}))
}

// BulkRevokeByProduct atomically revokes every active or suspended
// license for the given product in the current env. Returns the
// number of licenses revoked. Routed as DELETE on the collection
// (DELETE /v1/products/:id/licenses) to match the singular DELETE
// /v1/licenses/:id semantic where "delete" means "revoke".
func (h *LicenseHandler) BulkRevokeByProduct(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	auth, err := authz(c, rbac.LicenseRevoke)
	if err != nil {
		return err
	}
	count, err := h.svc.BulkRevokeForProduct(c.Context(), auth.TargetAccountID, auth.Environment, productID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(bulkRevokeResponse{Revoked: count})
}

// Get retrieves a single license by ID.
func (h *LicenseHandler) Get(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	auth, err := authz(c, rbac.LicenseRead)
	if err != nil {
		return err
	}
	result, err := h.svc.Get(c.Context(), auth.TargetAccountID, auth.Environment, licenseID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Revoke permanently revokes a license.
func (h *LicenseHandler) Revoke(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	auth, err := authz(c, rbac.LicenseRevoke)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	if err := h.svc.Revoke(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, attr); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Suspend temporarily suspends a license.
func (h *LicenseHandler) Suspend(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	auth, err := authz(c, rbac.LicenseSuspend)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	result, err := h.svc.Suspend(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, attr)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Reinstate reactivates a suspended license.
func (h *LicenseHandler) Reinstate(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	result, err := h.svc.Reinstate(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, attr)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Activate registers a new machine for a license.
func (h *LicenseHandler) Activate(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	var req licensing.ActivateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	result, err := h.svc.Activate(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, req, attr)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Deactivate removes a machine by fingerprint.
func (h *LicenseHandler) Deactivate(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	var req licensing.DeactivateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.MachineDeactivate)
	if err != nil {
		return err
	}
	attr := attributionFromAuth(auth)
	if err := h.svc.Deactivate(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, req, attr); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Checkin renews a machine's lease and returns a fresh lease token.
func (h *LicenseHandler) Checkin(c fiber.Ctx) error {
	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid license id")
	}
	fingerprint := c.Params("fingerprint")
	attr := attributionFromAuth(auth)
	result, err := h.svc.Checkin(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, fingerprint, attr)
	if err != nil {
		return err
	}
	return c.JSON(result)
}

// Update applies partial updates to a license. Supported fields are
// overrides, expires_at, customer_id. PATCH uses **time.Time for
// expires_at so callers can explicitly clear it (null = perpetual).
func (h *LicenseHandler) Update(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	var req licensing.UpdateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	result, err := h.svc.Update(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Freeze snapshots the license's current effective quantitative values
// into its overrides so future policy changes no longer affect it.
// POST /v1/licenses/:id/freeze.
func (h *LicenseHandler) Freeze(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}
	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	result, err := h.svc.Freeze(c.Context(), auth.TargetAccountID, auth.Environment, licenseID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// attachPolicyRequest is the POST /v1/licenses/:id/attach-policy body.
// clear_overrides wipes per-license overrides so the new policy's raw
// values take full effect.
type attachPolicyRequest struct {
	PolicyID       core.PolicyID `json:"policy_id"`
	ClearOverrides bool          `json:"clear_overrides"`
}

// bulkRevokeResponse is the DELETE /v1/products/:id/licenses body —
// the count of active/suspended licenses revoked in one tx.
type bulkRevokeResponse struct {
	Revoked int `json:"revoked"`
}

// AttachPolicy moves a license to a different policy under the same
// product, optionally clearing its overrides so the new policy's values
// take effect unchanged. POST /v1/licenses/:id/attach-policy.
func (h *LicenseHandler) AttachPolicy(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}
	var req attachPolicyRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	result, err := h.svc.AttachPolicy(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, req.PolicyID, req.ClearOverrides)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// ListMachines returns a cursor-paginated list of machines for the
// license. Optional `status` query param (active|stale|dead) filters
// by lifecycle state; invalid values return 422. This is the vendor
// path; grantees call the sister route at
// GET /v1/grants/:grant_id/licenses/:license_id/machines.
//
// Route: GET /v1/licenses/:id/machines
func (h *LicenseHandler) ListMachines(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}
	auth, err := authz(c, rbac.MachineRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	// Vendor route — callerGrantID is nil. The service's grantee gate
	// only fires for grant-scoped callers (Task 8's route). Status
	// validation happens inside the service.
	rows, hasMore, err := h.svc.ListMachines(
		c.Context(), auth.TargetAccountID, auth.Environment,
		licenseID, c.Query("status"), cursor, limit, nil,
	)
	if err != nil {
		return err
	}
	return c.JSON(pageFromCursor(rows, hasMore, func(m domain.Machine) core.Cursor {
		return core.Cursor{CreatedAt: m.CreatedAt, ID: uuid.UUID(m.ID)}
	}))
}
