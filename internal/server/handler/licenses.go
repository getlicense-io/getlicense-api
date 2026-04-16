package handler

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// parseLicenseListFilters pulls `status` and `q` from the request query
// string and validates enum values. Invalid enums return 422 so the
// dashboard can surface the problem instead of silently ignoring it.
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
	return f, nil
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
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseCreate)
	if err != nil {
		return err
	}
	opts := licensing.CreateOptions{
		CreatedByAccountID:  auth.ActingAccountID,
		CreatedByIdentityID: auth.IdentityID,
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
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseCreate)
	if err != nil {
		return err
	}
	opts := licensing.CreateOptions{
		CreatedByAccountID:  auth.ActingAccountID,
		CreatedByIdentityID: auth.IdentityID,
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
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"revoked": count})
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
	if err := h.svc.Revoke(c.Context(), auth.TargetAccountID, auth.Environment, licenseID); err != nil {
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
	result, err := h.svc.Suspend(c.Context(), auth.TargetAccountID, auth.Environment, licenseID)
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
	result, err := h.svc.Reinstate(c.Context(), auth.TargetAccountID, auth.Environment, licenseID)
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
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	result, err := h.svc.Activate(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// Deactivate removes a machine by fingerprint.
func (h *LicenseHandler) Deactivate(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	var req licensing.DeactivateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.MachineDeactivate)
	if err != nil {
		return err
	}
	if err := h.svc.Deactivate(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, req); err != nil {
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
	result, err := h.svc.Checkin(c.Context(), auth.TargetAccountID, auth.Environment, licenseID, fingerprint)
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
	if err := c.Bind().Body(&req); err != nil {
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

// AttachPolicyRequest is the POST /v1/licenses/:id/attach-policy body.
// clear_overrides wipes per-license overrides so the new policy's raw
// values take full effect.
type AttachPolicyRequest struct {
	PolicyID       core.PolicyID `json:"policy_id"`
	ClearOverrides bool          `json:"clear_overrides"`
}

// AttachPolicy moves a license to a different policy under the same
// product, optionally clearing its overrides so the new policy's values
// take effect unchanged. POST /v1/licenses/:id/attach-policy.
func (h *LicenseHandler) AttachPolicy(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}
	var req AttachPolicyRequest
	if err := c.Bind().Body(&req); err != nil {
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

