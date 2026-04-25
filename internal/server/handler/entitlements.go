package handler

import (
	"context"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/entitlement"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// EntitlementHandler serves entitlement registry CRUD plus
// policy/license attach and detach endpoints. The entitlement service
// is pure (no internal tx), so every handler method is the tx boundary.
//
// The license repo is injected for ListLicenseEntitlements which needs
// the license's PolicyID to compute the three-set response. The policy
// repo verifies policy visibility on policy-entitlement endpoints.
// Injecting the repos (not services) avoids nested transactions.
type EntitlementHandler struct {
	tx          domain.TxManager
	svc         *entitlement.Service
	licenseRepo domain.LicenseRepository
	policyRepo  domain.PolicyRepository
}

// NewEntitlementHandler constructs an EntitlementHandler.
func NewEntitlementHandler(tx domain.TxManager, svc *entitlement.Service, licenseRepo domain.LicenseRepository, policyRepo domain.PolicyRepository) *EntitlementHandler {
	return &EntitlementHandler{tx: tx, svc: svc, licenseRepo: licenseRepo, policyRepo: policyRepo}
}

// codesRequest is the body shape for attach/replace operations.
type codesRequest struct {
	Codes []string `json:"codes"`
}

// ---------------------------------------------------------------------------
// Registry CRUD
// ---------------------------------------------------------------------------

// List returns a paginated list of entitlements for the authenticated
// tenant. Accepts an optional ?code_prefix= filter.
// GET /v1/entitlements
func (h *EntitlementHandler) List(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EntitlementRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	codePrefix := c.Query("code_prefix")

	var page core.Page[domain.Entitlement]
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		items, hasMore, lerr := h.svc.List(ctx, auth.TargetAccountID, codePrefix, cursor, limit)
		if lerr != nil {
			return lerr
		}
		page = pageFromCursor(items, hasMore, func(e domain.Entitlement) core.Cursor {
			return core.Cursor{CreatedAt: e.CreatedAt, ID: uuid.UUID(e.ID)}
		})
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(page)
}

// Create inserts a new entitlement into the registry.
// POST /v1/entitlements
func (h *EntitlementHandler) Create(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EntitlementWrite)
	if err != nil {
		return err
	}
	var req entitlement.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	var created *domain.Entitlement
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var cerr error
		created, cerr = h.svc.Create(ctx, auth.TargetAccountID, req)
		return cerr
	})
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

// Get retrieves a single entitlement by ID.
// GET /v1/entitlements/:id
func (h *EntitlementHandler) Get(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EntitlementRead)
	if err != nil {
		return err
	}
	id, err := core.ParseEntitlementID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid entitlement id")
	}
	var got *domain.Entitlement
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var gerr error
		got, gerr = h.svc.Get(ctx, id)
		return gerr
	})
	if err != nil {
		return err
	}
	return c.JSON(got)
}

// Update applies a partial change (name, metadata). Code is immutable.
// PATCH /v1/entitlements/:id
func (h *EntitlementHandler) Update(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EntitlementWrite)
	if err != nil {
		return err
	}
	id, err := core.ParseEntitlementID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid entitlement id")
	}
	var req entitlement.UpdateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	var updated *domain.Entitlement
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		var uerr error
		updated, uerr = h.svc.Update(ctx, id, req)
		return uerr
	})
	if err != nil {
		return err
	}
	return c.JSON(updated)
}

// Delete removes an entitlement from the registry. Returns 409
// entitlement_in_use if the entitlement is attached to a policy or
// license. DELETE /v1/entitlements/:id
func (h *EntitlementHandler) Delete(c fiber.Ctx) error {
	auth, err := authz(c, rbac.EntitlementDelete)
	if err != nil {
		return err
	}
	id, err := core.ParseEntitlementID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid entitlement id")
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		return h.svc.Delete(ctx, id)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ---------------------------------------------------------------------------
// Policy entitlement surface
// ---------------------------------------------------------------------------

// ListPolicyEntitlements returns sorted entitlement codes attached to a
// policy. GET /v1/policies/:id/entitlements
func (h *EntitlementHandler) ListPolicyEntitlements(c fiber.Ctx) error {
	auth, err := authz(c, rbac.PolicyRead)
	if err != nil {
		return err
	}
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid policy id")
	}
	var codes []string
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify policy is visible to the calling tenant.
		p, perr := h.policyRepo.Get(ctx, policyID)
		if perr != nil {
			return perr
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		// Product-scope gate: a product-scoped API key must not read
		// entitlements on a policy outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, p.ProductID); perr != nil {
			return perr
		}
		var lerr error
		codes, lerr = h.svc.ListPolicyCodes(ctx, policyID)
		return lerr
	})
	if err != nil {
		return err
	}
	if codes == nil {
		codes = []string{}
	}
	return c.JSON(codes)
}

// AttachPolicyEntitlements attaches entitlement codes to a policy.
// POST /v1/policies/:id/entitlements
func (h *EntitlementHandler) AttachPolicyEntitlements(c fiber.Ctx) error {
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid policy id")
	}
	var req codesRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify policy is visible to the calling tenant.
		p, perr := h.policyRepo.Get(ctx, policyID)
		if perr != nil {
			return perr
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		// Product-scope gate: a product-scoped API key must not mutate
		// entitlements on a policy outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, p.ProductID); perr != nil {
			return perr
		}
		return h.svc.AttachToPolicy(ctx, policyID, req.Codes, auth.TargetAccountID)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ReplacePolicyEntitlements replaces all entitlement codes on a policy.
// PUT /v1/policies/:id/entitlements
func (h *EntitlementHandler) ReplacePolicyEntitlements(c fiber.Ctx) error {
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid policy id")
	}
	var req codesRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify policy is visible to the calling tenant.
		p, perr := h.policyRepo.Get(ctx, policyID)
		if perr != nil {
			return perr
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		// Product-scope gate: a product-scoped API key must not replace
		// entitlements on a policy outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, p.ProductID); perr != nil {
			return perr
		}
		return h.svc.ReplacePolicyAttachments(ctx, policyID, req.Codes, auth.TargetAccountID)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DetachPolicyEntitlement detaches a single entitlement code from a policy.
// DELETE /v1/policies/:id/entitlements/:code
func (h *EntitlementHandler) DetachPolicyEntitlement(c fiber.Ctx) error {
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid policy id")
	}
	code := c.Params("code")
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify policy is visible to the calling tenant.
		p, perr := h.policyRepo.Get(ctx, policyID)
		if perr != nil {
			return perr
		}
		if p == nil {
			return core.NewAppError(core.ErrPolicyNotFound, "policy not found")
		}
		// Product-scope gate: a product-scoped API key must not detach
		// entitlements on a policy outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, p.ProductID); perr != nil {
			return perr
		}
		return h.svc.DetachFromPolicy(ctx, policyID, code, auth.TargetAccountID)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ---------------------------------------------------------------------------
// License entitlement surface
// ---------------------------------------------------------------------------

// ListLicenseEntitlements returns the three-set response (policy,
// license, effective) for a license's entitlements. The license's
// PolicyID is needed to compute the policy set.
// GET /v1/licenses/:id/entitlements
func (h *EntitlementHandler) ListLicenseEntitlements(c fiber.Ctx) error {
	auth, err := authz(c, rbac.LicenseRead)
	if err != nil {
		return err
	}
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid license id")
	}
	var sets entitlement.EntitlementSets
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		license, lerr := h.licenseRepo.GetByID(ctx, licenseID)
		if lerr != nil {
			return lerr
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "license not found")
		}
		// Product-scope gate: a product-scoped API key must not read
		// entitlements on a license outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, license.ProductID); perr != nil {
			return perr
		}
		var serr error
		sets, serr = h.svc.ThreeSetResponse(ctx, licenseID, license.PolicyID)
		return serr
	})
	if err != nil {
		return err
	}
	return c.JSON(sets)
}

// AttachLicenseEntitlements attaches entitlement codes to a license.
// POST /v1/licenses/:id/entitlements
func (h *EntitlementHandler) AttachLicenseEntitlements(c fiber.Ctx) error {
	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid license id")
	}
	var req codesRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify license is visible to the calling tenant.
		license, lerr := h.licenseRepo.GetByID(ctx, licenseID)
		if lerr != nil {
			return lerr
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "license not found")
		}
		// Product-scope gate: a product-scoped API key must not attach
		// entitlements on a license outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, license.ProductID); perr != nil {
			return perr
		}
		return h.svc.AttachToLicense(ctx, licenseID, req.Codes, auth.TargetAccountID)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ReplaceLicenseEntitlements replaces all entitlement codes on a license.
// PUT /v1/licenses/:id/entitlements
func (h *EntitlementHandler) ReplaceLicenseEntitlements(c fiber.Ctx) error {
	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid license id")
	}
	var req codesRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify license is visible to the calling tenant.
		license, lerr := h.licenseRepo.GetByID(ctx, licenseID)
		if lerr != nil {
			return lerr
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "license not found")
		}
		// Product-scope gate: a product-scoped API key must not replace
		// entitlements on a license outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, license.ProductID); perr != nil {
			return perr
		}
		return h.svc.ReplaceLicenseAttachments(ctx, licenseID, req.Codes, auth.TargetAccountID)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// DetachLicenseEntitlement detaches a single entitlement code from a license.
// DELETE /v1/licenses/:id/entitlements/:code
func (h *EntitlementHandler) DetachLicenseEntitlement(c fiber.Ctx) error {
	auth, err := authz(c, rbac.LicenseUpdate)
	if err != nil {
		return err
	}
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid license id")
	}
	code := c.Params("code")
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify license is visible to the calling tenant.
		license, lerr := h.licenseRepo.GetByID(ctx, licenseID)
		if lerr != nil {
			return lerr
		}
		if license == nil {
			return core.NewAppError(core.ErrLicenseNotFound, "license not found")
		}
		// Product-scope gate: a product-scoped API key must not detach
		// entitlements on a license outside its bound product.
		if perr := middleware.EnforceProductScope(ctx, license.ProductID); perr != nil {
			return perr
		}
		return h.svc.DetachFromLicense(ctx, licenseID, code, auth.TargetAccountID)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
