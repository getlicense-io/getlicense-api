package handler

import (
	"context"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/policy"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// PolicyHandler exposes policy CRUD + default-promotion. Policies are
// account-scoped (not environment-scoped) — every handler still runs
// inside a WithTargetAccount tx so the RLS policy on the policies table
// sees the tenant, and so the licensing side-effects of Delete (which
// reassigns licenses back to the default policy) stay within one atomic
// unit alongside the policy mutation.
//
// The policy service is pure — its methods do not open transactions.
// Every handler method here is the tx boundary.
//
// The products repo is injected so ListByProduct can verify the parent
// product exists in the tenant and return 404 instead of an empty list
// when the id is bogus or cross-tenant. Create does not need a pre-check
// — the FK violation is classified in PolicyRepo.Create.
type PolicyHandler struct {
	svc      *policy.Service
	tx       domain.TxManager
	products domain.ProductRepository
}

// NewPolicyHandler constructs a PolicyHandler. The TxManager is required
// because policy.Service methods are pure and assume the caller has
// already opened a WithTargetAccount transaction.
func NewPolicyHandler(svc *policy.Service, tx domain.TxManager, products domain.ProductRepository) *PolicyHandler {
	return &PolicyHandler{svc: svc, tx: tx, products: products}
}

// ListByProduct returns a cursor-paginated list of policies for a
// product. GET /v1/products/:id/policies.
func (h *PolicyHandler) ListByProduct(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}
	auth, err := authz(c, rbac.PolicyRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}

	var (
		items   []domain.Policy
		hasMore bool
	)
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// Verify the parent product exists in the tenant before listing.
		// Without this the endpoint returns 200 {"data":[]} for a bogus
		// or cross-tenant product id, which is a BOLA-lite leak (clients
		// can probe for product ids) and also confuses dashboards that
		// distinguish "no policies yet" from "product not found".
		prod, perr := h.products.GetByID(ctx, productID)
		if perr != nil {
			return perr
		}
		if prod == nil {
			return core.NewAppError(core.ErrProductNotFound, "product not found")
		}
		items, hasMore, err = h.svc.ListByProduct(ctx, productID, cursor, limit)
		return err
	}); err != nil {
		return err
	}
	return c.JSON(pageFromCursor(items, hasMore, func(p domain.Policy) core.Cursor {
		return core.Cursor{CreatedAt: p.CreatedAt, ID: uuid.UUID(p.ID)}
	}))
}

// Create creates a non-default policy under a product.
// POST /v1/products/:id/policies.
func (h *PolicyHandler) Create(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}
	var req policy.CreateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}

	var result *domain.Policy
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		// RLS-scoped pre-check. PolicyRepo.Create also translates a bare
		// FK violation into ErrProductNotFound for bogus UUIDs, but FK
		// checks bypass RLS — so a cross-tenant product id would
		// otherwise succeed and leak `policies.account_id = caller`
		// + `policies.product_id = other tenant`. The RLS-scoped
		// lookup here hides any product the caller does not own,
		// so both "doesn't exist" and "belongs to another tenant"
		// collapse into the same 404.
		prod, perr := h.products.GetByID(ctx, productID)
		if perr != nil {
			return perr
		}
		if prod == nil {
			return core.NewAppError(core.ErrProductNotFound, "product not found")
		}
		p, err := h.svc.Create(ctx, auth.TargetAccountID, productID, req, false)
		if err != nil {
			return err
		}
		result = p
		return nil
	}); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// Get retrieves a single policy by ID. GET /v1/policies/:id.
func (h *PolicyHandler) Get(c fiber.Ctx) error {
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid policy ID")
	}
	auth, err := authz(c, rbac.PolicyRead)
	if err != nil {
		return err
	}

	var result *domain.Policy
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		p, err := h.svc.Get(ctx, policyID)
		if err != nil {
			return err
		}
		result = p
		return nil
	}); err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Update applies partial updates to a policy. PATCH /v1/policies/:id.
func (h *PolicyHandler) Update(c fiber.Ctx) error {
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid policy ID")
	}
	var req policy.UpdateRequest
	if err := bindStrict(c, &req); err != nil {
		return err
	}
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}

	var result *domain.Policy
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		p, err := h.svc.Update(ctx, policyID, req)
		if err != nil {
			return err
		}
		result = p
		return nil
	}); err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Delete removes a policy. The default policy cannot be deleted. If the
// policy is referenced by licenses, callers must pass `?force=true` to
// reassign those licenses back onto the product's default policy in the
// same transaction. DELETE /v1/policies/:id.
func (h *PolicyHandler) Delete(c fiber.Ctx) error {
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid policy ID")
	}
	auth, err := authz(c, rbac.PolicyDelete)
	if err != nil {
		return err
	}
	force := c.Query("force") == "true"

	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		return h.svc.Delete(ctx, policyID, force)
	}); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// SetDefault promotes a policy to the product's default. The previous
// default is demoted in the same transaction.
// POST /v1/policies/:id/set-default.
func (h *PolicyHandler) SetDefault(c fiber.Ctx) error {
	policyID, err := core.ParsePolicyID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid policy ID")
	}
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}

	var result *domain.Policy
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		if err := h.svc.SetDefault(ctx, policyID); err != nil {
			return err
		}
		p, err := h.svc.Get(ctx, policyID)
		if err != nil {
			return err
		}
		result = p
		return nil
	}); err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}
