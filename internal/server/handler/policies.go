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
type PolicyHandler struct {
	svc *policy.Service
	tx  domain.TxManager
}

// NewPolicyHandler constructs a PolicyHandler. The TxManager is required
// because policy.Service methods are pure and assume the caller has
// already opened a WithTargetAccount transaction.
func NewPolicyHandler(svc *policy.Service, tx domain.TxManager) *PolicyHandler {
	return &PolicyHandler{svc: svc, tx: tx}
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
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	auth, err := authz(c, rbac.PolicyWrite)
	if err != nil {
		return err
	}

	var result *domain.Policy
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
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
	if err := c.Bind().Body(&req); err != nil {
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
