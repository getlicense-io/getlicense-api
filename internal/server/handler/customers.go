package handler

import (
	"context"

	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/customer"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// CustomerHandler serves /v1/customers — direct, vendor-side customer
// CRUD plus the per-customer license listing. Tx discipline lives here
// (not in customer.Service) so we can compose multi-step operations in
// one RLS-scoped transaction, matching PolicyHandler.
//
// The licensing service is injected solely for ListLicenses; the
// endpoint does the customer-existence check first (so the 404
// surfaces before the list query) and then delegates to
// licensing.Service.ListByCustomer which opens its own tx under the
// same target account.
type CustomerHandler struct {
	tx         domain.TxManager
	svc        *customer.Service
	licenseSvc *licensing.Service
}

// NewCustomerHandler constructs a CustomerHandler. The licensing
// service is required for GET /v1/customers/:id/licenses.
func NewCustomerHandler(tx domain.TxManager, svc *customer.Service, licenseSvc *licensing.Service) *CustomerHandler {
	return &CustomerHandler{tx: tx, svc: svc, licenseSvc: licenseSvc}
}

// List returns a page of customers for the authenticated tenant.
// Filters: ?email= (case-insensitive prefix), ?created_by_account_id=
// (exact match, uuid). GET /v1/customers.
func (h *CustomerHandler) List(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerRead)
	if err != nil {
		return err
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	filter := domain.CustomerListFilter{
		Email: c.Query("email"),
	}
	if s := c.Query("created_by_account_id"); s != "" {
		id, perr := core.ParseAccountID(s)
		if perr != nil {
			return core.NewAppError(core.ErrValidationError, "invalid created_by_account_id")
		}
		filter.CreatedByAccountID = &id
	}
	var page core.Page[domain.Customer]
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		items, hasMore, err := h.svc.List(ctx, auth.TargetAccountID, filter, cursor, limit)
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

// Create inserts a new customer. Email normalization happens inside
// the customer service. POST /v1/customers.
func (h *CustomerHandler) Create(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerWrite)
	if err != nil {
		return err
	}
	var req customer.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	var created *domain.Customer
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

// Get fetches a single customer by ID. The RLS scope ensures that a
// customer owned by another account surfaces as the same 404 as one
// that does not exist — we never leak cross-tenant existence.
// GET /v1/customers/:id.
func (h *CustomerHandler) Get(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerRead)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	var got *domain.Customer
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

// Update applies a partial change (name, metadata). Email is immutable
// post-create per spec. PATCH /v1/customers/:id.
func (h *CustomerHandler) Update(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerWrite)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	var req customer.UpdateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}
	var updated *domain.Customer
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

// Delete refuses customers that have licenses referencing them
// (customer.Service returns ErrCustomerInUse → 409). Successful deletes
// return 204. DELETE /v1/customers/:id.
func (h *CustomerHandler) Delete(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerDelete)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	err = h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		return h.svc.Delete(ctx, id)
	})
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListLicenses returns a page of licenses owned by this customer.
// Verifies the customer exists (and is visible under this tenant's RLS)
// before running the list query, so a stale/cross-tenant ID returns
// a clean 404 instead of an empty page. GET /v1/customers/:id/licenses.
func (h *CustomerHandler) ListLicenses(c fiber.Ctx) error {
	auth, err := authz(c, rbac.CustomerRead)
	if err != nil {
		return err
	}
	id, err := core.ParseCustomerID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "invalid customer id")
	}
	cursor, limit, err := cursorParams(c)
	if err != nil {
		return err
	}
	// Verify the customer exists and is visible first so a 404
	// surfaces before the list query runs.
	if err := h.tx.WithTargetAccount(c.Context(), auth.TargetAccountID, auth.Environment, func(ctx context.Context) error {
		_, gerr := h.svc.Get(ctx, id)
		return gerr
	}); err != nil {
		return err
	}
	items, hasMore, err := h.licenseSvc.ListByCustomer(c.Context(), auth.TargetAccountID, auth.Environment, id, cursor, limit)
	if err != nil {
		return err
	}
	page := pageFromCursor(items, hasMore, func(l domain.License) core.Cursor {
		return core.Cursor{CreatedAt: l.CreatedAt, ID: uuid.UUID(l.ID)}
	})
	return c.JSON(page)
}
