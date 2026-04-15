package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// ProductHandler handles product CRUD endpoints. The single-product
// GET response composes a product with its license-count summary in
// one round-trip — see Get below.
type ProductHandler struct {
	svc        *product.Service
	licenseSvc *licensing.Service
}

// NewProductHandler creates a new ProductHandler.
func NewProductHandler(svc *product.Service, licenseSvc *licensing.Service) *ProductHandler {
	return &ProductHandler{svc: svc, licenseSvc: licenseSvc}
}

// productDetailResponse is the wire shape of GET /v1/products/:id.
// We embed *domain.Product and add a license_counts summary so the
// dashboard's product-detail page (and any API client building a
// blocking-delete UI) gets accurate counts in one round-trip
// regardless of how many licenses the product has.
type productDetailResponse struct {
	*domain.Product
	LicenseCounts domain.LicenseStatusCounts `json:"license_counts"`
}

// Create creates a new product.
func (h *ProductHandler) Create(c fiber.Ctx) error {
	var req product.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.ProductCreate)
	if err != nil {
		return err
	}
	result, err := h.svc.Create(c.Context(), auth.TargetAccountID, auth.Environment, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a paginated list of products.
func (h *ProductHandler) List(c fiber.Ctx) error {
	limit, offset := paginationParams(c)

	auth, err := authz(c, rbac.ProductRead)
	if err != nil {
		return err
	}

	products, total, err := h.svc.List(c.Context(), auth.TargetAccountID, auth.Environment, limit, offset)
	if err != nil {
		return err
	}
	return listJSON(c, products, limit, offset, total)
}

// Get retrieves a single product by ID along with its per-status
// license count summary for the active env. The composition lives
// here (not in the product or licensing service) so neither domain
// service has to know about the other — the handler is the seam.
func (h *ProductHandler) Get(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	auth, err := authz(c, rbac.ProductRead)
	if err != nil {
		return err
	}
	p, err := h.svc.Get(c.Context(), auth.TargetAccountID, auth.Environment, productID)
	if err != nil {
		return err
	}
	counts, err := h.licenseSvc.CountsByProductStatus(c.Context(), auth.TargetAccountID, auth.Environment, productID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(productDetailResponse{
		Product:       p,
		LicenseCounts: counts,
	})
}

// Update applies partial updates to a product.
func (h *ProductHandler) Update(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	var req product.UpdateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	auth, err := authz(c, rbac.ProductUpdate)
	if err != nil {
		return err
	}
	result, err := h.svc.Update(c.Context(), auth.TargetAccountID, auth.Environment, productID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}

// Delete removes a product by ID.
func (h *ProductHandler) Delete(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	auth, err := authz(c, rbac.ProductDelete)
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.Context(), auth.TargetAccountID, auth.Environment, productID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
