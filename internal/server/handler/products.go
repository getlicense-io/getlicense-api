package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/product"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// ProductHandler handles product CRUD endpoints.
type ProductHandler struct {
	svc *product.Service
}

// NewProductHandler creates a new ProductHandler.
func NewProductHandler(svc *product.Service) *ProductHandler {
	return &ProductHandler{svc: svc}
}

// Create creates a new product.
func (h *ProductHandler) Create(c fiber.Ctx) error {
	var req product.CreateRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	a := middleware.FromContext(c)
	result, err := h.svc.Create(c.Context(), a.AccountID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a paginated list of products.
func (h *ProductHandler) List(c fiber.Ctx) error {
	limit, offset := paginationParams(c)
	a := middleware.FromContext(c)

	products, total, err := h.svc.List(c.Context(), a.AccountID, limit, offset)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(domain.ListResponse[domain.Product]{
		Data: products,
		Pagination: domain.Pagination{
			Limit:  limit,
			Offset: offset,
			Total:  total,
		},
	})
}

// Get retrieves a single product by ID.
func (h *ProductHandler) Get(c fiber.Ctx) error {
	productID, err := core.ParseProductID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid product ID")
	}

	a := middleware.FromContext(c)
	result, err := h.svc.Get(c.Context(), a.AccountID, productID)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
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

	a := middleware.FromContext(c)
	result, err := h.svc.Update(c.Context(), a.AccountID, productID, req)
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

	a := middleware.FromContext(c)
	if err := h.svc.Delete(c.Context(), a.AccountID, productID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
