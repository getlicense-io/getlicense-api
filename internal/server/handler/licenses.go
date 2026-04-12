package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/licensing"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

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

	a := middleware.FromContext(c)
	result, err := h.svc.Create(c.Context(), a.AccountID, a.Environment, productID, req)
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

	a := middleware.FromContext(c)
	result, err := h.svc.BulkCreate(c.Context(), a.AccountID, a.Environment, productID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(result)
}

// List returns a paginated list of licenses.
func (h *LicenseHandler) List(c fiber.Ctx) error {
	limit, offset := paginationParams(c)
	a := middleware.FromContext(c)

	licenses, total, err := h.svc.List(c.Context(), a.AccountID, a.Environment, limit, offset)
	if err != nil {
		return err
	}
	return listJSON(c, licenses, limit, offset, total)
}

// Get retrieves a single license by ID.
func (h *LicenseHandler) Get(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	a := middleware.FromContext(c)
	result, err := h.svc.Get(c.Context(), a.AccountID, a.Environment, licenseID)
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

	a := middleware.FromContext(c)
	if err := h.svc.Revoke(c.Context(), a.AccountID, a.Environment, licenseID); err != nil {
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

	a := middleware.FromContext(c)
	result, err := h.svc.Suspend(c.Context(), a.AccountID, a.Environment, licenseID)
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

	a := middleware.FromContext(c)
	result, err := h.svc.Reinstate(c.Context(), a.AccountID, a.Environment, licenseID)
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

	a := middleware.FromContext(c)
	result, err := h.svc.Activate(c.Context(), a.AccountID, a.Environment, licenseID, req)
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

	a := middleware.FromContext(c)
	if err := h.svc.Deactivate(c.Context(), a.AccountID, a.Environment, licenseID, req); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Heartbeat updates the last-seen timestamp for a machine.
func (h *LicenseHandler) Heartbeat(c fiber.Ctx) error {
	licenseID, err := core.ParseLicenseID(c.Params("id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid license ID")
	}

	var req licensing.HeartbeatRequest
	if err := c.Bind().Body(&req); err != nil {
		return err
	}

	a := middleware.FromContext(c)
	result, err := h.svc.Heartbeat(c.Context(), a.AccountID, a.Environment, licenseID, req)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusOK).JSON(result)
}
