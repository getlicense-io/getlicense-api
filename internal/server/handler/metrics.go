package handler

import (
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/analytics"
	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
)

// MetricsHandler handles the metrics snapshot endpoint.
type MetricsHandler struct {
	svc *analytics.Service
}

// NewMetricsHandler creates a new MetricsHandler.
func NewMetricsHandler(svc *analytics.Service) *MetricsHandler {
	return &MetricsHandler{svc: svc}
}

// Snapshot returns a KPI snapshot for the authenticated account+environment.
// GET /v1/metrics?from=<iso>&to=<iso>
func (h *MetricsHandler) Snapshot(c fiber.Ctx) error {
	auth, err := authz(c, rbac.MetricsRead)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	from := now.AddDate(0, 0, -30)
	to := now

	if raw := c.Query("from"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid from timestamp (expected RFC3339)")
		}
		from = t
	}
	if raw := c.Query("to"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid to timestamp (expected RFC3339)")
		}
		to = t
	}

	if to.Before(from) {
		return core.NewAppError(core.ErrValidationError, "to must be after from")
	}
	if to.Sub(from) > 365*24*time.Hour {
		return core.NewAppError(core.ErrValidationError, "Date range must not exceed 365 days")
	}

	snap, err := h.svc.Snapshot(c.Context(), auth.TargetAccountID, auth.Environment, from, to)
	if err != nil {
		return err
	}

	return c.JSON(snap)
}
