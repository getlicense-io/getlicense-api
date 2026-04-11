package server

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/server/handler"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// registerRoutes wires all API endpoints to their handlers.
func registerRoutes(app *fiber.App, deps *Deps) {
	v1 := app.Group("/v1")
	authMw := middleware.RequireAuth(deps.APIKeyRepo, deps.MasterKey)

	// Auth (public).
	ah := handler.NewAuthHandler(deps.AuthService)
	v1.Post("/auth/signup", ah.Signup)
	v1.Post("/auth/login", ah.Login)
	v1.Post("/auth/refresh", ah.Refresh)
	v1.Post("/auth/logout", ah.Logout)
	v1.Get("/auth/me", authMw, ah.Me)

	// Products (authenticated).
	ph := handler.NewProductHandler(deps.ProductService)
	products := v1.Group("/products", authMw)
	products.Post("/", ph.Create)
	products.Get("/", ph.List)
	products.Get("/:id", ph.Get)
	products.Patch("/:id", ph.Update)
	products.Delete("/:id", ph.Delete)

	// License creation under product.
	lh := handler.NewLicenseHandler(deps.LicenseService)
	products.Post("/:id/licenses", lh.Create)

	// Licenses (authenticated).
	licenses := v1.Group("/licenses", authMw)
	licenses.Get("/", lh.List)
	licenses.Get("/:id", lh.Get)
	licenses.Delete("/:id", lh.Revoke)
	licenses.Post("/:id/suspend", lh.Suspend)
	licenses.Post("/:id/reinstate", lh.Reinstate)
	licenses.Post("/:id/activate", lh.Activate)
	licenses.Post("/:id/deactivate", lh.Deactivate)
	licenses.Post("/:id/heartbeat", lh.Heartbeat)

	// Validate (public).
	vh := handler.NewValidateHandler(deps.LicenseService)
	v1.Post("/validate", vh.Validate)

	// API Keys (authenticated).
	akh := handler.NewAPIKeyHandler(deps.AuthService)
	apiKeys := v1.Group("/api-keys", authMw)
	apiKeys.Post("/", akh.Create)
	apiKeys.Get("/", akh.List)
	apiKeys.Delete("/:id", akh.Delete)

	// Webhooks (authenticated).
	wh := handler.NewWebhookHandler(deps.WebhookService)
	webhooks := v1.Group("/webhooks", authMw)
	webhooks.Post("/", wh.Create)
	webhooks.Get("/", wh.List)
	webhooks.Delete("/:id", wh.Delete)
}
