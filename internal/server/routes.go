package server

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/server/handler"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// registerRoutes wires all API endpoints to their handlers.
func registerRoutes(app *fiber.App, deps *Deps) {
	v1 := app.Group("/v1")
	authMw := middleware.RequireAuth(middleware.Dependencies{
		APIKeys:     deps.APIKeyRepo,
		Memberships: deps.MembershipRepo,
		MasterKey:   deps.MasterKey,
		AdminRole:   deps.AdminRole,
	})
	mgmtLimit := middleware.ManagementRateLimit()
	validateLimit := middleware.ValidationRateLimit()

	// Auth (public).
	ah := handler.NewAuthHandler(deps.AuthService)
	v1.Post("/auth/signup", ah.Signup)
	v1.Post("/auth/login", ah.Login)
	v1.Post("/auth/login/totp", ah.LoginTOTP)
	v1.Post("/auth/refresh", ah.Refresh)
	v1.Post("/auth/logout", ah.Logout)
	v1.Get("/auth/me", authMw, mgmtLimit, ah.Me)
	v1.Post("/auth/switch", authMw, mgmtLimit, ah.Switch)

	// Identity TOTP management (authenticated, identity auth only).
	ih := handler.NewIdentityHandler(deps.IdentityService)
	identityGroup := v1.Group("/identity", authMw, mgmtLimit)
	identityGroup.Post("/totp/enroll", ih.EnrollTOTP)
	identityGroup.Post("/totp/activate", ih.ActivateTOTP)
	identityGroup.Post("/totp/disable", ih.DisableTOTP)

	// Products (authenticated). The product handler depends on the
	// licensing service so the singular GET can return a license-count
	// summary in one round-trip.
	ph := handler.NewProductHandler(deps.ProductService, deps.LicenseService)
	products := v1.Group("/products", authMw, mgmtLimit)
	products.Post("/", ph.Create)
	products.Get("/", ph.List)
	products.Get("/:id", ph.Get)
	products.Patch("/:id", ph.Update)
	products.Delete("/:id", ph.Delete)

	// License creation under a product. Listing/single-license actions
	// live at the top-level /v1/licenses group; the only product-nested
	// license operations are bulk creation (POST .../licenses/bulk)
	// and bulk revocation, which uses DELETE on the collection to
	// match the singular DELETE /v1/licenses/:id semantic where
	// "delete" means "revoke" (soft-delete via status transition).
	lh := handler.NewLicenseHandler(deps.LicenseService)
	products.Get("/:id/licenses", lh.ListByProduct)
	products.Post("/:id/licenses", lh.Create)
	products.Post("/:id/licenses/bulk", lh.BulkCreate)
	products.Delete("/:id/licenses", lh.BulkRevokeByProduct)

	// Licenses (authenticated).
	licenses := v1.Group("/licenses", authMw, mgmtLimit)
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
	v1.Post("/validate", validateLimit, vh.Validate)

	// API Keys (authenticated).
	akh := handler.NewAPIKeyHandler(deps.AuthService)
	apiKeys := v1.Group("/api-keys", authMw, mgmtLimit)
	apiKeys.Post("/", akh.Create)
	apiKeys.Get("/", akh.List)
	apiKeys.Delete("/:id", akh.Delete)

	// Webhooks (authenticated).
	wh := handler.NewWebhookHandler(deps.WebhookService)
	webhooks := v1.Group("/webhooks", authMw, mgmtLimit)
	webhooks.Post("/", wh.Create)
	webhooks.Get("/", wh.List)
	webhooks.Delete("/:id", wh.Delete)

	// Environments (authenticated). Per-account metadata that drives
	// the dashboard account switcher. Note: list/create/delete are
	// account-scoped, not environment-scoped — the environments
	// themselves are the scope.
	eh := handler.NewEnvironmentHandler(deps.EnvironmentService)
	envs := v1.Group("/environments", authMw, mgmtLimit)
	envs.Get("/", eh.List)
	envs.Post("/", eh.Create)
	envs.Delete("/:id", eh.Delete)

	// Invitations
	inh := handler.NewInvitationHandler(deps.InvitationService)

	// Unauthenticated preview — the raw token in the URL is the access credential.
	v1.Get("/invitations/:token/lookup", inh.Lookup)

	// Authenticated accept.
	v1.Post("/invitations/:token/accept", authMw, mgmtLimit, inh.Accept)

	// Issuance — scoped to an account the caller has permission to manage.
	invAccountGroup := v1.Group("/accounts/:account_id/invitations", authMw, mgmtLimit)
	invAccountGroup.Post("/", inh.CreateMembership)

	// Grants — issuance, lifecycle, and grant-scoped license creation.
	gh := handler.NewGrantHandler(deps.GrantService, deps.LicenseService, deps.TxManager)

	// Grantor-side operations scoped to an account. Using account-scoped
	// paths for Issue, Revoke, and Suspend means TargetAccountID equals
	// the path account (no RLS switch needed — the grantor IS the target).
	grantAccountGroup := v1.Group("/accounts/:account_id/grants", authMw, mgmtLimit)
	grantAccountGroup.Post("/", gh.Issue)
	grantAccountGroup.Post("/:grant_id/revoke", gh.Revoke)
	grantAccountGroup.Post("/:grant_id/suspend", gh.Suspend)

	// Grantee-side operations. ResolveGrant validates the caller is the
	// grantee and flips TargetAccountID to the grantor before the handler
	// runs. Accept does NOT use ResolveGrant because the grant is still
	// pending (RequireActive would fail); the service verifies ownership.
	resolveGrant := middleware.ResolveGrant(deps.GrantService)
	v1.Post("/grants/:grant_id/accept", authMw, mgmtLimit, gh.Accept)
	v1.Post("/grants/:grant_id/licenses", authMw, mgmtLimit, resolveGrant, gh.CreateLicense)
}
