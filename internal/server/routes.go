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
	// F-011: signup is unauthenticated and expensive — bucket each
	// source IP to prevent account farming. Dev gets a much higher
	// limit so e2e scenarios (which create ~20 tenants in a burst
	// from the same IP) do not trip the guard.
	signupMax := 5
	if deps.Config.IsDevelopment() {
		signupMax = 1000
	}
	signupLimit := middleware.SignupRateLimit(signupMax)

	// Auth (public).
	ah := handler.NewAuthHandler(deps.AuthService)
	v1.Post("/auth/signup", signupLimit, ah.Signup)
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

	// Policies under a product — listing + creation of secondary
	// policies. Single-policy operations (GET / PATCH / DELETE /
	// set-default) live at the top-level /v1/policies group below.
	polh := handler.NewPolicyHandler(deps.PolicyService, deps.TxManager, deps.ProductRepo)
	products.Get("/:id/policies", polh.ListByProduct)
	products.Post("/:id/policies", polh.Create)

	// Entitlements (authenticated) — registry CRUD + policy/license
	// attach surface. The handler owns all entitlement endpoints
	// including those nested under policies and licenses.
	enth := handler.NewEntitlementHandler(deps.TxManager, deps.EntitlementService, deps.LicenseRepo, deps.PolicyRepo)
	entitlements := v1.Group("/entitlements", authMw, mgmtLimit)
	entitlements.Get("/", enth.List)
	entitlements.Post("/", enth.Create)
	entitlements.Get("/:id", enth.Get)
	entitlements.Patch("/:id", enth.Update)
	entitlements.Delete("/:id", enth.Delete)

	// Policies (authenticated) — single-policy operations.
	policies := v1.Group("/policies", authMw, mgmtLimit)
	policies.Get("/:id", polh.Get)
	policies.Patch("/:id", polh.Update)
	policies.Delete("/:id", polh.Delete)
	policies.Post("/:id/set-default", polh.SetDefault)
	// Policy entitlement attach/detach (L3).
	policies.Get("/:id/entitlements", enth.ListPolicyEntitlements)
	policies.Post("/:id/entitlements", enth.AttachPolicyEntitlements)
	policies.Put("/:id/entitlements", enth.ReplacePolicyEntitlements)
	policies.Delete("/:id/entitlements/:code", enth.DetachPolicyEntitlement)

	// Customers (L4) — direct vendor-side registry. Grant-scoped
	// customer listing is registered under the grant routes below.
	ch := handler.NewCustomerHandler(deps.TxManager, deps.CustomerService, deps.LicenseService)
	customers := v1.Group("/customers", authMw, mgmtLimit)
	customers.Get("/", ch.List)
	customers.Post("/", ch.Create)
	customers.Get("/:id", ch.Get)
	customers.Patch("/:id", ch.Update)
	customers.Delete("/:id", ch.Delete)
	customers.Get("/:id/licenses", ch.ListLicenses)

	// Licenses (authenticated).
	licenses := v1.Group("/licenses", authMw, mgmtLimit)
	licenses.Get("/", lh.List)
	licenses.Get("/:id", lh.Get)
	licenses.Patch("/:id", lh.Update)
	licenses.Delete("/:id", lh.Revoke)
	licenses.Post("/:id/suspend", lh.Suspend)
	licenses.Post("/:id/reinstate", lh.Reinstate)
	licenses.Post("/:id/activate", lh.Activate)
	licenses.Post("/:id/deactivate", lh.Deactivate)
	licenses.Post("/:id/machines/:fingerprint/checkin", lh.Checkin)
	licenses.Post("/:id/freeze", lh.Freeze)
	licenses.Post("/:id/attach-policy", lh.AttachPolicy)
	// License entitlement attach/detach (L3).
	licenses.Get("/:id/entitlements", enth.ListLicenseEntitlements)
	licenses.Post("/:id/entitlements", enth.AttachLicenseEntitlements)
	licenses.Put("/:id/entitlements", enth.ReplaceLicenseEntitlements)
	licenses.Delete("/:id/entitlements/:code", enth.DetachLicenseEntitlement)

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
	// Webhook deliveries (O3) — sub-resource under webhook endpoints.
	webhooks.Get("/:id/deliveries", wh.ListDeliveries)
	webhooks.Get("/:id/deliveries/:delivery_id", wh.GetDelivery)
	webhooks.Post("/:id/deliveries/:delivery_id/redeliver", wh.Redeliver)

	// Domain events (authenticated).
	evh := handler.NewEventHandler(deps.TxManager, deps.DomainEventRepo)
	events := v1.Group("/events", authMw, mgmtLimit)
	events.Get("/", evh.List)
	events.Get("/:id", evh.Get)

	// Metrics snapshot (authenticated).
	mh := handler.NewMetricsHandler(deps.AnalyticsService)
	v1.Get("/metrics", authMw, mgmtLimit, mh.Snapshot)

	// Global search (authenticated — any role, RLS scopes results).
	sh := handler.NewSearchHandler(deps.SearchService)
	v1.Get("/search", authMw, mgmtLimit, sh.Search)

	// Environments (authenticated). Per-account metadata that drives
	// the dashboard account switcher. Note: list/create/delete are
	// account-scoped, not environment-scoped — the environments
	// themselves are the scope.
	eh := handler.NewEnvironmentHandler(deps.EnvironmentService)
	envs := v1.Group("/environments", authMw, mgmtLimit)
	envs.Get("/", eh.List)
	envs.Post("/", eh.Create)
	envs.Delete("/:id", eh.Delete)

	// Account summary (authenticated) — read-only counterparty lookup.
	// MUST be registered BEFORE any /accounts/:account_id/* sub-routes
	// below so Fiber resolves the bare path to this handler instead of
	// a prefix-scoped group. The service gates visibility by membership
	// or non-terminal grant relationship and collapses everything else
	// to 404 to avoid existence leaks.
	accounth := handler.NewAccountHandler(deps.AccountService)
	v1.Get("/accounts/:account_id", authMw, mgmtLimit, accounth.GetSummary)

	// Invitations
	inh := handler.NewInvitationHandler(deps.InvitationService)

	// Unauthenticated preview — the raw token in the URL is the access credential.
	v1.Get("/invitations/:token/lookup", inh.Lookup)

	// Authenticated accept.
	v1.Post("/invitations/:token/accept", authMw, mgmtLimit, inh.Accept)

	// Issuance + listing — scoped to an account the caller has permission
	// to manage. Create requires user:invite (+grant:issue for grant kind);
	// List is authenticated-only (any active membership can enumerate).
	invAccountGroup := v1.Group("/accounts/:account_id/invitations", authMw, mgmtLimit)
	invAccountGroup.Post("/", inh.Create)
	invAccountGroup.Get("/", inh.List)

	// Single-invitation lifecycle operations. Get is RLS-scoped to the
	// caller's target account; Resend and Delete additionally require
	// the creator identity OR the kind-appropriate permission.
	v1.Get("/invitations/:invitation_id", authMw, mgmtLimit, inh.Get)
	v1.Post("/invitations/:invitation_id/resend", authMw, mgmtLimit, inh.Resend)
	v1.Delete("/invitations/:invitation_id", authMw, mgmtLimit, inh.Delete)

	// Grants — issuance, lifecycle, and grant-scoped license creation.
	gh := handler.NewGrantHandler(deps.GrantService, deps.LicenseService, deps.CustomerService, deps.TxManager)

	// Grantor-side operations scoped to an account. Using account-scoped
	// paths for Issue, Revoke, and Suspend means TargetAccountID equals
	// the path account (no RLS switch needed — the grantor IS the target).
	grantAccountGroup := v1.Group("/accounts/:account_id/grants", authMw, mgmtLimit)
	grantAccountGroup.Get("/", gh.ListByGrantor)
	grantAccountGroup.Post("/", gh.Issue)
	grantAccountGroup.Patch("/:grant_id", gh.Update)
	grantAccountGroup.Post("/:grant_id/revoke", gh.Revoke)
	grantAccountGroup.Post("/:grant_id/suspend", gh.Suspend)
	grantAccountGroup.Post("/:grant_id/reinstate", gh.Reinstate)

	// Grantee-side list scoped to the caller's account, sibling to
	// /v1/accounts/:account_id/grants. Uses a different RBAC permission
	// (grant:use) so operator-role callers can see received grants.
	v1.Get("/accounts/:account_id/received-grants", authMw, mgmtLimit, gh.ListReceived)

	// Grantee-side operations. ResolveGrant validates the caller is the
	// grantee and flips TargetAccountID to the grantor before the handler
	// runs. Accept does NOT use ResolveGrant because the grant is still
	// pending (RequireActive would fail); the service verifies ownership.
	// Get and ListByGrantee likewise skip ResolveGrant — their service
	// calls run in the caller's own tenant context and the grants RLS
	// policy permits reads when the caller is grantor OR grantee.
	resolveGrant := middleware.ResolveGrant(deps.GrantService)
	v1.Get("/grants/received", authMw, mgmtLimit, gh.ListByGrantee)
	v1.Get("/grants/:grant_id", authMw, mgmtLimit, gh.Get)
	v1.Post("/grants/:grant_id/accept", authMw, mgmtLimit, gh.Accept)
	// Leave is the grantee's self-service exit. Authenticated only
	// (no RBAC check) — any grantee can walk away from a grant they hold.
	v1.Post("/grants/:grant_id/leave", authMw, mgmtLimit, gh.Leave)
	v1.Post("/grants/:grant_id/licenses", authMw, mgmtLimit, resolveGrant, gh.CreateLicense)
	// L4: grantees list customers they created under this grant's
	// scope. ResolveGrant flips TargetAccountID to the grantor;
	// ListCustomers additionally filters by created_by_account_id=acting
	// (grantee) so only this grantee's own customers are returned.
	v1.Get("/grants/:grant_id/customers", authMw, mgmtLimit, resolveGrant, gh.ListCustomers)
}
