package server

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/server/handler"
)

func registerCatalogRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	ph := handler.NewProductHandler(deps.ProductService, deps.LicenseService)
	lh := handler.NewLicenseHandler(deps.LicenseService)
	polh := handler.NewPolicyHandler(deps.PolicyService, deps.TxManager, deps.ProductRepo)
	enth := handler.NewEntitlementHandler(deps.TxManager, deps.EntitlementService, deps.LicenseRepo, deps.PolicyRepo)
	ch := handler.NewCustomerHandler(deps.TxManager, deps.CustomerService, deps.LicenseService)

	products := v1.Group("/products", mw.authMw, mw.mgmtLimit)
	products.Post("/", mw.rejectProductKey, ph.Create)
	products.Get("/", mw.rejectProductKey, ph.List)
	products.Get("/:id", ph.Get)
	products.Patch("/:id", ph.Update)
	products.Delete("/:id", ph.Delete)
	products.Get("/:id/licenses", lh.ListByProduct)
	products.Post("/:id/licenses", lh.Create)
	products.Post("/:id/licenses/bulk", lh.BulkCreate)
	products.Delete("/:id/licenses", lh.BulkRevokeByProduct)
	products.Get("/:id/policies", polh.ListByProduct)
	products.Post("/:id/policies", polh.Create)

	entitlements := v1.Group("/entitlements", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	entitlements.Get("/", enth.List)
	entitlements.Post("/", enth.Create)
	entitlements.Get("/:id", enth.Get)
	entitlements.Patch("/:id", enth.Update)
	entitlements.Delete("/:id", enth.Delete)

	policies := v1.Group("/policies", mw.authMw, mw.mgmtLimit)
	policies.Get("/:id", polh.Get)
	policies.Patch("/:id", polh.Update)
	policies.Delete("/:id", polh.Delete)
	policies.Post("/:id/set-default", polh.SetDefault)
	policies.Get("/:id/entitlements", enth.ListPolicyEntitlements)
	policies.Post("/:id/entitlements", enth.AttachPolicyEntitlements)
	policies.Put("/:id/entitlements", enth.ReplacePolicyEntitlements)
	policies.Delete("/:id/entitlements/:code", enth.DetachPolicyEntitlement)

	customers := v1.Group("/customers", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	customers.Get("/", ch.List)
	customers.Post("/", ch.Create)
	customers.Get("/:id", ch.Get)
	customers.Patch("/:id", ch.Update)
	customers.Delete("/:id", ch.Delete)
	customers.Get("/:id/licenses", ch.ListLicenses)
}

func registerLicenseRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	lh := handler.NewLicenseHandler(deps.LicenseService)
	enth := handler.NewEntitlementHandler(deps.TxManager, deps.EntitlementService, deps.LicenseRepo, deps.PolicyRepo)

	licenses := v1.Group("/licenses", mw.authMw, mw.mgmtLimit)
	licenses.Get("/", lh.List)
	licenses.Get("/:id", lh.Get)
	licenses.Patch("/:id", lh.Update)
	licenses.Delete("/:id", lh.Revoke)
	licenses.Post("/:id/suspend", lh.Suspend)
	licenses.Post("/:id/reinstate", lh.Reinstate)
	licenses.Post("/:id/activate", lh.Activate)
	licenses.Post("/:id/deactivate", lh.Deactivate)
	licenses.Get("/:id/machines", lh.ListMachines)
	licenses.Post("/:id/machines/:fingerprint/checkin", lh.Checkin)
	licenses.Post("/:id/freeze", lh.Freeze)
	licenses.Post("/:id/attach-policy", lh.AttachPolicy)
	licenses.Get("/:id/entitlements", enth.ListLicenseEntitlements)
	licenses.Post("/:id/entitlements", enth.AttachLicenseEntitlements)
	licenses.Put("/:id/entitlements", enth.ReplaceLicenseEntitlements)
	licenses.Delete("/:id/entitlements/:code", enth.DetachLicenseEntitlement)
}

func registerPublicValidationRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	vh := handler.NewValidateHandler(deps.LicenseService)
	v1.Post("/validate", mw.validateLimit, vh.Validate)
}

func registerSecurityRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	akh := handler.NewAPIKeyHandler(deps.AuthService)
	apiKeys := v1.Group("/api-keys", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	apiKeys.Post("/", akh.Create)
	apiKeys.Get("/", akh.List)
	apiKeys.Delete("/:id", akh.Delete)

	wh := handler.NewWebhookHandler(deps.WebhookService)
	webhooks := v1.Group("/webhooks", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	webhooks.Post("/", wh.Create)
	webhooks.Get("/", wh.List)
	webhooks.Delete("/:id", wh.Delete)
	webhooks.Post("/:id/rotate-signing-secret", wh.RotateSigningSecret)
	webhooks.Post("/:id/finish-signing-secret-rotation", wh.FinishSigningSecretRotation)
	webhooks.Get("/:id/deliveries", wh.ListDeliveries)
	webhooks.Get("/:id/deliveries/:delivery_id", wh.GetDelivery)
	webhooks.Post("/:id/deliveries/:delivery_id/redeliver", wh.Redeliver)
}

func registerObservabilityRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	evh := handler.NewEventHandler(deps.TxManager, deps.DomainEventRepo, deps.Config.EventsCSVMaxRows)
	events := v1.Group("/events", mw.authMw, mw.mgmtLimit)
	events.Get("/", evh.List)
	events.Get("/:id", mw.rejectProductKey, evh.Get)

	mh := handler.NewMetricsHandler(deps.AnalyticsService)
	v1.Get("/metrics", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, mh.Snapshot)

	sh := handler.NewSearchHandler(deps.SearchService)
	v1.Get("/search", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, sh.Search)

	eh := handler.NewEnvironmentHandler(deps.EnvironmentService)
	envs := v1.Group("/environments", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	envs.Get("/", eh.List)
	envs.Post("/", eh.Create)
	envs.Delete("/:id", eh.Delete)
}

func registerAccountRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	accounth := handler.NewAccountHandler(deps.AccountService)
	v1.Get("/accounts/:account_id", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, accounth.GetSummary)

	memberh := handler.NewMemberHandler(deps.MembershipService)
	v1.Get("/accounts/:account_id/members", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, memberh.List)
}
