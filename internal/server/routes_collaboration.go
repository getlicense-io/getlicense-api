package server

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/server/handler"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

func registerInvitationRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	inh := handler.NewInvitationHandler(deps.InvitationService)

	v1.Get("/invitations/:token/lookup", inh.Lookup)
	v1.Post("/invitations/:token/accept", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, inh.Accept)

	invAccountGroup := v1.Group("/accounts/:account_id/invitations", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	invAccountGroup.Post("/", inh.Create)
	invAccountGroup.Get("/", inh.List)

	v1.Get("/invitations/:invitation_id", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, inh.Get)
	v1.Post("/invitations/:invitation_id/resend", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, inh.Resend)
	v1.Delete("/invitations/:invitation_id", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, inh.Delete)
}

func registerGrantRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	gh := handler.NewGrantHandler(deps.GrantService, deps.LicenseService, deps.CustomerService, deps.TxManager)

	grantAccountGroup := v1.Group("/accounts/:account_id/grants", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	grantAccountGroup.Get("/", gh.ListByGrantor)
	grantAccountGroup.Post("/", gh.Issue)
	grantAccountGroup.Patch("/:grant_id", gh.Update)
	grantAccountGroup.Post("/:grant_id/revoke", gh.Revoke)
	grantAccountGroup.Post("/:grant_id/suspend", gh.Suspend)
	grantAccountGroup.Post("/:grant_id/reinstate", gh.Reinstate)

	v1.Get("/accounts/:account_id/received-grants", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, gh.ListReceived)

	resolveGrant := middleware.ResolveGrant(deps.GrantService)
	v1.Get("/grants/received", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, gh.ListByGrantee)
	v1.Get("/grants/:grant_id", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, gh.Get)
	v1.Post("/grants/:grant_id/accept", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, gh.Accept)
	v1.Post("/grants/:grant_id/leave", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, gh.Leave)
	v1.Post("/grants/:grant_id/licenses", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, resolveGrant, gh.CreateLicense)
	v1.Get("/grants/:grant_id/licenses/:license_id/machines",
		mw.authMw, mw.mgmtLimit, mw.rejectProductKey, resolveGrant, gh.ListLicenseMachines)
	v1.Get("/grants/:grant_id/customers", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, resolveGrant, gh.ListCustomers)
}

func registerChannelRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	ch := handler.NewChannelHandler(deps.ChannelService)

	// Vendor-side: account-scoped, requires membership access.
	channelAccountGroup := v1.Group("/accounts/:account_id/channels", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	channelAccountGroup.Get("/", ch.ListByVendor)
	channelAccountGroup.Get("/:channel_id", ch.GetByVendor)

	// Caller-scoped: works for both vendor and partner.
	v1.Get("/channels/:channel_id", mw.authMw, mw.mgmtLimit, mw.rejectProductKey, ch.GetByCaller)
}
