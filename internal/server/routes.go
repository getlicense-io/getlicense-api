package server

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

type routeMiddleware struct {
	authMw           fiber.Handler
	mgmtLimit        fiber.Handler
	validateLimit    fiber.Handler
	signupLimit      fiber.Handler
	rejectProductKey fiber.Handler

	loginIPLimit    fiber.Handler
	loginEmailLimit fiber.Handler
	totpIPLimit     fiber.Handler
	totpTokenLimit  fiber.Handler
	refreshIPLimit  fiber.Handler
	logoutIPLimit   fiber.Handler
}

// registerRoutes wires all API endpoints to their handlers.
func registerRoutes(app *fiber.App, deps *Deps) {
	v1 := app.Group("/v1")
	mw := buildRouteMiddleware(deps)

	registerAuthRoutes(v1, deps, mw)
	registerCatalogRoutes(v1, deps, mw)
	registerLicenseRoutes(v1, deps, mw)
	registerPublicValidationRoutes(v1, deps, mw)
	registerSecurityRoutes(v1, deps, mw)
	registerObservabilityRoutes(v1, deps, mw)
	registerAccountRoutes(v1, deps, mw)
	registerInvitationRoutes(v1, deps, mw)
	registerGrantRoutes(v1, deps, mw)
	registerChannelRoutes(v1, deps, mw)
}

func buildRouteMiddleware(deps *Deps) routeMiddleware {
	authMw := middleware.RequireAuth(middleware.Dependencies{
		APIKeys:        deps.APIKeyRepo,
		Memberships:    deps.MembershipRepo,
		MasterKey:      deps.MasterKey,
		TxManager:      deps.TxManager,
		AdminRole:      deps.AdminRole,
		JWTRevocations: deps.JWTRevocationRepo,
	})
	rateLimiter := deps.RateLimiter
	mgmtLimit := middleware.ManagementRateLimit(rateLimiter)
	validateLimit := middleware.ValidationRateLimit(rateLimiter)
	// F-011: signup is unauthenticated and expensive — bucket each
	// source IP to prevent account farming. Dev gets a much higher
	// limit so e2e scenarios (which create ~20 tenants in a burst
	// from the same IP) do not trip the guard.
	signupMax := 5
	if deps.Config.IsDevelopment() {
		signupMax = 1000
	}
	signupLimit := middleware.SignupRateLimit(signupMax, rateLimiter)
	rejectProductKey := middleware.RejectProductScopedKey()

	// PR-2: per-IP caps on the public auth flow. Production uses the
	// tight defaults (60/min for login/refresh/logout, 20/min for TOTP);
	// dev gets a much higher cap so e2e scenarios that exercise the
	// auth surface do not trip the guard. Per-credential caps (email /
	// pending_token) stay tight in every environment — they protect the
	// actual security guarantee and the e2e scenario that exercises the
	// per-email cap uses a unique address.
	loginIPMax := 60
	totpIPMax := 20
	refreshIPMax := 60
	logoutIPMax := 60
	if deps.Config.IsDevelopment() {
		loginIPMax = 1000
		totpIPMax = 1000
		refreshIPMax = 1000
		logoutIPMax = 1000
	}
	loginIPLimit := middleware.LoginRateLimitPerIP(loginIPMax, rateLimiter)
	loginEmailLimit := middleware.LoginRateLimitPerEmail(rateLimiter)
	totpIPLimit := middleware.LoginTOTPRateLimitPerIP(totpIPMax, rateLimiter)
	totpTokenLimit := middleware.LoginTOTPRateLimitPerToken(rateLimiter)
	refreshIPLimit := middleware.RefreshRateLimitPerIP(refreshIPMax, rateLimiter)
	logoutIPLimit := middleware.LogoutRateLimitPerIP(logoutIPMax, rateLimiter)

	return routeMiddleware{
		authMw:           authMw,
		mgmtLimit:        mgmtLimit,
		validateLimit:    validateLimit,
		signupLimit:      signupLimit,
		rejectProductKey: rejectProductKey,
		loginIPLimit:     loginIPLimit,
		loginEmailLimit:  loginEmailLimit,
		totpIPLimit:      totpIPLimit,
		totpTokenLimit:   totpTokenLimit,
		refreshIPLimit:   refreshIPLimit,
		logoutIPLimit:    logoutIPLimit,
	}
}
