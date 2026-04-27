package server

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/server/handler"
)

func registerAuthRoutes(v1 fiber.Router, deps *Deps, mw routeMiddleware) {
	ah := handler.NewAuthHandler(deps.AuthService)
	v1.Post("/auth/signup", mw.signupLimit, ah.Signup)
	v1.Post("/auth/login", mw.loginIPLimit, mw.loginEmailLimit, ah.Login)
	v1.Post("/auth/login/totp", mw.totpIPLimit, mw.totpTokenLimit, ah.LoginTOTP)
	v1.Post("/auth/refresh", mw.refreshIPLimit, ah.Refresh)
	v1.Post("/auth/logout", mw.logoutIPLimit, mw.authMw, ah.Logout)
	v1.Post("/auth/logout-all", mw.logoutIPLimit, mw.authMw, ah.LogoutAll)
	v1.Get("/auth/me", mw.authMw, mw.mgmtLimit, ah.Me)
	v1.Post("/auth/switch", mw.authMw, mw.mgmtLimit, ah.Switch)

	ih := handler.NewIdentityHandler(deps.IdentityService)
	identityGroup := v1.Group("/identity", mw.authMw, mw.mgmtLimit, mw.rejectProductKey)
	identityGroup.Post("/totp/enroll", ih.EnrollTOTP)
	identityGroup.Post("/totp/activate", ih.ActivateTOTP)
	identityGroup.Post("/totp/disable", ih.DisableTOTP)
}
