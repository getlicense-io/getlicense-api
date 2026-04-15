package handler

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/rbac"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// mustAuth returns the AuthContext populated by RequireAuth middleware.
// Returns an authentication error if nothing is in the context — this
// would only happen from a programming mistake that skipped middleware.
func mustAuth(c fiber.Ctx) (*middleware.AuthContext, error) {
	auth := middleware.AuthFromContext(c)
	if auth == nil {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Authentication required")
	}
	return auth, nil
}

// authz combines mustAuth + rbac.Require into one call. Every handler
// method starts with `auth, err := authz(c, rbac.<Perm>)` — if err is
// non-nil, return it; otherwise proceed with the service call using
// auth.TargetAccountID + auth.Environment.
//
// For standard (non-grant) routes, TargetAccountID == ActingAccountID.
// They diverge only in grant-routed requests (future phase). Handlers
// that scope writes to a tenant must use TargetAccountID.
func authz(c fiber.Ctx, perm rbac.Permission) (*middleware.AuthContext, error) {
	auth, err := mustAuth(c)
	if err != nil {
		return nil, err
	}
	checker := rbac.NewChecker(auth.Role)
	if err := checker.Require(perm); err != nil {
		return nil, err
	}
	return auth, nil
}

// requireIdentityAuth is the "identity-only" gate. Handlers that
// cannot serve API-key callers (anything touching the current user's
// personal state — TOTP setup, invitations, /me, /switch) call this
// helper. It returns the AuthContext on success or ErrAuthenticationRequired
// when the caller is API-key authenticated.
//
// For endpoints that need a custom error message, keep using
// mustAuth + an inline IsAPIKey() check instead.
func requireIdentityAuth(c fiber.Ctx) (*middleware.AuthContext, error) {
	auth, err := mustAuth(c)
	if err != nil {
		return nil, err
	}
	if auth.IsAPIKey() {
		return nil, core.NewAppError(core.ErrAuthenticationRequired, "Identity authentication required")
	}
	return auth, nil
}
