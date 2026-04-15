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
// For standard routes, TargetAccountID == ActingAccountID. They
// diverge on grant-routed requests: ResolveGrant middleware flips
// TargetAccountID to the grantor while ActingAccountID stays the
// grantee. Handlers that scope writes to a tenant must use
// TargetAccountID.
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

// requirePathAccountMatch validates that the `:account_id` path
// parameter parses as a valid AccountID AND matches the authenticated
// target account. Handlers that expose routes under
// /v1/accounts/:account_id/... use this to enforce that the path
// and the auth context agree — without the check, clients could
// send any UUID and the server would silently use their real
// authenticated account regardless.
//
// Returns ErrValidationError on parse failure or mismatch.
func requirePathAccountMatch(c fiber.Ctx, auth *middleware.AuthContext) error {
	pathAccountID, err := core.ParseAccountID(c.Params("account_id"))
	if err != nil {
		return core.NewAppError(core.ErrValidationError, "Invalid account_id in path")
	}
	if pathAccountID != auth.TargetAccountID {
		return core.NewAppError(core.ErrValidationError, "account_id in path does not match authenticated account")
	}
	return nil
}
