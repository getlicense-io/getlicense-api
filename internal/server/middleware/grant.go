package middleware

import (
	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/grant"
)

const localsKeyGrant = "grant"

// GrantFromContext returns the Grant resolved by ResolveGrant
// middleware, or nil if the current route is not grant-scoped.
func GrantFromContext(c fiber.Ctx) *domain.Grant {
	v := c.Locals(localsKeyGrant)
	if v == nil {
		return nil
	}
	g, ok := v.(*domain.Grant)
	if !ok {
		return nil
	}
	return g
}

// ResolveGrant is applied to /v1/grants/:grant_id/... routes where the
// caller is the grantee exercising a capability. It:
//  1. Extracts :grant_id from the URL path
//  2. Calls grant.Service.Resolve — verifies the acting account is
//     the grantee and loads the grant row
//  3. Calls grant.Service.RequireActive — checks status and expiry
//  4. Stores the grant on locals for downstream handlers
//  5. Flips AuthContext.TargetAccountID to the grantor so downstream
//     RLS scopes writes to the grantor's tenant space
//  6. Records the grant ID on AuthContext for audit attribution
func ResolveGrant(svc *grant.Service) fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := AuthFromContext(c)
		if auth == nil {
			return core.NewAppError(core.ErrAuthenticationRequired, "Authentication required")
		}
		grantID, err := core.ParseGrantID(c.Params("grant_id"))
		if err != nil {
			return core.NewAppError(core.ErrValidationError, "Invalid grant ID")
		}

		g, err := svc.Resolve(c.Context(), grantID, auth.ActingAccountID)
		if err != nil {
			return err
		}
		if err := svc.RequireActive(g); err != nil {
			return err
		}

		c.Locals(localsKeyGrant, g)
		auth.GrantID = &g.ID
		auth.TargetAccountID = g.GrantorAccountID
		return c.Next()
	}
}
