package middleware

import (
	"context"

	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// EnforceProductScope returns nil if the caller is permitted to
// operate on resourceProductID, or core.ErrAPIKeyScopeMismatch (403)
// otherwise.
//
// Passes for:
//   - nil auth (background jobs, unauthenticated paths — the gate
//     isn't an authentication check)
//   - identity callers (role-based auth doesn't use key scope)
//   - account-wide API keys (scope != product)
//   - product-scoped API keys whose bound product matches
//     resourceProductID
//
// Rejects for:
//   - product-scoped API keys whose bound product differs
//   - product-scoped API keys with nil APIKeyProductID (malformed —
//     shouldn't happen in production but defensive)
//
// Called from inside services after the existing tenant load step,
// e.g. `EnforceProductScope(ctx, license.ProductID)` after a
// licenses.GetByID call.
func EnforceProductScope(ctx context.Context, resourceProductID core.ProductID) error {
	auth := AuthFromGoContext(ctx)
	if auth == nil {
		return nil
	}
	if auth.ActorKind != ActorKindAPIKey {
		return nil
	}
	if auth.APIKeyScope != core.APIKeyScopeProduct {
		return nil
	}
	if auth.APIKeyProductID != nil && *auth.APIKeyProductID == resourceProductID {
		return nil
	}
	return core.NewAppError(core.ErrAPIKeyScopeMismatch,
		"API key is product-scoped and does not cover this resource")
}

// RejectProductScopedKey returns a Fiber middleware that 403s any
// request authenticated with a product-scoped API key. Use on
// inherently cross-product or management-only routes/groups (api
// keys, products list, customers, webhooks, metrics, search, auth,
// identity, environments, account / invitation / grant admin).
//
// Identity callers and account-wide-key callers are passed through
// unchanged. Nil auth is also passed through — another middleware
// ahead of this one is responsible for authn.
func RejectProductScopedKey() fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := AuthFromContext(c)
		if auth == nil {
			return c.Next()
		}
		if auth.ActorKind != ActorKindAPIKey {
			return c.Next()
		}
		if auth.APIKeyScope != core.APIKeyScopeProduct {
			return c.Next()
		}
		return core.NewAppError(core.ErrAPIKeyScopeMismatch,
			"Product-scoped API keys cannot access this resource")
	}
}
