package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// localsKeyAuth is the key used to store the authenticated account in Fiber locals.
const localsKeyAuth = "auth"

// AuthenticatedAccount holds the identity extracted from a valid Authorization header.
// For API key auth, UserID and Role are nil.
type AuthenticatedAccount struct {
	AccountID   core.AccountID
	UserID      *core.UserID
	Role        *core.UserRole
	Environment core.Environment
}

// FromContext retrieves the AuthenticatedAccount stored during RequireAuth.
// Returns nil if no authentication has been performed.
func FromContext(c fiber.Ctx) *AuthenticatedAccount {
	v := c.Locals(localsKeyAuth)
	if v == nil {
		return nil
	}
	a, ok := v.(*AuthenticatedAccount)
	if !ok {
		return nil
	}
	return a
}

// RequireAuth returns middleware that validates either an API key or a JWT bearer token.
func RequireAuth(apiKeyRepo domain.APIKeyRepository, masterKey *crypto.MasterKey) fiber.Handler {
	return func(c fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" {
			return core.NewAppError(core.ErrAuthenticationRequired, "Missing Authorization header")
		}

		token := strings.TrimPrefix(header, "Bearer ")
		if token == header {
			// No "Bearer " prefix found.
			return core.NewAppError(core.ErrAuthenticationRequired, "Invalid Authorization header format")
		}

		// API key authentication.
		if strings.HasPrefix(token, core.APIKeyPrefixLive) || strings.HasPrefix(token, core.APIKeyPrefixTest) {
			keyHash := masterKey.HMAC(token)
			apiKey, err := apiKeyRepo.GetByHash(c.Context(), keyHash)
			if err != nil || apiKey == nil {
				return core.NewAppError(core.ErrInvalidAPIKey, "Invalid API key")
			}

			c.Locals(localsKeyAuth, &AuthenticatedAccount{
				AccountID:   apiKey.AccountID,
				Environment: apiKey.Environment,
			})
			return c.Next()
		}

		// JWT authentication.
		claims, err := masterKey.VerifyJWT(token)
		if err != nil {
			return core.NewAppError(core.ErrAuthenticationRequired, "Invalid or expired token")
		}

		c.Locals(localsKeyAuth, &AuthenticatedAccount{
			AccountID:   claims.AccountID,
			UserID:      &claims.UserID,
			Role:        &claims.Role,
			Environment: core.EnvironmentLive,
		})
		return c.Next()
	}
}

// RequireRole returns middleware that enforces a minimum user role.
// API key authentication (where Role is nil) bypasses role checks.
func RequireRole(required core.UserRole) fiber.Handler {
	return func(c fiber.Ctx) error {
		auth := FromContext(c)
		if auth == nil {
			return core.NewAppError(core.ErrAuthenticationRequired, "Authentication required")
		}

		// API key auth bypasses role checks.
		if auth.Role == nil {
			return c.Next()
		}

		if !auth.Role.AtLeast(required) {
			return core.NewAppError(core.ErrInsufficientPermissions, "Insufficient permissions")
		}

		return c.Next()
	}
}
