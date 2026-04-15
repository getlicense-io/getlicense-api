package middleware

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// ManagementRateLimit returns a rate limiter for authenticated management endpoints.
// 1000 requests per minute, keyed by account ID from auth context.
func ManagementRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               1000,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			auth := AuthFromContext(c)
			if auth != nil {
				return "mgmt:" + auth.ActingAccountID.String()
			}
			return "mgmt:anonymous"
		},
		LimitReached: rateLimitReached,
	})
}

// ValidationRateLimit returns a rate limiter for the public validation endpoint.
// 10000 requests per minute, keyed by client IP.
func ValidationRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               10000,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			return "validate:" + c.IP()
		},
		LimitReached: rateLimitReached,
	})
}

// SignupRateLimit caps account creation per client IP per hour.
// F-011: the signup path creates 7+ DB rows per call (identity,
// account, membership, 2 environments, 2 API keys) and runs Argon2
// under a transaction. Without this limit, an unauthenticated
// attacker can farm accounts indefinitely, fill the DB, and pollute
// the metrics. c.IP() is the socket IP by default — X-Forwarded-For
// is only honored for trusted proxies, which the API does not
// configure, so spoofing is not a bypass.
//
// Callers pass a larger max in development so e2e scenarios (which
// sign up ~20 tenants sequentially from the same IP) don't trip
// the limit. Production should use 5/hour.
func SignupRateLimit(max int) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        1 * time.Hour,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			return "signup:" + c.IP()
		},
		LimitReached: rateLimitReached,
	})
}

// rateLimitReached returns a typed AppError so the envelope carries
// the canonical rate_limit_exceeded code instead of being downgraded
// to validation_error by the fiber.Error branch of errorHandler.
// Clients rely on this code to drive Retry-After backoff. F-005.
func rateLimitReached(_ fiber.Ctx) error {
	return core.NewAppError(core.ErrRateLimitExceeded, "Rate limit exceeded")
}
