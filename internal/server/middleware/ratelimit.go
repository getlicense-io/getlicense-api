package middleware

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
)

// ManagementRateLimit returns a rate limiter for authenticated management endpoints.
// 1000 requests per minute, keyed by account ID from auth context.
func ManagementRateLimit() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               1000,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			auth := FromContext(c)
			if auth != nil {
				return "mgmt:" + auth.AccountID.String()
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

func rateLimitReached(c fiber.Ctx) error {
	return fiber.NewError(fiber.StatusTooManyRequests, "Rate limit exceeded")
}
