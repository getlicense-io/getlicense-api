package middleware

import (
	"encoding/json"
	"strconv"
	"strings"
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

// LoginRateLimitPerEmail caps login attempts per (lowercased) email
// across all sources at 5 per 15 minutes — tight, but a real user
// fumbling their password 5 times in a row is rare and the lockout
// resets in under 15 minutes. PR-2: this is the user-credential gate
// that prevents an attacker from forcing Argon2 work against a known
// email at request rate.
//
// Email is extracted from the JSON body. A body that fails to parse
// or has no email field falls through to a "_malformed" sentinel
// bucket — the handler will reject the malformed request anyway, so
// the bucket exists only to bound CPU on a flood of garbage.
func LoginRateLimitPerEmail() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               5,
		Expiration:        15 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			email := peekJSONField(c.Body(), "email")
			if email == "" {
				// Malformed / missing email — share one sentinel bucket
				// across every garbage request so they self-throttle.
				return "login:email:_malformed"
			}
			return "login:email:" + strings.ToLower(strings.TrimSpace(email))
		},
		LimitReached: authRateLimitReached(900),
	})
}

// LoginRateLimitPerIP caps login attempts per source IP. Defaults to
// 60/min in production; callers pass a larger max in development so
// e2e scenarios (which run sequentially against one IP) do not trip
// the guard. Distributed enumeration from a single IP gets caught here.
func LoginRateLimitPerIP(max int) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			return "login:ip:" + c.IP()
		},
		LimitReached: authRateLimitReached(60),
	})
}

// LoginTOTPRateLimitPerToken caps step-2 attempts per pending token
// at 5. Pending tokens are short-lived (5 min) and single-use, so
// once consumed the bucket is dead by construction. The 15-minute
// window is long enough to outlive the pending token.
func LoginTOTPRateLimitPerToken() fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               5,
		Expiration:        15 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			tok := peekJSONField(c.Body(), "pending_token")
			if tok == "" {
				return "totp:token:_malformed"
			}
			return "totp:token:" + tok
		},
		LimitReached: authRateLimitReached(900),
	})
}

// LoginTOTPRateLimitPerIP caps step-2 attempts per IP as a backstop
// against distributed token-guessing. Defaults to 20/min in production
// with a higher dev value for e2e.
func LoginTOTPRateLimitPerIP(max int) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			return "totp:ip:" + c.IP()
		},
		LimitReached: authRateLimitReached(60),
	})
}

// RefreshRateLimitPerIP caps refresh requests per source IP. The
// refresh-token rotation race fix in PR-1.2 (atomic
// ConsumeRefreshToken) makes brute-forcing a token useless even
// without this limit; the IP cap is a CPU-DoS guard.
func RefreshRateLimitPerIP(max int) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			return "refresh:ip:" + c.IP()
		},
		LimitReached: authRateLimitReached(60),
	})
}

// LogoutRateLimitPerIP caps logout requests per source IP. Cheap
// server-side but worth a per-IP gate to prevent trivial DB-write
// DoS via repeated logouts.
func LogoutRateLimitPerIP(max int) fiber.Handler {
	return limiter.New(limiter.Config{
		Max:               max,
		Expiration:        1 * time.Minute,
		LimiterMiddleware: limiter.SlidingWindow{},
		KeyGenerator: func(c fiber.Ctx) string {
			return "logout:ip:" + c.IP()
		},
		LimitReached: authRateLimitReached(60),
	})
}

// rateLimitReached returns a typed AppError so the envelope carries
// the canonical rate_limit_exceeded code instead of being downgraded
// to validation_error by the fiber.Error branch of errorHandler.
// Clients rely on this code to drive Retry-After backoff. F-005.
func rateLimitReached(_ fiber.Ctx) error {
	return core.NewAppError(core.ErrRateLimitExceeded, "Rate limit exceeded")
}

// authRateLimitReached extends rateLimitReached with a Retry-After
// header. The value approximates worst-case wait time for the caller's
// bucket — for sliding-window limiters it's the window length; the
// actual wait may be shorter once individual requests age out.
//
// PR-2: header lets clients (and SDKs) implement deterministic backoff
// instead of guessing. Set on the response BEFORE returning the
// AppError so the value survives the ErrorHandler's JSON serialization.
func authRateLimitReached(retryAfterSeconds int) func(fiber.Ctx) error {
	return func(c fiber.Ctx) error {
		c.Set("Retry-After", strconv.Itoa(retryAfterSeconds))
		return rateLimitReached(c)
	}
}

// peekJSONField reads a single top-level string field from a JSON
// body without consuming or rewinding it. Returns "" on any error
// (including type mismatches and missing fields). Cheap when the
// expected body shape is small (auth requests are tiny).
//
// Fiber v3 buffers the request body via fasthttp, so c.Body() can be
// called from middleware before the handler's Bind().Body() — the
// handler still sees the full unmodified body.
func peekJSONField(body []byte, field string) string {
	if len(body) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	v, ok := m[field]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
