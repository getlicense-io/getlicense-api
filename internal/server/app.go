package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

// extendedRequestMethods is Fiber's DefaultMethods plus a handful of
// non-standard verbs that appear in the wild (WebDAV, fuzzers, HTTP
// extension drafts). Registering them lets the router match-miss those
// requests as "method not allowed" on a known path rather than short-
// circuiting to a bare 501 outside the ErrorHandler.
var extendedRequestMethods = []string{
	fiber.MethodGet,
	fiber.MethodHead,
	fiber.MethodPost,
	fiber.MethodPut,
	fiber.MethodDelete,
	fiber.MethodConnect,
	fiber.MethodOptions,
	fiber.MethodTrace,
	fiber.MethodPatch,
	"QUERY",
	"LINK",
	"UNLINK",
	"PURGE",
	"LOCK",
	"UNLOCK",
	"PROPFIND",
	"VIEW",
}

// structValidator wraps go-playground/validator for Fiber's StructValidator interface.
type structValidator struct {
	validate *validator.Validate
}

// Validate runs struct validation and wraps errors as AppError.
func (v *structValidator) Validate(out any) error {
	if err := v.validate.Struct(out); err != nil {
		return core.NewAppError(core.ErrValidationError, err.Error())
	}
	return nil
}

// NewApp creates a configured Fiber v3 application with all middleware and routes.
func NewApp(deps *Deps) *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler:    errorHandler,
		StructValidator: &structValidator{validate: validator.New()},
		BodyLimit:       512 * 1024, // 512 KB
		ReadTimeout:     10 * time.Second,
		WriteTimeout:    10 * time.Second,
		// Fiber's default router emits 501 Not Implemented for any
		// HTTP verb it doesn't recognize (QUERY, LINK, UNLINK, PURGE,
		// LOCK, etc.), short-circuiting the ErrorHandler below. That
		// confuses fuzzers (schemathesis) and clients because the
		// convention for "method known but not allowed on this
		// resource" is 405, not 501. Register the non-standard verbs
		// here so the router treats them as "known but unhandled"
		// and surfaces fiber.ErrMethodNotAllowed — which errorHandler
		// translates to our typed 405 envelope below.
		RequestMethods: append([]string{}, extendedRequestMethods...),
	})

	// Health check — before middleware so probes skip logging/CORS/headers.
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Swagger UI at /docs — registered before the middleware stack so
	// the JSON-API CSP (default-src 'none') does not reach the docs
	// page. The middleware only matches /docs*; other requests fall
	// through to the normal chain below.
	registerDocs(app)

	// Middleware stack.
	app.Use(recover.New())
	app.Use(requestLogger(deps.Config))
	// F-008: explicit CORS allowlist. Wildcard is only allowed when
	// GETLICENSE_ENV=development; prod boots refuse to start without
	// GETLICENSE_ALLOWED_ORIGINS. Authorization header is echoed
	// because dashboards send Bearer tokens from browser origins.
	app.Use(cors.New(cors.Config{
		AllowOrigins:     deps.Config.AllowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-Environment"},
		AllowCredentials: false,
		MaxAge:           86400,
	}))
	app.Use(securityHeadersMiddleware(deps.Config))

	// Register all API routes.
	registerRoutes(app, deps)

	return app
}

// errorHandler converts errors to structured JSON responses.
//
// Ordering matters: match the most-specific error types first. The
// fiber.Error branch runs last among the typed checks so that, for
// example, a 413 from the BodyLimit middleware lands on its own case
// rather than being collapsed into the generic validation_error bucket.
func errorHandler(c fiber.Ctx, err error) error {
	// Handle AppError (domain errors).
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		return c.Status(appErr.HTTPStatus()).JSON(appErr)
	}

	// F-010: JSON parse errors from c.Bind().Body() — wrong shape,
	// bare scalars, numeric overflow. Default errorHandler used to
	// drop these into "unhandled error" → 500, which gave any
	// authenticated caller a DoS primitive on every write endpoint.
	// Map them to validation_error with its canonical 422 status —
	// previously this path hard-coded 400, which drifted from
	// validator-level failures and let two functionally identical
	// mistakes (bad JSON shape vs. failing a `validate:` tag) land
	// on different status codes.
	var jsonSyntaxErr *json.SyntaxError
	var jsonTypeErr *json.UnmarshalTypeError
	if errors.As(err, &jsonSyntaxErr) || errors.As(err, &jsonTypeErr) {
		wrapped := core.NewAppError(core.ErrValidationError, "Invalid request body")
		return c.Status(wrapped.HTTPStatus()).JSON(wrapped)
	}

	// F-016: Postgres rejects 0x00 in text columns (SQLSTATE 22021).
	// Treat the encoding-error class as a client bug instead of a
	// 500 server error. Same 422 routing as the JSON-shape branch
	// above — both are "your request body failed validation".
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "22021" {
		wrapped := core.NewAppError(core.ErrValidationError, "Invalid byte sequence in request body")
		return c.Status(wrapped.HTTPStatus()).JSON(wrapped)
	}

	// Handle Fiber errors (e.g. 404 Not Found, 413 Payload Too Large).
	var fe *fiber.Error
	if errors.As(err, &fe) {
		// F-017: the body-limit middleware returns 413 here — map to
		// the typed request_too_large code so clients can distinguish
		// "payload too big" from generic validation.
		if fe.Code == fiber.StatusRequestEntityTooLarge {
			wrapped := core.NewAppError(core.ErrRequestTooLarge, "Request body exceeds size limit")
			return c.Status(fe.Code).JSON(wrapped)
		}
		// Router match-miss on a known path but unsupported verb —
		// surface as the typed method_not_allowed 405 so fuzzers and
		// clients see a consistent error envelope instead of a Fiber
		// default plaintext body. Paired with the extended
		// RequestMethods config above, this also catches non-standard
		// verbs like QUERY / LINK / UNLINK.
		if fe.Code == fiber.StatusMethodNotAllowed {
			wrapped := core.NewAppError(core.ErrMethodNotAllowed, "Method not allowed on this resource")
			return c.Status(fe.Code).JSON(wrapped)
		}
		wrapped := core.NewAppError(core.ErrValidationError, fe.Message)
		return c.Status(fe.Code).JSON(wrapped)
	}

	// Fallback: internal server error.
	slog.Error("unhandled error", "error", err.Error())
	fallback := core.NewAppError(core.ErrInternalError, "Internal server error")
	return c.Status(fiber.StatusInternalServerError).JSON(fallback)
}

// requestLogger logs each HTTP request with method, path, status, and latency.
func requestLogger(cfg *Config) fiber.Handler {
	return func(c fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		latency := time.Since(start)

		status := c.Response().StatusCode()
		attrs := []any{
			"method", c.Method(),
			"path", c.Path(),
			"status", status,
			"latency_ms", latency.Milliseconds(),
		}

		switch {
		case status >= 500:
			slog.Error("request", attrs...)
		case status >= 400:
			slog.Warn("request", attrs...)
		default:
			slog.Info("request", attrs...)
		}

		return err
	}
}

// securityHeadersMiddleware sets standard security response headers.
// F-009: adds Referrer-Policy, Permissions-Policy, and CSP. HSTS is
// only set in production because local development uses plain HTTP.
func securityHeadersMiddleware(cfg *Config) fiber.Handler {
	isDev := cfg.IsDevelopment()
	return func(c fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Cache-Control", "no-store")
		c.Set("X-API-Version", "1")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Permissions-Policy", "interest-cohort=()")
		// JSON API returns no HTML; deny every content source by default
		// and forbid framing entirely. Does nothing useful on its own
		// for a JSON response but hardens browser handling if a client
		// ever mishandles Content-Type.
		c.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if !isDev {
			// HSTS is meaningless over HTTP — only set in prod where
			// the API is reachable over HTTPS. 1-year max-age with
			// includeSubDomains is the conventional baseline.
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		return c.Next()
	}
}
