package server

import (
	"errors"
	"log/slog"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/recover"

	"github.com/getlicense-io/getlicense-api/internal/core"
)

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
	})

	// Health check — before middleware so probes skip logging/CORS/headers.
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Middleware stack.
	app.Use(recover.New())
	app.Use(requestLogger(deps.Config))
	app.Use(cors.New())
	app.Use(securityHeaders)

	// Register all API routes.
	registerRoutes(app, deps)

	return app
}

// errorHandler converts errors to structured JSON responses.
func errorHandler(c fiber.Ctx, err error) error {
	// Handle AppError (domain errors).
	var appErr *core.AppError
	if errors.As(err, &appErr) {
		return c.Status(appErr.HTTPStatus()).JSON(appErr)
	}

	// Handle Fiber errors (e.g. 404 Not Found, 400 Bad Request).
	var fe *fiber.Error
	if errors.As(err, &fe) {
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

// securityHeaders sets standard security response headers.
func securityHeaders(c fiber.Ctx) error {
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set("X-Frame-Options", "DENY")
	c.Set("Cache-Control", "no-store")
	c.Set("X-API-Version", "1")
	return c.Next()
}
