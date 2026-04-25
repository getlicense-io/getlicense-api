package middleware_test

import (
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

func TestEnforceProductScope_NilAuthPasses(t *testing.T) {
	// Background jobs and unauthenticated paths have no auth in ctx.
	// The gate should be a no-op — auth checking is someone else's job.
	require.NoError(t, middleware.EnforceProductScope(context.Background(), core.NewProductID()))
}

func TestEnforceProductScope_IdentityCallerPasses(t *testing.T) {
	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind: middleware.ActorKindIdentity,
	})
	require.NoError(t, middleware.EnforceProductScope(ctx, core.NewProductID()))
}

func TestEnforceProductScope_AccountWideKeyPasses(t *testing.T) {
	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeAccountWide,
	})
	require.NoError(t, middleware.EnforceProductScope(ctx, core.NewProductID()))
}

func TestEnforceProductScope_ProductKeyMatchPasses(t *testing.T) {
	pid := core.NewProductID()
	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &pid,
	})
	require.NoError(t, middleware.EnforceProductScope(ctx, pid))
}

func TestEnforceProductScope_ProductKeyMismatchRejects(t *testing.T) {
	pid := core.NewProductID()
	other := core.NewProductID()
	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &pid,
	})
	err := middleware.EnforceProductScope(ctx, other)
	var ae *core.AppError
	require.True(t, errors.As(err, &ae))
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, ae.Code)
}

func TestEnforceProductScope_ProductKeyNilProductIDRejects(t *testing.T) {
	// Defensive: scope says "product" but APIKeyProductID is nil.
	// Should still reject — malformed state is not a free pass.
	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeProduct,
		// APIKeyProductID intentionally nil
	})
	err := middleware.EnforceProductScope(ctx, core.NewProductID())
	var ae *core.AppError
	require.True(t, errors.As(err, &ae))
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, ae.Code)
}

func TestRejectProductScopedKey_AllowsIdentity(t *testing.T) {
	app := fiber.New()
	// localsKeyAuth == "auth" (unexported in middleware package).
	app.Get("/protected", func(c fiber.Ctx) error {
		// Emulate RequireAuth setting an identity AuthContext on locals.
		c.Locals("auth", &middleware.AuthContext{ActorKind: middleware.ActorKindIdentity})
		return c.Next()
	}, middleware.RejectProductScopedKey(), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 200, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "ok", string(body))
}

func TestRejectProductScopedKey_AllowsAccountWideKey(t *testing.T) {
	app := fiber.New()
	app.Get("/protected", func(c fiber.Ctx) error {
		c.Locals("auth", &middleware.AuthContext{
			ActorKind:   middleware.ActorKindAPIKey,
			APIKeyScope: core.APIKeyScopeAccountWide,
		})
		return c.Next()
	}, middleware.RejectProductScopedKey(), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})
	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 200, resp.StatusCode)
}

func TestRejectProductScopedKey_RejectsProductScopedKey(t *testing.T) {
	pid := core.NewProductID()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c fiber.Ctx, err error) error {
			var ae *core.AppError
			if errors.As(err, &ae) {
				return c.Status(ae.HTTPStatus()).JSON(ae)
			}
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
	app.Get("/protected", func(c fiber.Ctx) error {
		c.Locals("auth", &middleware.AuthContext{
			ActorKind:       middleware.ActorKindAPIKey,
			APIKeyScope:     core.APIKeyScopeProduct,
			APIKeyProductID: &pid,
		})
		return c.Next()
	}, middleware.RejectProductScopedKey(), func(c fiber.Ctx) error {
		return c.SendString("ok")
	})
	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 403, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "api_key_scope_mismatch")
}
