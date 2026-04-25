package handler

import (
	"errors"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// ctxWithAuth constructs a *fiber.Ctx with the given AuthContext
// seeded on Locals under the same key RequireAuth uses. Uses Fiber v3's
// AcquireCtx API against a fasthttp.RequestCtx so the tests stay narrow
// on the helper's behavior without spinning up a full app + routes.
func ctxWithAuth(t *testing.T, app *fiber.App, auth *middleware.AuthContext) fiber.Ctx {
	t.Helper()
	fctx := &fasthttp.RequestCtx{}
	c := app.AcquireCtx(fctx)
	if auth != nil {
		c.Locals("auth", auth)
	}
	t.Cleanup(func() { app.ReleaseCtx(c) })
	return c
}

func TestApplyAPIKeyProductScope_NilAuthIsNoOp(t *testing.T) {
	app := fiber.New()
	c := ctxWithAuth(t, app, nil)

	var filters domain.LicenseListFilters
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	assert.Nil(t, filters.ProductID)
}

func TestApplyAPIKeyProductScope_IdentityCallerUnchanged(t *testing.T) {
	app := fiber.New()
	iid := core.NewIdentityID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:  middleware.ActorKindIdentity,
		IdentityID: &iid,
	})

	var filters domain.LicenseListFilters
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	assert.Nil(t, filters.ProductID, "identity caller must not get auto-scope injection")
}

func TestApplyAPIKeyProductScope_IdentityCallerWithExplicitFilterKept(t *testing.T) {
	// Identity callers can explicitly pass `?product_id=` — that filter
	// must survive the scope check untouched.
	app := fiber.New()
	iid := core.NewIdentityID()
	explicitPID := core.NewProductID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:  middleware.ActorKindIdentity,
		IdentityID: &iid,
	})

	filters := domain.LicenseListFilters{ProductID: &explicitPID}
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	require.NotNil(t, filters.ProductID)
	assert.Equal(t, explicitPID, *filters.ProductID)
}

func TestApplyAPIKeyProductScope_AccountWideKeyUnchanged(t *testing.T) {
	app := fiber.New()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeAccountWide,
	})

	var filters domain.LicenseListFilters
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	assert.Nil(t, filters.ProductID, "account-wide API key must not get auto-scope injection")
}

func TestApplyAPIKeyProductScope_AccountWideKeyExplicitFilterKept(t *testing.T) {
	app := fiber.New()
	explicitPID := core.NewProductID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeAccountWide,
	})

	filters := domain.LicenseListFilters{ProductID: &explicitPID}
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	require.NotNil(t, filters.ProductID)
	assert.Equal(t, explicitPID, *filters.ProductID)
}

func TestApplyAPIKeyProductScope_ProductKeyInjectsWhenFilterAbsent(t *testing.T) {
	app := fiber.New()
	boundPID := core.NewProductID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &boundPID,
	})

	var filters domain.LicenseListFilters
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	require.NotNil(t, filters.ProductID)
	assert.Equal(t, boundPID, *filters.ProductID)
}

func TestApplyAPIKeyProductScope_ProductKeyAllowsMatchingExplicitFilter(t *testing.T) {
	app := fiber.New()
	boundPID := core.NewProductID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &boundPID,
	})

	same := boundPID
	filters := domain.LicenseListFilters{ProductID: &same}
	require.NoError(t, applyAPIKeyProductScope(c, &filters))
	require.NotNil(t, filters.ProductID)
	assert.Equal(t, boundPID, *filters.ProductID)
}

func TestApplyAPIKeyProductScope_ProductKeyRejectsMismatchingExplicitFilter(t *testing.T) {
	app := fiber.New()
	boundPID := core.NewProductID()
	otherPID := core.NewProductID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &boundPID,
	})

	filters := domain.LicenseListFilters{ProductID: &otherPID}
	err := applyAPIKeyProductScope(c, &filters)
	require.Error(t, err)
	var ae *core.AppError
	require.True(t, errors.As(err, &ae))
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, ae.Code)
}

func TestApplyAPIKeyProductScope_ProductKeyNilProductIDRejects(t *testing.T) {
	// Defensive: scope says "product" but APIKeyProductID is nil.
	app := fiber.New()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeProduct,
		// APIKeyProductID intentionally nil
	})

	var filters domain.LicenseListFilters
	err := applyAPIKeyProductScope(c, &filters)
	require.Error(t, err)
	var ae *core.AppError
	require.True(t, errors.As(err, &ae))
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, ae.Code)
}

// --- Events helper ---

func TestApplyEventAPIKeyProductScope_NilAuthIsNoOp(t *testing.T) {
	app := fiber.New()
	c := ctxWithAuth(t, app, nil)

	var filter domain.DomainEventFilter
	require.NoError(t, applyEventAPIKeyProductScope(c, &filter))
	assert.Nil(t, filter.RestrictToLicenseProductID)
}

func TestApplyEventAPIKeyProductScope_IdentityCallerUnchanged(t *testing.T) {
	app := fiber.New()
	iid := core.NewIdentityID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:  middleware.ActorKindIdentity,
		IdentityID: &iid,
	})

	var filter domain.DomainEventFilter
	require.NoError(t, applyEventAPIKeyProductScope(c, &filter))
	assert.Nil(t, filter.RestrictToLicenseProductID, "identity caller must not get auto-scope injection")
}

func TestApplyEventAPIKeyProductScope_AccountWideKeyUnchanged(t *testing.T) {
	app := fiber.New()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeAccountWide,
	})

	var filter domain.DomainEventFilter
	require.NoError(t, applyEventAPIKeyProductScope(c, &filter))
	assert.Nil(t, filter.RestrictToLicenseProductID, "account-wide API key must not get auto-scope injection")
}

func TestApplyEventAPIKeyProductScope_ProductKeyInjects(t *testing.T) {
	app := fiber.New()
	boundPID := core.NewProductID()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		APIKeyScope:     core.APIKeyScopeProduct,
		APIKeyProductID: &boundPID,
	})

	var filter domain.DomainEventFilter
	require.NoError(t, applyEventAPIKeyProductScope(c, &filter))
	require.NotNil(t, filter.RestrictToLicenseProductID)
	assert.Equal(t, boundPID, *filter.RestrictToLicenseProductID)
}

func TestApplyEventAPIKeyProductScope_ProductKeyNilProductIDRejects(t *testing.T) {
	app := fiber.New()
	c := ctxWithAuth(t, app, &middleware.AuthContext{
		ActorKind:   middleware.ActorKindAPIKey,
		APIKeyScope: core.APIKeyScopeProduct,
		// APIKeyProductID intentionally nil
	})

	var filter domain.DomainEventFilter
	err := applyEventAPIKeyProductScope(c, &filter)
	require.Error(t, err)
	var ae *core.AppError
	require.True(t, errors.As(err, &ae))
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, ae.Code)
}
