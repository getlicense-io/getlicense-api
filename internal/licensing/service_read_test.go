package licensing

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

// --- Get tests ---

func TestGet_NotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Get(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID())
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestGet_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	found, err := env.svc.Get(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.License.ID, found.ID)
}

// --- Validate tests ---

func TestValidate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, created.License.ID, result.License.ID)
}

func TestValidate_ReMintsTokenWithCurrentEffectiveTTL(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	initialTTL := 600
	policySeeded := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ValidationTTLSec = &initialTTL
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Load the product's Ed25519 public key so we can verify the re-minted token.
	productRow, err := env.products.GetByID(context.Background(), product.ID)
	require.NoError(t, err)
	require.NotNil(t, productRow)
	privBytes, err := env.mk.Decrypt(productRow.PrivateKeyEnc, crypto.ProductPrivateKeyAAD(productRow.ID))
	require.NoError(t, err)
	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)

	// 1. Initial validate — mirror + signed claim both report 600.
	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.Equal(t, 600, result.ValidationTTLSec)
	claims, err := crypto.VerifyToken(result.License.Token, pub)
	require.NoError(t, err)
	assert.Equal(t, 600, claims.TTL)

	// 2. Bump policy TTL. The stored licenses.token is unchanged; only
	// Validate returns a freshly-minted token with the new value.
	newTTL := 900
	policySeeded.ValidationTTLSec = &newTTL
	require.NoError(t, env.policies.Update(context.Background(), policySeeded))

	result, err = env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.Equal(t, 900, result.ValidationTTLSec)
	claims, err = crypto.VerifyToken(result.License.Token, pub)
	require.NoError(t, err)
	assert.Equal(t, 900, claims.TTL)
}

func TestValidate_InvalidKey(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Validate(context.Background(), "GETL-FAKE-FAKE-FAKE")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvalidLicenseKey, appErr.Code)
}

func TestValidate_RevokeAccessExpiredLicense(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ExpirationStrategy = core.ExpirationStrategyRevokeAccess
	})

	past := time.Now().Add(-1 * time.Hour)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		ExpiresAt: &past,
		Customer:  inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Validate(context.Background(), created.LicenseKey)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestValidate_MaintainAccessIgnoresExpiry(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ExpirationStrategy = core.ExpirationStrategyMaintainAccess
	})

	past := time.Now().Add(-1 * time.Hour)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		ExpiresAt: &past,
		Customer:  inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
}

func TestValidate_ReturnsEntitlements(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	pol := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	entA := seedEntitlement(t, env, testAccountID, "OFFLINE_ACCESS")

	err := env.entitlementSvc.AttachToPolicy(context.Background(), pol.ID, []string{entA.Code}, testAccountID)
	require.NoError(t, err)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("validate-ent@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Seed the license → policy mapping.
	env.entitlements.SetLicensePolicy(created.License.ID, pol.ID)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, []string{"OFFLINE_ACCESS"}, result.Entitlements)
}

// --- List tests ---

func TestList_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	for range 3 {
		_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
		require.NoError(t, err)
	}

	licenses, hasMore, err := env.svc.List(context.Background(), testAccountID, core.EnvironmentLive, domain.LicenseListFilters{}, core.Cursor{}, 10)
	require.NoError(t, err)
	assert.False(t, hasMore)
	assert.Len(t, licenses, 3)
}

func TestList_SearchByCustomerEmail(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("target-search@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("someone-else@other.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	licenses, _, err := env.svc.List(context.Background(), testAccountID, core.EnvironmentLive, domain.LicenseListFilters{Q: "target-search"}, core.Cursor{}, 10)
	require.NoError(t, err)
	require.Len(t, licenses, 1)
}

// --- Product-scope gate tests (Frontend Unblock Batch - Task 12) ---
//
// These exercise the read-side gate paths:
//   - requireLicense (Get/List/ListMachines/transitionStatus)
//   - pre-tx ListByProduct/BulkRevokeForProduct gate
//
// Plus two pass-through cases (identity caller, account-wide API key).

func TestLicensing_ProductScopedKey_MismatchRejected_OnGet(t *testing.T) {
	env := newTestEnv(t)
	// License exists under product A (seedLicenseForListMachines mints a
	// fresh ProductID for the license).
	lic := seedLicenseForListMachines(t, env, nil)
	// Caller's API key is scoped to product B (different product).
	otherProductID := core.NewProductID()
	ctx := productScopedKeyCtx(otherProductID)

	_, err := env.svc.Get(ctx, testAccountID, core.EnvironmentLive, lic.ID)
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, appErr.Code)
}

func TestLicensing_ProductScopedKey_MatchAllowed_OnGet(t *testing.T) {
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil)
	// Caller's API key is scoped to the SAME product as the license.
	ctx := productScopedKeyCtx(lic.ProductID)

	found, err := env.svc.Get(ctx, testAccountID, core.EnvironmentLive, lic.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, lic.ID, found.ID)
}

func TestLicensing_IdentityCaller_NoGateFires(t *testing.T) {
	// Identity callers don't have an APIKeyScope. The gate must be a
	// no-op regardless of which license they touch.
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil)

	identityID := core.NewIdentityID()
	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:       middleware.ActorKindIdentity,
		IdentityID:      &identityID,
		ActingAccountID: testAccountID,
		TargetAccountID: testAccountID,
		Environment:     core.EnvironmentLive,
	})

	found, err := env.svc.Get(ctx, testAccountID, core.EnvironmentLive, lic.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, lic.ID, found.ID)
}

func TestLicensing_AccountWideKey_NoGateFires(t *testing.T) {
	// Account-wide API keys have APIKeyScope=account_wide; the gate
	// must pass regardless of the resource's product.
	env := newTestEnv(t)
	lic := seedLicenseForListMachines(t, env, nil)

	ctx := middleware.WithAuthForTest(context.Background(), &middleware.AuthContext{
		ActorKind:       middleware.ActorKindAPIKey,
		ActingAccountID: testAccountID,
		TargetAccountID: testAccountID,
		Environment:     core.EnvironmentLive,
		APIKeyScope:     core.APIKeyScopeAccountWide,
	})

	found, err := env.svc.Get(ctx, testAccountID, core.EnvironmentLive, lic.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, lic.ID, found.ID)
}

func TestLicensing_ProductScopedKey_MismatchRejected_OnListByProduct(t *testing.T) {
	// A product-scoped API key for product A must not be able to list
	// licenses on product B via GET /v1/products/{B}/licenses. The gate
	// fires pre-tx so the underlying ProductRepo / LicenseRepo are
	// never reached — confirmed by the empty product/license stores.
	env := newTestEnv(t)
	otherProductID := core.NewProductID()
	ctx := productScopedKeyCtx(otherProductID)

	// Path productID is a *different* product than the key is bound to.
	pathProductID := core.NewProductID()

	rows, hasMore, err := env.svc.ListByProduct(ctx, testAccountID, core.EnvironmentLive,
		pathProductID, domain.LicenseListFilters{}, core.Cursor{}, 50)
	require.Error(t, err)
	assert.Nil(t, rows)
	assert.False(t, hasMore)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, appErr.Code)
}

func TestLicensing_ProductScopedKey_MismatchRejected_OnBulkRevokeByProduct(t *testing.T) {
	// A product-scoped key for product A must not bulk-revoke licenses
	// on product B via DELETE /v1/products/{B}/licenses. Pre-tx gate.
	env := newTestEnv(t)
	otherProductID := core.NewProductID()
	ctx := productScopedKeyCtx(otherProductID)

	pathProductID := core.NewProductID()

	count, err := env.svc.BulkRevokeForProduct(ctx, testAccountID, core.EnvironmentLive, pathProductID)
	require.Error(t, err)
	assert.Equal(t, 0, count)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, appErr.Code)
}
