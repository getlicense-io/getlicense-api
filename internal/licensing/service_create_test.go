package licensing

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- Create tests ---

func TestCreate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, result)

	// License key is in the expected format.
	assert.True(t, strings.HasPrefix(result.LicenseKey, "GETL-"))
	assert.Len(t, result.LicenseKey, 19) // GETL-XXXX-XXXX-XXXX

	// License is persisted with the default policy attached.
	require.NotNil(t, result.License)
	assert.Equal(t, core.LicenseStatusActive, result.License.Status)
	assert.Equal(t, testAccountID, result.License.AccountID)
	assert.Equal(t, product.ID, result.License.ProductID)
	assert.NotEqual(t, core.PolicyID{}, result.License.PolicyID)

	// Token is non-empty and stored.
	assert.True(t, strings.HasPrefix(result.License.Token, "gl1."))

	// Key hash is stored (HMAC of the full key).
	expectedHash := env.mk.HMAC(result.LicenseKey)
	assert.Equal(t, expectedHash, result.License.KeyHash)

	// Prefix matches the first 9 chars.
	assert.Equal(t, result.LicenseKey[:9], result.License.KeyPrefix)

	// Stored in repo.
	stored, ok := env.licenses.byID[result.License.ID]
	require.True(t, ok)
	assert.Equal(t, result.License.KeyHash, stored.KeyHash)
}

func TestCreate_NoDefaultPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyNotFound, appErr.Code)
}

func TestCreate_ExplicitPolicyFromOtherProductRejected(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	otherProductID := core.NewProductID()
	otherPolicy := seedDefaultPolicy(t, env.policies, testAccountID, otherProductID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		PolicyID: &otherPolicy.ID,
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyProductMismatch, appErr.Code)
}

func TestCreate_FromCreation_StampsExpiresAtFromPolicyDuration(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 30 * 24 * 60 * 60 // 30 days
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromCreation
	})

	before := time.Now().UTC()
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	after := time.Now().UTC()

	require.NotNil(t, result.License.ExpiresAt)
	expectedMin := before.Add(time.Duration(dur) * time.Second)
	expectedMax := after.Add(time.Duration(dur) * time.Second)
	assert.True(t, !result.License.ExpiresAt.Before(expectedMin), "expires_at before expected min")
	assert.True(t, !result.License.ExpiresAt.After(expectedMax), "expires_at after expected max")
}

func TestCreate_FromFirstActivation_LeavesExpiresAtNil(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 30 * 24 * 60 * 60
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromFirstActivation
	})

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, result.License.ExpiresAt)
	assert.Nil(t, result.License.FirstActivatedAt)
}

func TestCreate_ProductNotFound(t *testing.T) {
	env := newTestEnv(t)

	unknownProductID := core.NewProductID()
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, unknownProductID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

// --- AllowedPolicyIDs (grant allowlist) tests ---

func TestCreateLicense_AllowedPolicyIDs_EmptyAllows(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Nil allowlist — any policy permitted.
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   nil,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Empty-but-non-nil allowlist — same semantics as nil.
	result2, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{},
	})
	require.NoError(t, err)
	require.NotNil(t, result2)
}

func TestCreateLicense_AllowedPolicyIDs_ExplicitPolicy_InSet(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	alt := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		PolicyID: &alt.ID,
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{alt.ID},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, alt.ID, result.License.PolicyID)
}

func TestCreateLicense_AllowedPolicyIDs_ExplicitPolicy_NotInSet(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	alt := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)
	other := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		PolicyID: &alt.ID,
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{other.ID},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantPolicyNotAllowed, appErr.Code)
}

func TestCreateLicense_AllowedPolicyIDs_DefaultPolicy_Resolved(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	def := seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// The caller omits PolicyID; the default resolves; the allowlist
	// contains a different ID; the check rejects.
	other := seedNonDefaultPolicy(t, env.policies, testAccountID, product.ID)
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{other.ID},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantPolicyNotAllowed, appErr.Code)

	// Same setup but the allowlist contains the default policy —
	// omitted req.PolicyID succeeds because the resolved default is
	// a member.
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{def.ID},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, def.ID, result.License.PolicyID)
}

// --- Customer integration tests (L4 Task 6) ---

func TestCreate_WithCustomerID(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	existing := seedCustomer(t, env, testAccountID, "alice@example.com", nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		CustomerID: customerIDPtr(existing.ID),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, existing.ID, result.License.CustomerID)
}

func TestCreate_WithInlineCustomer_NewEmail_CreatesRow(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("brand-new@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Customer row was inserted under the target account.
	c, err := env.customers.GetByEmail(context.Background(), testAccountID, "brand-new@example.com")
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, result.License.CustomerID, c.ID)
}

func TestCreate_WithInlineCustomer_ExistingEmail_ReusesRow(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	first, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("shared@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	second, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("shared@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Both licenses reference the same customer row — upsert hit the
	// existing row on the second call.
	assert.Equal(t, first.License.CustomerID, second.License.CustomerID)
}

func TestCreate_BothCustomerAndCustomerID_Returns422(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	existing := seedCustomer(t, env, testAccountID, "alice@example.com", nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		CustomerID: customerIDPtr(existing.ID),
		Customer:   inlineCustomer("alice@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrCustomerAmbiguous, appErr.Code)
}

func TestCreate_NeitherCustomerNorCustomerID_Returns422(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrCustomerRequired, appErr.Code)
}

func TestCreate_GrantScopedInline_SetsCreatedByAccountID(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	granteeAccountID := core.NewAccountID()
	grantID := core.NewGrantID()

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("grantee-inline@example.com"),
	}, CreateOptions{
		GrantID:            &grantID,
		CreatedByAccountID: granteeAccountID,
	})
	require.NoError(t, err)

	c, err := env.customers.GetByEmail(context.Background(), testAccountID, "grantee-inline@example.com")
	require.NoError(t, err)
	require.NotNil(t, c)
	require.NotNil(t, c.CreatedByAccountID)
	assert.Equal(t, granteeAccountID, *c.CreatedByAccountID)
}

func TestCreate_CustomerEmailPattern_Enforced(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Pattern rejects the inline email.
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@other.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)

	// Pattern accepts the matching email.
	_, err = env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.NoError(t, err)
}

// TestCreate_CustomerEmailPattern_Unanchored_IsAnchored is the
// regression test for the security fix that wraps the grantor-supplied
// pattern in full-match anchors. A pattern like `.*@example\.com`
// without an explicit trailing anchor should still match the intended
// "user@example.com" but MUST reject "user@example.com.evil.net" —
// which the prior unanchored regexp.MatchString silently allowed
// because the substring `@example.com` matched anywhere in the input.
func TestCreate_CustomerEmailPattern_Unanchored_IsAnchored(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Pattern lacking a trailing $ accepts the intended match — the
	// helper wraps with ^(?:...)$ so the .* prefix can absorb the
	// local-part.
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.NoError(t, err)

	// Same pattern MUST reject the substring-evasion attempt. Without
	// the helper's full-match anchors, the substring "@example.com"
	// would match anywhere in "user@example.com.evil.net" and the
	// grantor's intent (restrict to the example.com domain) would be
	// silently bypassed.
	_, err = env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com.evil.net"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `.*@example\.com`,
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

func TestCreate_CustomerEmailPattern_InvalidRegex_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{
		CreatedByAccountID:   testAccountID,
		CustomerEmailPattern: `[invalid(`,
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantConstraintViolated, appErr.Code)
}

// --- Entitlement integration tests (L3 Task 7) ---

func TestCreate_InlineEntitlements(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "CODE_A")
	seedEntitlement(t, env, testAccountID, "CODE_B")

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("inline-ent@example.com"),
		Entitlements: []string{"CODE_A", "CODE_B"},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify the entitlements were attached to the license.
	codes, err := env.entitlementSvc.ListLicenseCodes(context.Background(), created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"CODE_A", "CODE_B"}, codes)
}

func TestCreate_InlineEntitlements_AllowedCodesRejectsUnknown(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "ALLOWED")
	seedEntitlement(t, env, testAccountID, "FORBIDDEN")

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("restricted@example.com"),
		Entitlements: []string{"ALLOWED", "FORBIDDEN"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{"ALLOWED"},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantEntitlementNotAllowed, appErr.Code)
}

// --- Grant AllowedEntitlementCodes enforcement (L3 Task 8) ---

func TestCreateLicense_AllowedEntitlementCodes_Allowed(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "FEATURE_X")
	seedEntitlement(t, env, testAccountID, "FEATURE_Y")

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("allowed-ent@example.com"),
		Entitlements: []string{"FEATURE_X", "FEATURE_Y"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{"FEATURE_X", "FEATURE_Y"},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify entitlements were attached.
	codes, err := env.entitlementSvc.ListLicenseCodes(context.Background(), created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"FEATURE_X", "FEATURE_Y"}, codes)
}

func TestCreateLicense_AllowedEntitlementCodes_NotAllowed(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "APPROVED")
	seedEntitlement(t, env, testAccountID, "BLOCKED")

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("blocked-ent@example.com"),
		Entitlements: []string{"APPROVED", "BLOCKED"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{"APPROVED"},
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrGrantEntitlementNotAllowed, appErr.Code)
}

func TestCreateLicense_AllowedEntitlementCodes_Empty_AllowsAll(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	seedEntitlement(t, env, testAccountID, "ANY_CODE")
	seedEntitlement(t, env, testAccountID, "ANY_OTHER")

	// Empty AllowedEntitlementCodes means no constraint — all codes are permitted.
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:     inlineCustomer("unrestricted@example.com"),
		Entitlements: []string{"ANY_CODE", "ANY_OTHER"},
	}, CreateOptions{
		CreatedByAccountID:      testAccountID,
		AllowedEntitlementCodes: []string{},
	})
	require.NoError(t, err)
	require.NotNil(t, created)

	// Verify entitlements were attached.
	codes, err := env.entitlementSvc.ListLicenseCodes(context.Background(), created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"ANY_CODE", "ANY_OTHER"}, codes)
}

func TestCreate_RejectsOverrideTTLBelowMin(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	too := 10
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:  inlineCustomer("user@example.com"),
		Overrides: domain.LicenseOverrides{ValidationTTLSec: &too},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyInvalidTTL, appErr.Code)
}

func TestCreate_RejectsOverrideTTLAboveMax(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	tooBig := 2_592_001
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer:  inlineCustomer("user@example.com"),
		Overrides: domain.LicenseOverrides{ValidationTTLSec: &tooBig},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyInvalidTTL, appErr.Code)
}

// --- Product-scope gate test for Create ---

func TestLicensing_ProductScopedKey_MismatchRejected_OnCreate(t *testing.T) {
	// Exercises the pre-tx gate. Create takes productID directly from
	// the route, so the gate fires BEFORE any DB work or key pre-gen.
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Key scoped to a DIFFERENT product than the route path specifies.
	otherProductID := core.NewProductID()
	ctx := productScopedKeyCtx(otherProductID)

	_, err := env.svc.Create(ctx, testAccountID, core.EnvironmentLive, product.ID,
		CreateRequest{Customer: inlineCustomer("user@example.com")},
		CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrAPIKeyScopeMismatch, appErr.Code)
}
