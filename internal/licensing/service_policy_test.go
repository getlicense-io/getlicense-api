package licensing

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- Update tests ---

func TestUpdate_ReassignCustomer(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("original@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	newCustomer := seedCustomer(t, env, testAccountID, "replacement@example.com", nil)

	updated, err := env.svc.Update(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, UpdateRequest{
		CustomerID: customerIDPtr(newCustomer.ID),
	})
	require.NoError(t, err)
	assert.Equal(t, newCustomer.ID, updated.CustomerID)
}

func TestUpdate_ReassignCustomer_AccountMismatch_Returns422(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("original@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Seed a customer under a DIFFERENT account.
	otherAccountID := core.NewAccountID()
	foreign := seedCustomer(t, env, otherAccountID, "foreign@example.com", nil)

	_, err = env.svc.Update(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, UpdateRequest{
		CustomerID: customerIDPtr(foreign.ID),
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrCustomerAccountMismatch, appErr.Code)
}

func TestUpdate_RejectsOverrideTTLBelowMin(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Customer: inlineCustomer("user@example.com"),
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	too := 30
	_, err = env.svc.Update(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, UpdateRequest{
		Overrides: &domain.LicenseOverrides{ValidationTTLSec: &too},
	})
	require.Error(t, err)
	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyInvalidTTL, appErr.Code)
}

// --- Freeze + AttachPolicy tests ---

func TestFreeze_SnapshotsEffectiveOverrides(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 5
	checkout := 3600
	maxCheckout := 7200
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
		p.CheckoutIntervalSec = checkout
		p.MaxCheckoutDurationSec = maxCheckout
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, created.License.Overrides.MaxMachines)

	frozen, err := env.svc.Freeze(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	require.NotNil(t, frozen)

	require.NotNil(t, frozen.Overrides.MaxMachines)
	assert.Equal(t, maxM, *frozen.Overrides.MaxMachines)
	require.NotNil(t, frozen.Overrides.CheckoutIntervalSec)
	assert.Equal(t, checkout, *frozen.Overrides.CheckoutIntervalSec)
	require.NotNil(t, frozen.Overrides.MaxCheckoutDurationSec)
	assert.Equal(t, maxCheckout, *frozen.Overrides.MaxCheckoutDurationSec)
}

func TestAttachPolicy_MovesLicense(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Second policy under the same product.
	newPolicy := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 testAccountID,
		ProductID:                 product.ID,
		Name:                      "Premium",
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		CreatedAt:                 time.Now().UTC(),
		UpdatedAt:                 time.Now().UTC(),
	}
	require.NoError(t, env.policies.Create(context.Background(), newPolicy))

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.AttachPolicy(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, newPolicy.ID, false)
	require.NoError(t, err)
	assert.Equal(t, newPolicy.ID, result.PolicyID)
}

func TestAttachPolicy_RejectsForeignProduct(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	otherProductID := core.NewProductID()
	otherPolicy := seedDefaultPolicy(t, env.policies, testAccountID, otherProductID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.AttachPolicy(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, otherPolicy.ID, false)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyProductMismatch, appErr.Code)
}
