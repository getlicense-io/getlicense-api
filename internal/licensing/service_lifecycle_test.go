package licensing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/audit"
	"github.com/getlicense-io/getlicense-api/internal/core"
)

// --- Suspend / Revoke / Reinstate tests ---

func TestSuspend_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusSuspended, suspended.Status)
}

func TestSuspend_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Revoke first, then try to suspend.
	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestRevoke_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)

	stored := env.licenses.byID[created.License.ID]
	assert.Equal(t, core.LicenseStatusRevoked, stored.Status)
}

func TestReinstate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)

	reinstated, err := env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusActive, reinstated.Status)
}

func TestReinstate_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{Customer: inlineCustomer("user@example.com")}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, audit.Attribution{})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseInvalidTransition, appErr.Code)
}
