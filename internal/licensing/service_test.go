package licensing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/getlicense-io/getlicense-api/internal/core"
	"github.com/getlicense-io/getlicense-api/internal/crypto"
	"github.com/getlicense-io/getlicense-api/internal/domain"
)

// --- mock TxManager (passthrough) ---

type mockTxManager struct{}

func (m *mockTxManager) WithTenant(_ context.Context, _ core.AccountID, fn func(context.Context) error) error {
	return fn(context.Background())
}

func (m *mockTxManager) WithTx(_ context.Context, fn func(context.Context) error) error {
	return fn(context.Background())
}

// --- mock ProductRepository ---

type mockProductRepo struct {
	byID map[core.ProductID]*domain.Product
}

func newMockProductRepo() *mockProductRepo {
	return &mockProductRepo{byID: make(map[core.ProductID]*domain.Product)}
}

func (r *mockProductRepo) Create(_ context.Context, p *domain.Product) error {
	r.byID[p.ID] = p
	return nil
}

func (r *mockProductRepo) GetByID(_ context.Context, id core.ProductID) (*domain.Product, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (r *mockProductRepo) List(_ context.Context, _, _ int) ([]domain.Product, int, error) {
	return nil, 0, nil
}

func (r *mockProductRepo) Update(_ context.Context, _ core.ProductID, _ domain.UpdateProductParams) (*domain.Product, error) {
	return nil, nil
}

func (r *mockProductRepo) Delete(_ context.Context, _ core.ProductID) error {
	return nil
}

// --- mock LicenseRepository ---

type mockLicenseRepo struct {
	byID      map[core.LicenseID]*domain.License
	byKeyHash map[string]*domain.License
	list      []*domain.License
}

func newMockLicenseRepo() *mockLicenseRepo {
	return &mockLicenseRepo{
		byID:      make(map[core.LicenseID]*domain.License),
		byKeyHash: make(map[string]*domain.License),
	}
}

func (r *mockLicenseRepo) Create(_ context.Context, l *domain.License) error {
	r.byID[l.ID] = l
	r.byKeyHash[l.KeyHash] = l
	r.list = append(r.list, l)
	return nil
}

func (r *mockLicenseRepo) GetByID(_ context.Context, id core.LicenseID) (*domain.License, error) {
	l, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return l, nil
}

func (r *mockLicenseRepo) GetByKeyHash(_ context.Context, keyHash string) (*domain.License, error) {
	l, ok := r.byKeyHash[keyHash]
	if !ok {
		return nil, nil
	}
	return l, nil
}

func (r *mockLicenseRepo) List(_ context.Context, limit, offset int) ([]domain.License, int, error) {
	total := len(r.list)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := make([]domain.License, end-offset)
	for i, l := range r.list[offset:end] {
		out[i] = *l
	}
	return out, total, nil
}

func (r *mockLicenseRepo) UpdateStatus(_ context.Context, id core.LicenseID, status core.LicenseStatus) error {
	l, ok := r.byID[id]
	if !ok {
		return errors.New("not found")
	}
	l.Status = status
	return nil
}

func (r *mockLicenseRepo) ExpireActive(_ context.Context) ([]domain.License, error) {
	return nil, nil
}

// --- mock MachineRepository ---

type machineKey struct {
	licenseID   core.LicenseID
	fingerprint string
}

type mockMachineRepo struct {
	byKey map[machineKey]*domain.Machine
}

func newMockMachineRepo() *mockMachineRepo {
	return &mockMachineRepo{
		byKey: make(map[machineKey]*domain.Machine),
	}
}

func (r *mockMachineRepo) Create(_ context.Context, m *domain.Machine) error {
	key := machineKey{licenseID: m.LicenseID, fingerprint: m.Fingerprint}
	r.byKey[key] = m
	return nil
}

func (r *mockMachineRepo) GetByFingerprint(_ context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	key := machineKey{licenseID: licenseID, fingerprint: fingerprint}
	m, ok := r.byKey[key]
	if !ok {
		return nil, nil
	}
	return m, nil
}

func (r *mockMachineRepo) CountByLicense(_ context.Context, licenseID core.LicenseID) (int, error) {
	count := 0
	for k := range r.byKey {
		if k.licenseID == licenseID {
			count++
		}
	}
	return count, nil
}

func (r *mockMachineRepo) DeleteByFingerprint(_ context.Context, licenseID core.LicenseID, fingerprint string) error {
	key := machineKey{licenseID: licenseID, fingerprint: fingerprint}
	if _, ok := r.byKey[key]; !ok {
		return core.NewAppError(core.ErrMachineNotFound, "Machine not found")
	}
	delete(r.byKey, key)
	return nil
}

func (r *mockMachineRepo) UpdateHeartbeat(_ context.Context, licenseID core.LicenseID, fingerprint string) (*domain.Machine, error) {
	key := machineKey{licenseID: licenseID, fingerprint: fingerprint}
	m, ok := r.byKey[key]
	if !ok {
		return nil, core.NewAppError(core.ErrMachineNotFound, "Machine not found")
	}
	now := time.Now().UTC()
	m.LastSeenAt = &now
	return m, nil
}

// --- test helpers ---

func testMasterKey(t *testing.T) *crypto.MasterKey {
	t.Helper()
	mk, err := crypto.NewMasterKey("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	require.NoError(t, err)
	return mk
}

// createTestProduct creates an encrypted product in the mock repo and returns it.
func createTestProduct(t *testing.T, repo *mockProductRepo, mk *crypto.MasterKey, accountID core.AccountID) *domain.Product {
	t.Helper()

	pub, priv, err := crypto.GenerateEd25519Keypair()
	require.NoError(t, err)

	privEnc, err := crypto.EncryptAESGCM(mk.EncryptionKey, priv)
	require.NoError(t, err)

	product := &domain.Product{
		ID:            core.NewProductID(),
		AccountID:     accountID,
		Name:          "Test Product",
		Slug:          "test-product",
		PublicKey:     crypto.EncodePublicKey(pub),
		PrivateKeyEnc: privEnc,
		ValidationTTL: 86400,
		GracePeriod:   604800,
		CreatedAt:     time.Now().UTC(),
	}
	repo.byID[product.ID] = product
	return product
}

type testEnv struct {
	svc      *Service
	products *mockProductRepo
	licenses *mockLicenseRepo
	machines *mockMachineRepo
	mk       *crypto.MasterKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	mk := testMasterKey(t)
	products := newMockProductRepo()
	licenses := newMockLicenseRepo()
	machines := newMockMachineRepo()
	svc := NewService(&mockTxManager{}, licenses, products, machines, mk)
	return &testEnv{
		svc:      svc,
		products: products,
		licenses: licenses,
		machines: machines,
		mk:       mk,
	}
}

var testAccountID = core.NewAccountID()

// --- Create tests ---

func TestCreate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	result, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// License key is in the expected format.
	assert.True(t, strings.HasPrefix(result.LicenseKey, "GETL-"))
	assert.Len(t, result.LicenseKey, 19) // GETL-XXXX-XXXX-XXXX

	// License is persisted.
	assert.NotNil(t, result.License)
	assert.Equal(t, core.LicenseStatusActive, result.License.Status)
	assert.Equal(t, core.LicenseTypePerpetual, result.License.LicenseType)
	assert.Equal(t, testAccountID, result.License.AccountID)
	assert.Equal(t, product.ID, result.License.ProductID)

	// Token is non-empty.
	assert.True(t, strings.HasPrefix(result.License.Token, "gl1."))

	// Key hash is stored (HMAC of the full key).
	expectedHash := crypto.HMACSHA256(env.mk.HMACKey, result.LicenseKey)
	assert.Equal(t, expectedHash, result.License.KeyHash)

	// Prefix matches the first 9 chars.
	assert.Equal(t, result.LicenseKey[:9], result.License.KeyPrefix)

	// Stored in repo.
	stored, ok := env.licenses.byID[result.License.ID]
	require.True(t, ok)
	assert.Equal(t, result.License.KeyHash, stored.KeyHash)
}

func TestCreate_WithOptionalFields(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	maxM := 5
	maxS := 10
	ent := json.RawMessage(`{"feature":"pro"}`)
	name := "Alice"
	email := "alice@example.com"
	exp := time.Now().Add(30 * 24 * time.Hour).UTC()

	result, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType:   "timed",
		MaxMachines:   &maxM,
		MaxSeats:      &maxS,
		Entitlements:  &ent,
		LicenseeName:  &name,
		LicenseeEmail: &email,
		ExpiresAt:     &exp,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, core.LicenseTypeTimed, result.License.LicenseType)
	assert.Equal(t, &maxM, result.License.MaxMachines)
	assert.Equal(t, &maxS, result.License.MaxSeats)
	assert.JSONEq(t, `{"feature":"pro"}`, string(result.License.Entitlements))
	assert.Equal(t, &name, result.License.LicenseeName)
	assert.Equal(t, &email, result.License.LicenseeEmail)
	assert.NotNil(t, result.License.ExpiresAt)
}

func TestCreate_InvalidLicenseType(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	_, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "bogus",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestCreate_ProductNotFound(t *testing.T) {
	env := newTestEnv(t)

	unknownProductID := core.NewProductID()
	_, err := env.svc.Create(context.Background(), testAccountID, unknownProductID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

// --- Get tests ---

func TestGet_NotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Get(context.Background(), testAccountID, core.NewLicenseID())
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestGet_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	found, err := env.svc.Get(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.License.ID, found.ID)
}

// --- Validate tests ---

func TestValidate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
	assert.Equal(t, created.License.ID, result.License.ID)
}

func TestValidate_InvalidKey(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Validate(context.Background(), "GETL-FAKE-FAKE-FAKE")
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrInvalidLicenseKey, appErr.Code)
}

func TestValidate_ExpiredLicense(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	past := time.Now().Add(-1 * time.Hour)
	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "timed",
		ExpiresAt:   &past,
	})
	require.NoError(t, err)

	_, err = env.svc.Validate(context.Background(), created.LicenseKey)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

// --- Suspend / Revoke / Reinstate tests ---

func TestSuspend_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusSuspended, suspended.Status)
}

func TestSuspend_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	// Revoke first, then try to suspend.
	err = env.svc.Revoke(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestRevoke_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	err = env.svc.Revoke(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)

	// Verify in repo.
	stored := env.licenses.byID[created.License.ID]
	assert.Equal(t, core.LicenseStatusRevoked, stored.Status)
}

func TestRevoke_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	// Revoke it.
	err = env.svc.Revoke(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)

	// Try to revoke again -- already revoked.
	err = env.svc.Revoke(context.Background(), testAccountID, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

func TestReinstate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	// Suspend first.
	_, err = env.svc.Suspend(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)

	// Reinstate.
	reinstated, err := env.svc.Reinstate(context.Background(), testAccountID, created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusActive, reinstated.Status)
}

func TestReinstate_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	// Try to reinstate an active license (not suspended).
	_, err = env.svc.Reinstate(context.Background(), testAccountID, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// --- Activate tests ---

func TestActivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	maxM := 3
	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
		MaxMachines: &maxM,
	})
	require.NoError(t, err)

	machine, err := env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-abc-123",
	})
	require.NoError(t, err)
	require.NotNil(t, machine)
	assert.Equal(t, "fp-abc-123", machine.Fingerprint)
	assert.Equal(t, created.License.ID, machine.LicenseID)
	assert.Equal(t, testAccountID, machine.AccountID)
}

func TestActivate_DuplicateFingerprint(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	maxM := 3
	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
		MaxMachines: &maxM,
	})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	})
	require.NoError(t, err)

	// Activate again with same fingerprint.
	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineAlreadyActivated, appErr.Code)
}

func TestActivate_MachineLimitExceeded(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	maxM := 2
	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
		MaxMachines: &maxM,
	})
	require.NoError(t, err)

	// Fill up the machine limit.
	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-1",
	})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-2",
	})
	require.NoError(t, err)

	// Third activation should fail.
	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-3",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineLimitExceeded, appErr.Code)
}

func TestActivate_LicenseNotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Activate(context.Background(), testAccountID, core.NewLicenseID(), ActivateRequest{
		Fingerprint: "fp-orphan",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestActivate_NoMachineLimit(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	// No MaxMachines set -- should allow unlimited activations.
	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	for i := range 5 {
		fp := "fp-" + string(rune('a'+i))
		_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}
}

// --- Deactivate tests ---

func TestDeactivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-remove",
	})
	require.NoError(t, err)

	err = env.svc.Deactivate(context.Background(), testAccountID, created.License.ID, DeactivateRequest{
		Fingerprint: "fp-remove",
	})
	require.NoError(t, err)

	// Verify machine is gone.
	key := machineKey{licenseID: created.License.ID, fingerprint: "fp-remove"}
	_, ok := env.machines.byKey[key]
	assert.False(t, ok)
}

func TestDeactivate_EmptyFingerprint(t *testing.T) {
	env := newTestEnv(t)

	err := env.svc.Deactivate(context.Background(), testAccountID, core.NewLicenseID(), DeactivateRequest{
		Fingerprint: "",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrValidationError, appErr.Code)
}

// --- Heartbeat tests ---

func TestHeartbeat_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	created, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
		LicenseType: "perpetual",
	})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, created.License.ID, ActivateRequest{
		Fingerprint: "fp-heartbeat",
	})
	require.NoError(t, err)

	machine, err := env.svc.Heartbeat(context.Background(), testAccountID, created.License.ID, HeartbeatRequest{
		Fingerprint: "fp-heartbeat",
	})
	require.NoError(t, err)
	require.NotNil(t, machine)
	assert.NotNil(t, machine.LastSeenAt)
}

func TestHeartbeat_MachineNotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Heartbeat(context.Background(), testAccountID, core.NewLicenseID(), HeartbeatRequest{
		Fingerprint: "fp-unknown",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineNotFound, appErr.Code)
}

// --- List tests ---

func TestList_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)

	for range 3 {
		_, err := env.svc.Create(context.Background(), testAccountID, product.ID, CreateRequest{
			LicenseType: "perpetual",
		})
		require.NoError(t, err)
	}

	licenses, total, err := env.svc.List(context.Background(), testAccountID, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, licenses, 3)
}
