package licensing

import (
	"context"
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

func (m *mockTxManager) WithTargetAccount(_ context.Context, _ core.AccountID, _ core.Environment, fn func(context.Context) error) error {
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

func (r *mockProductRepo) List(_ context.Context, _ core.Cursor, _ int) ([]domain.Product, bool, error) {
	return nil, false, nil
}

func (r *mockProductRepo) Update(_ context.Context, _ core.ProductID, _ domain.UpdateProductParams) (*domain.Product, error) {
	return nil, nil
}

func (r *mockProductRepo) Delete(_ context.Context, _ core.ProductID) error {
	return nil
}

// --- mock PolicyRepository ---

type mockPolicyRepo struct {
	byID     map[core.PolicyID]*domain.Policy
	defaults map[core.ProductID]core.PolicyID
}

func newMockPolicyRepo() *mockPolicyRepo {
	return &mockPolicyRepo{
		byID:     make(map[core.PolicyID]*domain.Policy),
		defaults: make(map[core.ProductID]core.PolicyID),
	}
}

func (r *mockPolicyRepo) Create(_ context.Context, p *domain.Policy) error {
	r.byID[p.ID] = p
	if p.IsDefault {
		r.defaults[p.ProductID] = p.ID
	}
	return nil
}

func (r *mockPolicyRepo) Get(_ context.Context, id core.PolicyID) (*domain.Policy, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return p, nil
}

func (r *mockPolicyRepo) GetByProduct(_ context.Context, _ core.ProductID, _ core.Cursor, _ int) ([]domain.Policy, bool, error) {
	return nil, false, nil
}

func (r *mockPolicyRepo) GetDefaultForProduct(_ context.Context, productID core.ProductID) (*domain.Policy, error) {
	id, ok := r.defaults[productID]
	if !ok {
		return nil, nil
	}
	p := r.byID[id]
	return p, nil
}

func (r *mockPolicyRepo) Update(_ context.Context, p *domain.Policy) error {
	r.byID[p.ID] = p
	return nil
}

func (r *mockPolicyRepo) Delete(_ context.Context, id core.PolicyID) error {
	delete(r.byID, id)
	return nil
}

func (r *mockPolicyRepo) SetDefault(_ context.Context, _ core.ProductID, _ core.PolicyID) error {
	return nil
}

func (r *mockPolicyRepo) ReassignLicensesFromPolicy(_ context.Context, _, _ core.PolicyID) (int, error) {
	return 0, nil
}

func (r *mockPolicyRepo) CountReferencingLicenses(_ context.Context, _ core.PolicyID) (int, error) {
	return 0, nil
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

func (r *mockLicenseRepo) BulkCreate(ctx context.Context, licenses []*domain.License) error {
	for _, l := range licenses {
		if err := r.Create(ctx, l); err != nil {
			return err
		}
	}
	return nil
}

func (r *mockLicenseRepo) GetByID(_ context.Context, id core.LicenseID) (*domain.License, error) {
	l, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	return l, nil
}

func (r *mockLicenseRepo) GetByIDForUpdate(_ context.Context, id core.LicenseID) (*domain.License, error) {
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

// mockLicenseListMatches mirrors the domain filter semantics so tests
// that drive filters through the service exercise the same narrowing
// the real repo does.
func mockLicenseListMatches(l *domain.License, f domain.LicenseListFilters) bool {
	if f.Status != "" && l.Status != f.Status {
		return false
	}
	if f.Q != "" {
		needle := strings.ToLower(f.Q)
		hay := strings.ToLower(l.KeyPrefix)
		if l.LicenseeName != nil {
			hay += " " + strings.ToLower(*l.LicenseeName)
		}
		if l.LicenseeEmail != nil {
			hay += " " + strings.ToLower(*l.LicenseeEmail)
		}
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

func (r *mockLicenseRepo) Update(_ context.Context, l *domain.License) error {
	existing, ok := r.byID[l.ID]
	if !ok {
		return errors.New("not found")
	}
	existing.PolicyID = l.PolicyID
	existing.Overrides = l.Overrides
	existing.ExpiresAt = l.ExpiresAt
	existing.FirstActivatedAt = l.FirstActivatedAt
	existing.LicenseeName = l.LicenseeName
	existing.LicenseeEmail = l.LicenseeEmail
	existing.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *mockLicenseRepo) UpdateStatus(_ context.Context, id core.LicenseID, _, to core.LicenseStatus) (time.Time, error) {
	l, ok := r.byID[id]
	if !ok {
		return time.Time{}, errors.New("not found")
	}
	l.Status = to
	return time.Now().UTC(), nil
}

func (r *mockLicenseRepo) CountByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}

func (r *mockLicenseRepo) CountsByProductStatus(_ context.Context, _ core.ProductID) (domain.LicenseStatusCounts, error) {
	return domain.LicenseStatusCounts{}, nil
}

func (r *mockLicenseRepo) BulkRevokeByProduct(_ context.Context, _ core.ProductID) (int, error) {
	return 0, nil
}

func (r *mockLicenseRepo) List(_ context.Context, filters domain.LicenseListFilters, _ core.Cursor, limit int) ([]domain.License, bool, error) {
	matched := make([]*domain.License, 0, len(r.list))
	for _, l := range r.list {
		if mockLicenseListMatches(l, filters) {
			matched = append(matched, l)
		}
	}
	hasMore := len(matched) > limit
	if hasMore {
		matched = matched[:limit]
	}
	out := make([]domain.License, len(matched))
	for i, l := range matched {
		out[i] = *l
	}
	return out, hasMore, nil
}

func (r *mockLicenseRepo) ListByProduct(_ context.Context, productID core.ProductID, filters domain.LicenseListFilters, _ core.Cursor, limit int) ([]domain.License, bool, error) {
	matched := make([]*domain.License, 0, len(r.list))
	for _, l := range r.list {
		if l.ProductID != productID {
			continue
		}
		if !mockLicenseListMatches(l, filters) {
			continue
		}
		matched = append(matched, l)
	}
	hasMore := len(matched) > limit
	if hasMore {
		matched = matched[:limit]
	}
	out := make([]domain.License, len(matched))
	for i, l := range matched {
		out[i] = *l
	}
	return out, hasMore, nil
}

func (r *mockLicenseRepo) HasBlocking(_ context.Context) (bool, error) { return false, nil }

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

	privEnc, err := mk.Encrypt(priv)
	require.NoError(t, err)

	product := &domain.Product{
		ID:            core.NewProductID(),
		AccountID:     accountID,
		Name:          "Test Product",
		Slug:          "test-product",
		PublicKey:     crypto.EncodePublicKey(pub),
		PrivateKeyEnc: privEnc,
		CreatedAt:     time.Now().UTC(),
	}
	repo.byID[product.ID] = product
	return product
}

// seedDefaultPolicy inserts a default policy for the given product with
// the provided tweaks applied. The returned policy is stored in the mock
// and registered as the product's default.
func seedDefaultPolicy(t *testing.T, repo *mockPolicyRepo, accountID core.AccountID, productID core.ProductID, tweak func(p *domain.Policy)) *domain.Policy {
	t.Helper()
	now := time.Now().UTC()
	p := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      "Default",
		IsDefault:                 true,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	if tweak != nil {
		tweak(p)
	}
	require.NoError(t, repo.Create(context.Background(), p))
	return p
}

type testEnv struct {
	svc      *Service
	products *mockProductRepo
	policies *mockPolicyRepo
	licenses *mockLicenseRepo
	machines *mockMachineRepo
	mk       *crypto.MasterKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	mk := testMasterKey(t)
	products := newMockProductRepo()
	policies := newMockPolicyRepo()
	licenses := newMockLicenseRepo()
	machines := newMockMachineRepo()
	svc := NewService(&mockTxManager{}, licenses, products, machines, policies, mk, nil)
	return &testEnv{
		svc:      svc,
		products: products,
		policies: policies,
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
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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

	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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

	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, result.License.ExpiresAt)
	assert.Nil(t, result.License.FirstActivatedAt)
}

func TestCreate_ProductNotFound(t *testing.T) {
	env := newTestEnv(t)

	unknownProductID := core.NewProductID()
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, unknownProductID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrProductNotFound, appErr.Code)
}

// --- AllowedPolicyIDs (grant allowlist) tests ---

// seedNonDefaultPolicy creates an additional policy attached to the
// same product without flipping the default flag.
func seedNonDefaultPolicy(t *testing.T, repo *mockPolicyRepo, accountID core.AccountID, productID core.ProductID) *domain.Policy {
	t.Helper()
	now := time.Now().UTC()
	p := &domain.Policy{
		ID:                        core.NewPolicyID(),
		AccountID:                 accountID,
		ProductID:                 productID,
		Name:                      "Alt",
		IsDefault:                 false,
		ExpirationStrategy:        core.ExpirationStrategyRevokeAccess,
		ExpirationBasis:           core.ExpirationBasisFromCreation,
		ComponentMatchingStrategy: core.ComponentMatchingAny,
		CheckoutIntervalSec:       86400,
		MaxCheckoutDurationSec:    604800,
		CreatedAt:                 now,
		UpdatedAt:                 now,
	}
	repo.byID[p.ID] = p
	return p
}

func TestCreateLicense_AllowedPolicyIDs_EmptyAllows(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	// Nil allowlist — any policy permitted.
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   nil,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Empty-but-non-nil allowlist — same semantics as nil.
	result2, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{
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
	_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{
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
	result, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{
		CreatedByAccountID: testAccountID,
		AllowedPolicyIDs:   []core.PolicyID{def.ID},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, def.ID, result.License.PolicyID)
}

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

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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

func TestValidate_RevokeAccessExpiredLicense(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.ExpirationStrategy = core.ExpirationStrategyRevokeAccess
	})

	past := time.Now().Add(-1 * time.Hour)
	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		ExpiresAt: &past,
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
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	result, err := env.svc.Validate(context.Background(), created.LicenseKey)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Valid)
}

// --- Suspend / Revoke / Reinstate tests ---

func TestSuspend_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	suspended, err := env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusSuspended, suspended.Status)
}

func TestSuspend_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Revoke first, then try to suspend.
	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestRevoke_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	err = env.svc.Revoke(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)

	stored := env.licenses.byID[created.License.ID]
	assert.Equal(t, core.LicenseStatusRevoked, stored.Status)
}

func TestReinstate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Suspend(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)

	reinstated, err := env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.NoError(t, err)
	assert.Equal(t, core.LicenseStatusActive, reinstated.Status)
}

func TestReinstate_InvalidTransition(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Reinstate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseInvalidTransition, appErr.Code)
}

// --- Activate tests ---

func TestActivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	machine, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
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
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-dup",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineAlreadyActivated, appErr.Code)
}

func TestActivate_MachineLimitExceeded_FromPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	maxM := 2
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &maxM
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for _, fp := range []string{"fp-1", "fp-2"} {
		_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-3",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrMachineLimitExceeded, appErr.Code)
}

func TestActivate_MachineLimitFromOverrideBeatsPolicy(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	// Policy caps at 1 but the per-license override raises it to 3.
	policyCap := 1
	overrideCap := 3
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.MaxMachines = &policyCap
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{
		Overrides: domain.LicenseOverrides{MaxMachines: &overrideCap},
	}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for _, fp := range []string{"fp-a", "fp-b", "fp-c"} {
		_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}
}

func TestActivate_LicenseNotFound(t *testing.T) {
	env := newTestEnv(t)

	_, err := env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), ActivateRequest{
		Fingerprint: "fp-orphan",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseNotFound, appErr.Code)
}

func TestActivate_RevokedLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	// Force the license into a revoked state directly in the mock so
	// Activate hits the terminal-status guard before any policy lookup.
	env.licenses.byID[created.License.ID].Status = core.LicenseStatusRevoked

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-revoked",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseRevoked, appErr.Code)
}

func TestActivate_SuspendedLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	env.licenses.byID[created.License.ID].Status = core.LicenseStatusSuspended

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-suspended",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseSuspended, appErr.Code)
}

func TestActivate_ExpiredLicense_ReturnsError(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	env.licenses.byID[created.License.ID].Status = core.LicenseStatusExpired

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-expired",
	})
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrLicenseExpired, appErr.Code)
}

func TestActivate_NoMachineLimit(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	for i := range 5 {
		fp := "fp-" + string(rune('a'+i))
		_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
			Fingerprint: fp,
		})
		require.NoError(t, err)
	}
}

func TestActivate_FromFirstActivation_StampsFirstActivatedAtAndExpiresAt(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	dur := 7 * 24 * 60 * 60
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, func(p *domain.Policy) {
		p.DurationSeconds = &dur
		p.ExpirationBasis = core.ExpirationBasisFromFirstActivation
	})

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)
	assert.Nil(t, created.License.ExpiresAt)

	before := time.Now().UTC()
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-first",
	})
	require.NoError(t, err)
	after := time.Now().UTC()

	stored := env.licenses.byID[created.License.ID]
	require.NotNil(t, stored.FirstActivatedAt)
	assert.True(t, !stored.FirstActivatedAt.Before(before) && !stored.FirstActivatedAt.After(after))
	require.NotNil(t, stored.ExpiresAt)
	assert.True(t, stored.ExpiresAt.After(before.Add(time.Duration(dur)*time.Second - time.Second)))

	// A second activation must not re-stamp first_activated_at.
	origStamp := *stored.FirstActivatedAt
	time.Sleep(2 * time.Millisecond)
	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-second",
	})
	require.NoError(t, err)
	assert.Equal(t, origStamp, *stored.FirstActivatedAt)
}

// --- Deactivate tests ---

func TestDeactivate_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-remove",
	})
	require.NoError(t, err)

	err = env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, DeactivateRequest{
		Fingerprint: "fp-remove",
	})
	require.NoError(t, err)

	key := machineKey{licenseID: created.License.ID, fingerprint: "fp-remove"}
	_, ok := env.machines.byKey[key]
	assert.False(t, ok)
}

func TestDeactivate_EmptyFingerprint(t *testing.T) {
	env := newTestEnv(t)

	err := env.svc.Deactivate(context.Background(), testAccountID, core.EnvironmentLive, core.NewLicenseID(), DeactivateRequest{
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
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.Activate(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, ActivateRequest{
		Fingerprint: "fp-heartbeat",
	})
	require.NoError(t, err)

	machine, err := env.svc.Heartbeat(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, HeartbeatRequest{
		Fingerprint: "fp-heartbeat",
	})
	require.NoError(t, err)
	require.NotNil(t, machine)
	assert.NotNil(t, machine.LastSeenAt)
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

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
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

	created, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
	require.NoError(t, err)

	_, err = env.svc.AttachPolicy(context.Background(), testAccountID, core.EnvironmentLive, created.License.ID, otherPolicy.ID, false)
	require.Error(t, err)

	var appErr *core.AppError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, core.ErrPolicyProductMismatch, appErr.Code)
}

// --- List tests ---

func TestList_HappyPath(t *testing.T) {
	env := newTestEnv(t)
	product := createTestProduct(t, env.products, env.mk, testAccountID)
	seedDefaultPolicy(t, env.policies, testAccountID, product.ID, nil)

	for range 3 {
		_, err := env.svc.Create(context.Background(), testAccountID, core.EnvironmentLive, product.ID, CreateRequest{}, CreateOptions{CreatedByAccountID: testAccountID})
		require.NoError(t, err)
	}

	licenses, hasMore, err := env.svc.List(context.Background(), testAccountID, core.EnvironmentLive, domain.LicenseListFilters{}, core.Cursor{}, 10)
	require.NoError(t, err)
	assert.False(t, hasMore)
	assert.Len(t, licenses, 3)
}
